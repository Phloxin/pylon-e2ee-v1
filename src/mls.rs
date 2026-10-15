//! The group protocol (plan section 5): settings shared by the node's delivery service (`ds`) and
//! every member (`client`). Both ends must agree on all of it, so it lives in one place.
//!
//! Every message crosses the wire as TLS-serialized MLS bytes:
//! - key packages as a bare `KeyPackage`;
//! - group infos, proposals, commits and welcomes as an `MlsMessage`;
//! - ratchet trees as a bare `RatchetTree`;
//! - the node's external sender as a bare `ExternalSender`.

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "ds")]
pub mod ds;
#[cfg(all(test, feature = "client", feature = "ds"))]
mod harness;
#[cfg(feature = "client")]
pub mod session;

use {
    openmls::prelude::{
        BasicCredential, Ciphersuite, Credential, CredentialType, ExternalSender, KeyPackage,
        KeyPackageIn, MlsMessageBodyIn, MlsMessageIn, ProtocolVersion, tls_codec::Deserialize as _,
    },
    openmls_rust_crypto::OpenMlsRustCrypto,
    openmls_traits::OpenMlsProvider as _,
};

/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (plan 5.9).
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

const VERSION: ProtocolVersion = ProtocolVersion::Mls10;

/// The credential identity format: `[1][client_id u64 BE]` in phase 1, `[2][client_id][device_id]`
/// once devices have persistent keys (plan 5.3). The DS only ever reads the client id.
const IDENTITY_V1: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsError {
    /// Bytes that don't decode as the MLS structure expected.
    Malformed,
    /// A key package that fails a check: signature, ciphersuite, lifetime or credential.
    InvalidKeyPackage,
    /// A credential that doesn't name the client it came from.
    WrongIdentity,
    /// There's no group, or the message is for another group or epoch.
    WrongGroup,
    /// A message that's valid MLS but breaks one of the plan's rules (5.3, 5.4).
    Rejected,
    /// openmls refused the message: a bad signature, tree or path.
    Invalid,
    /// A bug, or a crypto or storage failure.
    Internal,
}

impl MlsError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::InvalidKeyPackage => "invalid-key-package",
            Self::WrongIdentity => "wrong-identity",
            Self::WrongGroup => "wrong-group",
            Self::Rejected => "rejected",
            Self::Invalid => "invalid",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for MlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for MlsError {}

/// The credential identity bytes for `client_id`.
pub fn identity(client_id: u64) -> Vec<u8> {
    let mut identity = Vec::with_capacity(9);
    identity.push(IDENTITY_V1);
    identity.extend_from_slice(&client_id.to_be_bytes());
    identity
}

/// The client id a credential names, if it's a basic credential in a format we know.
pub fn client_id(credential: &Credential) -> Option<u64> {
    if credential.credential_type() != CredentialType::Basic {
        return None;
    }
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    match basic.identity() {
        [IDENTITY_V1, id @ ..] => Some(u64::from_be_bytes(id.try_into().ok()?)),
        _ => None,
    }
}

/// Whether two credentials name the same identity. A commit's path may not change it (5.3).
pub(crate) fn same_identity(a: &Credential, b: &Credential) -> bool {
    a.credential_type() == b.credential_type() && a.serialized_content() == b.serialized_content()
}

pub(crate) fn provider() -> OpenMlsRustCrypto {
    OpenMlsRustCrypto::default()
}

pub(crate) fn mls_message(bytes: &[u8]) -> Result<MlsMessageBodyIn, MlsError> {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map(MlsMessageIn::extract)
        .map_err(|_| MlsError::Malformed)
}

/// Decodes `GroupParams.external_sender`: the sender every group on a node must name.
#[cfg_attr(not(feature = "client"), allow(dead_code))]
pub(crate) fn external_sender(bytes: &[u8]) -> Result<ExternalSender, MlsError> {
    ExternalSender::tls_deserialize_exact(bytes).map_err(|_| MlsError::Malformed)
}

/// A key package that passed every check that needs no group state (plan 5.3).
#[derive(Debug, Clone)]
pub struct CheckedKeyPackage {
    #[cfg_attr(not(feature = "ds"), allow(dead_code))]
    pub(crate) key_package: KeyPackage,
    client_id: u64,
}

impl CheckedKeyPackage {
    pub fn client_id(&self) -> u64 {
        self.client_id
    }
}

/// Checks a key package's signature, ciphersuite, lifetime and credential, and that it belongs to
/// `client_id`. The session runs this before forwarding a key package, so a bad one fails the
/// request instead of vanishing inside the DS, and the DS runs it again.
pub fn check_key_package(bytes: &[u8], client_id: u64) -> Result<CheckedKeyPackage, MlsError> {
    let key_package = KeyPackageIn::tls_deserialize_exact(bytes)
        .map_err(|_| MlsError::Malformed)?
        .validate(provider().crypto(), VERSION)
        .map_err(|_| MlsError::InvalidKeyPackage)?;

    if key_package.ciphersuite() != CIPHERSUITE {
        return Err(MlsError::InvalidKeyPackage);
    }

    match self::client_id(key_package.leaf_node().credential()) {
        Some(id) if id == client_id => Ok(CheckedKeyPackage {
            key_package,
            client_id,
        }),
        _ => Err(MlsError::WrongIdentity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_round_trip() {
        for id in [0, 1, 0x0123_4567_89AB_CDEF, u64::MAX] {
            assert_eq!(identity(id).len(), 9);
            assert_eq!(
                client_id(&BasicCredential::new(identity(id)).into()),
                Some(id)
            );
        }
        assert_eq!(
            client_id(&BasicCredential::new(vec![2, 0, 0, 0, 0, 0, 0, 0, 1]).into()),
            None
        );
        assert_eq!(client_id(&BasicCredential::new(vec![1, 0, 0]).into()), None);
    }
}

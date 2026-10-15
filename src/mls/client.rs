//! One group member: the client's side of the group protocol (plan 5.3-5.5, 9.3). It holds at
//! most one group, checks what the node sends it (5.4), and commits with a path when it's the
//! designated committer. `Session` builds the frame keys on top of it.

use {
    crate::mls::{
        CIPHERSUITE, MlsError, client_id, external_sender, identity, mls_message, provider,
        same_identity,
    },
    openmls::prelude::{
        BasicCredential, Credential, CredentialWithKey, Extension, Extensions, ExternalSender,
        GroupId, KeyPackage, LeafNodeIndex, Lifetime, MlsGroup, MlsGroupCreateConfig,
        MlsGroupJoinConfig, MlsMessageBodyIn, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ProcessedMessageContent, Proposal, ProposalOrRefType, RatchetTreeIn, Sender, StagedWelcome,
        tls_codec::Deserialize as _,
    },
    openmls_basic_credential::SignatureKeyPair,
    openmls_rust_crypto::OpenMlsRustCrypto,
    openmls_traits::OpenMlsProvider as _,
    std::collections::HashSet,
};

const WEEK: u64 = 7 * 24 * 60 * 60;

/// Key packages handed out but not yet used. Only the newest few can still come back in a
/// `Welcome`; anything older belongs to a join that was abandoned.
const MAX_SIGNERS: usize = 8;

/// A week in the past to eleven weeks ahead (plan 5.9). openmls's default starts only an hour
/// back, which rejects anyone whose clock is more than an hour fast. The total stays inside
/// openmls's twelve weeks and an hour.
pub(crate) fn key_package_lifetime(now: u64) -> Lifetime {
    Lifetime::init(now.saturating_sub(WEEK), now + 11 * WEEK)
}

fn credential(client_id: u64) -> Credential {
    BasicCredential::new(identity(client_id)).into()
}

fn new_signer() -> Result<SignatureKeyPair, MlsError> {
    SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(|_| MlsError::Internal)
}

fn serialize(value: &impl tls_codec::Serialize) -> Result<Vec<u8>, MlsError> {
    value
        .tls_serialize_detached()
        .map_err(|_| MlsError::Internal)
}

/// What applying a commit did to this member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// Merged; this is the new epoch.
    Merged(u64),
    /// The commit removed this member, so it no longer has a group.
    Removed,
}

struct Group {
    mls: MlsGroup,
    signer: SignatureKeyPair,
    /// The commit this member uploaded in the current epoch, to recognise its echo.
    pending: Option<Vec<u8>>,
}

pub struct Member {
    client_id: u64,
    provider: OpenMlsRustCrypto,
    /// The node's external sender, from the channel's `GroupParams`. Every group must name it.
    external_sender: Option<ExternalSender>,
    /// One signature key per key package handed out, newest last. Each leaf gets its own, since
    /// a rejoin's commit removes the old leaf and adds the new one at once, and openmls forbids
    /// two leaves sharing a key.
    signers: Vec<SignatureKeyPair>,
    group: Option<Group>,
}

impl Member {
    pub fn new(client_id: u64) -> Self {
        Self {
            client_id,
            provider: provider(),
            external_sender: None,
            signers: Vec::new(),
            group: None,
        }
    }

    pub fn client_id(&self) -> u64 {
        self.client_id
    }

    /// The node's external sender, as `GroupParams.external_sender` carries it.
    pub fn set_external_sender(&mut self, encoded: &[u8]) -> Result<(), MlsError> {
        self.external_sender = Some(external_sender(encoded)?);
        Ok(())
    }

    fn credential_with_key(&self, signer: &SignatureKeyPair) -> CredentialWithKey {
        CredentialWithKey {
            credential: credential(self.client_id),
            signature_key: signer.to_public_vec().into(),
        }
    }

    /// A fresh key package to join (or rejoin) with. `now` is unix seconds.
    pub fn key_package(&mut self, now: u64) -> Result<Vec<u8>, MlsError> {
        let signer = new_signer()?;
        let bundle = KeyPackage::builder()
            .key_package_lifetime(key_package_lifetime(now))
            .build(
                CIPHERSUITE,
                &self.provider,
                &signer,
                self.credential_with_key(&signer),
            )
            .map_err(|_| MlsError::Internal)?;

        self.signers.push(signer);
        if self.signers.len() > MAX_SIGNERS {
            self.signers.remove(0);
        }
        serialize(bundle.key_package())
    }

    /// Founds the group the node asked for (`CreateGroup`), replacing any group this member had,
    /// and returns the signed group info with the ratchet tree for `GroupCreated`.
    pub fn found(&mut self, group_id: &[u8], now: u64) -> Result<Vec<u8>, MlsError> {
        let sender = self.external_sender.clone().ok_or(MlsError::WrongGroup)?;
        let extensions = Extensions::single(Extension::ExternalSenders(vec![sender]))
            .map_err(|_| MlsError::Internal)?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .lifetime(key_package_lifetime(now))
            .with_group_context_extensions(extensions)
            .build();

        let signer = new_signer()?;
        let mls = MlsGroup::new_with_group_id(
            &self.provider,
            &signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential_with_key(&signer),
        )
        .map_err(|_| MlsError::Internal)?;
        let info = mls
            .export_group_info(self.provider.crypto(), &signer, true)
            .map_err(|_| MlsError::Internal)?;
        let info = serialize(&info)?;

        self.replace(Group {
            mls,
            signer,
            pending: None,
        });
        Ok(info)
    }

    /// Joins from a `Welcome` with the ratchet tree the node served, replacing any group this
    /// member had. Returns the epoch joined.
    pub fn join(&mut self, welcome: &[u8], ratchet_tree: &[u8]) -> Result<u64, MlsError> {
        let MlsMessageBodyIn::Welcome(welcome) = mls_message(welcome)? else {
            return Err(MlsError::Malformed);
        };
        let tree =
            RatchetTreeIn::tls_deserialize_exact(ratchet_tree).map_err(|_| MlsError::Malformed)?;
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();

        let mut mls = StagedWelcome::build_from_welcome(&self.provider, &config, welcome)
            .map_err(|_| MlsError::Invalid)?
            .with_ratchet_tree(tree)
            .replace_old_group()
            .build()
            .map_err(|_| MlsError::Invalid)?
            .into_group(&self.provider)
            .map_err(|_| MlsError::Invalid)?;

        let checked = (|| {
            let sender = self.external_sender.as_ref().ok_or(MlsError::WrongGroup)?;
            let senders = mls.extensions().external_senders();
            if mls.ciphersuite() != CIPHERSUITE
                || senders.map(Vec::as_slice) != Some(std::slice::from_ref(sender))
            {
                return Err(MlsError::Rejected);
            }

            let leaf = mls.own_leaf_node().ok_or(MlsError::Internal)?;
            if client_id(leaf.credential()) != Some(self.client_id) {
                return Err(MlsError::WrongIdentity);
            }
            let key = leaf.signature_key().as_slice();
            let at = self
                .signers
                .iter()
                .position(|signer| signer.public() == key)
                .ok_or(MlsError::WrongGroup)?;
            Ok(self.signers.remove(at))
        })();

        let signer = match checked {
            Ok(signer) => signer,
            Err(err) => {
                let _ = mls.delete(self.provider.storage());
                return Err(err);
            }
        };

        let epoch = mls.epoch().as_u64();
        self.replace(Group {
            mls,
            signer,
            pending: None,
        });
        Ok(epoch)
    }

    fn replace(&mut self, group: Group) {
        self.leave();
        self.group = Some(group);
    }

    /// Drops the group, e.g. on a channel move.
    pub fn leave(&mut self) {
        if let Some(mut old) = self.group.take() {
            let _ = old.mls.delete(self.provider.storage());
        }
    }

    /// Takes the node's proposals for `epoch` (plan 5.4). Only Adds and Removes from the external
    /// sender are accepted, and no Add may bring in a client that keeps a leaf. Anything else is
    /// `Rejected`, and the caller rejoins.
    pub fn proposals(&mut self, epoch: u64, proposals: &[Vec<u8>]) -> Result<(), MlsError> {
        let provider = &self.provider;
        let group = self
            .group
            .as_mut()
            .filter(|group| group.mls.epoch().as_u64() == epoch)
            .ok_or(MlsError::WrongGroup)?;

        let checked = (|| {
            let mut queued = Vec::with_capacity(proposals.len());
            for bytes in proposals {
                let MlsMessageBodyIn::PublicMessage(public) = mls_message(bytes)? else {
                    return Err(MlsError::Malformed);
                };
                let processed = group
                    .mls
                    .process_message(provider, public)
                    .map_err(|_| MlsError::Invalid)?;
                if !matches!(processed.sender(), Sender::External(_)) {
                    return Err(MlsError::Rejected);
                }
                let ProcessedMessageContent::ProposalMessage(proposal) = processed.into_content()
                else {
                    return Err(MlsError::Rejected);
                };
                queued.push(*proposal);
            }

            let removed: HashSet<LeafNodeIndex> = queued
                .iter()
                .filter_map(|queued| match queued.proposal() {
                    Proposal::Remove(remove) => Some(remove.removed()),
                    _ => None,
                })
                .collect();
            let mut present: HashSet<u64> = group
                .mls
                .members()
                .filter(|member| !removed.contains(&member.index))
                .filter_map(|member| client_id(&member.credential))
                .collect();
            for queued in &queued {
                match queued.proposal() {
                    Proposal::Remove(_) => {}
                    Proposal::Add(add) => {
                        let id = client_id(add.key_package().leaf_node().credential())
                            .ok_or(MlsError::WrongIdentity)?;
                        if !present.insert(id) {
                            return Err(MlsError::Rejected);
                        }
                    }
                    _ => return Err(MlsError::Rejected),
                }
            }
            Ok(queued)
        })();

        let queued = match checked {
            Ok(queued) => queued,
            Err(err) => {
                let _ = group.mls.clear_pending_proposals(provider.storage());
                return Err(err);
            }
        };
        for proposal in queued {
            group
                .mls
                .store_pending_proposal(provider.storage(), proposal)
                .map_err(|_| MlsError::Internal)?;
        }
        Ok(())
    }

    /// Commits to the node's proposals, always with a path (plan 5.3), as the designated
    /// committer. Returns the commit and, if it adds anyone, the welcome. The commit only takes
    /// effect when the node echoes it back to `apply_commit`.
    pub fn commit(&mut self) -> Result<(Vec<u8>, Option<Vec<u8>>), MlsError> {
        self.commit_with(true)
    }

    /// A commit without a path when no proposal needs one, which the node must refuse.
    #[cfg(all(test, feature = "ds"))]
    pub(crate) fn commit_without_path(&mut self) -> Result<(Vec<u8>, Option<Vec<u8>>), MlsError> {
        self.commit_with(false)
    }

    fn commit_with(&mut self, path: bool) -> Result<(Vec<u8>, Option<Vec<u8>>), MlsError> {
        let provider = &self.provider;
        let group = self.group.as_mut().ok_or(MlsError::WrongGroup)?;
        if group.mls.pending_commit().is_some() {
            group
                .mls
                .clear_pending_commit(provider.storage())
                .map_err(|_| MlsError::Internal)?;
        }

        let bundle = group
            .mls
            .commit_builder()
            .consume_proposal_store(true)
            .force_self_update(path)
            .load_psks(provider.storage())
            .map_err(|_| MlsError::Internal)?
            .build(provider.rand(), provider.crypto(), &group.signer, |_| true)
            .map_err(|_| MlsError::Invalid)?
            .stage_commit(provider)
            .map_err(|_| MlsError::Internal)?;

        let (commit, welcome, _) = bundle.into_messages();
        let commit = serialize(&commit)?;
        let welcome = welcome.map(|welcome| serialize(&welcome)).transpose()?;
        group.pending = Some(commit.clone());
        Ok((commit, welcome))
    }

    /// Applies the commit the node accepted for `epoch` (plan 5.3 Transition). Our own echo
    /// merges what we staged; anyone else's is checked (5.4: proposals by reference only, and
    /// the path keeps the committer's identity) and merged.
    pub fn apply_commit(&mut self, epoch: u64, commit: &[u8]) -> Result<Applied, MlsError> {
        let provider = &self.provider;
        let group = self
            .group
            .as_mut()
            .filter(|group| group.mls.epoch().as_u64() == epoch)
            .ok_or(MlsError::WrongGroup)?;

        if group.pending.take().as_deref() == Some(commit) {
            group
                .mls
                .merge_pending_commit(provider)
                .map_err(|_| MlsError::Internal)?;
            return Ok(Applied::Merged(group.mls.epoch().as_u64()));
        }
        if group.mls.pending_commit().is_some() {
            group
                .mls
                .clear_pending_commit(provider.storage())
                .map_err(|_| MlsError::Internal)?;
        }

        let MlsMessageBodyIn::PublicMessage(public) = mls_message(commit)? else {
            return Err(MlsError::Malformed);
        };
        let processed = group
            .mls
            .process_message(provider, public)
            .map_err(|_| MlsError::Invalid)?;
        let Sender::Member(leaf) = *processed.sender() else {
            return Err(MlsError::Rejected);
        };
        let committer = group.mls.member(leaf).cloned().ok_or(MlsError::Rejected)?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(MlsError::Rejected);
        };

        if staged
            .queued_proposals()
            .any(|proposal| proposal.proposal_or_ref_type() != ProposalOrRefType::Reference)
        {
            return Err(MlsError::Rejected);
        }
        let path_leaf = staged.update_path_leaf_node().ok_or(MlsError::Rejected)?;
        if !same_identity(path_leaf.credential(), &committer) {
            return Err(MlsError::WrongIdentity);
        }

        if staged.self_removed() {
            self.leave();
            return Ok(Applied::Removed);
        }
        group
            .mls
            .merge_staged_commit(provider, *staged)
            .map_err(|_| MlsError::Internal)?;
        Ok(Applied::Merged(group.mls.epoch().as_u64()))
    }

    pub fn epoch(&self) -> Option<u64> {
        self.group.as_ref().map(|group| group.mls.epoch().as_u64())
    }

    pub fn group_id(&self) -> Option<&[u8]> {
        self.group
            .as_ref()
            .map(|group| group.mls.group_id().as_slice())
    }

    /// The current epoch's frame root (plan 4). openmls only exports from the current epoch, so
    /// callers take it the moment they enter one.
    pub fn root(&self) -> Result<[u8; crate::key::ROOT_LEN], MlsError> {
        let group = self.group.as_ref().ok_or(MlsError::WrongGroup)?;
        group
            .mls
            .export_secret(
                self.provider.crypto(),
                crate::key::ROOT_LABEL,
                &[],
                crate::key::ROOT_LEN,
            )
            .map_err(|_| MlsError::Internal)?
            .try_into()
            .map_err(|_| MlsError::Internal)
    }

    /// The client ids in the group, which is who the participant list shows (plan 5.7).
    pub fn roster(&self) -> Vec<u64> {
        self.group.as_ref().map_or_else(Vec::new, |group| {
            group
                .mls
                .members()
                .filter_map(|member| client_id(&member.credential))
                .collect()
        })
    }

    /// The current epoch's authenticator, which the call code is made from (plan 5.7).
    pub fn epoch_authenticator(&self) -> Option<Vec<u8>> {
        self.group
            .as_ref()
            .map(|group| group.mls.epoch_authenticator().as_slice().to_vec())
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        self.leave();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_fits_openmls_range() {
        let lifetime = key_package_lifetime(1_800_000_000);
        assert!(lifetime.has_acceptable_range());
        assert_eq!(lifetime.not_before(), 1_800_000_000 - WEEK);
    }
}

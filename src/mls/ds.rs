//! The node's side of the group protocol (plan 5.1-5.3). The external sender turns joins and
//! leaves into signed Add and Remove proposals. `DsGroup` is a public view of one channel's group:
//! it checks every commit and serves the ratchet tree to joiners. It never holds a key that
//! decrypts media.
//!
//! What to propose, who commits and when the epoch switches is the caller's state machine (vsfu's
//! `group` module); this only does the MLS.

use {
    crate::mls::{
        CIPHERSUITE, CheckedKeyPackage, MlsError, client_id, mls_message, provider, same_identity,
    },
    openmls::ciphersuite::hash_ref::ProposalRef,
    openmls::prelude::{
        BasicCredential, ExternalProposal, ExternalSender, GroupId, LeafNodeIndex,
        MlsMessageBodyIn, MlsMessageOut, ProcessedMessageContent, ProposalOrRefType, ProposalStore,
        PublicGroup, Sender, SenderExtensionIndex, tls_codec::Serialize as _,
    },
    openmls_basic_credential::SignatureKeyPair,
    openmls_rust_crypto::OpenMlsRustCrypto,
    openmls_traits::OpenMlsProvider as _,
};

/// The node's external sender identity in every group it runs.
const NODE_IDENTITY: &[u8] = b"pylon-node";

/// The node's external sender (plan 5.1): an Ed25519 key generated at boot, never stored, that
/// only signs Add and Remove proposals.
pub struct ExternalSenderKey {
    signer: SignatureKeyPair,
    sender: ExternalSender,
    encoded: Vec<u8>,
}

impl ExternalSenderKey {
    pub fn generate() -> Result<Self, MlsError> {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|_| MlsError::Internal)?;
        let sender = ExternalSender::new(
            signer.to_public_vec().into(),
            BasicCredential::new(NODE_IDENTITY.to_vec()).into(),
        );
        let encoded = sender
            .tls_serialize_detached()
            .map_err(|_| MlsError::Internal)?;
        Ok(Self {
            signer,
            sender,
            encoded,
        })
    }

    /// The TLS-serialized `ExternalSender`, which the channel snapshot hands to clients
    /// (`GroupParams.external_sender`). The founder puts exactly this in `external_senders`.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

/// What a commit did, once checked and merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged {
    /// The epoch the commit created.
    pub epoch: u64,
    /// The welcome for the members it added, if it added any.
    pub welcome: Option<Vec<u8>>,
}

/// One channel's group, as the delivery service sees it.
pub struct DsGroup {
    group: PublicGroup,
    provider: OpenMlsRustCrypto,
    /// Proposals made in the current epoch. A commit must cover exactly these.
    pending: Vec<ProposalRef>,
}

impl DsGroup {
    /// Starts tracking a group from its founder's `GroupCreated` (plan 5.3 Founding), after
    /// checking it's the group this attempt asked for: the right id, epoch 0, the founder as the
    /// only member, and the node as the only external sender.
    pub fn found(
        group_info: &[u8],
        group_id: &[u8],
        founder: u64,
        sender: &ExternalSenderKey,
    ) -> Result<Self, MlsError> {
        let MlsMessageBodyIn::GroupInfo(info) = mls_message(group_info)? else {
            return Err(MlsError::Malformed);
        };
        if info.group_id().as_slice() != group_id || info.epoch().as_u64() != 0 {
            return Err(MlsError::WrongGroup);
        }
        if info.ciphersuite() != CIPHERSUITE {
            return Err(MlsError::Rejected);
        }
        let tree = info
            .extensions()
            .ratchet_tree()
            .ok_or(MlsError::Malformed)?
            .ratchet_tree()
            .clone();

        let provider = provider();
        let (group, _) = PublicGroup::from_external(
            provider.crypto(),
            provider.storage(),
            tree,
            info,
            ProposalStore::new(),
        )
        .map_err(|_| MlsError::Invalid)?;

        let ds = Self {
            group,
            provider,
            pending: Vec::new(),
        };

        let external_senders = ds.group.group_context().extensions().external_senders();
        if external_senders.map(Vec::as_slice) != Some(std::slice::from_ref(&sender.sender)) {
            return Err(MlsError::Rejected);
        }
        match ds.leaves().as_slice() {
            [(_, id)] if *id == founder => Ok(ds),
            [_] => Err(MlsError::WrongIdentity),
            _ => Err(MlsError::Rejected),
        }
    }

    pub fn group_id(&self) -> &[u8] {
        self.group.group_id().as_slice()
    }

    pub fn epoch(&self) -> u64 {
        self.group.group_context().epoch().as_u64()
    }

    /// Every leaf and the client it belongs to.
    pub fn leaves(&self) -> Vec<(u32, u64)> {
        self.group
            .members()
            .filter_map(|member| Some((member.index.u32(), client_id(&member.credential)?)))
            .collect()
    }

    /// The TLS-serialized ratchet tree, for joiners' `Welcome`s (plan 5.3 Transition).
    pub fn ratchet_tree(&self) -> Result<Vec<u8>, MlsError> {
        self.group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(|_| MlsError::Internal)
    }

    /// Signs a Remove for each leaf and an Add for each key package, queues them as this epoch's
    /// change, and returns the proposal messages to send to the members. Leaves that aren't in
    /// the group are skipped.
    pub fn propose(
        &mut self,
        sender: &ExternalSenderKey,
        removes: &[u32],
        adds: Vec<CheckedKeyPackage>,
    ) -> Result<Vec<Vec<u8>>, MlsError> {
        let group_id = GroupId::from_slice(self.group_id());
        let epoch = self.group.group_context().epoch();
        let index = SenderExtensionIndex::new(0);

        let mut messages = Vec::with_capacity(removes.len() + adds.len());
        for &leaf in removes {
            let leaf = LeafNodeIndex::new(leaf);
            if self.group.leaf(leaf).is_none() {
                continue;
            }
            let message = ExternalProposal::new_remove::<OpenMlsRustCrypto>(
                leaf,
                group_id.clone(),
                epoch,
                &sender.signer,
                index,
            )
            .map_err(|_| MlsError::Internal)?;
            messages.push(self.queue(message)?);
        }
        for add in adds {
            let message = ExternalProposal::new_add::<OpenMlsRustCrypto>(
                add.key_package,
                group_id.clone(),
                epoch,
                &sender.signer,
                index,
            )
            .map_err(|_| MlsError::Internal)?;
            messages.push(self.queue(message)?);
        }
        Ok(messages)
    }

    /// Runs one of our own proposals through the public group, so it's in the proposal store a
    /// commit is checked against.
    fn queue(&mut self, message: MlsMessageOut) -> Result<Vec<u8>, MlsError> {
        let bytes = message
            .tls_serialize_detached()
            .map_err(|_| MlsError::Internal)?;
        let MlsMessageBodyIn::PublicMessage(public) = mls_message(&bytes)? else {
            return Err(MlsError::Internal);
        };
        let processed = self
            .group
            .process_message(self.provider.crypto(), public)
            .map_err(|_| MlsError::Internal)?;
        let ProcessedMessageContent::ProposalMessage(proposal) = processed.into_content() else {
            return Err(MlsError::Internal);
        };

        self.pending.push(proposal.proposal_reference_ref().clone());
        self.group
            .add_proposal(self.provider.storage(), *proposal)
            .map_err(|_| MlsError::Internal)?;
        Ok(bytes)
    }

    /// Whether proposals are waiting for a commit.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Checks a commit from `committer` (plan 5.3 Commit validation) and merges it:
    /// - a PublicMessage for the current epoch, from `committer`'s leaf;
    /// - covering exactly this epoch's proposals, by reference, with nothing inline;
    /// - with a path, whose leaf keeps the committer's credential identity;
    /// - with a welcome exactly when it adds someone.
    pub fn commit(
        &mut self,
        committer: u64,
        commit: &[u8],
        welcome: Option<&[u8]>,
    ) -> Result<Merged, MlsError> {
        let MlsMessageBodyIn::PublicMessage(public) = mls_message(commit)? else {
            return Err(MlsError::Malformed);
        };
        if public.epoch() != self.group.group_context().epoch() {
            return Err(MlsError::WrongGroup);
        }
        let processed = self
            .group
            .process_message(self.provider.crypto(), public)
            .map_err(|_| MlsError::Invalid)?;

        let Sender::Member(leaf) = *processed.sender() else {
            return Err(MlsError::Rejected);
        };
        let committer_leaf = self.group.leaf(leaf).ok_or(MlsError::Rejected)?;
        if client_id(committer_leaf.credential()) != Some(committer) {
            return Err(MlsError::WrongIdentity);
        }
        let committer_credential = committer_leaf.credential().clone();

        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(MlsError::Rejected);
        };

        let mut covered = Vec::new();
        for proposal in staged.queued_proposals() {
            if proposal.proposal_or_ref_type() != ProposalOrRefType::Reference {
                return Err(MlsError::Rejected);
            }
            covered.push(proposal.proposal_reference_ref().clone());
        }
        if covered.len() != self.pending.len() || !covered.iter().all(|r| self.pending.contains(r))
        {
            return Err(MlsError::Rejected);
        }

        let path_leaf = staged.update_path_leaf_node().ok_or(MlsError::Rejected)?;
        if !same_identity(path_leaf.credential(), &committer_credential) {
            return Err(MlsError::WrongIdentity);
        }

        let adds = staged.add_proposals().count() > 0;
        let welcome = match (adds, welcome) {
            (true, Some(welcome)) => match mls_message(welcome)? {
                MlsMessageBodyIn::Welcome(_) => Some(welcome.to_vec()),
                _ => return Err(MlsError::Malformed),
            },
            (false, None) => None,
            _ => return Err(MlsError::Rejected),
        };

        self.group
            .merge_commit(self.provider.storage(), *staged)
            .map_err(|_| MlsError::Internal)?;
        self.pending.clear();

        Ok(Merged {
            epoch: self.epoch(),
            welcome,
        })
    }
}

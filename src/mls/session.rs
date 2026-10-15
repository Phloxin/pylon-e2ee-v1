//! Everything the client's E2EE worker holds (plan 9.1): the group member and the frame keys it
//! derives. The worker feeds it the node's group events and its own media frames; secrets never
//! leave it.
//!
//! Keys follow the plan's barrier (5.3): a member can decrypt an epoch as soon as it enters it
//! (founding, a `Welcome`, or merging a commit), but only sends under it after `Execute`. Old
//! epochs stay decryptable until `retire`, which the worker calls about 10 s after the `Execute`
//! that replaced them (plan 4).

use {
    crate::{
        Codec, Decryptor, Encryptor, Format, FrameError, Source,
        key::{ROOT_LEN, sender_key},
        mls::{
            CIPHERSUITE, MlsError,
            client::{Applied, Member},
        },
    },
    std::collections::HashMap,
};

/// Roots kept at most, in case the worker stops retiring them.
const MAX_ROOTS: usize = 4;

/// Digits in the call code (plan 5.7), shown in groups of five.
const CALL_CODE_GROUPS: usize = 6;

pub struct Session {
    member: Member,
    format: Option<Format>,
    encryptor: Encryptor,
    /// The frame root of every epoch this member can decrypt, oldest first.
    roots: Vec<(u64, [u8; ROOT_LEN])>,
    /// One per sender we've received from. Each holds that sender's key for every root.
    decryptors: HashMap<u64, Decryptor>,
    /// The epoch frames are sent under.
    sending: Option<u64>,
}

/// The trailer carries the low 8 bits of the epoch (plan 3.4).
fn epoch_byte(epoch: u64) -> u8 {
    epoch as u8
}

impl Session {
    /// `kid` and `counter` are this process's key slot and first counter value (plan 3.4).
    pub fn new(client_id: u64, kid: u8, counter: u32) -> Self {
        Self {
            member: Member::new(client_id),
            format: None,
            encryptor: Encryptor::new(kid, counter),
            roots: Vec::new(),
            decryptors: HashMap::new(),
            sending: None,
        }
    }

    pub fn client_id(&self) -> u64 {
        self.member.client_id()
    }

    /// The channel's `GroupParams`. Fails if this build can't speak the node's ciphersuite or
    /// frame format, which means the client needs an update (plan 5.8).
    pub fn set_params(
        &mut self,
        ciphersuite: u16,
        external_sender: &[u8],
        format: u8,
    ) -> Result<(), MlsError> {
        let format = Format::from_id(format).ok_or(MlsError::Rejected)?;
        if ciphersuite != u16::from(CIPHERSUITE) {
            return Err(MlsError::Rejected);
        }
        self.member.set_external_sender(external_sender)?;
        self.format = Some(format);
        Ok(())
    }

    /// A fresh key package (plan 5.3 Join, and every rejoin). `now` is unix seconds.
    pub fn key_package(&mut self, now: u64) -> Result<Vec<u8>, MlsError> {
        self.member.key_package(now)
    }

    /// Founds the group (`CreateGroup`) and returns the group info for `GroupCreated`. The
    /// founder is alone, so it sends at once.
    pub fn found(&mut self, group_id: &[u8], now: u64) -> Result<Vec<u8>, MlsError> {
        let info = self.member.found(group_id, now)?;
        self.forget_keys();
        let epoch = self.enter_epoch()?;
        self.execute(epoch)?;
        Ok(info)
    }

    /// Joins from a `Welcome` for `epoch`. Senders are still on the previous epoch, so this
    /// member keeps sending as before until `Execute`.
    pub fn join(
        &mut self,
        epoch: u64,
        welcome: &[u8],
        ratchet_tree: &[u8],
    ) -> Result<(), MlsError> {
        let previous = self.member.group_id().map(<[u8]>::to_vec);
        let joined = self.member.join(welcome, ratchet_tree)?;
        if joined != epoch {
            self.leave();
            return Err(MlsError::WrongGroup);
        }
        // A rejoin into the same group keeps the old epochs: everyone else still sends under
        // them until `Execute`. A different group's keys are useless.
        if previous.as_deref() != self.member.group_id() {
            self.forget_keys();
        }
        self.enter_epoch()?;
        Ok(())
    }

    /// The node's proposals for `epoch` (plan 5.4).
    pub fn proposals(&mut self, epoch: u64, proposals: &[Vec<u8>]) -> Result<(), MlsError> {
        self.member.proposals(epoch, proposals)
    }

    /// Commits as the designated committer: the commit, and a welcome if it adds anyone.
    pub fn commit(&mut self) -> Result<(Vec<u8>, Option<Vec<u8>>), MlsError> {
        self.member.commit()
    }

    /// Applies the commit the node accepted for `epoch`. Returns the new epoch, which the
    /// worker reports with `Ready`, or `None` if the commit removed this member.
    pub fn apply_commit(&mut self, epoch: u64, commit: &[u8]) -> Result<Option<u64>, MlsError> {
        match self.member.apply_commit(epoch, commit)? {
            Applied::Merged(_) => self.enter_epoch().map(Some),
            Applied::Removed => {
                self.leave();
                Ok(None)
            }
        }
    }

    /// Starts sending under `epoch` (`Execute`). Returns the epoch it replaces, which the worker
    /// retires a little later. Fails if this member never entered `epoch`.
    pub fn execute(&mut self, epoch: u64) -> Result<Option<u64>, MlsError> {
        let format = self.format.ok_or(MlsError::WrongGroup)?;
        let root = self.root(epoch).ok_or(MlsError::WrongGroup)?;
        let key = sender_key(&root, self.client_id());
        self.encryptor.set_key(format, epoch_byte(epoch), &key);
        Ok(self.sending.replace(epoch).filter(|old| *old != epoch))
    }

    /// Stops decrypting `epoch`. Never retires the epoch being sent under.
    pub fn retire(&mut self, epoch: u64) {
        if self.sending == Some(epoch) {
            return;
        }
        self.roots.retain(|(e, _)| *e != epoch);
        for decryptor in self.decryptors.values_mut() {
            decryptor.remove_key(epoch_byte(epoch));
        }
    }

    /// Drops the group and every key, e.g. on a channel move (plan 5.5) or a failed join.
    pub fn leave(&mut self) {
        self.member.leave();
        self.forget_keys();
    }

    fn forget_keys(&mut self) {
        self.roots.clear();
        self.decryptors.clear();
        self.encryptor.clear_key();
        self.sending = None;
    }

    fn root(&self, epoch: u64) -> Option<[u8; ROOT_LEN]> {
        self.roots
            .iter()
            .find(|(e, _)| *e == epoch)
            .map(|(_, root)| *root)
    }

    /// Takes the frame root of the epoch just entered (plan 4: one exporter call per epoch, the
    /// moment it's entered) and gives every known sender a key for it.
    fn enter_epoch(&mut self) -> Result<u64, MlsError> {
        let format = self.format.ok_or(MlsError::WrongGroup)?;
        let epoch = self.member.epoch().ok_or(MlsError::WrongGroup)?;
        let root = self.member.root()?;

        self.roots.retain(|(e, _)| *e != epoch);
        self.roots.push((epoch, root));
        while self.roots.len() > MAX_ROOTS {
            let sending = self.sending;
            let Some(at) = self.roots.iter().position(|(e, _)| Some(*e) != sending) else {
                break;
            };
            let (old, _) = self.roots.remove(at);
            for decryptor in self.decryptors.values_mut() {
                decryptor.remove_key(epoch_byte(old));
            }
        }
        for (sender, decryptor) in &mut self.decryptors {
            decryptor.set_key(format, epoch_byte(epoch), &sender_key(&root, *sender));
        }
        Ok(epoch)
    }

    pub fn encrypt(
        &mut self,
        codec: Codec,
        source: &Source,
        frame: &[u8],
    ) -> Result<Vec<u8>, FrameError> {
        self.encryptor.encrypt(codec, source, frame)
    }

    /// Decrypts a frame from `sender` (the sink's `ChannelSource.owner`).
    pub fn decrypt(
        &mut self,
        sender: u64,
        codec: Codec,
        source: &Source,
        frame: &[u8],
    ) -> Result<Vec<u8>, FrameError> {
        let format = self.format.ok_or(FrameError::NoKey)?;
        let roots = &self.roots;
        let decryptor = self.decryptors.entry(sender).or_insert_with(|| {
            let mut decryptor = Decryptor::new();
            for (epoch, root) in roots {
                decryptor.set_key(format, epoch_byte(*epoch), &sender_key(root, sender));
            }
            decryptor
        });
        decryptor.decrypt(codec, source, frame)
    }

    #[cfg(all(test, feature = "ds"))]
    pub(crate) fn member_mut(&mut self) -> &mut Member {
        &mut self.member
    }

    /// Forgets a sender's keys once nothing receives from it any more.
    pub fn forget_sender(&mut self, sender: u64) {
        self.decryptors.remove(&sender);
    }

    pub fn epoch(&self) -> Option<u64> {
        self.member.epoch()
    }

    pub fn sending_epoch(&self) -> Option<u64> {
        self.sending
    }

    /// The client ids in the MLS group: the participant list (plan 5.7).
    pub fn roster(&self) -> Vec<u64> {
        self.member.roster()
    }

    /// The call code (plan 5.7): 30 digits from the epoch authenticator, as six groups of five.
    /// Everyone in the same epoch of the same group sees the same code.
    pub fn call_code(&self) -> Option<String> {
        let authenticator = self.member.epoch_authenticator()?;
        let groups: Vec<String> = authenticator
            .as_chunks::<5>()
            .0
            .iter()
            .take(CALL_CODE_GROUPS)
            .map(|chunk| {
                let value = chunk
                    .iter()
                    .fold(0u64, |value, byte| value << 8 | u64::from(*byte));
                format!("{:05}", value % 100_000)
            })
            .collect();
        (groups.len() == CALL_CODE_GROUPS).then(|| groups.join(" "))
    }
}

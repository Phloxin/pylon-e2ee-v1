//! Phase 1a (plan section 11): the delivery service and several members in one process, run
//! through every flow of section 5 with no network. The node's real state machine (vsfu's
//! `group` module) sequences these same calls.

use {
    crate::{
        Codec, FrameError, Source,
        mls::{
            CIPHERSUITE, MlsError, check_key_package,
            ds::{DsGroup, ExternalSenderKey, Merged},
            session::Session,
        },
    },
    std::time::{SystemTime, UNIX_EPOCH},
};

const FORMAT: u8 = 1;
const HOUR: u64 = 60 * 60;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The node and the members of one channel. Members are indexed by position; their client id is
/// `100 + position` unless a test reuses one.
struct Call {
    sender: ExternalSenderKey,
    incarnation: u64,
    ds: Option<DsGroup>,
    members: Vec<Session>,
}

impl Call {
    fn new() -> Self {
        Self {
            sender: ExternalSenderKey::generate().unwrap(),
            incarnation: 0,
            ds: None,
            members: Vec::new(),
        }
    }

    fn session(&self, client_id: u64) -> Session {
        let mut session = Session::new(client_id, 0, 0, 1024);
        session
            .set_params(u16::from(CIPHERSUITE), self.sender.encoded(), FORMAT)
            .unwrap();
        session
    }

    fn ds(&mut self) -> &mut DsGroup {
        self.ds.as_mut().expect("no group")
    }

    /// Founds a new group from a new member, as after an empty roster or a refound.
    fn found(&mut self, client_id: u64) -> usize {
        self.incarnation += 1;
        let group_id = format!("channel:boot:{}", self.incarnation).into_bytes();
        let mut founder = self.session(client_id);
        let info = founder.found(&group_id, now()).unwrap();
        self.ds = Some(DsGroup::found(&info, &group_id, client_id, &self.sender).unwrap());
        self.members = vec![founder];
        0
    }

    fn leaf_of(&mut self, client_id: u64) -> u32 {
        self.ds()
            .leaves()
            .into_iter()
            .find(|(_, id)| *id == client_id)
            .map(|(leaf, _)| leaf)
            .expect("client has no leaf")
    }

    /// Runs one change through the whole flow (plan 5.3): proposals to the old roster, a commit
    /// from `committer`, the echo and `Ready`, welcomes to the joiners, then `Execute`.
    /// `removes` are positions in `members`; `joiners` are new sessions with a key package each.
    /// Removed members leave `members`; joiners are appended.
    fn change(&mut self, committer: usize, removes: &[usize], joiners: Vec<(Session, Vec<u8>)>) {
        let epoch = self.ds().epoch();
        let removed_leaves: Vec<u32> = removes
            .iter()
            .map(|&at| {
                let id = self.members[at].client_id();
                self.leaf_of(id)
            })
            .collect();
        let adds = joiners
            .iter()
            .map(|(session, kp)| check_key_package(kp, session.client_id()).unwrap())
            .collect();
        let proposals = self
            .ds
            .as_mut()
            .unwrap()
            .propose(&self.sender, &removed_leaves, adds)
            .unwrap();

        let staying: Vec<usize> = (0..self.members.len())
            .filter(|at| !removes.contains(at))
            .collect();
        for &at in &staying {
            self.members[at].proposals(epoch, &proposals).unwrap();
        }

        let (commit, welcome) = self.members[committer].commit().unwrap();
        let committer_id = self.members[committer].client_id();
        let Merged {
            epoch: new_epoch,
            welcome,
        } = self
            .ds()
            .commit(committer_id, &commit, welcome.as_deref())
            .unwrap();
        assert_eq!(new_epoch, epoch + 1);

        for &at in &staying {
            let ready = self.members[at].apply_commit(epoch, &commit).unwrap();
            assert_eq!(ready, Some(new_epoch));
        }

        let tree = self.ds().ratchet_tree().unwrap();
        let mut members: Vec<Session> = std::mem::take(&mut self.members)
            .into_iter()
            .enumerate()
            .filter(|(at, _)| !removes.contains(at))
            .map(|(_, session)| session)
            .collect();
        for (mut joiner, _) in joiners {
            joiner
                .join(new_epoch, welcome.as_deref().unwrap(), &tree)
                .unwrap();
            members.push(joiner);
        }
        for member in &mut members {
            member.execute(new_epoch).unwrap();
        }
        self.members = members;
    }

    fn join(&mut self, committer: usize, client_id: u64) -> usize {
        let mut joiner = self.session(client_id);
        let kp = joiner.key_package(now()).unwrap();
        self.change(committer, &[], vec![(joiner, kp)]);
        self.members.len() - 1
    }

    fn assert_everyone_hears_everyone(&mut self) {
        for from in 0..self.members.len() {
            for to in 0..self.members.len() {
                if from != to {
                    assert_hears(&mut self.members, from, to);
                }
            }
        }
        let code = self.members[0].call_code().unwrap();
        let mut roster = self.members[0].roster();
        roster.sort();
        for member in &self.members {
            assert_eq!(member.call_code().unwrap(), code);
            let mut other = member.roster();
            other.sort();
            assert_eq!(other, roster);
        }
    }
}

fn seal(members: &mut [Session], from: usize, frame: &[u8]) -> Vec<u8> {
    members[from]
        .encrypt(Codec::Opus, &Source::mic(), frame)
        .unwrap()
}

fn open(
    members: &mut [Session],
    to: usize,
    sender: u64,
    sealed: &[u8],
) -> Result<Vec<u8>, FrameError> {
    members[to].decrypt(sender, Codec::Opus, &Source::mic(), sealed)
}

fn assert_hears(members: &mut [Session], from: usize, to: usize) {
    let frame = [from as u8, to as u8, 0xAA, 0x55, 7, 7, 7];
    let sender = members[from].client_id();
    let sealed = seal(members, from, &frame);
    assert_eq!(
        open(members, to, sender, &sealed),
        Ok(frame.to_vec()),
        "{to} can't hear {from}"
    );
}

#[test]
fn founding_then_joins() {
    let mut call = Call::new();
    call.found(100);
    assert_eq!(call.ds().epoch(), 0);
    assert_eq!(call.members[0].sending_epoch(), Some(0));

    call.join(0, 101);
    call.join(1, 102);
    assert_eq!(call.ds().epoch(), 2);
    assert_eq!(call.ds().leaves().len(), 3);
    call.assert_everyone_hears_everyone();
}

#[test]
fn leaving_member_loses_the_new_epoch() {
    let mut call = Call::new();
    call.found(100);
    call.join(0, 101);
    call.join(0, 102);

    let mut gone = call.members.remove(2);
    let leaf = call.leaf_of(102);
    let epoch = call.ds().epoch();
    let proposals = call
        .ds
        .as_mut()
        .unwrap()
        .propose(&call.sender, &[leaf], Vec::new())
        .unwrap();
    for member in &mut call.members {
        member.proposals(epoch, &proposals).unwrap();
    }
    let (commit, welcome) = call.members[1].commit().unwrap();
    assert!(welcome.is_none());
    call.ds().commit(101, &commit, None).unwrap();
    for member in &mut call.members {
        member.apply_commit(epoch, &commit).unwrap();
        member.execute(epoch + 1).unwrap();
    }
    call.assert_everyone_hears_everyone();

    let sealed = seal(&mut call.members, 0, b"after");
    assert_eq!(
        gone.decrypt(100, Codec::Opus, &Source::mic(), &sealed),
        Err(FrameError::NoKey)
    );
}

#[test]
fn old_epoch_stays_decryptable_across_the_barrier() {
    let mut call = Call::new();
    call.found(100);
    call.join(0, 101);
    let epoch = call.ds().epoch();

    // Sealed under the current epoch, delivered after everyone merged the next commit but
    // before `Execute`.
    let early = seal(&mut call.members, 0, b"in flight");

    let mut joiner = call.session(102);
    let kp = joiner.key_package(now()).unwrap();
    let proposals = call
        .ds
        .as_mut()
        .unwrap()
        .propose(
            &call.sender,
            &[],
            vec![check_key_package(&kp, 102).unwrap()],
        )
        .unwrap();
    for member in &mut call.members {
        member.proposals(epoch, &proposals).unwrap();
    }
    let (commit, welcome) = call.members[0].commit().unwrap();
    let merged = call.ds().commit(100, &commit, welcome.as_deref()).unwrap();
    for member in &mut call.members {
        assert_eq!(
            member.apply_commit(epoch, &commit).unwrap(),
            Some(epoch + 1)
        );
    }
    let tree = call.ds().ratchet_tree().unwrap();
    joiner
        .join(epoch + 1, merged.welcome.as_deref().unwrap(), &tree)
        .unwrap();

    // Still sending under the old epoch, and still heard.
    assert_eq!(
        open(&mut call.members, 1, 100, &early),
        Ok(b"in flight".to_vec())
    );
    let still_old = seal(&mut call.members, 0, b"before execute");
    assert_eq!(
        open(&mut call.members, 1, 100, &still_old),
        Ok(b"before execute".to_vec())
    );
    // The joiner never had the old epoch.
    assert_eq!(
        joiner.decrypt(100, Codec::Opus, &Source::mic(), &still_old),
        Err(FrameError::NoKey)
    );

    call.members.push(joiner);
    for member in &mut call.members {
        assert_eq!(
            member.execute(epoch + 1).unwrap(),
            if member.client_id() == 102 {
                None
            } else {
                Some(epoch)
            }
        );
    }
    call.assert_everyone_hears_everyone();

    // Retiring the old epoch drops its frames.
    for member in &mut call.members {
        member.retire(epoch);
    }
    assert_eq!(
        open(&mut call.members, 1, 100, &early),
        Err(FrameError::NoKey)
    );
}

#[test]
fn rejoin_replaces_the_leaf_in_one_commit() {
    let mut call = Call::new();
    call.found(100);
    call.join(0, 101);
    call.join(0, 102);

    // 102 hit an invalid commit, say, and sends a fresh key package from the same session.
    let rejoiner = call.members.remove(2);
    let mut rejoiner = rejoiner;
    let kp = rejoiner.key_package(now()).unwrap();
    let old_leaf = call.leaf_of(102);
    let epoch = call.ds().epoch();
    let proposals = call
        .ds
        .as_mut()
        .unwrap()
        .propose(
            &call.sender,
            &[old_leaf],
            vec![check_key_package(&kp, 102).unwrap()],
        )
        .unwrap();
    for member in &mut call.members {
        member.proposals(epoch, &proposals).unwrap();
    }
    let (commit, welcome) = call.members[1].commit().unwrap();
    let merged = call.ds().commit(101, &commit, welcome.as_deref()).unwrap();
    for member in &mut call.members {
        member.apply_commit(epoch, &commit).unwrap();
    }
    let tree = call.ds().ratchet_tree().unwrap();
    rejoiner
        .join(merged.epoch, merged.welcome.as_deref().unwrap(), &tree)
        .unwrap();
    call.members.push(rejoiner);
    for member in &mut call.members {
        member.execute(merged.epoch).unwrap();
    }

    assert_eq!(
        call.ds()
            .leaves()
            .iter()
            .filter(|(_, id)| *id == 102)
            .count(),
        1
    );
    call.assert_everyone_hears_everyone();
}

#[test]
fn reconnect_replaces_an_older_session() {
    let mut call = Call::new();
    call.found(100);
    call.join(0, 101);

    // 101 reconnects: a new session (new generation) with the same client id.
    let mut fresh = call.session(101);
    let kp = fresh.key_package(now()).unwrap();
    call.change(0, &[1], vec![(fresh, kp)]);

    assert_eq!(call.ds().leaves().len(), 2);
    call.assert_everyone_hears_everyone();
}

#[test]
fn refound_starts_a_new_group() {
    let mut call = Call::new();
    call.found(100);
    call.join(0, 101);
    let old_group = call.ds().group_id().to_vec();
    let old_frame = seal(&mut call.members, 0, b"old group");

    // Everyone reconnected at once: nobody survives the batch, so the node founds again.
    call.found(100);
    call.join(0, 101);
    assert_ne!(call.ds().group_id(), old_group);
    call.assert_everyone_hears_everyone();
    assert_eq!(
        open(&mut call.members, 1, 100, &old_frame),
        Err(FrameError::Auth)
    );
}

#[test]
fn key_packages_from_skewed_clocks_are_accepted() {
    let mut call = Call::new();
    call.found(100);
    for (id, skew) in [(101, now() + 5 * HOUR), (102, now() - 5 * HOUR)] {
        let mut joiner = call.session(id);
        let kp = joiner.key_package(skew).unwrap();
        check_key_package(&kp, id).unwrap();
        call.change(0, &[], vec![(joiner, kp)]);
    }
    call.assert_everyone_hears_everyone();
}

#[test]
fn key_package_checks() {
    let call = Call::new();
    let mut session = call.session(7);
    let kp = session.key_package(now()).unwrap();
    assert!(check_key_package(&kp, 7).is_ok());
    assert_eq!(
        check_key_package(&kp, 8).unwrap_err(),
        MlsError::WrongIdentity
    );

    let mut broken = kp.clone();
    let last = broken.len() - 1;
    broken[last] ^= 1;
    assert!(check_key_package(&broken, 7).is_err());
    assert_eq!(
        check_key_package(b"junk", 7).unwrap_err(),
        MlsError::Malformed
    );

    // Expired, and not yet valid.
    let old = session.key_package(now() - 13 * 7 * 24 * HOUR).unwrap();
    assert_eq!(
        check_key_package(&old, 7).unwrap_err(),
        MlsError::InvalidKeyPackage
    );
    let future = session.key_package(now() + 2 * 7 * 24 * HOUR).unwrap();
    assert_eq!(
        check_key_package(&future, 7).unwrap_err(),
        MlsError::InvalidKeyPackage
    );
}

#[test]
fn members_reject_an_add_for_a_client_that_keeps_its_leaf() {
    let mut call = Call::new();
    call.found(100);
    call.join(0, 101);

    let mut twin = call.session(101);
    let kp = twin.key_package(now()).unwrap();
    let epoch = call.ds().epoch();
    let proposals = call
        .ds
        .as_mut()
        .unwrap()
        .propose(
            &call.sender,
            &[],
            vec![check_key_package(&kp, 101).unwrap()],
        )
        .unwrap();
    assert_eq!(
        call.members[0].proposals(epoch, &proposals),
        Err(MlsError::Rejected)
    );
}

#[test]
fn node_rejects_bad_commits() {
    let mut call = Call::new();
    call.found(100);
    call.join(0, 101);
    let epoch = call.ds().epoch();

    let mut a = call.session(102);
    let mut b = call.session(103);
    let adds = vec![
        check_key_package(&a.key_package(now()).unwrap(), 102).unwrap(),
        check_key_package(&b.key_package(now()).unwrap(), 103).unwrap(),
    ];
    let proposals = call
        .ds
        .as_mut()
        .unwrap()
        .propose(&call.sender, &[], adds)
        .unwrap();

    // Covering only some of the proposals.
    call.members[0].proposals(epoch, &proposals[..1]).unwrap();
    let (partial, welcome) = call.members[0].commit().unwrap();
    assert_eq!(
        call.ds().commit(100, &partial, welcome.as_deref()),
        Err(MlsError::Rejected)
    );

    // From someone else's leaf.
    call.members[1].proposals(epoch, &proposals).unwrap();
    let (commit, welcome) = call.members[1].commit().unwrap();
    assert_eq!(
        call.ds().commit(100, &commit, welcome.as_deref()),
        Err(MlsError::WrongIdentity)
    );
    // Without the welcome it needs.
    assert_eq!(
        call.ds().commit(101, &commit, None),
        Err(MlsError::Rejected)
    );

    // Without a path (Adds alone don't need one in MLS, but we always require it).
    let (pathless, welcome) = call.members[1].member_mut().commit_without_path().unwrap();
    assert_eq!(
        call.ds().commit(101, &pathless, welcome.as_deref()),
        Err(MlsError::Rejected)
    );

    // The good one still goes through, and the first committer applies it instead of its own.
    let (commit, welcome) = call.members[1].commit().unwrap();
    let merged = call.ds().commit(101, &commit, welcome.as_deref()).unwrap();
    assert_eq!(merged.epoch, epoch + 1);
    call.members[0].proposals(epoch, &proposals[1..]).unwrap();
    for member in &mut call.members {
        assert_eq!(
            member.apply_commit(epoch, &commit).unwrap(),
            Some(epoch + 1)
        );
    }
    // A stale echo for the old epoch is refused.
    assert_eq!(
        call.members[0].apply_commit(epoch, &commit),
        Err(MlsError::WrongGroup)
    );

    let tree = call.ds().ratchet_tree().unwrap();
    for joiner in [&mut a, &mut b] {
        joiner
            .join(merged.epoch, merged.welcome.as_deref().unwrap(), &tree)
            .unwrap();
    }
    call.members.push(a);
    call.members.push(b);
    for member in &mut call.members {
        member.execute(merged.epoch).unwrap();
    }
    call.assert_everyone_hears_everyone();
}

#[test]
fn committer_failover_uses_the_same_proposals() {
    let mut call = Call::new();
    call.found(100);
    call.join(0, 101);
    let epoch = call.ds().epoch();

    let mut joiner = call.session(102);
    let kp = joiner.key_package(now()).unwrap();
    let proposals = call
        .ds
        .as_mut()
        .unwrap()
        .propose(
            &call.sender,
            &[],
            vec![check_key_package(&kp, 102).unwrap()],
        )
        .unwrap();
    for member in &mut call.members {
        member.proposals(epoch, &proposals).unwrap();
    }

    // The designated committer (100) commits too late; the node asked 101 instead.
    let (late, _) = call.members[0].commit().unwrap();
    let (commit, welcome) = call.members[1].commit().unwrap();
    let merged = call.ds().commit(101, &commit, welcome.as_deref()).unwrap();
    assert_eq!(
        call.ds().commit(100, &late, None),
        Err(MlsError::WrongGroup)
    );

    for member in &mut call.members {
        assert_eq!(
            member.apply_commit(epoch, &commit).unwrap(),
            Some(epoch + 1)
        );
    }
    let tree = call.ds().ratchet_tree().unwrap();
    joiner
        .join(merged.epoch, merged.welcome.as_deref().unwrap(), &tree)
        .unwrap();
    call.members.push(joiner);
    for member in &mut call.members {
        member.execute(merged.epoch).unwrap();
    }
    call.assert_everyone_hears_everyone();
}

#[test]
fn node_checks_the_founding_group() {
    let call = Call::new();
    let mut founder = call.session(100);
    let info = founder.found(b"attempt-2", now()).unwrap();

    assert_eq!(
        DsGroup::found(&info, b"attempt-1", 100, &call.sender).err(),
        Some(MlsError::WrongGroup)
    );
    assert_eq!(
        DsGroup::found(&info, b"attempt-2", 101, &call.sender).err(),
        Some(MlsError::WrongIdentity)
    );
    let other_node = ExternalSenderKey::generate().unwrap();
    assert_eq!(
        DsGroup::found(&info, b"attempt-2", 100, &other_node).err(),
        Some(MlsError::Rejected)
    );
    assert!(DsGroup::found(&info, b"attempt-2", 100, &call.sender).is_ok());
}

#[test]
fn joiners_check_the_external_sender() {
    let mut call = Call::new();
    call.found(100);

    // This joiner was told a different node's sender.
    let other_node = ExternalSenderKey::generate().unwrap();
    let mut joiner = Session::new(101, 0, 0, 1024);
    joiner
        .set_params(u16::from(CIPHERSUITE), other_node.encoded(), FORMAT)
        .unwrap();
    let kp = joiner.key_package(now()).unwrap();
    let epoch = call.ds().epoch();
    let proposals = call
        .ds
        .as_mut()
        .unwrap()
        .propose(
            &call.sender,
            &[],
            vec![check_key_package(&kp, 101).unwrap()],
        )
        .unwrap();
    call.members[0].proposals(epoch, &proposals).unwrap();
    let (commit, welcome) = call.members[0].commit().unwrap();
    let merged = call.ds().commit(100, &commit, welcome.as_deref()).unwrap();
    let tree = call.ds().ratchet_tree().unwrap();
    assert_eq!(
        joiner.join(merged.epoch, merged.welcome.as_deref().unwrap(), &tree),
        Err(MlsError::Rejected)
    );
    assert_eq!(joiner.epoch(), None);
}

#[test]
fn params_gate_unsupported_formats() {
    let call = Call::new();
    let mut session = Session::new(1, 0, 0, 1024);
    assert_eq!(
        session.set_params(u16::from(CIPHERSUITE), call.sender.encoded(), 9),
        Err(MlsError::Rejected)
    );
    assert_eq!(
        session.set_params(2, call.sender.encoded(), FORMAT),
        Err(MlsError::Rejected)
    );
}

#[test]
fn a_bigger_channel() {
    let mut call = Call::new();
    call.found(100);
    // Joins in batches, as the node's batch window coalesces them.
    for batch in 0..4 {
        let joiners = (0..6)
            .map(|n| {
                let mut joiner = call.session(200 + batch * 10 + n);
                let kp = joiner.key_package(now()).unwrap();
                (joiner, kp)
            })
            .collect();
        call.change(0, &[], joiners);
    }
    assert_eq!(call.ds().leaves().len(), 25);
    // A few leave at once, committed by a member that isn't the founder.
    call.change(3, &[1, 5, 9], Vec::new());
    assert_eq!(call.ds().leaves().len(), 22);
    for from in [0, 7, 21] {
        for to in [2, 11, 20] {
            assert_hears(&mut call.members, from, to);
        }
    }
}

//! Shared by the frame code and the node, which pins one format per group.

/// The frame format (plan section 5.8): the layout and key schedule clients use with each other.
/// The node pins one per group; a client may support several during a rollout. It's the first
/// AAD byte, so frames of another format fail authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Format {
    V1 = 1,
}

impl Format {
    /// Every format this build reads and writes. Clients send this in `SetCapabilities`.
    pub const SUPPORTED: &[Self] = &[Self::V1];

    pub fn from_id(id: u8) -> Option<Self> {
        Self::SUPPORTED
            .iter()
            .copied()
            .find(|format| *format as u8 == id)
    }
}

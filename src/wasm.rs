//! Bindings for the client's E2EE worker. Failures throw an `Error` whose message is the
//! `FrameError` or `MlsError` name (`no-key`, `auth`, `rejected`, ...), which the worker counts
//! as the drop reason or reports.
//!
//! Client ids are decimal strings, since snowflakes don't fit a JS number. Epochs are numbers.

use {
    crate::{
        Codec, Decryptor, Encryptor, Format, FrameError, Source, key,
        mls::{MlsError, session::Session},
    },
    wasm_bindgen::prelude::*,
};

fn key16(key: &[u8]) -> Result<[u8; key::KEY_LEN], JsError> {
    key.try_into()
        .map_err(|_| JsError::new("key must be 16 bytes"))
}

fn codec(id: u8) -> Result<Codec, JsError> {
    Codec::from_id(id).ok_or_else(|| JsError::new("unknown-codec"))
}

fn format(id: u8) -> Result<Format, JsError> {
    Format::from_id(id).ok_or_else(|| JsError::new("unsupported-format"))
}

fn frame_error(err: FrameError) -> JsError {
    JsError::new(err.as_str())
}

fn client_id(id: &str) -> Result<u64, JsError> {
    id.parse()
        .map_err(|_| JsError::new("client id must be a decimal u64"))
}

fn mls_error(err: MlsError) -> JsError {
    JsError::new(err.as_str())
}

/// Epochs and times cross as JS numbers, which hold any integer below 2^53 exactly.
fn whole(value: f64) -> Result<u64, JsError> {
    if value.fract() == 0.0 && (0.0..9_007_199_254_740_992.0).contains(&value) {
        Ok(value as u64)
    } else {
        Err(JsError::new("expected a whole number"))
    }
}

fn number(value: u64) -> f64 {
    value as f64
}

/// The codec id for a codec name or MIME type, or 0 when it is not one we encrypt.
#[wasm_bindgen(js_name = codecId)]
pub fn codec_id(name: &str) -> u8 {
    Codec::from_name(name).map_or(0, |codec| codec as u8)
}

/// Every frame format this build supports, for `SetCapabilities.e2ee_formats`.
#[wasm_bindgen(js_name = supportedFormats)]
pub fn supported_formats() -> Vec<u8> {
    Format::SUPPORTED
        .iter()
        .map(|format| *format as u8)
        .collect()
}

/// A sender's key under `root` (plan section 4).
#[wasm_bindgen(js_name = senderKey)]
pub fn sender_key(root: &[u8], sender: &str) -> Result<Vec<u8>, JsError> {
    Ok(key::sender_key(root, client_id(sender)?).to_vec())
}

/// What a transform's frames are bound to (plan 3.4): 1 mic, 2 webcam, 3 stream and 4 stream
/// audio. Streams take their stream key.
#[wasm_bindgen]
pub struct FrameSource(Source);

#[wasm_bindgen]
impl FrameSource {
    #[wasm_bindgen(constructor)]
    pub fn new(tag: u8, stream_key: Option<String>) -> Result<FrameSource, JsError> {
        Source::new(tag, stream_key.as_deref())
            .map(FrameSource)
            .ok_or_else(|| JsError::new("invalid source"))
    }

    /// The encoded binding, which frame captures record.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

#[wasm_bindgen]
pub struct Sender(Encryptor);

#[wasm_bindgen]
impl Sender {
    #[wasm_bindgen(constructor)]
    pub fn new(kid: u8, counter: u32) -> Sender {
        Sender(Encryptor::new(kid, counter))
    }

    #[wasm_bindgen(js_name = setKey)]
    pub fn set_key(&mut self, format_id: u8, epoch: u8, key: &[u8]) -> Result<(), JsError> {
        self.0.set_key(format(format_id)?, epoch, &key16(key)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = clearKey)]
    pub fn clear_key(&mut self) {
        self.0.clear_key();
    }

    pub fn encrypt(
        &mut self,
        codec_id: u8,
        source: &FrameSource,
        frame: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .encrypt(codec(codec_id)?, &source.0, frame)
            .map_err(frame_error)
    }
}

#[wasm_bindgen]
pub struct Receiver(Decryptor);

#[wasm_bindgen]
impl Receiver {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Receiver {
        Receiver(Decryptor::new())
    }

    #[wasm_bindgen(js_name = setKey)]
    pub fn set_key(&mut self, format_id: u8, epoch: u8, key: &[u8]) -> Result<(), JsError> {
        self.0.set_key(format(format_id)?, epoch, &key16(key)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = removeKey)]
    pub fn remove_key(&mut self, epoch: u8) {
        self.0.remove_key(epoch);
    }

    pub fn decrypt(
        &self,
        codec_id: u8,
        source: &FrameSource,
        frame: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .decrypt(codec(codec_id)?, &source.0, frame)
            .map_err(frame_error)
    }
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}

/// What `E2eeSession.commit` produced: the commit, and a welcome if it adds anyone.
#[wasm_bindgen]
pub struct CommitOut {
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl CommitOut {
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Vec<u8> {
        self.commit.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Option<Vec<u8>> {
        self.welcome.clone()
    }
}

/// The worker's whole E2EE state: its group member and frame keys (plan 9.1). See
/// `mls::session::Session` for what each call means.
#[wasm_bindgen]
pub struct E2eeSession(Session);

#[wasm_bindgen]
impl E2eeSession {
    #[wasm_bindgen(constructor)]
    pub fn new(self_id: &str, kid: u8, counter: u32) -> Result<E2eeSession, JsError> {
        Ok(E2eeSession(Session::new(client_id(self_id)?, kid, counter)))
    }

    #[wasm_bindgen(js_name = setParams)]
    pub fn set_params(
        &mut self,
        ciphersuite: u16,
        external_sender: &[u8],
        format: u8,
    ) -> Result<(), JsError> {
        self.0
            .set_params(ciphersuite, external_sender, format)
            .map_err(mls_error)
    }

    /// `now` is unix seconds.
    #[wasm_bindgen(js_name = keyPackage)]
    pub fn key_package(&mut self, now: f64) -> Result<Vec<u8>, JsError> {
        self.0.key_package(whole(now)?).map_err(mls_error)
    }

    pub fn found(&mut self, group_id: &[u8], now: f64) -> Result<Vec<u8>, JsError> {
        self.0.found(group_id, whole(now)?).map_err(mls_error)
    }

    pub fn join(&mut self, epoch: f64, welcome: &[u8], ratchet_tree: &[u8]) -> Result<(), JsError> {
        self.0
            .join(whole(epoch)?, welcome, ratchet_tree)
            .map_err(mls_error)
    }

    pub fn proposals(
        &mut self,
        epoch: f64,
        proposals: Vec<js_sys::Uint8Array>,
    ) -> Result<(), JsError> {
        let proposals: Vec<Vec<u8>> = proposals.iter().map(js_sys::Uint8Array::to_vec).collect();
        self.0
            .proposals(whole(epoch)?, &proposals)
            .map_err(mls_error)
    }

    pub fn commit(&mut self) -> Result<CommitOut, JsError> {
        let (commit, welcome) = self.0.commit().map_err(mls_error)?;
        Ok(CommitOut { commit, welcome })
    }

    /// The new epoch to report with `Ready`, or `undefined` if the commit removed us.
    #[wasm_bindgen(js_name = applyCommit)]
    pub fn apply_commit(&mut self, epoch: f64, commit: &[u8]) -> Result<Option<f64>, JsError> {
        self.0
            .apply_commit(whole(epoch)?, commit)
            .map(|epoch| epoch.map(number))
            .map_err(mls_error)
    }

    /// The epoch this replaced, to retire a little later.
    pub fn execute(&mut self, epoch: f64) -> Result<Option<f64>, JsError> {
        self.0
            .execute(whole(epoch)?)
            .map(|old| old.map(number))
            .map_err(mls_error)
    }

    pub fn retire(&mut self, epoch: f64) -> Result<(), JsError> {
        self.0.retire(whole(epoch)?);
        Ok(())
    }

    pub fn leave(&mut self) {
        self.0.leave();
    }

    pub fn encrypt(
        &mut self,
        codec_id: u8,
        source: &FrameSource,
        frame: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .encrypt(codec(codec_id)?, &source.0, frame)
            .map_err(frame_error)
    }

    pub fn decrypt(
        &mut self,
        sender: &str,
        codec_id: u8,
        source: &FrameSource,
        frame: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .decrypt(client_id(sender)?, codec(codec_id)?, &source.0, frame)
            .map_err(frame_error)
    }

    #[wasm_bindgen(js_name = forgetSender)]
    pub fn forget_sender(&mut self, sender: &str) -> Result<(), JsError> {
        self.0.forget_sender(client_id(sender)?);
        Ok(())
    }

    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> Option<f64> {
        self.0.epoch().map(number)
    }

    #[wasm_bindgen(getter, js_name = sendingEpoch)]
    pub fn sending_epoch(&self) -> Option<f64> {
        self.0.sending_epoch().map(number)
    }

    /// Client ids in the MLS group, as decimal strings.
    pub fn roster(&self) -> Vec<String> {
        self.0
            .roster()
            .into_iter()
            .map(|id| id.to_string())
            .collect()
    }

    #[wasm_bindgen(js_name = callCode)]
    pub fn call_code(&self) -> Option<String> {
        self.0.call_code()
    }
}

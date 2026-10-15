//! Bindings for the client's E2EE worker. Failures throw an `Error` whose message is the
//! `FrameError` name (`no-key`, `auth`, ...), which the worker counts as the drop reason.

use {
    crate::{Codec, Decryptor, Encryptor, FrameError, key},
    wasm_bindgen::prelude::*,
};

fn key16(key: &[u8]) -> Result<[u8; key::KEY_LEN], JsError> {
    key.try_into()
        .map_err(|_| JsError::new("key must be 16 bytes"))
}

fn codec(id: u8) -> Result<Codec, JsError> {
    Codec::from_id(id).ok_or_else(|| JsError::new("unknown-codec"))
}

fn frame_error(err: FrameError) -> JsError {
    JsError::new(err.as_str())
}

/// The codec id for a codec name or MIME type, or 0 when it is not one we encrypt.
#[wasm_bindgen(js_name = codecId)]
pub fn codec_id(name: &str) -> u8 {
    Codec::from_name(name).map_or(0, |codec| codec as u8)
}

#[wasm_bindgen(js_name = staticSenderKey)]
pub fn static_sender_key(root: &[u8], client_id: &str) -> Result<Vec<u8>, JsError> {
    let client_id = client_id
        .parse()
        .map_err(|_| JsError::new("client id must be a decimal u64"))?;
    Ok(key::static_sender_key(root, client_id).to_vec())
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
    pub fn set_key(&mut self, epoch: u8, key: &[u8]) -> Result<(), JsError> {
        self.0.set_key(epoch, &key16(key)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = clearKey)]
    pub fn clear_key(&mut self) {
        self.0.clear_key();
    }

    pub fn encrypt(&mut self, codec_id: u8, frame: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0.encrypt(codec(codec_id)?, frame).map_err(frame_error)
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
    pub fn set_key(&mut self, epoch: u8, key: &[u8]) -> Result<(), JsError> {
        self.0.set_key(epoch, &key16(key)?);
        Ok(())
    }

    pub fn decrypt(&self, codec_id: u8, frame: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0.decrypt(codec(codec_id)?, frame).map_err(frame_error)
    }
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}

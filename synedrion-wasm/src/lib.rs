use bincode::{
    config::{
        BigEndian, Bounded, RejectTrailing, VarintEncoding, WithOtherEndian, WithOtherIntEncoding,
        WithOtherLimit, WithOtherTrailing,
    },
    DefaultOptions, Options,
};
use js_sys::{Error, Uint8Array};
use rand_core::OsRng;
use synedrion::TestSchemeParams;
use wasm_bindgen::{
    prelude::{wasm_bindgen, JsValue},
    JsCast,
};

/// Max message length allowed to be (de)serialized
const MAX_MSG_LEN: u64 = 1000 * 1000; // 1 MB

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Uint8Array[]")]
    pub type ShareArray;
}

/// Create a set of key shares
#[wasm_bindgen(js_name = makeKeyShares)]
pub fn make_key_shares(num_parties: usize) -> Result<ShareArray, Error> {
    let shares = synedrion::make_key_shares::<TestSchemeParams>(&mut OsRng, num_parties);

    let bincode = bincoder();
    let mut shares_vec = Vec::<JsValue>::with_capacity(num_parties);

    for share in shares.iter() {
        let share_serialized = bincode
            .serialize(&share)
            .map_err(|err| Error::new(&format!("{}", err)))?;

        let share_js: JsValue = Uint8Array::from(share_serialized.as_ref()).into();
        shares_vec.push(share_js)
    }

    Ok(shares_vec
        .into_iter()
        .collect::<js_sys::Array>()
        .unchecked_into::<ShareArray>())
}

/// Prepare a `bincode` serde backend with our preferred config
/// This is copied from `entropy-core/crypto/kvdb/src/kv_manager/helpers.rs`
/// In the hope that it gives us shares which are encoded just the same as
/// the are in the key value store there.
// TODO: can we ensure consistency here? Should `entropy-core` expose the serialization function?
#[allow(clippy::type_complexity)]
fn bincoder() -> WithOtherTrailing<
    WithOtherIntEncoding<
        WithOtherEndian<WithOtherLimit<DefaultOptions, Bounded>, BigEndian>,
        VarintEncoding,
    >,
    RejectTrailing,
> {
    DefaultOptions::new()
        .with_limit(MAX_MSG_LEN)
        .with_big_endian() // big endian representation for integers
        .with_varint_encoding() // saves a lot of space in smaller messages
        .reject_trailing_bytes() // do not ignore extra bytes at the end of the buffer
}

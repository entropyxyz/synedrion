use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

use synedrion_wasm::{KeyShare, SigningKey};

fn into_js_option<T, U>(val: Option<U>) -> T
where
    JsValue: From<U>,
    T: JsCast,
{
    let js_val = match val {
        None => JsValue::UNDEFINED,
        Some(val) => val.into(),
    };
    js_val.unchecked_into::<T>()
}

#[wasm_bindgen_test]
fn test_make_key_shares() {
    let sk: Option<SigningKey> = None;
    let shares: Vec<KeyShare> = KeyShare::new_centralized(3, &into_js_option(sk)).unwrap();
    let _shares_serialized = shares
        .iter()
        .map(|share| share.to_bytes())
        .collect::<Vec<_>>();
    // TODO: serialize synedrion::KeyShare and compare sizes?
}

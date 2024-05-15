use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

use synedrion_wasm::{KeyShare, SigningKey, VerifyingKey};

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

fn into_js_array<T, U>(value: impl IntoIterator<Item = U>) -> T
where
    JsValue: From<U>,
    T: JsCast,
{
    value
        .into_iter()
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<T>()
}

#[wasm_bindgen_test]
fn test_make_key_shares() {
    let sk: Option<SigningKey> = None;
    let parties = (0..3).map(|_| VerifyingKey::random()).collect::<Vec<_>>();
    let shares: Vec<KeyShare> = KeyShare::new_centralized(&into_js_array(parties), &into_js_option(sk)).unwrap();
    let _shares_serialized = shares
        .iter()
        .map(|share| share.to_bytes())
        .collect::<Vec<_>>();
    // TODO (#84): some assertions needed here. Serialize synedrion::KeyShare and compare sizes?
}

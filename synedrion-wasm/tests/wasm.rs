use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

use synedrion_wasm::{make_key_shares, KeyShare, SigningKey};

fn try_from_js_array<T>(val: impl Into<JsValue>) -> Vec<T>
where
    for<'a> T: TryFrom<&'a JsValue>,
    for<'a> <T as TryFrom<&'a JsValue>>::Error: core::fmt::Debug,
{
    let js_array: js_sys::Array = val.into().dyn_into().unwrap();
    js_array
        .iter()
        .map(|js| T::try_from(&js).unwrap())
        .collect()
}

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
    let shares_js = make_key_shares(3, &into_js_option(sk)).unwrap();
    let shares = try_from_js_array::<KeyShare>(shares_js);
    let _shares_serialized = shares
        .iter()
        .map(|share| share.to_bytes())
        .collect::<Vec<_>>();
    // TODO: serialize synedrion::KeyShare and compare sizes?
}

# Wasm bindings for Synedrion

Currently only `synedrion::make_key_shares` is exposed.

`make_key_shares`, if successful, returns an array of Uint8Arrays containing `bincode` encoded shares.

- Build with `wasm-pack build`

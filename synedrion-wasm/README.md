# Wasm bindings for Synedrion

Currently only `synedrion::make_key_shares` is exposed.

`make_key_shares`, if successful, returns an array of Uint8Arrays containing `bincode` encoded shares.

The package is built using [`wasm-pack`](https://github.com/rustwasm/wasm-pack).
Instead of running `wasm-build` directly, use the included `Makefile`, since it has to do some additional actions that `wasm-build` currently does not support:

```bash
$ make
```

## Tests

To run JS-side tests, go to `tests-js` directory and run

```bash
$ yarn install
$ yarn test
```

To run the Rust-side tests, go to `synedrion-wasm` directory and run

```bash
$ wasm-pack test --node
```

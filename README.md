# sodium-js
A web compatible version of sodium-native. Based on tweetnacl, sodium-javascript &amp; libsodium-wrappers-sumo

## what u get
- node and bare get `sodium-native`, it already has everything
- browsers get `sodium-js` plus the stuff our p2p stack needs that it doesnt have
  - `crypto_scalarmult_ed25519_noclamp` from libsodium.js (`libsodium-wrappers-sumo`, libsodium as wasm). noise-curve-ed needs it for the noise handshake, so a browser can do the handshake itself (dht-relay with `custodial: false`)
  - `crypto_aead_xchacha20poly1305_ietf_*` and `crypto_kx_*` from `@geut/sodium-javascript-plus` (blind-pairing uses them)
  - `extension_pbkdf2_sha512_async` for bip39-mnemonic seeds, from the browsers web crypto, so only on https or localhost. theres no pbkdf2 of our own (libsodium doesnt have one)

## how to use it
put this in your package.json so every `sodium-crypto` in the tree is this package

```json
"overrides": { "sodium-universal": "github:serapath/sodium-crypto" }
```

libsodium.js loads async, so in a browser do this once before the first handshake (calling noclamp before that throws a clear error)

```js
const sodium = require('sodium-universal')
await sodium.ready
```

browserify 17 cant parse libsodium.js (it uses newer syntax), so bundle it with `--noparse=<path to libsodium-sumo/dist/modules-sumo/libsodium-sumo.js>`, `demo/server.js` shows how. with esbuild u need `external: ['node:*']` instead

## tests
`npm test` checks `browser.js` against sodium-native in node. noclamp on 1000 random scalars and points, both refuse the identity and a small order point, pbkdf2 against sodium-native and node crypto, xchacha20poly1305 and kx

## demo
`npm run demo` starts a local testnet, a dht-relay the native peer can reach over udp (`firewalled: false`, like a relay on a public ip), a native hyperswarm peer and budo. open the url it prints, the page joins the topic through the relay with `custodial: false` and gets a message from the native peer. the relay never gets the browsers secret key

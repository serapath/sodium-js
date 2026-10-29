# sodium-js
A web compatible version of sodium-native. Based on tweetnacl, sodium-javascript &amp; libsodium-wrappers-sumo

## what u get
- node and bare get `sodium-native`, it already has everything
- browsers get `sodium-javascript` plus the stuff our p2p stack needs that it doesnt have
  - `crypto_scalarmult_ed25519_noclamp` from libsodium.js (`libsodium-wrappers-sumo`, libsodium as wasm). noise-curve-ed needs it for the noise handshake, so a browser can do the handshake itself (dht-relay with `custodial: false`)
  - `crypto_aead_xchacha20poly1305_ietf_*` and `crypto_kx_*` from `@geut/sodium-javascript-plus` (blind-pairing uses them)
  - `extension_pbkdf2_sha512_async` for bip39-mnemonic seeds, from the browsers web crypto, so only on https or localhost. theres no pbkdf2 of our own (libsodium doesnt have one)
- and in browsers `crypto_generichash`, `crypto_generichash_batch`, `crypto_sign_detached`, `crypto_sign_verify_detached`, `crypto_sign_keypair` and `crypto_sign_seed_keypair` go to libsodium.js once its loaded, 20x to 110x faster than sodium-javascript (see speed). before that they run on sodium-javascript, same output

## how to use it
u normally dont depend on this one directly, [sodium-crypto](https://github.com/serapath/sodium-crypto) gives node and bare `sodium-native` and browsers this package. to use it for every `sodium-universal` in the tree put this in your package.json

```json
"overrides": { "sodium-universal": "github:serapath/sodium-crypto" }
```

libsodium.js loads async, so in a browser do this once before the first handshake (calling noclamp before that throws a clear error, the fast functions just stay on sodium-javascript till then)

```js
const sodium = require('sodium-universal')
await sodium.ready
```

browserify 17 cant parse libsodium.js. it has 2 `??=` (es2021, browserify parses es2020) and a `require("node:fs")` browserify cant resolve, both in libsodium's own generated file. so bundle it with `--noparse=<path to libsodium-sumo/dist/modules-sumo/libsodium-sumo.js>`, `demo/server.js` shows how. the fs part only runs in node

## tests
`npm test` checks `browser.js` against sodium-native in node. noclamp on 1000 random scalars and points, both refuse the identity and a small order point. generichash (16 / 32 / 64 bytes, with and without a key), generichash_batch, seed keypair and sign on random input, verify also with a wrong signature, bad public keys and wrong lengths, and the same functions before `sodium.ready`. pbkdf2 against sodium-native and node crypto, and its error without web crypto. xchacha20poly1305 and kx

## speed
libsodium.js against sodium-javascript, ops per second on a 1KB message (node 26, same v8 as chrome)
- generichash 49k vs 1.1M (22x)
- sign 371 vs 41k (110x), verify 192 vs 18k (95x)
- sha512 394k vs 548k and xchacha20poly1305 392k vs 445k, so those stay on sodium-javascript. randombytes is slower in libsodium.js
- size, libsodium.js is 1.17MB (383KB gzipped), sodium-javascript 80KB (15KB gzipped). its needed for noclamp anyway

## demo
`npm run demo` starts a local testnet, a dht-relay the native peer can reach over udp (`firewalled: false`, like a relay on a public ip), a native hyperswarm peer and budo. open the url it prints, the page joins the topic through the relay with `custodial: false` and gets a message from the native peer. the relay never gets the browsers secret key

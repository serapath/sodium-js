// browsers: sodium-javascript plus what it doesnt have but our p2p stack needs
const sodium = require('sodium-javascript')
const extend = require('@geut/sodium-javascript-plus/extend')
const libsodium = require('libsodium-wrappers-sumo')
const { extension_pbkdf2_sha512_async } = require('./lib/pbkdf2')

let loaded = false

/******************************************************************************
  xchacha20poly1305 and kx (blind-pairing), from @geut/sodium-javascript-plus
******************************************************************************/
extend(sodium)

/******************************************************************************
  pbkdf2 sha512 (bip39-mnemonic seeds), web crypto with a js fallback
******************************************************************************/
sodium.extension_pbkdf2_sha512_async = extension_pbkdf2_sha512_async

/******************************************************************************
  crypto_scalarmult_ed25519_noclamp (noise-curve-ed, so secret-stream handshakes),
  from libsodium.js (libsodium compiled to wasm). it loads async, so a browser
  has to await sodium.ready before the first handshake
******************************************************************************/
sodium.crypto_scalarmult_ed25519_BYTES = 32
sodium.crypto_scalarmult_ed25519_SCALARBYTES = 32
sodium.ready = libsodium.ready.then(handle_ready)
sodium.crypto_scalarmult_ed25519_noclamp = crypto_scalarmult_ed25519_noclamp

module.exports = sodium

function handle_ready () { loaded = true }

function crypto_scalarmult_ed25519_noclamp (q, n, p) {
  if (!loaded) throw new Error('sodium-crypto is not ready yet, await sodium.ready first')
  q.set(libsodium.crypto_scalarmult_ed25519_noclamp(n, p))
}

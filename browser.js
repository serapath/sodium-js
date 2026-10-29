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
  pbkdf2 sha512 (bip39-mnemonic seeds), from the browsers web crypto
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

/******************************************************************************
  blake2b and ed25519, the ones hypercore calls all the time. libsodium.js does
  them 20x to 110x faster than sodium-javascript, so once its loaded they go
  there, before that they stay on sodium-javascript (same output)
******************************************************************************/
const js = {
  crypto_generichash: sodium.crypto_generichash,
  crypto_generichash_batch: sodium.crypto_generichash_batch,
  crypto_sign_detached: sodium.crypto_sign_detached,
  crypto_sign_verify_detached: sodium.crypto_sign_verify_detached,
  crypto_sign_keypair: sodium.crypto_sign_keypair,
  crypto_sign_seed_keypair: sodium.crypto_sign_seed_keypair
}
sodium.crypto_generichash = crypto_generichash
sodium.crypto_generichash_batch = crypto_generichash_batch
sodium.crypto_sign_detached = crypto_sign_detached
sodium.crypto_sign_verify_detached = crypto_sign_verify_detached
sodium.crypto_sign_keypair = crypto_sign_keypair
sodium.crypto_sign_seed_keypair = crypto_sign_seed_keypair

module.exports = sodium

function handle_ready () { loaded = true }

function crypto_scalarmult_ed25519_noclamp (q, n, p) {
  if (!loaded) throw new Error('sodium-js is not ready yet, await sodium.ready first')
  q.set(libsodium.crypto_scalarmult_ed25519_noclamp(n, p))
}

function crypto_generichash (out, input, key) {
  if (!loaded) return js.crypto_generichash(out, input, key)
  out.set(libsodium.crypto_generichash(out.length, input, key || null))
}

function crypto_generichash_batch (out, inputs, key) {
  if (!loaded) return js.crypto_generichash_batch(out, inputs, key)
  const state = libsodium.crypto_generichash_init(key || null, out.length)
  for (const input of inputs) libsodium.crypto_generichash_update(state, input)
  out.set(libsodium.crypto_generichash_final(state, out.length))
}

function crypto_sign_detached (sig, message, sk) {
  if (!loaded) return js.crypto_sign_detached(sig, message, sk)
  sig.set(libsodium.crypto_sign_detached(message, sk))
}

function crypto_sign_verify_detached (sig, message, pk) {
  if (!loaded) return js.crypto_sign_verify_detached(sig, message, pk)
  return libsodium.crypto_sign_verify_detached(sig, message, pk)
}

function crypto_sign_keypair (pk, sk) {
  if (!loaded) return js.crypto_sign_keypair(pk, sk)
  const keys = libsodium.crypto_sign_keypair()
  pk.set(keys.publicKey)
  sk.set(keys.privateKey)
}

function crypto_sign_seed_keypair (pk, sk, seed) {
  if (!loaded) return js.crypto_sign_seed_keypair(pk, sk, seed)
  const keys = libsodium.crypto_sign_seed_keypair(seed)
  pk.set(keys.publicKey)
  sk.set(keys.privateKey)
}

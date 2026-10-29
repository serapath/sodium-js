// browsers: sodium-javascript plus what it doesnt have but our p2p stack needs
const sodium = require('sodium-javascript')
const libsodium = require('libsodium-wrappers-sumo')
const { extension_pbkdf2_sha512_async } = require('./lib/pbkdf2')

let loaded = false

/******************************************************************************
  xchacha20poly1305 and the kx session keys (blind-pairing), from libsodium.js,
  so like noclamp below they need sodium.ready
******************************************************************************/
sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32
sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24
sodium.crypto_aead_xchacha20poly1305_ietf_NSECBYTES = 0
sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES = 16
sodium.crypto_kx_SESSIONKEYBYTES = 32
sodium.crypto_stream_xor_STATEBYTES = 136
sodium.crypto_aead_xchacha20poly1305_ietf_encrypt = crypto_aead_xchacha20poly1305_ietf_encrypt
sodium.crypto_aead_xchacha20poly1305_ietf_decrypt = crypto_aead_xchacha20poly1305_ietf_decrypt
sodium.crypto_kx_client_session_keys = crypto_kx_client_session_keys
sodium.crypto_kx_server_session_keys = crypto_kx_server_session_keys

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

function check_ready () { if (!loaded) throw new Error('sodium-js is not ready yet, await sodium.ready first') }

function crypto_scalarmult_ed25519_noclamp (q, n, p) {
  check_ready()
  q.set(libsodium.crypto_scalarmult_ed25519_noclamp(n, p))
}

function crypto_aead_xchacha20poly1305_ietf_encrypt (c, m, ad, nsec, npub, k) {
  check_ready()
  c.set(libsodium.crypto_aead_xchacha20poly1305_ietf_encrypt(m, ad || null, null, npub, k))
  return m.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
}

// throws if the ciphertext was changed, like sodium-native
function crypto_aead_xchacha20poly1305_ietf_decrypt (m, nsec, c, ad, npub, k) {
  check_ready()
  m.set(libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, c, ad || null, npub, k))
  return c.length - sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
}

function crypto_kx_client_session_keys (rx, tx, client_pk, client_sk, server_pk) {
  check_ready()
  set_session_keys(rx, tx, libsodium.crypto_kx_client_session_keys(client_pk, client_sk, server_pk))
}

function crypto_kx_server_session_keys (rx, tx, server_pk, server_sk, client_pk) {
  check_ready()
  set_session_keys(rx, tx, libsodium.crypto_kx_server_session_keys(server_pk, server_sk, client_pk))
}

// sodium-native lets rx or tx be null when only one of them is needed
function set_session_keys (rx, tx, keys) {
  if (rx) rx.set(keys.sharedRx)
  if (tx) tx.set(keys.sharedTx)
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

// pbkdf2 with hmac-sha512, the same as sodium-native's extension_pbkdf2_sha512_async (bip39-mnemonic makes seeds with it)
// web crypto when the page has it (a secure context), otherwise hmac over sodium-javascript's sha512
const sodium = require('sodium-javascript')

const HASH_BYTES = 64
const BLOCK_BYTES = 128

module.exports = { extension_pbkdf2_sha512_async, pbkdf2_js }

async function extension_pbkdf2_sha512_async (out, password, salt, iterations, keylen) {
  if (out.length < keylen) throw new Error('out is shorter than keylen')
  const subtle = typeof crypto !== 'undefined' && crypto.subtle
  if (!subtle) return pbkdf2_js(out, password, salt, iterations, keylen)
  const key = await subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits'])
  const bits = await subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-512' }, key, keylen * 8)
  out.set(new Uint8Array(bits))
  return out
}

function pbkdf2_js (out, password, salt, iterations, keylen) {
  const block_salt = new Uint8Array(salt.length + 4)
  block_salt.set(salt)
  for (let block = 1, offset = 0; offset < keylen; block++, offset += HASH_BYTES) {
    new DataView(block_salt.buffer).setUint32(salt.length, block)
    let u = hmac_sha512(password, block_salt)
    const t = u.slice()
    for (let i = 1; i < iterations; i++) {
      u = hmac_sha512(password, u)
      for (let j = 0; j < HASH_BYTES; j++) t[j] ^= u[j]
    }
    out.set(t.subarray(0, Math.min(HASH_BYTES, keylen - offset)), offset)
  }
  return out
}

function hmac_sha512 (key, data) {
  if (key.length > BLOCK_BYTES) key = sha512(key)
  const inner = new Uint8Array(BLOCK_BYTES + data.length)
  const outer = new Uint8Array(BLOCK_BYTES + HASH_BYTES)
  for (let i = 0; i < BLOCK_BYTES; i++) {
    inner[i] = (key[i] || 0) ^ 0x36
    outer[i] = (key[i] || 0) ^ 0x5c
  }
  inner.set(data, BLOCK_BYTES)
  outer.set(sha512(inner), BLOCK_BYTES)
  return sha512(outer)
}

function sha512 (data) {
  const hash = new Uint8Array(HASH_BYTES)
  sodium.crypto_hash_sha512(hash, data)
  return hash
}

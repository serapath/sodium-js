// the browser side: hyperswarm over the relay with custodial: false, so the browser runs the noise handshake
// itself and the relay never gets its secret key. sodium-universal is sodium-crypto here (package.json overrides)
const sodium = require('sodium-universal')
const Hyperswarm = require('hyperswarm')
const DHT = require('@hyperswarm/dht-relay')
const Stream = require('@hyperswarm/dht-relay/ws')
const b4a = require('b4a')

const params = new URLSearchParams(location.search)
const out = document.body.appendChild(document.createElement('pre'))

window.addEventListener('error', e => show('not ok', 'crashed ' + e.message))
window.addEventListener('unhandledrejection', e => show('not ok', 'crashed ' + (e.reason && e.reason.message)))
main().catch(err => show('not ok', err.stack || err.message))

async function main () {
  await sodium.ready // libsodium.js (noclamp) loads async
  const ws = new WebSocket(params.get('relay'))
  await new Promise(resolve => ws.addEventListener('open', resolve))
  const dht = new DHT(new Stream(true, ws), { custodial: false })
  const swarm = new Hyperswarm({ dht })
  swarm.on('connection', handle_connection)
  swarm.join(b4a.from(params.get('topic'), 'hex'), { server: false, client: true })
  show('info', 'joined the topic through the relay, custodial: false')
}

function handle_connection (socket) {
  socket.on('error', err => show('not ok', 'socket ' + err.message))
  socket.once('data', data => show('ok', 'got "' + b4a.toString(data) + '" from the native peer'))
}

function show (type, text) {
  window.results = (window.results || []).concat({ type, text })
  out.textContent += type + '  ' + text + '\n'
}

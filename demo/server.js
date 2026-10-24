// a local testnet, a relay that browsers reach over a websocket, a native peer, and budo for the page.
// the relay has firewalled: false, like a relay on a public ip with udp open. with custodial: false the
// browser does the noise handshake itself, so the native peer has to reach the relay over udp
const path = require('path')
const createTestnet = require('@hyperswarm/testnet')
const HyperDHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const { relay } = require('@hyperswarm/dht-relay')
const Stream = require('@hyperswarm/dht-relay/ws')
const { WebSocketServer } = require('ws')
const crypto = require('hypercore-crypto')
const budo = require('budo')

const RELAY_PORT = 49443
const PAGE_PORT = 9966

if (require.main === module) start().then(print_url)
module.exports = start

async function start () {
  const testnet = await createTestnet(3)
  const relay_dht = new HyperDHT({ bootstrap: testnet.bootstrap, firewalled: false, ephemeral: false, host: '127.0.0.1' })
  await relay_dht.fullyBootstrapped()
  const wss = new WebSocketServer({ port: RELAY_PORT })
  wss.on('connection', socket => relay(relay_dht, new Stream(false, socket)))

  const topic = crypto.randomBytes(32).toString('hex')
  const native = new Hyperswarm({ bootstrap: testnet.bootstrap })
  native.on('connection', handle_connection)
  await native.join(Buffer.from(topic, 'hex'), { server: true, client: false }).flushed()

  // browserify 17 cant parse libsodium-sumo.js (es2021 syntax), so it goes in unparsed
  const libsodium_sumo = require.resolve('libsodium-sumo', { paths: [require.resolve('libsodium-wrappers-sumo')] })
  const server = budo(path.join(__dirname, 'page.js') + ':bundle.js', { port: PAGE_PORT, dir: __dirname, browserify: { noParse: [libsodium_sumo] } })
  await new Promise(resolve => server.on('connect', resolve))
  const url = `http://localhost:${PAGE_PORT}/?relay=ws://localhost:${RELAY_PORT}&topic=${topic}`
  return { url, close }

  function handle_connection (socket) {
    socket.on('error', () => {})
    socket.write('hello from a native peer')
  }
  async function close () {
    server.close()
    wss.close()
    await native.destroy()
    await relay_dht.destroy()
    await testnet.destroy()
  }
}

function print_url ({ url }) { console.log('open ' + url) }

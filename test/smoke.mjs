// Real PKCS#11 round-trip via the gateway's pkcs11js backend.
//
// Drives a sequence of Pkcs11Request frames through ws-gateway-server
// against a *real* libpkcs11.so loaded via pkcs11js -- verifies the
// full chain end-to-end: WsTunnelManager.sendPkcs11Request →
// KSW1 Pkcs11Request → server dispatch → pkcs11js → libpkcs11 →
// libpkcs11 → pkcs11js → Pkcs11Response → adapter codec decode.
//
// PREREQS the script does NOT do for you:
//   1. `cd web && npm i pkcs11js` — Node N-API binding for PKCS#11 v2.40
//   2. Install a PKCS#11 module (SoftHSM, OpenSC, Yubikey, ...):
//        macOS:  brew install softhsm
//        Linux:  apt install softhsm2  /  pacman -S softhsm
//   3. Initialise the token:
//        export SOFTHSM2_CONF=/usr/local/etc/softhsm/softhsm2.conf  (Mac)
//        softhsm2-util --init-token --slot 0 --label test \
//                      --so-pin 1234 --pin 1234
//   4. Locate libsofthsm2 (or whichever module):
//        export PKCS11_LIB=/opt/homebrew/lib/softhsm/libsofthsm2.so
//
// Then: `PKCS11_BACKEND=pkcs11js node web/test-pkcs11js-real.mjs`
//
// What it tests, in order:
//   a. C_Initialize via lazy-load on first call (GetSlotList)
//   b. C_GetSlotList(token_present=true) -> >=1 slot
//   c. C_OpenSession(slot, RW|SERIAL) -> session handle
//   d. C_Login(session, USER, "1234")
//   e. C_GenerateRandom(session, 16)
//   f. C_SeedRandom(session, "deterministic-seed")
//   g. C_GetMechanismList(slot) -> non-empty list of CKM_*
//   h. C_Logout(session)
//   i. C_CloseSession(session)
//
// Verifies the full Pkcs11Fn -> C_* mapping landed correctly in
// web/ws-gateway-pkcs11.mjs's makePkcs11JsBackend.

import { createServer } from 'node:http'
import {
  WsTunnelManager,
  Pkcs11Fn,
  Pkcs11Writer,
  Pkcs11Reader,
  Pkcs11Status,
} from '@tegmentum/wasi-polyfill/plugins/ws-gateway'
import { startGateway } from '../src/index.mjs'

if (process.env.PKCS11_BACKEND !== 'pkcs11js') {
  console.error('PKCS11_BACKEND must be set to "pkcs11js"')
  console.error('also set PKCS11_LIB to the libsofthsm2 / libpkcs11.so path')
  console.error('and `cd web && npm i pkcs11js` first')
  process.exit(2)
}
if (!process.env.PKCS11_LIB) {
  console.error('PKCS11_LIB is not set')
  process.exit(2)
}

// 0. Ephemeral gateway port + in-process server (no spawn).
const port = await new Promise((resolve, reject) => {
  const probe = createServer()
  probe.listen(0, '127.0.0.1', () => { const p = probe.address().port; probe.close(() => resolve(p)) })
  probe.on('error', reject)
})

const gateway = await startGateway({
  port,
  log: (msg) => process.stderr.write(`[server] ${msg}\n`),
})

const tunnel = new WsTunnelManager({ gatewayUrl: gateway.address, connectTimeoutMs: 5000 })

let exitCode = 1
let sessionHandle = null
let slot = null

try {
  await tunnel.connect()
  console.log(`tunnel connected (features=0x${tunnel.features.toString(16)})`)

  async function rpc(fnName, payload) {
    const fnId = Pkcs11Fn[fnName]
    const res = await tunnel.sendPkcs11Request(fnId, payload, 10_000)
    if (res.status === Pkcs11Status.Ok) {
      return new Pkcs11Reader(res.body)
    }
    const body = res.body
    let msg = ''
    if (body.length > 4) {
      const v = new DataView(body.buffer, body.byteOffset)
      const slen = v.getUint32(0, true)
      msg = new TextDecoder().decode(body.slice(4, 4 + slen))
    }
    throw new Error(`${fnName}: status=${res.status} body="${msg}"`)
  }

  // (b) GetSlotList(token_present=true)
  {
    const w = new Pkcs11Writer(); w.bool(true)
    const r = await rpc('GetSlotList', w.finish())
    const slots = r.list(() => r.u64())
    if (slots.length === 0) throw new Error('no slots with token present')
    slot = slots[0]
    console.log(`(b) GetSlotList -> ${slots.length} slot(s); using slot=${slot}`)
  }

  // (g) GetMechanismList(slot) -- before login, doesn't need session
  {
    const w = new Pkcs11Writer(); w.u32(Number(slot))
    const r = await rpc('SlotMgrGetMechList', w.finish())
    const mechs = r.list(() => r.u64())
    console.log(`(g) GetMechanismList -> ${mechs.length} mechs (first 5: ${
      mechs.slice(0, 5).map(m => '0x' + m.toString(16)).join(',')})`)
    if (mechs.length === 0) throw new Error('no mechs reported')
  }

  // (c) OpenSession(slot, rw=1 | serial=2 -> CKF 0x6)
  {
    const w = new Pkcs11Writer()
    w.u32(Number(slot))
    w.u32(0x3)   // rw-session (bit0) + serial-session (bit1)
    const r = await rpc('OpenSession', w.finish())
    sessionHandle = r.u32()
    console.log(`(c) OpenSession -> handle=${sessionHandle}`)
  }

  // (d) Login(session, USER=1, "1234")
  {
    const w = new Pkcs11Writer()
    w.u32(sessionHandle)
    w.u32(1)  // CKU_USER
    w.bytes(new TextEncoder().encode('1234'))
    await rpc('SessionLogin', w.finish())
    console.log('(d) Login(USER) ok')
  }

  // (e) GenerateRandom(session, 16)
  {
    const w = new Pkcs11Writer()
    w.u32(sessionHandle); w.u32(16)
    const r = await rpc('SessionGenerateRandom', w.finish())
    const bytes = r.bytes()
    if (bytes.length !== 16) throw new Error(`expected 16, got ${bytes.length}`)
    console.log(`(e) GenerateRandom(16) -> ${
      Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')}`)
  }

  // (f) SeedRandom(session, "deterministic-seed")
  {
    const w = new Pkcs11Writer()
    w.u32(sessionHandle)
    w.bytes(new TextEncoder().encode('deterministic-seed'))
    await rpc('SessionSeedRandom', w.finish())
    console.log('(f) SeedRandom(18 bytes) ok')
  }

  // (h) Logout
  {
    const w = new Pkcs11Writer(); w.u32(sessionHandle)
    await rpc('SessionLogout', w.finish())
    console.log('(h) Logout ok')
  }

  // (i) CloseSession
  {
    const w = new Pkcs11Writer(); w.u32(sessionHandle)
    await rpc('SessionClose', w.finish())
    console.log('(i) CloseSession ok')
  }

  console.log('\nOK -- pkcs11js backend round-trip through ws-gateway-server ' +
              'verified end-to-end against a real PKCS#11 module.')
  exitCode = 0
} catch (err) {
  console.error('FAIL:', err.message || err)
} finally {
  await tunnel.disconnect()
  await gateway.close()
  process.exitCode = exitCode
}

// PKCS#11 backend for the ws-gateway-server. The gateway tunnels
// Pkcs11Request/Response frames; this module provides the per-method
// dispatch + the actual PKCS#11 call.
//
// `createPkcs11Backend({ kind })` returns an object with:
//   handle(fnId, argsBytes) -> Promise<{ status, body }>
//
// Backends:
//   - 'stub'  (default): always returns Pkcs11Status.Internal -- the
//             wire format is exercised end-to-end (browser polyfill
//             sends Pkcs11Request, server decodes fn-id, encodes the
//             status byte + error message). Useful for smoke-testing
//             the KSW1 plumbing without a real HSM.
//   - 'pkcs11js' (TODO): wire through the pkcs11js N-API binding so
//             dev gateways can serve SoftHSM/Yubikey/Luna directly.
//             Tracked as Phase 4b follow-up.
//
// All real PKCS#11 work is server-side; the gateway holds the PIN
// and decides which slots/objects/mechs the browser can reach (per
// the trust model in plans/openssl-provider-wit.md).

import {
  Pkcs11Fn, Pkcs11Status, Pkcs11Reader, Pkcs11Writer,
  readAttribute, readMechanism, writeAttribute, AttrTag,
} from '@tegmentum/wasi-polyfill/plugins/ws-gateway'

const DEFAULT_KIND = process.env.PKCS11_BACKEND ?? 'stub'

export function createPkcs11Backend(opts = {}) {
  const kind = opts.kind ?? DEFAULT_KIND
  switch (kind) {
    case 'stub':     return makeStubBackend()
    case 'pkcs11js': return makePkcs11JsBackend(opts)
    default: throw new Error(`unknown pkcs11 backend kind: ${kind}`)
  }
}

// --------------------------------------------------------------------------
// Stub backend -- always reports unimplemented but proves the wire format
// round-trips. The browser-side adapter (Phase 4b proper) can verify it
// sends a well-formed request and parses the error response.

function makeStubBackend() {
  return {
    kind: 'stub',
    async handle(fnId, args) {
      // Decode just enough to log; ignore arg content for stub.
      const fnName = Pkcs11Fn[fnId] ?? `0x${fnId.toString(16).padStart(4, '0')}`
      const msg = `stub backend: ${fnName} (${args.length} arg bytes) -- not implemented`
      return errorResponse(Pkcs11Status.Internal, msg)
    },
  }
}

// --------------------------------------------------------------------------
// pkcs11js backend -- wires real PKCS#11 calls via the pkcs11js N-API
// binding. Requires:
//
//   1. `npm i pkcs11js`  (PeculiarVentures' Node binding for PKCS#11 v2.40)
//   2. `PKCS11_LIB`     env var -> absolute path to libsofthsm2.so /
//                                  opensc-pkcs11.so / yubihsm_pkcs11.so / ...
//
// Lazy-imports pkcs11js on first call so the gateway boots cleanly
// without the dep installed (the stub backend is the default).
// Returns a clear error message if pkcs11js is missing.
//
// Resource-handle table: server-side u32 row-ids minted on session
// open / object find / search cursor creation, freed on
// Fn::HandleDrop. The browser-side adapter shuttles them opaquely.

function makePkcs11JsBackend(opts) {
  /** @type {Promise<{lib: any, mod: any} | {err: string}> | null} */
  let initPromise = null

  /**
   * Lazy-load pkcs11js and Module.load+initialize. Memoized: subsequent
   * calls reuse the same Module handle.
   */
  async function ensureModule() {
    if (initPromise) return initPromise
    initPromise = (async () => {
      let pkcs11
      try {
        pkcs11 = await import('pkcs11js')
      } catch (e) {
        return { err: `pkcs11js not installed: ${e?.message ?? e}. ` +
          `Run \`cd web && npm i pkcs11js\` and set PKCS11_LIB=/path/to/libpkcs11.so` }
      }
      const lib = opts?.lib ?? process.env.PKCS11_LIB
      if (!lib) {
        return { err: 'PKCS11_LIB is not set (path to libpkcs11.so). ' +
          'Example: PKCS11_LIB=/opt/homebrew/lib/softhsm/libsofthsm2.so' }
      }
      try {
        const mod = new pkcs11.PKCS11()
        mod.load(lib)
        mod.C_Initialize()
        return { lib, mod }
      } catch (e) {
        return { err: `pkcs11 module load/init failed: ${e?.message ?? e}` }
      }
    })()
    return initPromise
  }

  // --- handle table ---
  let nextId = 1
  // Session/Cursor: Map<u32 row, native handle>. Object also carries
  // a refcount so bind-object (Pkcs11Fn.ObjectBind) can hand out new
  // wrappers around an existing native handle without freeing under
  // the first Drop.
  const tables = {
    1: new Map(), // Session: row -> native
    2: new Map(), // Object:  row -> { native, rc }
    3: new Map(), // Cursor:  row -> native
  }
  function mintHandle(kind, native) {
    const id = nextId++
    if (kind === 2) tables[2].set(id, { native, rc: 1 })
    else            tables[kind].set(id, native)
    return id
  }
  function lookupHandle(kind, id) {
    const v = tables[kind].get(id)
    return kind === 2 ? v?.native : v
  }
  function dropHandle(kind, id) {
    if (kind === 2) {
      const v = tables[2].get(id)
      if (!v) return
      if (--v.rc <= 0) tables[2].delete(id)
    } else {
      tables[kind].delete(id)
    }
  }
  /** Increment refcount on an existing Object row. Returns the same id
   *  on success, undefined if the row has been freed. */
  function bindObject(id) {
    const v = tables[2].get(id)
    if (!v) return undefined
    v.rc += 1
    return id
  }

  // Expose "first open session" for ObjectGetAttributes -- it needs
  // a session handle but our WIT models attribute reads on Object
  // alone. The bridge always has one open session by the time it
  // touches objects.
  globalThis.__pkcs11js_first_session = () => {
    for (const v of tables[1].values()) return v
    return undefined
  }

  return {
    kind: 'pkcs11js',
    async handle(fnId, args) {
      const init = await ensureModule()
      if (init.err) return errorResponse(Pkcs11Status.Internal, init.err)
      const { mod } = init
      try {
        switch (fnId) {
          case Pkcs11Fn.GetSlotList: {
            const r = new Pkcs11Reader(args)
            const tokenPresent = r.bool()
            const slots = mod.C_GetSlotList(tokenPresent)
            // slots are returned as Buffer (CK_ULONG width); pkcs11js
            // makes them Buffer or number depending on platform. Coerce
            // each to BigInt then to u64 little-endian for the codec.
            const w = new Pkcs11Writer()
            w.u32(slots.length)
            for (const s of slots) {
              // Native CK_SLOT_ID is platform-dependent. pkcs11js
              // exposes it as a Buffer on 64-bit; convert to BigInt.
              const big = Buffer.isBuffer(s) ? bufferToBig(s) : BigInt(s)
              w.u64(big)
            }
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.OpenSession: {
            // Args: u32 slot, u32 flags (WIT bitflags: bit0=rw-session,
            // bit1=serial-session). Translate to CKF_*.
            const r = new Pkcs11Reader(args)
            const slot  = r.u32()
            const flags = r.u32()
            let ckfFlags = 0
            if (flags & 1) ckfFlags |= 0x00000002 /* CKF_RW_SESSION */
            if (flags & 2) ckfFlags |= 0x00000004 /* CKF_SERIAL_SESSION */
            // Some tokens REQUIRE serial-session; pkcs11js will reject otherwise.
            // Pass slot as an 8-byte LE Buffer (CK_SLOT_ID is 64-bit on
            // macOS pkcs11js builds and the binding rejects both Number
            // and BigInt for this arg — Buffer always works).
            const slotArg = slotToBuffer(slot)
            const native = mod.C_OpenSession(slotArg, ckfFlags)
            const id = mintHandle(1 /* Session */, native)
            const w = new Pkcs11Writer()
            w.u32(id)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionClose: {
            const r = new Pkcs11Reader(args)
            const id = r.u32()
            const native = lookupHandle(1, id)
            if (native === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session handle ${id}`)
            }
            mod.C_CloseSession(native)
            dropHandle(1, id)
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionLogin: {
            // Args: u32 handle, u32 user_type, bytes pin
            const r = new Pkcs11Reader(args)
            const id  = r.u32()
            const usr = r.u32()
            const pin = r.bytes()
            const native = lookupHandle(1, id)
            if (native === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session handle ${id}`)
            }
            // user_type wire: 0=so, 1=user, 2=context-specific
            // CK constants: CKU_SO=0, CKU_USER=1, CKU_CONTEXT_SPECIFIC=2 (matches)
            // pkcs11js wants PIN as String (utf8-decoded), not Buffer.
            mod.C_Login(native, usr, new TextDecoder().decode(pin))
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionLoginVendor: {
            // Args: u32 sess, u32 vendor_user_type, bytes pin
            const r = new Pkcs11Reader(args)
            const id  = r.u32()
            const usr = r.u32()
            const pin = r.bytes()
            const native = lookupHandle(1, id)
            if (native === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session handle ${id}`)
            }
            // pkcs11js's C_Login accepts any CK_USER_TYPE number, so a
            // vendor-defined one (>= 0x80000000) Just Works.
            mod.C_Login(native, usr, new TextDecoder().decode(pin))
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionLogout: {
            const r = new Pkcs11Reader(args)
            const id = r.u32()
            const native = lookupHandle(1, id)
            if (native === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session handle ${id}`)
            }
            mod.C_Logout(native)
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionInitPin: {
            // Args: u32 handle, bytes pin
            const r = new Pkcs11Reader(args)
            const id  = r.u32()
            const pin = r.bytes()
            const native = lookupHandle(1, id)
            if (native === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session handle ${id}`)
            }
            mod.C_InitPIN(native, new TextDecoder().decode(pin))
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.InitToken: {
            // Args: u32 slot, option<string> so_pin, string label
            const r = new Pkcs11Reader(args)
            const slot = slotToBuffer(r.u32())  // pkcs11js requires Buffer for slot args
            const soPin = r.option(() => r.str())
            const label = r.str()
            mod.C_InitToken(slot, soPin ?? '', label)
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionFindInit: {
            // Args: u32 handle, list<attribute> template
            const r = new Pkcs11Reader(args)
            const id = r.u32()
            const template = decodeAttributeTemplate(r)
            const native = lookupHandle(1, id)
            if (native === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session handle ${id}`)
            }
            mod.C_FindObjectsInit(native, template)
            // pkcs11js doesn't return a separate cursor handle — the
            // session itself owns the find state. Mint a logical cursor
            // id pointing back at the same session.
            const cursorId = mintHandle(3 /* Cursor */, native)
            const w = new Pkcs11Writer()
            w.u32(cursorId)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionFindNext: {
            const r = new Pkcs11Reader(args)
            const cur = r.u32()
            const max = r.u32()
            const sess = lookupHandle(3, cur)
            if (sess === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown cursor ${cur}`)
            }
            const handles = mod.C_FindObjects(sess, max)
            const w = new Pkcs11Writer()
            w.u32(handles.length)
            for (const h of handles) {
              const id = mintHandle(2 /* Object */, h)
              w.u32(id)
            }
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionFindFinal: {
            const r = new Pkcs11Reader(args)
            const cur = r.u32()
            const sess = lookupHandle(3, cur)
            if (sess === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown cursor ${cur}`)
            }
            mod.C_FindObjectsFinal(sess)
            dropHandle(3, cur)
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionGenKeyPair: {
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const pubT  = decodeAttributeTemplate(r)
            const privT = decodeAttributeTemplate(r)
            if (sess === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session`)
            }
            const { publicKey, privateKey } = mod.C_GenerateKeyPair(sess, mech, pubT, privT)
            const pubId  = mintHandle(2, publicKey)
            const privId = mintHandle(2, privateKey)
            const w = new Pkcs11Writer()
            w.u32(pubId); w.u32(privId)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionSign: {
            // Args: u32 sess, mechanism, u32 key_obj, bytes msg
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const key  = lookupHandle(2, r.u32())
            const data = r.bytes()
            if (sess === undefined || key === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session/key handle`)
            }
            mod.C_SignInit(sess, mech, key)
            // Allocate a generous output buffer; pkcs11js trims to actual length.
            const out = Buffer.alloc(512)
            const sig = mod.C_Sign(sess, Buffer.from(data), out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(sig))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionVerify: {
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const key  = lookupHandle(2, r.u32())
            const data = r.bytes()
            const sig  = r.bytes()
            if (sess === undefined || key === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session/key handle`)
            }
            mod.C_VerifyInit(sess, mech, key)
            mod.C_Verify(sess, Buffer.from(data), Buffer.from(sig))
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionEncrypt: {
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const key  = lookupHandle(2, r.u32())
            const pt   = r.bytes()
            const max  = r.u32()
            if (sess === undefined || key === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session/key handle`)
            }
            mod.C_EncryptInit(sess, mech, key)
            const out = Buffer.alloc(max)
            const ct  = mod.C_Encrypt(sess, Buffer.from(pt), out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(ct))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionDecrypt: {
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const key  = lookupHandle(2, r.u32())
            const ct   = r.bytes()
            const max  = r.u32()
            if (sess === undefined || key === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session/key handle`)
            }
            mod.C_DecryptInit(sess, mech, key)
            const out = Buffer.alloc(max)
            const pt  = mod.C_Decrypt(sess, Buffer.from(ct), out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(pt))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionDigest: {
            // Args: u32 sess, Mechanism, bytes data
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const data = r.bytes()
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            mod.C_DigestInit(sess, mech)
            const out = Buffer.alloc(512)
            const h = mod.C_Digest(sess, Buffer.from(data), out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(h))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionSeedRandom: {
            // Args: u32 sess, bytes seed
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const seed = r.bytes()
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            mod.C_SeedRandom(sess, Buffer.from(seed))
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionGenerateRandom: {
            // Args: u32 sess, u32 len
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const len  = r.u32()
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            const out = Buffer.alloc(len)
            mod.C_GenerateRandom(sess, out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(out))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionCancelFunc: {
            // Args: u32 sess. PKCS#11 has no C_CancelFunction in v2.40
            // (it was deprecated). pkcs11js exposes nothing for it
            // either -- we just return Ok. Real impl would call
            // C_CancelFunction if the loaded module advertises it.
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionSetPin: {
            // Args: u32 sess, bytes old, bytes new
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const oldPin = r.bytes()
            const newPin = r.bytes()
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            mod.C_SetPIN(sess, new TextDecoder().decode(oldPin), new TextDecoder().decode(newPin))
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionDigestKey: {
            // Args: u32 sess, u32 key
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const key  = lookupHandle(2, r.u32())
            if (sess === undefined || key === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session/key handle`)
            }
            mod.C_DigestKey(sess, key)
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionSignRecover: {
            // Args: u32 sess, mechanism, u32 key, bytes data, u32 max
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const key  = lookupHandle(2, r.u32())
            const data = r.bytes()
            const max  = r.u32()
            if (sess === undefined || key === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session/key handle`)
            }
            mod.C_SignRecoverInit(sess, mech, key)
            const out = Buffer.alloc(max)
            const sig = mod.C_SignRecover(sess, Buffer.from(data), out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(sig))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionVerifyRecover: {
            // Args: u32 sess, mechanism, u32 key, bytes sig, u32 max
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const key  = lookupHandle(2, r.u32())
            const sig  = r.bytes()
            const max  = r.u32()
            if (sess === undefined || key === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown session/key handle`)
            }
            mod.C_VerifyRecoverInit(sess, mech, key)
            const out = Buffer.alloc(max)
            const pt  = mod.C_VerifyRecover(sess, Buffer.from(sig), out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(pt))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionCreateObject: {
            // Args: u32 sess, list<attribute> template
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const template = decodeAttributeTemplate(r)
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            const native = mod.C_CreateObject(sess, template)
            const id = mintHandle(2 /* Object */, native)
            const w = new Pkcs11Writer()
            w.u32(id)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionGenerateKey: {
            // Args: u32 sess, mechanism, list<attribute>
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const tmpl = decodeAttributeTemplate(r)
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            const native = mod.C_GenerateKey(sess, mech, tmpl)
            const id = mintHandle(2, native)
            const w = new Pkcs11Writer()
            w.u32(id)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionDeriveKey: {
            // Args: u32 sess, u32 base, mechanism, list<attribute>
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const base = lookupHandle(2, r.u32())
            const mech = decodeMechanism(r)
            const tmpl = decodeAttributeTemplate(r)
            if (sess === undefined || base === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, 'unknown session/base-key handle')
            }
            const native = mod.C_DeriveKey(sess, mech, base, tmpl)
            const id = mintHandle(2, native)
            const w = new Pkcs11Writer()
            w.u32(id)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionWrapKey: {
            // Args: u32 sess, mechanism, u32 wrap_key, u32 key
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const wk   = lookupHandle(2, r.u32())
            const key  = lookupHandle(2, r.u32())
            if (sess === undefined || wk === undefined || key === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, 'unknown session/key handle')
            }
            // C_WrapKey output size: most modules return CKR_BUFFER_TOO_SMALL
            // on a small buffer with the required size, but pkcs11js trims
            // for us. Allocate a generous default (4 KiB covers RSA-4096 + AES-GCM).
            const out = Buffer.alloc(4096)
            const blob = mod.C_WrapKey(sess, mech, wk, key, out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(blob))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionUnwrapKey: {
            // Args: u32 sess, mechanism, u32 unwrap_key, bytes wrapped, list<attribute>
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const uk   = lookupHandle(2, r.u32())
            const wrapped = r.bytes()
            const tmpl = decodeAttributeTemplate(r)
            if (sess === undefined || uk === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, 'unknown session/unwrap-key handle')
            }
            const native = mod.C_UnwrapKey(sess, mech, uk, Buffer.from(wrapped), tmpl)
            const id = mintHandle(2, native)
            const w = new Pkcs11Writer()
            w.u32(id)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionCopyObject: {
            // Args: u32 sess, u32 src, list<attribute>
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const src  = lookupHandle(2, r.u32())
            const tmpl = decodeAttributeTemplate(r)
            if (sess === undefined || src === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, 'unknown session/src handle')
            }
            const native = mod.C_CopyObject(sess, src, tmpl)
            const id = mintHandle(2, native)
            const w = new Pkcs11Writer()
            w.u32(id)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionGetOpState: {
            // Args: u32 sess, u32 max
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const max  = r.u32()
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            const out = Buffer.alloc(max)
            const state = mod.C_GetOperationState(sess, out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(state))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionSetOpState: {
            // Args: u32 sess, bytes state, option<u32 enc>, option<u32 auth>
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const state = r.bytes()
            const enc  = r.option(() => lookupHandle(2, r.u32())) ?? 0
            const auth = r.option(() => lookupHandle(2, r.u32())) ?? 0
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            mod.C_SetOperationState(sess, Buffer.from(state), enc, auth)
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          // ---- Multipart crypto. Each *Init sends (sess, mech [, key])
          //      and dispatches C_*Init; *Update sends (sess, bytes, bool)
          //      and dispatches C_*Update; *Final sends (sess [, max | sig])
          //      and dispatches C_*Final; *Abort is a no-op success (PKCS#11
          //      v2.40 has no C_*Abort -- next *Init will see CKR_OPERATION_ACTIVE).

          case Pkcs11Fn.SessionEncryptInit: case Pkcs11Fn.SessionDecryptInit:
          case Pkcs11Fn.SessionSignInitMP:  case Pkcs11Fn.SessionVerifyInitMP: {
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            const key  = lookupHandle(2, r.u32())
            if (sess === undefined || key === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, 'unknown session/key handle')
            }
            const C_Init = {
              [Pkcs11Fn.SessionEncryptInit]: mod.C_EncryptInit,
              [Pkcs11Fn.SessionDecryptInit]: mod.C_DecryptInit,
              [Pkcs11Fn.SessionSignInitMP]:  mod.C_SignInit,
              [Pkcs11Fn.SessionVerifyInitMP]: mod.C_VerifyInit,
            }[fnId]
            C_Init.call(mod, sess, mech, key)
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }
          case Pkcs11Fn.SessionDigestInitMP: {
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const mech = decodeMechanism(r)
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            mod.C_DigestInit(sess, mech)
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionEncryptUpdate: case Pkcs11Fn.SessionDecryptUpdate: {
            // -> bytes (returned chunk of cipher/plaintext)
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const part = r.bytes()
            r.bool()  // `final` hint; ignored -- PKCS#11 streams have no per-part terminator
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            const out = Buffer.alloc(Math.max(part.length + 64, 256))
            const fn = fnId === Pkcs11Fn.SessionEncryptUpdate ? mod.C_EncryptUpdate : mod.C_DecryptUpdate
            const chunk = fn.call(mod, sess, Buffer.from(part), out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(chunk))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }
          case Pkcs11Fn.SessionSignUpdate: case Pkcs11Fn.SessionVerifyUpdate:
          case Pkcs11Fn.SessionDigestUpdate: {
            // -> () (sign/verify/digest accumulate; no output until final)
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const part = r.bytes()
            r.bool()  // `final` hint; ignored
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            const fn = {
              [Pkcs11Fn.SessionSignUpdate]:   mod.C_SignUpdate,
              [Pkcs11Fn.SessionVerifyUpdate]: mod.C_VerifyUpdate,
              [Pkcs11Fn.SessionDigestUpdate]: mod.C_DigestUpdate,
            }[fnId]
            fn.call(mod, sess, Buffer.from(part))
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionEncryptFinal: case Pkcs11Fn.SessionDecryptFinal: {
            // -> bytes (final tag/block)
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const max  = r.u32()
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            const out = Buffer.alloc(Math.max(max, 64))
            const fn = fnId === Pkcs11Fn.SessionEncryptFinal ? mod.C_EncryptFinal : mod.C_DecryptFinal
            const tail = fn.call(mod, sess, out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(tail))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }
          case Pkcs11Fn.SessionSignFinal: case Pkcs11Fn.SessionDigestFinal: {
            // -> bytes
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            const out = Buffer.alloc(1024)
            const fn = fnId === Pkcs11Fn.SessionSignFinal ? mod.C_SignFinal : mod.C_DigestFinal
            const result = fn.call(mod, sess, out)
            const w = new Pkcs11Writer()
            w.bytes(new Uint8Array(result))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }
          case Pkcs11Fn.SessionVerifyFinal: {
            // (sess, bytes signature) -> ()
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const sig  = r.bytes()
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            mod.C_VerifyFinal(sess, Buffer.from(sig))
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SessionEncryptAbort: case Pkcs11Fn.SessionDecryptAbort:
          case Pkcs11Fn.SessionSignAbort:    case Pkcs11Fn.SessionVerifyAbort:
          case Pkcs11Fn.SessionDigestAbort: {
            // PKCS#11 v2.40 doesn't expose per-op cancel. Best-effort no-op;
            // the next *Init on the session will return CKR_OPERATION_ACTIVE
            // if the caller really leaked an op.
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SlotMgrGetInfo: {
            const info = mod.C_GetInfo()
            const w = new Pkcs11Writer()
            writeModuleInfo(w, info)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SlotMgrGetSlotInfo: {
            const r = new Pkcs11Reader(args)
            const slot = slotToBuffer(r.u32())  // pkcs11js requires Buffer for slot args
            const info = mod.C_GetSlotInfo(slot)
            const w = new Pkcs11Writer()
            writeSlotInfo(w, info)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SlotMgrGetTokenInfo: {
            const r = new Pkcs11Reader(args)
            const slot = slotToBuffer(r.u32())  // pkcs11js requires Buffer for slot args
            const info = mod.C_GetTokenInfo(slot)
            const w = new Pkcs11Writer()
            writeTokenInfo(w, info)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SlotMgrWaitForSlotEvent: {
            const r = new Pkcs11Reader(args)
            const flags = r.u32()
            // PKCS#11 CKF_DONT_BLOCK = 1; matches our wait-flags bit 0.
            const ckf = (flags & 1) ? 1 : 0
            const ev = mod.C_WaitForSlotEvent(ckf)
            const w = new Pkcs11Writer()
            // pkcs11js returns null on no-event (when CKF_DONT_BLOCK set);
            // surface that as CkError CKR_NO_EVENT (0x08).
            if (!ev) {
              const msg = new TextEncoder().encode('CKR_NO_EVENT')
              const body = new Uint8Array(4 + msg.length)
              new DataView(body.buffer).setUint32(0, 0x08, true)
              body.set(msg, 4)
              return { status: Pkcs11Status.CkError, body }
            }
            const slot = typeof ev.slot === 'bigint' ? Number(ev.slot) : (ev.slot >>> 0)
            w.u32(slot)
            w.bool(!!ev.tokenPresent)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SlotMgrGetMechInfo: {
            const r = new Pkcs11Reader(args)
            const slot = slotToBuffer(r.u32())  // pkcs11js requires Buffer for slot args
            const mech = Number(r.u64())
            const info = mod.C_GetMechanismInfo(slot, mech)
            const w = new Pkcs11Writer()
            writeMechanismInfo(w, info)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SessionGetInfo: {
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            const info = mod.C_GetSessionInfo(sess)
            const w = new Pkcs11Writer()
            writeSessionInfo(w, info)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.SlotMgrInitialize: {
            // Args: option<string> config -- ignored; pkcs11js auto-inits
            // via ensureModule(). Idempotent success.
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SlotMgrFinalize: {
            // Args: ()
            try { mod.C_Finalize() } catch { /* idempotent */ }
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SlotMgrCloseAllSessions: {
            // Args: u32 slot
            const r = new Pkcs11Reader(args)
            const slot = slotToBuffer(r.u32())  // pkcs11js requires Buffer for slot args
            mod.C_CloseAllSessions(slot)
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.SlotMgrGetMechList: {
            // Args: u32 slot. Reply: list<u64> mech ids.
            const r = new Pkcs11Reader(args)
            const slot = slotToBuffer(r.u32())  // pkcs11js requires Buffer here
            const mechs = mod.C_GetMechanismList(slot)
            const w = new Pkcs11Writer()
            w.u32(mechs.length)
            for (const m of mechs) {
              const big = Buffer.isBuffer(m) ? bufferToBig(m) : BigInt(m)
              w.u64(big)
            }
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.ObjectGetSize: {
            // Args: u32 obj_handle. Reply: u64 size.
            const r = new Pkcs11Reader(args)
            const native = lookupHandle(2, r.u32())
            if (native === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown object')
            // C_GetObjectSize needs a session too.
            const sess = firstSessionHandle()
            if (sess === undefined) return errorResponse(Pkcs11Status.Internal, 'no open session')
            const size = mod.C_GetObjectSize(sess, native)
            const w = new Pkcs11Writer()
            w.u64(typeof size === 'bigint' ? size : BigInt(size))
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.ObjectSetAttributes: {
            // Args: u32 obj_handle, list<Attribute> template.
            const r = new Pkcs11Reader(args)
            const native = lookupHandle(2, r.u32())
            const template = decodeAttributeTemplate(r)
            if (native === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown object')
            const sess = firstSessionHandle()
            if (sess === undefined) return errorResponse(Pkcs11Status.Internal, 'no open session')
            mod.C_SetAttributeValue(sess, native, template)
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.ObjectDestroy: {
            // Args: u32 obj_handle.
            const r = new Pkcs11Reader(args)
            const id     = r.u32()
            const native = lookupHandle(2, id)
            if (native === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown object')
            const sess = firstSessionHandle()
            if (sess === undefined) return errorResponse(Pkcs11Status.Internal, 'no open session')
            mod.C_DestroyObject(sess, native)
            dropHandle(2, id)
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          case Pkcs11Fn.ObjectGetAttributes: {
            // Args: u32 obj_handle, list<u32> tags
            const r = new Pkcs11Reader(args)
            const objId = r.u32()
            const tags  = r.list(() => r.u32())
            const native = lookupHandle(2, objId)
            if (native === undefined) {
              return errorResponse(Pkcs11Status.ProtocolError, `unknown object ${objId}`)
            }
            // C_GetAttributeValue wants a template array of {type, value}.
            // pkcs11js auto-sizes if we pass {type} without value.
            const template = tags.map(t => ({ type: t }))
            // ObjectGetAttributes is on the session, not the object —
            // PKCS#11 ties attribute reads to a session. We don't carry
            // the session in object handles; for now assume the bridge
            // only calls get-attributes from within the session that
            // owns the object. pkcs11js attaches the session per call.
            // To keep things simple, find any open session.
            const anySess = firstSessionHandle()
            if (anySess === undefined) {
              return errorResponse(Pkcs11Status.Internal,
                'no open session; ObjectGetAttributes needs C_OpenSession first')
            }
            const filled = mod.C_GetAttributeValue(anySess, native, template)
            const w = new Pkcs11Writer()
            w.u32(filled.length)
            for (const a of filled) {
              writeAttribute(w, ckaToCodecAttribute(a))
            }
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.ObjectBind: {
            // Args: u32 sess, u32 obj_row
            const r = new Pkcs11Reader(args)
            const sess = lookupHandle(1, r.u32())
            const objId = r.u32()
            if (sess === undefined) return errorResponse(Pkcs11Status.ProtocolError, 'unknown session')
            const bound = bindObject(objId)
            if (bound === undefined) return errorResponse(Pkcs11Status.ProtocolError, `unknown object ${objId}`)
            const w = new Pkcs11Writer()
            w.u32(bound)
            return { status: Pkcs11Status.Ok, body: w.finish() }
          }

          case Pkcs11Fn.HandleDrop: {
            const r = new Pkcs11Reader(args)
            const kind = r.u8()
            const id   = r.u32()
            const native = lookupHandle(kind, id)
            dropHandle(kind, id)
            // Best-effort close. Different handle kinds need different calls.
            if (native !== undefined) {
              try {
                if (kind === 1 /* Session */) mod.C_CloseSession(native)
                else if (kind === 3 /* Cursor */) mod.C_FindObjectsFinal(native)
                // Object handles have no explicit close; they belong to the session.
              } catch { /* ignore — drop is best-effort */ }
            }
            return { status: Pkcs11Status.Ok, body: new Uint8Array(0) }
          }

          default: {
            // Other fn-ids still routed through the stub-style not-impl
            // until we wire them. Each addition is mechanical: decode
            // args via Pkcs11Reader -> mod.C_*(...) -> encode reply via
            // Pkcs11Writer. See codec spec in pkcs11-codec.ts + the
            // bridge's usage in pkcs11-bridge/src/lib.rs for what args
            // each fn expects.
            const fnName = Pkcs11Fn[fnId] ?? `0x${fnId.toString(16).padStart(4, '0')}`
            return errorResponse(Pkcs11Status.Internal,
              `pkcs11js backend: ${fnName} not yet wired (see ws-gateway-pkcs11.mjs)`)
          }
        }
      } catch (e) {
        // Map a CKR_-style exception from pkcs11js back to CkError so
        // the adapter can surface a meaningful ErrorCode. pkcs11js
        // throws Error with `code` set to the numeric CKR.
        const ckr = typeof e?.code === 'number' ? e.code : 0
        const msg = `pkcs11 fn 0x${fnId.toString(16)}: ${e?.message ?? e}`
        if (ckr !== 0) {
          // Body: u32 LE ckr + utf8 message (per Pkcs11Status.CkError).
          const msgBytes = new TextEncoder().encode(msg)
          const body = new Uint8Array(4 + msgBytes.length)
          new DataView(body.buffer).setUint32(0, ckr, true)
          body.set(msgBytes, 4)
          return { status: Pkcs11Status.CkError, body }
        }
        return errorResponse(Pkcs11Status.Internal, msg)
      }
    },
  }
}

/** Encode a slot/mech BigInt as the 8-byte LE Buffer pkcs11js wants
 *  on macOS, where CK_SLOT_ID/CK_MECHANISM_TYPE are 64-bit. Some
 *  pkcs11js binding paths (notably C_GetMechanismList, C_GetSlotInfo,
 *  C_GetMechanismInfo) reject BigInt and Number for ULONG args and
 *  require Buffer. C_OpenSession accepts BigInt directly; the binding
 *  is inconsistent. Buffer always works. */
function slotToBuffer(big) {
  const b = Buffer.alloc(8)
  let v = typeof big === 'bigint' ? big : BigInt(big)
  for (let i = 0; i < 8; i++) {
    b[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return b
}

function bufferToBig(buf) {
  // pkcs11js returns CK_ULONG as a little-endian Buffer on most platforms.
  let v = 0n
  for (let i = buf.length - 1; i >= 0; i--) {
    v = (v << 8n) | BigInt(buf[i])
  }
  return v
}

/**
 * Decode a list<attribute> from the wire into pkcs11js's attribute
 * template shape: `[{ type: CKA_*, value: ... }, ...]`. pkcs11js
 * accepts Buffer / boolean / number / BigInt for `value` depending
 * on CK_ATTRIBUTE_TYPE; we feed it whichever the AttrTag implies.
 */
function decodeAttributeTemplate(r) {
  const count = r.u32()
  const out = []
  for (let i = 0; i < count; i++) {
    out.push(codecAttributeToCka(readAttribute(r)))
  }
  return out
}

/** Codec.Attribute -> pkcs11js { type, value } */
function codecAttributeToCka(a) {
  const { cka, value } = a
  switch (value.tag) {
    case AttrTag.Boolean:        return { type: cka, value: value.val }
    case AttrTag.Uint32:
    case AttrTag.KeyKind:
    case AttrTag.ObjectClass:    return { type: cka, value: value.val }
    case AttrTag.Uint64:
    case AttrTag.MechanismType:  return { type: cka, value: Number(value.val) }
    case AttrTag.ByteString:
    case AttrTag.VendorBytes:    return { type: cka, value: Buffer.from(value.val) }
    case AttrTag.String:
    case AttrTag.DateString:     return { type: cka, value: Buffer.from(value.val, 'utf8') }
    default: throw new Error(`unknown AttrTag ${value.tag}`)
  }
}

/**
 * Best-effort pkcs11js->codec Attribute. The wire format needs a
 * tag; pkcs11js's attribute object after C_GetAttributeValue carries
 * `type` (CKA_*) + `value` (Buffer for opaque, number for ulong,
 * boolean for bool). Without CK_ATTRIBUTE schema we can't pick the
 * exact AttrTag, so default to ByteString for Buffer / Uint32 for
 * number / Boolean for bool — bridge callers care about the bytes
 * anyway.
 */
function ckaToCodecAttribute(a) {
  const cka = a.type
  let value
  if (Buffer.isBuffer(a.value)) {
    value = { tag: AttrTag.ByteString, val: new Uint8Array(a.value) }
  } else if (typeof a.value === 'boolean') {
    value = { tag: AttrTag.Boolean, val: a.value }
  } else if (typeof a.value === 'number') {
    value = { tag: AttrTag.Uint32, val: a.value >>> 0 }
  } else if (typeof a.value === 'bigint') {
    value = { tag: AttrTag.Uint64, val: a.value }
  } else {
    value = { tag: AttrTag.ByteString, val: new Uint8Array(0) }
  }
  return { cka, value }
}

/** Decode a Mechanism from the wire into pkcs11js shape: { mechanism, parameter? }. */
function decodeMechanism(r) {
  const m = readMechanism(r)
  // pkcs11js expects a number/bigint for mechanism kind.
  const out = { mechanism: Number(m.ckm) }
  if (m.parameter) out.parameter = Buffer.from(m.parameter)
  return out
}

/**
 * pkcs11js's C_GetAttributeValue requires a session handle even
 * though we model attribute reads on the Object resource. Return
 * any currently-open session's native handle so the call lands; the
 * bridge always has at least one open session by the time it reads
 * object attributes.
 */
function firstSessionHandle() {
  // (Sessions table lives in the closure; expose via this scope by
  // calling the parent backend's `tables[1]`. Use a module-level
  // reference set by makePkcs11JsBackend.)
  return globalThis.__pkcs11js_first_session?.()
}

// --------------------------------------------------------------------------
// Helpers

function errorResponse(status, message) {
  const w = new Pkcs11Writer()
  w.str(message)
  return { status, body: w.finish() }
}

// --------------------------------------------------------------------------
// Info-struct encoders. Wire layouts match the per-field decoders in
// pkcs11-gateway-adapter/src/lib.rs. Each field is little-endian.
//
// pkcs11js field naming is documented under each writer; the binding
// uses camelCase. Flag fields come back as numbers (CK_FLAGS).

// CK_VERSION { byte major; byte minor }
function writeVersion(w, v) {
  // pkcs11js: { major: number, minor: number }
  w.u8(v?.major ?? 0)
  w.u8(v?.minor ?? 0)
}

function writeBytesAsStr(w, val) {
  if (val == null) { w.str(''); return }
  if (Buffer.isBuffer(val)) {
    // PKCS#11 strings are space-padded fixed-width. Trim trailing spaces
    // + zero bytes so the WIT string matches CK_INFO.manufacturerID's
    // logical content.
    let end = val.length
    while (end > 0 && (val[end - 1] === 0x20 || val[end - 1] === 0x00)) end--
    w.str(val.slice(0, end).toString('utf8'))
  } else {
    w.str(String(val))
  }
}

// CK_INFO -> ModuleInfo
function writeModuleInfo(w, info) {
  // pkcs11js: { cryptokiVersion, manufacturerID, flags, libraryDescription, libraryVersion }
  writeVersion(w, info?.cryptokiVersion)
  writeBytesAsStr(w, info?.manufacturerID)
  w.u64(BigInt(info?.flags ?? 0))
  writeBytesAsStr(w, info?.libraryDescription)
  writeVersion(w, info?.libraryVersion)
}

// CK_SLOT_INFO -> SlotInfo
function writeSlotInfo(w, info) {
  // pkcs11js: { slotDescription, manufacturerID, flags, hardwareVersion, firmwareVersion }
  writeBytesAsStr(w, info?.slotDescription)
  writeBytesAsStr(w, info?.manufacturerID)
  w.u32(Number(info?.flags ?? 0) >>> 0)
  writeVersion(w, info?.hardwareVersion)
  writeVersion(w, info?.firmwareVersion)
}

// CK_TOKEN_INFO -> TokenInfo
function writeTokenInfo(w, info) {
  // pkcs11js: { label, manufacturerID, model, serialNumber, flags,
  //            maxSessionCount, sessionCount, maxRwSessionCount, rwSessionCount,
  //            maxPinLen, minPinLen,
  //            totalPublicMemory, freePublicMemory, totalPrivateMemory, freePrivateMemory,
  //            hardwareVersion, firmwareVersion, utcTime }
  writeBytesAsStr(w, info?.label)
  writeBytesAsStr(w, info?.manufacturerID)
  writeBytesAsStr(w, info?.model)
  writeBytesAsStr(w, info?.serialNumber)
  w.u32(Number(info?.flags ?? 0) >>> 0)
  for (const k of ['maxSessionCount','sessionCount','maxRwSessionCount','rwSessionCount','maxPinLen','minPinLen']) {
    w.u64(BigInt(info?.[k] ?? 0))
  }
  for (const k of ['totalPublicMemory','freePublicMemory','totalPrivateMemory','freePrivateMemory']) {
    const v = info?.[k]
    // PKCS#11 returns CK_UNAVAILABLE_INFORMATION (~0) when the token
    // doesn't expose this counter; surface that as `none`.
    const isUnavail = v == null || v === 0xffffffff_ffffffffn || v === -1 || v === 0xffffffff
    w.option(isUnavail ? null : v, (w, x) => w.u64(BigInt(x)))
  }
  writeVersion(w, info?.hardwareVersion)
  writeVersion(w, info?.firmwareVersion)
  // utcTime is a 16-byte zero-padded string. pkcs11js returns the
  // raw buffer or string. Surface as None if the token doesn't have
  // a clock (token-flags.clock-on-token bit absent).
  const utc = info?.utcTime
  if (!utc || (Buffer.isBuffer(utc) && utc.every(b => b === 0 || b === 0x20))) {
    w.option(null, () => {})
  } else {
    w.option(Buffer.isBuffer(utc) ? utc.toString('utf8') : String(utc),
             (w, s) => w.str(s))
  }
}

// CK_MECHANISM_INFO -> MechanismInfo
function writeMechanismInfo(w, info) {
  // pkcs11js: { minKeySize, maxKeySize, flags }
  w.u64(BigInt(info?.minKeySize ?? 0))
  w.u64(BigInt(info?.maxKeySize ?? 0))
  w.u32(Number(info?.flags ?? 0) >>> 0)
}

// CK_SESSION_INFO -> SessionInfo. PKCS#11 CK_STATE -> our session-state
// enum: CKS_RO_PUBLIC_SESSION=0, RO_USER=1, RW_PUBLIC=2, RW_USER=3, RW_SO=4.
function writeSessionInfo(w, info) {
  // pkcs11js: { slotID, state, flags, deviceError }
  w.u32(Number(info?.slotID ?? 0) >>> 0)
  w.u8(Number(info?.state ?? 0) & 0xff)
  w.u32(Number(info?.flags ?? 0) >>> 0)
  w.u64(BigInt(info?.deviceError ?? 0))
}

// Round-trip self-test for the codec: encode a few primitives, decode
// them back. Run with `node web/ws-gateway-pkcs11.mjs --self-test`.
if (process.argv.includes('--self-test')) {
  const w = new Pkcs11Writer()
  w.u32(0xdeadbeef)
  w.str('hello')
  w.bool(true)
  w.bytes(new Uint8Array([1, 2, 3]))
  const bytes = w.finish()
  const r = new Pkcs11Reader(bytes)
  const a = r.u32()
  const b = r.str()
  const c = r.bool()
  const d = r.bytes()
  const ok = a === 0xdeadbeef && b === 'hello' && c === true
    && d.length === 3 && d[0] === 1 && d[1] === 2 && d[2] === 3
  console.log(ok ? 'codec self-test OK' : 'codec self-test FAILED')
  process.exit(ok ? 0 : 1)
}

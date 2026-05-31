// Reference ws-gateway server for the @tegmentum/wasi-polyfill KSW1
// protocol. Lets a browser-hosted Polyfill open real TCP connections by
// tunneling frames through this WebSocket endpoint.
//
//   node web/ws-gateway-server.mjs        # listens on ws://127.0.0.1:8088/ws
//
// Then set in web/.env.local:
//   VITE_TCP_GATEWAY_URL=ws://127.0.0.1:8088/ws
//
// Implements: Hello/HelloAck handshake, Open->TCP-connect, bidirectional
// Data frames (with EOF half-close), Close/CloseAck, and DnsQuery via
// node:dns. Multiplexes many TCP streams over a single WebSocket via
// streamId. Single binary protocol per connection; no per-connection
// auth in this dev build (the tcp-adapter still sends the optional
// token field but we ignore it).

import { createServer } from 'node:http'
import * as net from 'node:net'
import * as dns from 'node:dns/promises'
import { WebSocketServer } from 'ws'
import {
  PROTOCOL_MAGIC,
  PROTOCOL_VERSION,
  HEADER_SIZE,
  MessageType,
  MessageFlags,
  Protocol,
  AddressKind,
  OpenError,
  Features,
  DnsError,
  encodeHeader,
  decodeHeader,
  decodeOpenPayload,
  encodeOpenErrPayload,
  decodeDnsQueryPayload,
  createFrame,
  createDataFrame,
  createCloseFrame,
  decodePkcs11RequestPayload,
  createPkcs11ResponseFrame,
} from '@tegmentum/wasi-polyfill/plugins/ws-gateway'
// (Pkcs11 codec symbols also re-exported from the barrel.)
import { createPkcs11Backend } from './pkcs11-backend.mjs'

// Defaults are env-driven so the CLI entry (src/bin.mjs) can stay
// trivial; programmatic users override via startGateway({ host, port, ... }).
const DEFAULT_PORT = parseInt(process.env.GATEWAY_PORT ?? '8088', 10)
const DEFAULT_HOST = process.env.GATEWAY_HOST ?? '127.0.0.1'
const DEFAULT_PATH = process.env.GATEWAY_PATH ?? '/ws'

// Mirror the client's negotiated feature set. We support everything the
// browser-side plugin requests except OpenToken auth (no caller
// validation in this dev build).
const SERVER_FEATURES =
  Features.HalfClose | Features.Dns | Features.Udp | Features.Pkcs11

// --------------------------------------------------------------------------
// Frame helpers (server-only)

function createHelloAckFrame(features, maxStreams) {
  const payload = new Uint8Array(8)
  const v = new DataView(payload.buffer)
  v.setUint32(0, features, true)
  v.setUint32(4, maxStreams, true)
  return createFrame(MessageType.HelloAck, 0, payload)
}

function createOpenOkFrame(streamId) {
  // localAddr/localPort are optional; we send an empty payload (clients
  // don't strictly require them).
  return createFrame(MessageType.OpenOk, streamId, new Uint8Array(0))
}

function createOpenErrFrame(streamId, error, message) {
  return createFrame(MessageType.OpenErr, streamId, encodeOpenErrPayload({ error, message }))
}

function createCloseAckFrame(streamId) {
  return createFrame(MessageType.CloseAck, streamId, new Uint8Array(4))
}

function createDnsResultFrame(queryId, addresses) {
  // payload = u16 count, then for each: u16 len + bytes
  let total = 2
  for (const a of addresses) total += 2 + a.length
  const out = new Uint8Array(total)
  const view = new DataView(out.buffer)
  view.setUint16(0, addresses.length, true)
  let off = 2
  for (const a of addresses) {
    view.setUint16(off, a.length, true); off += 2
    out.set(a, off); off += a.length
  }
  return createFrame(MessageType.DnsResult, queryId, out)
}

function createDnsErrFrame(queryId, error, message) {
  const msgBytes = new TextEncoder().encode(message)
  const out = new Uint8Array(3 + msgBytes.length)
  const view = new DataView(out.buffer)
  view.setUint8(0, error)
  view.setUint16(1, msgBytes.length, true)
  out.set(msgBytes, 3)
  return createFrame(MessageType.DnsErr, queryId, out)
}

// --------------------------------------------------------------------------
// Per-connection state machine

function handleConnection(ws, log, pkcs11Backend) {
  // streamId -> net.Socket
  const streams = new Map()
  let recvBuf = new Uint8Array(0)
  let helloDone = false

  const send = (frame) => {
    if (ws.readyState === ws.OPEN) ws.send(frame, { binary: true })
  }

  const closeStream = (streamId, reason = 0) => {
    const sock = streams.get(streamId)
    if (sock) {
      streams.delete(streamId)
      try { sock.destroy() } catch {}
    }
    send(createCloseFrame(streamId, reason))
  }

  ws.on('message', (data, isBinary) => {
    if (!isBinary) return  // ignore text frames
    // ws delivers Buffer; concat with leftover.
    const chunk = data instanceof Buffer ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data)
    const combined = new Uint8Array(recvBuf.length + chunk.length)
    combined.set(recvBuf, 0); combined.set(chunk, recvBuf.length)
    recvBuf = combined

    while (recvBuf.length >= HEADER_SIZE) {
      const hdr = decodeHeader(recvBuf)
      if (!hdr) { log('bad header — disconnecting'); ws.close(); return }
      const frameLen = HEADER_SIZE + hdr.payloadLen
      if (recvBuf.length < frameLen) break  // wait for more
      const payload = recvBuf.slice(HEADER_SIZE, frameLen)
      recvBuf = recvBuf.slice(frameLen)
      handleFrame(hdr, payload)
    }
  })

  ws.on('close', () => {
    for (const sock of streams.values()) {
      try { sock.destroy() } catch {}
    }
    streams.clear()
    log('ws closed')
  })

  ws.on('error', (err) => log(`ws error: ${err?.message || err}`))

  function handleFrame(hdr, payload) {
    switch (hdr.type) {
      case MessageType.Hello: {
        // Client features+maxStreams in payload (8 bytes); echo with our
        // intersection. We don't honor flow-control here so strip it.
        if (payload.length >= 8) {
          const v = new DataView(payload.buffer, payload.byteOffset, payload.length)
          const clientFeatures = v.getUint32(0, true)
          const negotiated = clientFeatures & SERVER_FEATURES
          const maxStreams = v.getUint32(4, true) || 256
          send(createHelloAckFrame(negotiated, maxStreams))
          helloDone = true
          log(`hello ok (features=0x${negotiated.toString(16)}, maxStreams=${maxStreams})`)
        }
        break
      }

      case MessageType.Open: {
        if (!helloDone) { log('open before hello'); ws.close(); return }
        const open = decodeOpenPayload(payload)
        if (!open) { send(createOpenErrFrame(hdr.streamId, OpenError.Internal, 'bad open payload')); return }
        if (open.proto !== Protocol.Tcp) {
          send(createOpenErrFrame(hdr.streamId, OpenError.Internal, 'only tcp supported in v1'))
          return
        }
        const host = decodeAddress(open.addrKind, open.addr)
        if (host == null) {
          send(createOpenErrFrame(hdr.streamId, OpenError.ResolveFail, 'bad address bytes'))
          return
        }
        const sock = net.connect({ host, port: open.port })
        const sid = hdr.streamId
        log(`open stream=${sid} -> ${host}:${open.port}`)
        sock.on('connect', () => {
          log(`tcp connected sid=${sid}`)
          streams.set(sid, sock)
          send(createOpenOkFrame(sid))
        })
        sock.on('data', (buf) => {
          send(createDataFrame(sid, new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)))
        })
        sock.on('end', () => {
          // Half-close: peer EOF'd. Send Data(eof=true) with empty payload.
          send(createDataFrame(sid, new Uint8Array(0), true))
        })
        sock.on('close', () => {
          log(`tcp closed sid=${sid}`)
          if (streams.has(sid)) {
            streams.delete(sid)
            send(createCloseFrame(sid, 0))
          }
        })
        sock.on('error', (err) => {
          log(`tcp error sid=${sid} code=${err?.code} msg=${err?.message}`)
          if (streams.has(sid)) {
            // Connection already up — surface as close.
            streams.delete(sid)
            send(createCloseFrame(sid, 1))
          } else {
            // Connect-time failure.
            const code = err?.code === 'ECONNREFUSED' ? OpenError.ConnRefused
                       : err?.code === 'EHOSTUNREACH' ? OpenError.Unreachable
                       : err?.code === 'ETIMEDOUT'    ? OpenError.Timeout
                       : OpenError.Internal
            send(createOpenErrFrame(sid, code, String(err?.message || err)))
          }
        })
        break
      }

      case MessageType.Data: {
        const sock = streams.get(hdr.streamId)
        if (!sock) return
        if (payload.length > 0) sock.write(Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength))
        if (hdr.flags & MessageFlags.Eof) {
          // Client half-closed write side -- end the TCP write half.
          sock.end()
        }
        break
      }

      case MessageType.Close: {
        closeStream(hdr.streamId, 0)
        send(createCloseAckFrame(hdr.streamId))
        break
      }

      case MessageType.DnsQuery: {
        if (!helloDone) return
        const q = decodeDnsQueryPayload(payload)
        if (!q) { send(createDnsErrFrame(hdr.streamId, DnsError.FormatError, 'bad dns query')); return }
        const family = q.family === 4 ? 4 : q.family === 6 ? 6 : 0
        log(`dns query=${hdr.streamId} ${q.hostname} family=${family || 'any'}`)
        dns.lookup(q.hostname, { all: true, family: family || 0 }).then((records) => {
          const addrs = records.map((r) => {
            if (r.family === 4) return Uint8Array.from(r.address.split('.').map(Number))
            // IPv6: parse via net.isIP heuristic; emit canonical 16-byte form
            const parts = ipv6ToBytes(r.address)
            return parts || new Uint8Array(0)
          }).filter((a) => a.length > 0)
          send(createDnsResultFrame(hdr.streamId, addrs))
        }).catch((err) => {
          const code = err?.code === 'ENOTFOUND' ? DnsError.NxDomain
                     : err?.code === 'EAI_AGAIN'  ? DnsError.Timeout
                     : DnsError.ServerFailure
          send(createDnsErrFrame(hdr.streamId, code, String(err?.message || err)))
        })
        break
      }

      case MessageType.Pkcs11Request: {
        if (!helloDone) return
        const req = decodePkcs11RequestPayload(payload)
        if (!req) {
          // Best-effort wire-error response. Body = utf8 message.
          const msg = new TextEncoder().encode('bad pkcs11 request payload')
          send(createPkcs11ResponseFrame(hdr.streamId, {
            status: 1 /* ProtocolError */,
            body: msg,
          }))
          return
        }
        log(`pkcs11 fn=0x${req.fnId.toString(16)} queryId=${hdr.streamId} ` +
            `args=${req.args.length}b backend=${pkcs11Backend.kind}`)
        pkcs11Backend.handle(req.fnId, req.args).then((res) => {
          send(createPkcs11ResponseFrame(hdr.streamId, res))
        }).catch((err) => {
          const msg = new TextEncoder().encode(
            `pkcs11 backend threw: ${err?.message ?? err}`)
          send(createPkcs11ResponseFrame(hdr.streamId, {
            status: 3 /* Internal */,
            body: msg,
          }))
        })
        break
      }

      case MessageType.Ping: {
        send(createFrame(MessageType.Pong, 0, payload))
        break
      }

      default:
        // Ignore unknown / unsupported.
        break
    }
  }
}

function decodeAddress(kind, bytes) {
  if (kind === AddressKind.Hostname) {
    return new TextDecoder().decode(bytes)
  } else if (kind === AddressKind.Ipv4 && bytes.length === 4) {
    return Array.from(bytes).join('.')
  } else if (kind === AddressKind.Ipv6 && bytes.length === 16) {
    const parts = []
    for (let i = 0; i < 16; i += 2) {
      parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16))
    }
    return parts.join(':')
  }
  return null
}

// Naive IPv6 expander: rejects shorthand, good enough for DNS results
// which Node returns in canonical form most of the time.
function ipv6ToBytes(s) {
  if (s.includes('::')) {
    // Expand :: to the right number of :0:0:0...
    const [head, tail] = s.split('::')
    const headParts = head ? head.split(':') : []
    const tailParts = tail ? tail.split(':') : []
    const missing = 8 - headParts.length - tailParts.length
    const all = [...headParts, ...Array(missing).fill('0'), ...tailParts]
    s = all.join(':')
  }
  const parts = s.split(':')
  if (parts.length !== 8) return null
  const out = new Uint8Array(16)
  for (let i = 0; i < 8; i++) {
    const v = parseInt(parts[i] || '0', 16)
    out[2 * i]     = (v >> 8) & 0xff
    out[2 * i + 1] = v & 0xff
  }
  return out
}

// --------------------------------------------------------------------------

/**
 * Start the ws-gateway server programmatically.
 *
 * @param {object} [opts]
 * @param {string} [opts.host='127.0.0.1']    listen address
 * @param {number} [opts.port=8088]           listen port
 * @param {string} [opts.path='/ws']          WebSocket path
 * @param {object} [opts.pkcs11Backend]       override the default Pkcs11 backend
 *                                            (createPkcs11Backend(opts) is called
 *                                            if not given; PKCS11_BACKEND env
 *                                            picks 'stub' or 'pkcs11js')
 * @param {(line: string) => void} [opts.log] log sink (defaults to console.log)
 * @returns {Promise<{ httpServer, wss, address, close }>} stoppable handle
 */
export async function startGateway(opts = {}) {
  const host = opts.host ?? DEFAULT_HOST
  const port = opts.port ?? DEFAULT_PORT
  const path = opts.path ?? DEFAULT_PATH
  const pkcs11Backend = opts.pkcs11Backend ?? pkcs11BackendShared
  const log = opts.log ?? ((msg) => console.log(msg))

  const httpServer = createServer()
  const wss = new WebSocketServer({ server: httpServer, path })

  let connId = 0
  wss.on('connection', (ws, req) => {
    const id = ++connId
    const connLog = (msg) => log(`[gateway:${id}] ${msg}`)
    connLog(`connect from ${req.socket.remoteAddress}`)
    handleConnection(ws, connLog, pkcs11Backend)
  })

  await new Promise((resolve) => httpServer.listen(port, host, resolve))
  const address = `ws://${host}:${port}${path}`
  log(`ws-gateway listening on ${address}  (magic=0x${PROTOCOL_MAGIC.toString(16)}, v${PROTOCOL_VERSION})`)

  return {
    httpServer,
    wss,
    address,
    close: () => new Promise((resolve) => {
      wss.close(() => httpServer.close(() => resolve()))
    }),
  }
}

// Module-level default backend so the test/bin paths share one Pkcs11
// instance (avoids the cost of loading libpkcs11.so twice).
const pkcs11BackendShared = createPkcs11Backend()

export { createPkcs11Backend }

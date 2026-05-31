# @tegmentum/ws-gateway-server

Reference Node server for the **KSW1** (KeyStone WebSocket v1) protocol used by [`@tegmentum/wasi-polyfill`](https://github.com/tegmentum/wasi-polyfill). Lets a browser-hosted wasm component reach real host resources — TCP sockets and PKCS#11 HSM tokens — through a single WebSocket.

Built as part of the [tegmentum/openssl-wasm](https://github.com/tegmentum/openssl-wasm) component stack; usable standalone for any project that needs the same browser↔host bridge.

## What it does

| Browser side (wasi-polyfill)          | This server                       | Reaches                            |
|---------------------------------------|-----------------------------------|------------------------------------|
| TCP socket via `wasi:sockets/tcp`     | `net.createConnection`            | Any host:port                      |
| DNS lookup via `wasi:sockets/ip-name-lookup` | `dns.lookup`               | System resolver                    |
| PKCS#11 calls via `tegmentum:pkcs11-tunnel` | `pkcs11js` → `libpkcs11.so` | SoftHSM / YubiHSM / Luna / any module |

Multiplexes many concurrent streams over one WebSocket; half-close + DnsQuery + Pkcs11 framing all on the same wire.

## Install

```sh
npm install @tegmentum/ws-gateway-server
# optional, for PKCS#11 backend:
npm install pkcs11js
```

## Use — CLI

```sh
# Stub PKCS#11 backend (proves the wire format works without a token):
npx ws-gateway-server

# Real PKCS#11 backend against SoftHSM (or any libpkcs11):
PKCS11_BACKEND=pkcs11js \
PKCS11_LIB=$(brew --prefix)/lib/softhsm/libsofthsm2.so \
  npx ws-gateway-server
```

Listens on `ws://127.0.0.1:8088/ws` by default. Override with `GATEWAY_HOST` / `GATEWAY_PORT` / `GATEWAY_PATH`.

## Use — Programmatic

```js
import { startGateway } from '@tegmentum/ws-gateway-server'

const gw = await startGateway({
  port: 9000,
  // Optional: a custom Pkcs11 backend object. Defaults to env-driven
  // (PKCS11_BACKEND=stub by default, or PKCS11_BACKEND=pkcs11js +
  // PKCS11_LIB for a real module).
})

// gw.address  -> "ws://127.0.0.1:9000/ws"
// gw.close()  -> stop listening; returns Promise<void>
```

For a custom Pkcs11 backend implementation, look at `src/pkcs11-backend.mjs` for the stub + pkcs11js examples. The contract is one `handle(fnId, argBytes) -> Promise<{ status, body }>` method per `Pkcs11Fn` enum value from the polyfill's `plugins/ws-gateway` codec.

## Protocol

KSW1 frames are defined in `@tegmentum/wasi-polyfill/plugins/ws-gateway`:

- Hello / HelloAck handshake (feature negotiation)
- Open / OpenOk / OpenErr (per-stream TCP connect)
- Data (bidirectional; supports half-close)
- Close / CloseAck
- DnsQuery / DnsResult / DnsErr
- Pkcs11Request / Pkcs11Response (queryId-multiplexed RPC)

All framed as binary WebSocket messages with a 4-byte magic prefix (`KSW1`) + version byte + per-frame type tag. See `@tegmentum/wasi-polyfill` source for the byte-level spec.

## Threat model

Default config is **dev-only** — no auth, listens on localhost. For production:

- Bind to a non-loopback interface (`GATEWAY_HOST=0.0.0.0`).
- Front with a reverse proxy that adds TLS + auth (the WebSocket protocol carries an `optional` token field in Hello that the current build ignores).
- Run pkcs11js with a token whose PIN is supplied via environment, not URI.

## License

Apache-2.0. See [LICENSE](LICENSE).

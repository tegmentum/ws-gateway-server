// Public API for @tegmentum/ws-gateway-server.
//
// Two consumption modes:
//
// 1. Programmatic — start the gateway from your own Node script:
//
//      import { startGateway } from '@tegmentum/ws-gateway-server'
//      const gw = await startGateway({ port: 8088 })
//      // ... later
//      await gw.close()
//
// 2. CLI — `npx @tegmentum/ws-gateway-server` (uses env vars
//    GATEWAY_HOST / GATEWAY_PORT / GATEWAY_PATH / PKCS11_BACKEND /
//    PKCS11_LIB to configure). See src/bin.mjs.
//
// 3. Custom Pkcs11 backend — pass `pkcs11Backend` to startGateway, or
//    use the exported `createPkcs11Backend({ kind })` factory for the
//    built-in 'stub' (default) / 'pkcs11js' (real PKCS#11 module).
//
// Wire-format compatibility: the gateway speaks KSW1 (KeyStone
// WebSocket v1) as defined in @tegmentum/wasi-polyfill's
// plugins/ws-gateway codec. Browsers using the polyfill's TCP/PKCS#11
// tunnel plugins connect here.

export { startGateway, createPkcs11Backend } from './server.mjs'

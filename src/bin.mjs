#!/usr/bin/env node
// CLI entry for @tegmentum/ws-gateway-server.
//
// Usage:
//   npx @tegmentum/ws-gateway-server          # ws://127.0.0.1:8088/ws, stub Pkcs11 backend
//   GATEWAY_PORT=9000 npx @tegmentum/ws-gateway-server
//   PKCS11_BACKEND=pkcs11js PKCS11_LIB=/usr/local/lib/softhsm/libsofthsm2.so \
//       npx @tegmentum/ws-gateway-server
//
// Programmatic users should import { startGateway } from
// '@tegmentum/ws-gateway-server' instead.

import { startGateway } from './server.mjs'

await startGateway()

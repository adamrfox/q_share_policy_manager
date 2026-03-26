#!/usr/bin/env node
/**
 * qpm-proxy.js — Local HTTPS proxy for Qumulo Policy Manager
 *
 * Listens on port 3002. nginx forwards /proxy/<target-url> here.
 * Strips the /proxy/ prefix, makes the request to the Qumulo cluster
 * with SSL verification disabled (handles self-signed certs), and
 * streams the response back.
 *
 * Usage:
 *   node qpm-proxy.js
 *   # or as a service: see qpm-proxy.service
 */

const http  = require('http');
const https = require('https');
const { URL } = require('url');

const PORT = 3002;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

http.createServer((req, res) => {

  // Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    res.end();
    return;
  }

  // Expect path like: /proxy/https://192.168.1.100:8000/v1/session/login
  const match = req.url.match(/^\/proxy\/(.+)$/);
  if (!match) {
    res.writeHead(400, CORS_HEADERS);
    res.end(JSON.stringify({ error: 'Missing target URL. Use /proxy/<full-url>' }));
    return;
  }

  let target;
  try {
    target = new URL(match[1]);
  } catch (e) {
    res.writeHead(400, CORS_HEADERS);
    res.end(JSON.stringify({ error: 'Invalid target URL: ' + e.message }));
    return;
  }

  // Forward headers, pass Authorization through, drop hop-by-hop headers
  const forwardHeaders = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const lower = k.toLowerCase();
    if (['host','connection','transfer-encoding','te','trailer','upgrade'].includes(lower)) continue;
    forwardHeaders[k] = v;
  }
  forwardHeaders['host'] = target.hostname + (target.port ? ':' + target.port : '');

  const options = {
    hostname: target.hostname,
    port:     target.port || (target.protocol === 'https:' ? 443 : 80),
    path:     target.pathname + target.search,
    method:   req.method,
    headers:  forwardHeaders,
    rejectUnauthorized: false,   // ← self-signed cert support
  };

  const protocol = target.protocol === 'https:' ? https : http;

  const proxyReq = protocol.request(options, (proxyRes) => {
    const responseHeaders = { ...CORS_HEADERS };
    for (const [k, v] of Object.entries(proxyRes.headers)) {
      if (k.toLowerCase() !== 'access-control-allow-origin') {
        responseHeaders[k] = v;
      }
    }
    res.writeHead(proxyRes.statusCode, responseHeaders);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    console.error('[qpm-proxy] error:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, CORS_HEADERS);
      res.end(JSON.stringify({ error: 'Proxy error: ' + err.message }));
    }
  });

  req.pipe(proxyReq);

}).listen(PORT, '127.0.0.1', () => {
  console.log('[qpm-proxy] listening on 127.0.0.1:' + PORT);
});

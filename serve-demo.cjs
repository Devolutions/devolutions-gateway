#!/usr/bin/env node
// Static + gateway-proxy server for the IronVNC H.264 demo.
//
// Why this exists: the gateway-ui Angular dev/build pipeline in this checkout fails to
// inject the entry script into index.html (entry classified as a "lazy" chunk), so both
// `ng serve` and the static `ng build` produce a blank app. This server sidesteps that:
// it serves the `ng build` output (whose index.html we patch with the missing
// <script>/<link> tags via inject-entry.cjs) and proxies the gateway API + the
// /jet/fwd/tcp WebSocket tunnel to the real Devolutions Gateway.
//
//   node serve-demo.cjs            # serves dist/gateway-ui on :4300, proxies /jet/* -> :7272
//
// Env: PORT (4300), GATEWAY (http://localhost:7272), DIST (webapp/dist/gateway-ui).

const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '4300', 10);
const GATEWAY = new URL(process.env.GATEWAY || 'http://localhost:7272');
const DIST = process.env.DIST || path.join(__dirname, 'webapp', 'dist', 'gateway-ui');
const BASE = '/jet/webapp/client';

const MIME = {
    '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.html': 'text/html',
    '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon', '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf',
    '.wasm': 'application/wasm', '.map': 'application/json', '.webmanifest': 'application/manifest+json',
};

function serveStatic(req, res, rel) {
    if (rel === '' || rel === '/') rel = '/index.html';
    // prevent path traversal
    const filePath = path.normalize(path.join(DIST, rel));
    if (!filePath.startsWith(path.normalize(DIST))) { res.writeHead(403); return res.end('forbidden'); }
    fs.stat(filePath, (err, st) => {
        if (!err && st.isFile()) return sendFile(filePath, res);
        // SPA fallback
        sendFile(path.join(DIST, 'index.html'), res);
    });
}

function sendFile(fp, res) {
    fs.readFile(fp, (err, buf) => {
        if (err) { res.writeHead(404); return res.end('not found'); }
        res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'application/octet-stream' });
        res.end(buf);
    });
}

function proxyHttp(req, res) {
    const opts = {
        hostname: GATEWAY.hostname, port: GATEWAY.port, path: req.url, method: req.method,
        headers: { ...req.headers, host: GATEWAY.host },
    };
    const up = http.request(opts, (pres) => {
        res.writeHead(pres.statusCode, pres.headers);
        pres.pipe(res);
    });
    up.on('error', (e) => { res.writeHead(502); res.end('proxy error: ' + e.message); });
    req.pipe(up);
}

const server = http.createServer((req, res) => {
    const urlPath = decodeURIComponent(req.url.split('?')[0]);
    if (urlPath === BASE || urlPath.startsWith(BASE + '/')) {
        return serveStatic(req, res, urlPath.slice(BASE.length));
    }
    if (urlPath.startsWith('/jet/')) return proxyHttp(req, res);
    // bare root -> redirect to the app
    if (urlPath === '/') { res.writeHead(302, { Location: BASE + '/' }); return res.end(); }
    res.writeHead(404); res.end('not found');
});

// WebSocket (and any Upgrade) tunneling -> gateway. Used by /jet/fwd/tcp and /jet/rdp.
server.on('upgrade', (req, socket, head) => {
    const upstream = net.connect(Number(GATEWAY.port), GATEWAY.hostname, () => {
        // replay the raw upgrade request
        let raw = `${req.method} ${req.url} HTTP/1.1\r\n`;
        for (let i = 0; i < req.rawHeaders.length; i += 2) {
            const k = req.rawHeaders[i];
            let v = req.rawHeaders[i + 1];
            if (k.toLowerCase() === 'host') v = GATEWAY.host;
            raw += `${k}: ${v}\r\n`;
        }
        raw += '\r\n';
        upstream.write(raw);
        if (head && head.length) upstream.write(head);
        socket.pipe(upstream);
        upstream.pipe(socket);
    });
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
});

server.listen(PORT, () => {
    console.log(`[serve-demo] static ${DIST}`);
    console.log(`[serve-demo] app:   http://localhost:${PORT}${BASE}/`);
    console.log(`[serve-demo] proxy: /jet/* -> ${GATEWAY.origin} (incl. ws upgrade)`);
});

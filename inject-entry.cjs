#!/usr/bin/env node
// Patches the ng-build output index.html with the entry references Angular's builder
// fails to inject in this checkout (it misclassifies the entry as a lazy chunk), plus the
// IronVNC H.264 -> WebCodecs presenter bridge. Idempotent; run after every `ng build`.
//
//   node inject-entry.cjs        # patches webapp/dist/gateway-ui/index.html in place

const fs = require('fs');
const path = require('path');

const DIST = process.env.DIST || path.join(__dirname, 'webapp', 'dist', 'gateway-ui');
const indexPath = path.join(DIST, 'index.html');
const MARKER = '<!-- ironvnc-injected -->';

let html = fs.readFileSync(indexPath, 'utf8');
if (html.includes(MARKER)) { console.log('[inject] already patched, nothing to do'); process.exit(0); }

const has = (f) => fs.existsSync(path.join(DIST, f));

// 1) global stylesheet
if (has('styles.css') && !html.includes('href="styles.css"')) {
    html = html.replace('</head>', '  <link rel="stylesheet" href="styles.css">\n</head>');
}

// 2) H.264 (OpenH264) -> WebCodecs bridge. The IronVNC wasm session dispatches a bubbling,
//    composed `ironvnc-video-access-unit` CustomEvent on the render canvas; decode it with
//    WebCodecs and composite back onto that same canvas. Classic script + @vite-ignore'd
//    dynamic import so the build never tries to resolve the presenter at build time.
const bridge = `<script id="ironvnc-h264-bridge">
  (function () {
    var presenters = new WeakMap();
    import(/* @vite-ignore */ '/jet/webapp/client/assets/webcodecs-presenter.js').then(function (mod) {
      var WebCodecsPresenter = mod.WebCodecsPresenter;
      document.addEventListener('ironvnc-video-access-unit', function (ev) {
        var canvas = (ev.composedPath && ev.composedPath()[0]) || ev.target;
        if (!(canvas instanceof HTMLCanvasElement)) return;
        var p = presenters.get(canvas);
        if (!p) {
          p = new WebCodecsPresenter(canvas, { onError: function (e) { console.error('[h264-presenter] error', e); } });
          presenters.set(canvas, p);
          console.log('[h264-presenter] attached to render canvas ' + canvas.width + 'x' + canvas.height);
        }
        var d = ev.detail;
        p.submit({
          encoding: d.encoding, left: d.left, top: d.top, width: d.width, height: d.height,
          resetContext: d.resetContext, resetAllContexts: d.resetAllContexts,
          keyframe: d.keyframe === true || d.resetContext === true, data: d.data,
        });
      }, true);
      window.__h264PresenterInstalled = true;
      console.log('[h264-presenter] listening for ironvnc-video-access-unit (OpenH264 -> WebCodecs)');
    }).catch(function (e) { console.error('[h264-presenter] failed to load presenter', e); });
  })();
</script>`;

// 3) entry scripts (polyfills must load before main)
const entry =
    (has('polyfills.js') ? '<script src="polyfills.js" type="module"></script>\n' : '') +
    '<script src="main.js" type="module"></script>';

html = html.replace('</body>', `${MARKER}\n${bridge}\n${entry}\n</body>`);
fs.writeFileSync(indexPath, html);
console.log('[inject] patched ' + indexPath);

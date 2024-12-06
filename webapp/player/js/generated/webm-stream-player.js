var u = Object.defineProperty;
var a = (o, t, e) => t in o ? u(o, t, { enumerable: !0, configurable: !0, writable: !0, value: e }) : o[t] = e;
var s = (o, t, e) => a(o, typeof t != "symbol" ? t + "" : t, e);
class c {
  constructor(t, e, r) {
    s(this, "sourceBuffer");
    s(this, "bufferQueue", []);
    s(this, "isAppending", !1);
    s(this, "next", () => {
    });
    s(this, "allBuffers", []);
    // Store all buffers for file creation
    s(this, "debug", !1);
    this.sourceBuffer = t.addSourceBuffer(
      `video/webm; codecs="${e}"`
    ), this.next = r, this.sourceBuffer.addEventListener("updateend", () => {
      this.tryAppendBuffer();
    }), this.sourceBuffer.addEventListener("error", (n) => {
      this.logErrorDetails(n), this.downloadBufferedFile();
    });
  }
  setDebug(t) {
    this.debug = t;
  }
  appendBuffer(t) {
    this.bufferQueue.push(t), this.debug && this.allBuffers.push(new Blob([t], { type: "video/webm" })), this.tryAppendBuffer();
  }
  tryAppendBuffer() {
    if (!this.isAppending && !this.sourceBuffer.updating && this.bufferQueue.length > 0) {
      this.isAppending = !0;
      try {
        const t = this.bufferQueue.shift();
        this.sourceBuffer.appendBuffer(t);
      } catch (t) {
        this.logErrorDetails(t);
      } finally {
        this.next(), this.isAppending = !1;
      }
    }
  }
  downloadBufferedFile() {
    const t = new Blob(this.allBuffers, { type: "video/webm" }), e = URL.createObjectURL(t), r = document.createElement("a");
    r.href = e, r.download = "buffered-video.webm", document.body.appendChild(r), r.click(), document.body.removeChild(r), URL.revokeObjectURL(e), console.log("Buffered file downloaded.");
  }
  logErrorDetails(t) {
    console.error("Error encountered in ReactiveSourceBuffer:"), console.error("Error object:", t), console.log("Current bufferQueue length:", this.bufferQueue.length), console.log("SourceBuffer updating:", this.sourceBuffer.updating), console.log("SourceBuffer buffered ranges:", this.getBufferedRanges());
  }
  getBufferedRanges() {
    const t = this.sourceBuffer.buffered;
    let e = "";
    for (let r = 0; r < t.length; r++)
      e += `[${t.start(r)} - ${t.end(r)}] `;
    return e.trim();
  }
}
function f(o) {
  const e = new DataView(o).getUint8(0);
  if (e === 0)
    return {
      type: "chunk",
      data: new Uint8Array(o, 1)
    };
  if (e === 1) {
    const r = new TextDecoder().decode(new Uint8Array(o, 1));
    return {
      type: "metadata",
      codec: JSON.parse(r).codec === "vp8" ? "vp8" : "vp9"
    };
  }
  if (e === 2) {
    const r = new TextDecoder().decode(new Uint8Array(o, 1));
    return {
      type: "error",
      error: JSON.parse(r).error
    };
  }
  throw new Error("Unknown message type");
}
function h(o) {
  if (o.type === "start")
    return new Uint8Array([0]);
  if (o.type === "pull")
    return new Uint8Array([1]);
  throw new Error("Unknown message type");
}
class p {
  constructor(t) {
    s(this, "ws");
    this.ws = new WebSocket(t);
  }
  onopen(t) {
    this.ws.onopen = t;
  }
  onmessage(t) {
    this.ws.onmessage = (e) => {
      const r = new FileReader();
      r.onload = () => {
        const n = r.result, i = f(n);
        t(i);
      }, r.readAsArrayBuffer(e.data);
    };
  }
  onclose(t) {
    this.ws.onclose = t;
  }
  onerror(t) {
    this.ws.onerror = t;
  }
  send(t) {
    this.ws.send(h(t));
  }
  isClosed() {
    return this.ws.readyState === WebSocket.CLOSED;
  }
}
class d extends HTMLElement {
  constructor() {
    super(...arguments);
    s(this, "shadowRoot", null);
    s(this, "_videoElement", null);
    s(this, "_src", null);
    s(this, "_buffer", null);
    s(this, "onErrorCallback", null);
    s(this, "debug", !1);
  }
  static get observedAttributes() {
    return [
      "src",
      "autoplay",
      "loop",
      "muted",
      "poster",
      "preload",
      "style",
      "width",
      "height"
    ];
  }
  setDebug(e) {
    this.debug = e, this._buffer && this._buffer.setDebug(e);
  }
  onError(e) {
    this.onErrorCallback = e;
  }
  attributeChangedCallback(e, r, n) {
    if (e === "src") {
      this.srcChange(n);
      return;
    }
    Object.prototype.hasOwnProperty.call(this.videoElement, e) && this.videoElement.setAttribute(e, n !== null ? n : "");
  }
  connectedCallback() {
    this.init();
  }
  init() {
    this.shadowRoot = this.attachShadow({ mode: "open" });
    const e = document.createElement("div");
    this.videoElement = document.createElement("video"), e.appendChild(this.videoElement), this.shadowRoot.appendChild(e), this.syncAttributes();
  }
  syncAttributes() {
    for (const e of d.observedAttributes) {
      const r = this.getAttribute(e);
      e === "src" && r !== null && this.srcChange(r), r !== null && this.videoElement.setAttribute(e, r);
    }
  }
  get videoElement() {
    return this._videoElement;
  }
  set videoElement(e) {
    this._videoElement = e;
  }
  play() {
    this.videoElement.play();
  }
  srcChange(e) {
    const r = new MediaSource();
    this._src = e, this.videoElement.src = URL.createObjectURL(r), r.addEventListener(
      "sourceopen",
      () => this.handleSourceOpen(r)
    );
  }
  async handleSourceOpen(e) {
    const r = new p(this._src);
    let n = null;
    r.onopen(() => {
      r.send({ type: "start" }), r.send({ type: "pull" });
    }), r.onmessage((i) => {
      if (e.readyState !== "closed") {
        if (i.type === "metadata") {
          const l = i.codec;
          n = new c(
            e,
            l,
            () => {
              r.send({ type: "pull" });
            }
          ), this._buffer = n;
        }
        if (i.type === "chunk" && n && (n.appendBuffer(i.data), this._videoElement && this._videoElement.duration - this._videoElement.currentTime > 5))
          try {
            this._videoElement.currentTime = this._videoElement.seekable.end(0);
          } catch (l) {
            this.debug && console.error("Error seeking:", l);
          }
        i.type === "error" && this.onErrorCallback && this.onErrorCallback(i);
      }
    }), r.onclose(() => {
      n && e.endOfStream();
    }), r.onerror((i) => {
      if (console.error("WebSocket error:", i), e.readyState === "open")
        try {
          e.endOfStream();
        } catch (l) {
          console.error("endOfStream error:", l);
        }
    });
  }
  downloadBUfferAsFile() {
    this._buffer && this.debug && this._buffer.downloadBufferedFile();
  }
}
customElements.define("shadow-player", d);
export {
  d as ShadowPlayer
};

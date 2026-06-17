// WebCodecsPresenter — the browser-side decoder/presenter for IronVNC video encodings.
//
// This is the consumer of `SessionEvent::VideoAccessUnit` on the web target. The
// WASM session never decodes video; it hands each compressed access unit to JS,
// and this presenter feeds it into a browser `VideoDecoder` and draws the decoded
// `VideoFrame` onto the render canvas, compositing with the RGB framebuffer plane.
//
// It is deliberately codec-agnostic: only the `codec` string in the per-encoding
// config differs (e.g. 'avc1.42E01E' for OpenH264). The decode/draw machinery is
// identical for H.264, VP8, VP9, or AV1, which is what lets the e2e harness exercise
// the exact same code path with a royalty-free codec where a given browser build
// lacks proprietary H.264.
//
// See docs/h264-architecture.md (§5 the presenter contract, §7 compositing/ordering).

/**
 * @typedef {Object} VideoAccessUnit
 * @property {string} encoding           Encoding name (e.g. "OPEN_H264").
 * @property {number} left
 * @property {number} top
 * @property {number} width
 * @property {number} height
 * @property {boolean} resetContext      Reset this region's decoder context first.
 * @property {boolean} resetAllContexts  Reset all decoder contexts first.
 * @property {Uint8Array} data           Compressed bitstream (e.g. H.264 Annex-B).
 */

/** Map an IronVNC encoding name to a WebCodecs decoder config. */
const ENCODING_CODECS = {
    // OpenH264 / TigerVNC sends an H.264 Annex-B bitstream. Omitting `description`
    // tells Chromium the stream is Annex-B (vs. length-prefixed avcC).
    OPEN_H264: { codec: 'avc1.42E01E' },
};

/** Key a decoder context by its rectangle geometry, matching the server's notion of a "context". */
function regionKey(au) {
    return `${au.left},${au.top},${au.width},${au.height}`;
}

class DecoderContext {
    /**
     * @param {string} key
     * @param {VideoDecoderConfig} config
     * @param {(frame: VideoFrame, region: {left:number,top:number,width:number,height:number}) => void} onFrame
     * @param {(err: Error) => void} onError
     */
    constructor(key, config, onFrame, onError) {
        this.key = key;
        this.config = config;
        this.onFrame = onFrame;
        this.onError = onError;
        this.region = null;
        this.configured = false;
        // Monotonic presentation timestamp (µs). MUST strictly increase: when the
        // server bursts several access units within one `performance.now()` tick,
        // a wall-clock timestamp can repeat or go backwards, which makes the H.264
        // `VideoDecoder` throw "Decoding error" and close. A simple per-context
        // counter keeps decode order well-defined regardless of arrival timing.
        this.nextTimestamp = 0;
        this.decoder = new VideoDecoder({
            output: (frame) => {
                try {
                    this.onFrame(frame, this.region);
                } finally {
                    frame.close();
                }
            },
            error: (e) => this.onError(e instanceof Error ? e : new Error(String(e))),
        });
    }

    /** Feed one access unit. `key` chunks force a keyframe (used on (re)configure/reset). */
    decode(au, isKeyframe) {
        this.region = { left: au.left, top: au.top, width: au.width, height: au.height };
        if (!this.configured) {
            // codedWidth/Height help the decoder before the first frame is parsed.
            this.decoder.configure({ ...this.config, codedWidth: au.width, codedHeight: au.height });
            this.configured = true;
            isKeyframe = true; // a freshly configured decoder must start on a keyframe
        }
        const chunk = new EncodedVideoChunk({
            type: isKeyframe ? 'key' : 'delta',
            timestamp: this.nextTimestamp, // µs; strictly increasing per context (see ctor)
            data: au.data,
        });
        this.nextTimestamp += 33333; // ~30fps spacing; only the ordering matters here
        this.decoder.decode(chunk);
    }

    reset() {
        // Drop queued work and require a fresh keyframe before the next decode.
        try { this.decoder.reset(); } catch { /* decoder may be closed */ }
        this.configured = false;
    }

    close() {
        try { this.decoder.close(); } catch { /* already closed */ }
    }
}

export class WebCodecsPresenter {
    /**
     * @param {HTMLCanvasElement|OffscreenCanvas} canvas  The render canvas (also holds the RGB framebuffer plane).
     * @param {{ onError?: (err: Error) => void }} [opts]
     */
    constructor(canvas, opts = {}) {
        this.canvas = canvas;
        this.ctx = canvas.getContext('2d');
        this.onError = opts.onError || ((e) => console.error('[WebCodecsPresenter]', e));
        /** @type {Map<string, DecoderContext>} */
        this.contexts = new Map();
        // Presentation ordering: a decoded VideoFrame may arrive after later RGB
        // draws. We stamp draws so a late frame does not clobber a newer region.
        // (See docs §7. For this minimal presenter we draw on arrival.)
        this.framesDrawn = 0;
    }

    /** Is a given IronVNC encoding decodable in this browser? Use to gate negotiation. */
    static async isEncodingSupported(encoding) {
        const cfg = ENCODING_CODECS[encoding];
        if (!cfg || !('VideoDecoder' in self)) return false;
        try {
            const res = await VideoDecoder.isConfigSupported({ ...cfg, codedWidth: 1920, codedHeight: 1080 });
            return !!res.supported;
        } catch {
            return false;
        }
    }

    /**
     * Submit one access unit. Returns a promise that resolves once the unit has been
     * submitted to the decoder (NOT once the frame is drawn — WebCodecs is a
     * fire-and-forget pipeline whose output callback does the drawing). This is the
     * `MaybeAsync` boundary from the design: synchronous on native, a real promise here.
     * @param {VideoAccessUnit} au
     */
    async submit(au) {
        if (au.resetAllContexts) {
            for (const c of this.contexts.values()) c.reset();
        }
        let codecCfg = this.codecOverride || ENCODING_CODECS[au.encoding];
        if (!codecCfg) {
            this.onError(new Error(`no WebCodecs config for encoding ${au.encoding}`));
            return;
        }

        const key = regionKey(au);
        let context = this.contexts.get(key);
        if (!context) {
            context = new DecoderContext(
                key,
                codecCfg,
                (frame, region) => this.#drawFrame(frame, region),
                this.onError,
            );
            this.contexts.set(key, context);
        }
        if (au.resetContext) context.reset();

        // A unit is a keyframe if the server flagged a context reset, or if the
        // bitstream itself is a keyframe (propagated as `au.keyframe`).
        context.decode(au, au.resetContext || au.keyframe === true);
    }

    /** Override the codec config (used by the e2e harness to exercise the pipeline with VP8/AV1). */
    setCodecOverride(config) {
        this.codecOverride = config;
    }

    #drawFrame(frame, region) {
        const r = region || { left: 0, top: 0, width: frame.displayWidth, height: frame.displayHeight };
        // Composite the decoded video frame onto the same canvas as the RGB plane.
        this.ctx.drawImage(frame, r.left, r.top, r.width, r.height);
        this.framesDrawn += 1;
    }

    /** Flush and tear down all decoders. */
    async close() {
        const all = [...this.contexts.values()];
        this.contexts.clear();
        await Promise.allSettled(all.map(async (c) => {
            try { await c.decoder.flush(); } catch { /* ignore */ }
            c.close();
        }));
    }
}

/** What `beforeClose` knows about the socket that closed. */
export interface CloseContext {
  /** Whether the socket opened before it closed. */
  opened: boolean;
  /** The subprotocols the socket offered. */
  protocols: string[];
}

type BeforeClose = (event: CloseEvent, context: CloseContext) => CloseEvent;

let beforeClose: BeforeClose = (event) => event;

export const OnBeforeClose = (callback: BeforeClose) => {
  beforeClose = callback;
};

const WebSocketProxy = new Proxy(window.WebSocket, {
  construct(target, args: [url: string | URL, protocols?: string | string[]]) {
    const ws = new target(...args); // Create the actual WebSocket instance
    const offered = args[1];
    const protocols = offered === undefined ? [] : typeof offered === 'string' ? [offered] : [...offered];
    let opened = false;
    ws.addEventListener('open', () => {
      opened = true;
    });
    const transform = (event: CloseEvent) => beforeClose(event, { opened, protocols });

    // Close listeners receive the transformed event; the wrappers are remembered so they can be removed.
    const closeListeners = new WeakMap<EventListenerOrEventListenerObject, EventListener>();
    const addEventListener = ws.addEventListener.bind(ws);
    const removeEventListener = ws.removeEventListener.bind(ws);
    ws.addEventListener = ((
      type: string,
      listener: EventListenerOrEventListenerObject | null,
      options?: boolean | AddEventListenerOptions,
    ) => {
      if (type !== 'close' || listener === null) {
        addEventListener(type, listener, options);
        return;
      }
      let wrapped = closeListeners.get(listener);
      if (!wrapped) {
        const original = listener;
        wrapped = (event) => {
          const transformed = transform(event as CloseEvent);
          if (typeof original === 'function') {
            original.call(ws, transformed);
          } else {
            original.handleEvent(transformed);
          }
        };
        closeListeners.set(listener, wrapped);
      }
      addEventListener(type, wrapped, options);
    }) as typeof ws.addEventListener;
    ws.removeEventListener = ((
      type: string,
      listener: EventListenerOrEventListenerObject | null,
      options?: boolean | EventListenerOptions,
    ) => {
      const wrapped = type === 'close' && listener !== null ? closeListeners.get(listener) : undefined;
      removeEventListener(type, wrapped ?? listener, options);
    }) as typeof ws.removeEventListener;

    // Proxy for intercepting `onclose`
    return new Proxy(ws, {
      set(target, prop, value) {
        if (prop === 'onclose') {
          const transformedValue = typeof value === 'function' ? (event: CloseEvent) => value(transform(event)) : value;
          return Reflect.set(target, prop, transformedValue);
        }
        return Reflect.set(target, prop, value);
      },
      get(target, prop) {
        // Native WebSocket getters such as `readyState` and `protocol` must run on the real WebSocket, not the Proxy.
        const value = Reflect.get(target, prop);
        // Because these methods are part of the native WebSocket prototype,
        // they must be called with the original WebSocket as `this`.
        // If they're called with the Proxy as `this`, it results in an "illegal invocation".
        // Binding them to the underlying `target` (the real WebSocket) avoids this issue.
        if (typeof value === 'function') {
          return value.bind(target);
        }
        return value;
      },
    });
  },
});

window.WebSocket = WebSocketProxy;

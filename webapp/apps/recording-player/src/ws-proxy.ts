let beforeClose = (args: CloseEvent): CloseEvent => {
  return args;
};

export const OnBeforeClose = (callback: (args: CloseEvent) => CloseEvent) => {
  beforeClose = callback;
};

const WebSocketProxy = new Proxy(window.WebSocket, {
  construct(target, args: [url: string | URL, protocols?: string | string[]]) {
    const ws = new target(...args); // Create the actual WebSocket instance

    // Proxy for intercepting `addEventListener`
    ws.addEventListener = new Proxy(ws.addEventListener, {
      apply(target, thisArg, args) {
        if (args[0] === 'close') {
          console.log('Intercepted addEventListener for close event');
          const transformedArgs = beforeClose(args as unknown as CloseEvent);
          return target.apply(thisArg, transformedArgs);
        }
        return target.apply(thisArg, args);
      },
    });

    // Proxy for intercepting `onclose`
    return new Proxy(ws, {
      set(target, prop, value) {
        if (prop === 'onclose') {
          console.log('Intercepted setting of onclose');
          const transformedValue = (...args) => {
            const transformedArgs = beforeClose(args[0] as unknown as CloseEvent);
            if (typeof value === 'function') {
              value(transformedArgs); // Call the original handler
            }
          };
          return Reflect.set(target, prop, transformedValue);
        }
        return Reflect.set(target, prop, value);
      },
      get(target, prop, receiver) {
        const value = Reflect.get(target, prop, receiver);
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

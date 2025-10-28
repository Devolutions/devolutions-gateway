import { ProgressManagerHandle } from './progress-manager';

export type AnyFunction<Arg extends unknown[], Return> = (...args: Arg) => Return;

export function throttle<Arg extends unknown[], Return>(
  fn: AnyFunction<Arg, Return>,
  wait = 30,
): (this: ThisParameterType<AnyFunction<Arg, Return>>, ...args: Arg) => Return | undefined {
  let last = performance.now();

  return function (this: ThisParameterType<AnyFunction<Arg, Return>>, ...args: Arg): Return | undefined {
    const now = performance.now();

    if (now - last >= wait) {
      last = now;
      return fn.apply(this, args);
    }
  };
}

export type Options = {
  children?: unknown[];
  className?: string;
  progressHandle: ProgressManagerHandle;
};

export namespace Dom {
  type Properties<T extends HTMLElement> = Partial<Omit<T, 'style'>> & {
    style?: Partial<CSSStyleDeclaration>;
  };

  export function createEl<K extends keyof HTMLElementTagNameMap>(
    tagName: K,
    properties?: Properties<HTMLElementTagNameMap[K]>,
    attributes?: Record<string, string>,
    content?: string | HTMLElement | (string | HTMLElement)[],
  ): HTMLElementTagNameMap[K] {
    const element = document.createElement(tagName);

    // Use Object.assign for property assignment instead of direct mutation
    if (properties) {
      const { style, ...restProps } = properties;
      Object.assign(element, restProps);

      // Apply styles separately using Object.assign
      if (style) {
        Object.assign(element.style, style);
      }
    }

    // Set attributes safely
    if (attributes) {
      for (const [name, value] of Object.entries(attributes)) {
        element.setAttribute(name, value);
      }
    }

    // Append content
    if (content) {
      if (Array.isArray(content)) {
        for (const item of content) {
          if (typeof item === 'string') {
            element.appendChild(document.createTextNode(item));
          } else {
            element.appendChild(item);
          }
        }
      } else if (typeof content === 'string') {
        element.textContent = content;
      } else {
        element.appendChild(content);
      }
    }

    return element;
  }
}

export class Percentage {
  value: number;

  constructor(value: number) {
    if (value < 0 || value > 100) {
      throw new Error('Invalid percentage value');
    }
    this.value = value;
  }

  toString() {
    return `${this.value.toFixed(2)}%`;
  }

  toStyle() {
    return `${this.value.toFixed(0)}%`;
  }

  toDecimal() {
    return this.value / 100;
  }

  static zero() {
    return new Percentage(0);
  }

  static devidedBy(value: number, total: number) {
    return new Percentage((value / total) * 100);
  }

  static full() {
    return new Percentage(100);
  }

  isZero() {
    return this.value === 0;
  }

  isFull() {
    return this.value === 100;
  }
}

export class VideoTime {
  seconds: number;
  constructor(seconds: number) {
    this.seconds = Math.floor(seconds);
    if (seconds < 0) {
      this.seconds = 0;
    }
  }

  formatted() {
    const days = Math.floor(this.seconds / 86400);
    const hours = Math.floor((this.seconds % 86400) / 3600);
    const minutes = Math.floor((this.seconds % 3600) / 60);
    const seconds = this.seconds % 60;

    const parts = [];
    if (days > 0) parts.push(String(days).padStart(2, '0'));
    if (hours > 0 || days > 0) parts.push(String(hours).padStart(2, '0'));
    parts.push(String(minutes).padStart(2, '0'));
    parts.push(String(seconds).padStart(2, '0'));

    return parts.join(':');
  }
}

// Represents if current video is playing, not started or ended
export type Status =
  | {
      status: 'playing';
      percentage: Percentage;
    }
  | {
      status: 'NotStarted';
    }
  | {
      status: 'ended';
    };

export class MaybeResolvedPromise<T> {
  resolvedState: resolvedState<T> = { resolved: false };
  promise: Promise<T>;
  private resolveFn!: (value: T) => void;
  private rejectFn!: (reason?: unknown) => void;

  constructor() {
    this.promise = new Promise<T>((resolve, reject) => {
      this.resolveFn = resolve;
      this.rejectFn = reject;
    });
  }

  resolve(value: T) {
    this.resolvedState = { resolved: true, value };
    this.resolveFn(value);
  }

  reject(reason?: unknown) {
    this.rejectFn(reason);
  }

  isResolved = () => this.resolvedState.resolved;
  wait = () => this.promise;
}

type resolvedState<T> =
  | {
      resolved: false;
    }
  | {
      resolved: true;
      value: T;
    };

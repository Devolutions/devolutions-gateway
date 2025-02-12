export enum LogLevel {
  DEBUG = 'DEBUG',
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
}

export namespace Logger {
  let level = LogLevel.INFO;
  let enabled = true;

  export const setLevel = (newLevel: LogLevel): void => {
    level = newLevel;
  };

  export const enable = (): void => {
    enabled = true;
  };

  export const disable = (): void => {
    enabled = false;
  };

  const formatMessage = (logLevel: LogLevel, message: string, args: unknown[]): string => {
    const timestamp = new Date().toISOString();
    const formattedArgs = args.length
      ? ` ${args
          .map((arg) => (typeof arg === 'object' && arg !== null ? JSON.stringify(arg, null, 2) : String(arg)))
          .join(' ')}`
      : '';
    return `[${timestamp}] ${logLevel}: ${message}${formattedArgs}`;
  };

  const shouldLog = (logLevel: LogLevel): boolean => {
    if (!enabled) return false;
    const levels = Object.values(LogLevel);
    return levels.indexOf(logLevel) >= levels.indexOf(level);
  };

  export const debug = (message: string, ...args: unknown[]): void => {
    if (shouldLog(LogLevel.DEBUG)) {
      console.debug(formatMessage(LogLevel.DEBUG, message, args));
    }
  };

  export const info = (message: string, ...args: unknown[]): void => {
    if (shouldLog(LogLevel.INFO)) {
      console.info(formatMessage(LogLevel.INFO, message, args));
    }
  };

  export const warn = (message: string, ...args: unknown[]): void => {
    if (shouldLog(LogLevel.WARN)) {
      console.warn(formatMessage(LogLevel.WARN, message, args));
    }
  };

  export const error = (message: string, ...args: unknown[]): void => {
    if (shouldLog(LogLevel.ERROR)) {
      console.error(formatMessage(LogLevel.ERROR, message, args));
    }
  };
}

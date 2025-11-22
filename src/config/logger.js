import { LOG_LEVEL } from './env.js';

const isDebugLoggingEnabled = LOG_LEVEL === 'debug';

const logger = {
  debug: (...args) => {
    if (isDebugLoggingEnabled) console.debug(...args);
  },
  info: (...args) => console.info(...args),
  warn: (...args) => console.warn(...args),
  error: (...args) => console.error(...args)
};

export { logger, isDebugLoggingEnabled };




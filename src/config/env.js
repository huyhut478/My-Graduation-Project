const NODE_ENV = process.env.NODE_ENV || 'development';
const isDevelopment = NODE_ENV !== 'production';
const LOG_LEVEL = process.env.LOG_LEVEL || (NODE_ENV === 'production' ? 'info' : 'debug');

export { NODE_ENV, isDevelopment, LOG_LEVEL };




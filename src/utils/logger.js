import winston from 'winston';

const logLevel = process.env.LOG_LEVEL || 'info';
const logToFile = process.env.LOG_TO_FILE === 'true';
const logToConsole = process.env.LOG_TO_CONSOLE !== 'false'; // default true
const logFilePath = process.env.LOG_FILE_PATH || 'auth-service.log';

const transports = [];
if (logToConsole) {
  transports.push(new winston.transports.Console({ format: winston.format.simple() }));
}
if (logToFile) {
  transports.push(new winston.transports.File({ filename: logFilePath, format: winston.format.json() }));
}

const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports,
});

function logWithTrace(level, message, meta = {}, traceId = null) {
  logger.log({
    level,
    message,
    traceId: traceId || meta.traceId || null,
    ...meta,
  });
}

export default {
  info: (msg, meta = {}, traceId = null) => logWithTrace('info', msg, meta, traceId),
  error: (msg, meta = {}, traceId = null) => logWithTrace('error', msg, meta, traceId),
  warn: (msg, meta = {}, traceId = null) => logWithTrace('warn', msg, meta, traceId),
  debug: (msg, meta = {}, traceId = null) => logWithTrace('debug', msg, meta, traceId),
};

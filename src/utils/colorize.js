/**
 * Console color utilities for terminal output
 * Provides color formatting for better log readability
 */

import colors from 'colors/safe.js';

/**
 * Color codes for different log levels
 */
export const LOG_COLORS = {
  error: 'red',
  warn: 'yellow',
  info: 'cyan',
  debug: 'green',
  trace: 'magenta',
};

/**
 * Colorize text based on log level
 * @param {string} text - Text to colorize
 * @param {string} level - Log level (error, warn, info, debug, trace)
 * @returns {string} - Colorized text
 */
export function colorizeLevel(text, level) {
  const color = LOG_COLORS[level] || 'white';
  return colors[color](text);
}

/**
 * Colorize error text
 * @param {string} text - Text to colorize
 * @returns {string} - Red colored text
 */
export function colorizeError(text) {
  return colors.red(text);
}

/**
 * Colorize warning text
 * @param {string} text - Text to colorize
 * @returns {string} - Yellow colored text
 */
export function colorizeWarning(text) {
  return colors.yellow(text);
}

/**
 * Colorize info text
 * @param {string} text - Text to colorize
 * @returns {string} - Cyan colored text
 */
export function colorizeInfo(text) {
  return colors.cyan(text);
}

/**
 * Colorize debug text
 * @param {string} text - Text to colorize
 * @returns {string} - Green colored text
 */
export function colorizeDebug(text) {
  return colors.green(text);
}

/**
 * Colorize success text
 * @param {string} text - Text to colorize
 * @returns {string} - Green colored text
 */
export function colorizeSuccess(text) {
  return colors.green.bold(text);
}

/**
 * Colorize timestamp
 * @param {string} text - Timestamp text
 * @returns {string} - Gray colored timestamp
 */
export function colorizeTimestamp(text) {
  return colors.gray(text);
}

/**
 * Colorize field name
 * @param {string} text - Field name
 * @returns {string} - Bright white field name
 */
export function colorizeField(text) {
  return colors.brightWhite(text);
}

/**
 * Colorize HTTP status code
 * @param {number} statusCode - HTTP status code
 * @returns {string} - Colored status code
 */
export function colorizeStatusCode(statusCode) {
  const code = String(statusCode);

  if (statusCode >= 500) {
    return colors.red.bold(code);
  } else if (statusCode >= 400) {
    return colors.yellow.bold(code);
  } else if (statusCode >= 300) {
    return colors.cyan(code);
  } else if (statusCode >= 200) {
    return colors.green(code);
  }

  return colors.white(code);
}

/**
 * Colorize HTTP method
 * @param {string} method - HTTP method (GET, POST, etc.)
 * @returns {string} - Colored method
 */
export function colorizeMethod(method) {
  const upperMethod = method.toUpperCase();

  switch (upperMethod) {
    case 'GET':
      return colors.green(upperMethod);
    case 'POST':
      return colors.yellow(upperMethod);
    case 'PUT':
      return colors.blue(upperMethod);
    case 'PATCH':
      return colors.cyan(upperMethod);
    case 'DELETE':
      return colors.red(upperMethod);
    default:
      return colors.white(upperMethod);
  }
}

/**
 * Strip colors from text
 * @param {string} text - Colored text
 * @returns {string} - Plain text without colors
 */
export function stripColors(text) {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\x1b\[[0-9;]*m/g, '');
}

/**
 * Create a colored box around text
 * @param {string} text - Text to box
 * @param {string} color - Box color
 * @returns {string} - Boxed text
 */
export function colorizeBox(text, color = 'cyan') {
  const lines = text.split('\n');
  const maxLength = Math.max(...lines.map((line) => stripColors(line).length));
  const border = '─'.repeat(maxLength + 2);

  const colorFn = colors[color] || colors.white;

  const boxed = [
    colorFn(`┌${border}┐`),
    ...lines.map((line) => {
      const padding = ' '.repeat(maxLength - stripColors(line).length);
      return colorFn(`│ ${line}${padding} │`);
    }),
    colorFn(`└${border}┘`),
  ];

  return boxed.join('\n');
}

export default {
  colorizeLevel,
  colorizeError,
  colorizeWarning,
  colorizeInfo,
  colorizeDebug,
  colorizeSuccess,
  colorizeTimestamp,
  colorizeField,
  colorizeStatusCode,
  colorizeMethod,
  stripColors,
  colorizeBox,
  LOG_COLORS,
};

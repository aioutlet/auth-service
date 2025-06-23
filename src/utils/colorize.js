import colors from 'colors';

export function colorizeLevel(level, message) {
  switch (level) {
    case 'error':
      return colors.red(message);
    case 'warn':
      return colors.yellow(message);
    case 'info':
      return colors.cyan(message);
    case 'debug':
      return colors.green(message);
    default:
      return message;
  }
}

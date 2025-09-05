const { format, createLogger, transports } = require("winston");

const { combine, timestamp, colorize } = format;
const logger = createLogger({
  level: process.env.DEBUG === "true" ? "debug" : "info",
  format: combine(
    colorize(),
    timestamp(),
    format.printf(
      (info) => `${info.timestamp} - ${info.level}: ${info.message}`,
    ),
  ),
  transports: [new transports.Console()],
  exitOnError: false,
});
module.exports = logger;

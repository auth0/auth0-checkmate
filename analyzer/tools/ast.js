const acorn = require("acorn");
const logger = require("../lib/logger");

/**
 * Parse JavaScript source into an ESTree AST. Returns null (after logging)
 * when the code is syntactically invalid so callers can skip the script;
 * any other error is re-thrown.
 */
function parseScript(code, scriptName) {
  try {
    return acorn.parse(String(code || ""), {
      ecmaVersion: "latest",
      locations: true,
    });
  } catch (e) {
    if (e instanceof SyntaxError) {
      logger.log(
        "error",
        `[ACORN PARSE ERROR] Skipping script "${scriptName}" due to malformed code`,
      );
      return null;
    }
    throw e;
  }
}

/** Rewrite `#name` private identifiers so acorn can parse them anywhere. */
function maskPrivateNames(code) {
  return String(code || "").replace(/(?!\w+#)\b#(\w+)/g, "_$1");
}

/** Values that are not worth flagging as hard-coded (flags, single chars, brackets). */
function isCommonException(value) {
  const exceptions = [
    /^[0-1]$/, // Allow 0 and 1
    /^[a-z]$/i, // Single letters
    /^\s*$/, // Whitespace-only
    /^[{}()[\]<>]+$/, // Common brackets
  ];
  return exceptions.some((regex) => regex.test(String(value)));
}

module.exports = { parseScript, maskPrivateNames, isCommonException };

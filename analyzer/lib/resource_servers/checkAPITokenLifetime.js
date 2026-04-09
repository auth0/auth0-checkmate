/*
Resource Server (API) - Token Lifetime Check

Validates that API access token lifetimes are appropriately configured.
Auth0 recommends shorter lifetimes for sensitive APIs (e.g., banking).

Thresholds:
- Default: 86400 seconds (24 hours)
- Warning: > 24 hours but < 7 days
- Fail: >= 7 days (604800 seconds)
- Maximum allowed by Auth0: 30 days (2592000 seconds)
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

// Token lifetime thresholds (in seconds)
const TOKEN_LIFETIME_DEFAULT = 86400; // 24 hours - Auth0 default
const TOKEN_LIFETIME_WARNING = 604800; // 7 days

function checkAPITokenLifetime(options) {
  return executeCheck("checkAPITokenLifetime", (callback) => {
    const { resourceServers } = options;
    const reports = [];

    if (_.isEmpty(resourceServers)) {
      return callback(reports);
    }

    resourceServers.forEach((api) => {
      // Skip the Auth0 Management API (system API)
      if (api.is_system) {
        return;
      }

      const report = [];
      const apiDisplayName = api.identifier
        ? `${api.name} (${api.identifier})`
        : api.name;

      const tokenLifetime = api.token_lifetime || TOKEN_LIFETIME_DEFAULT;

      if (tokenLifetime >= TOKEN_LIFETIME_WARNING) {
        report.push({
          name: apiDisplayName,
          api_name: api.name,
          field: "token_lifetime_too_long",
          status: CONSTANTS.FAIL,
          value: formatDuration(tokenLifetime),
          identifier: api.identifier,
        });
      } else if (tokenLifetime > TOKEN_LIFETIME_DEFAULT) {
        report.push({
          name: apiDisplayName,
          api_name: api.name,
          field: "token_lifetime_extended",
          status: CONSTANTS.WARN,
          value: formatDuration(tokenLifetime),
          identifier: api.identifier,
        });
      } else {
        report.push({
          name: apiDisplayName,
          api_name: api.name,
          field: "token_lifetime_appropriate",
          status: CONSTANTS.SUCCESS,
          value: formatDuration(tokenLifetime),
          identifier: api.identifier,
        });
      }

      if (report.length > 0) {
        reports.push({ name: apiDisplayName, report: report });
      }
    });

    return callback(reports);
  });
}

/**
 * Format duration in seconds to human-readable string
 * @param {number} seconds - Duration in seconds
 * @returns {string} - Formatted duration (e.g., "24 hours", "7 days")
 */
function formatDuration(seconds) {
  if (seconds >= 86400) {
    const days = Math.floor(seconds / 86400);
    return `${days} day${days > 1 ? "s" : ""} (${seconds} seconds)`;
  } else if (seconds >= 3600) {
    const hours = Math.floor(seconds / 3600);
    return `${hours} hour${hours > 1 ? "s" : ""} (${seconds} seconds)`;
  } else if (seconds >= 60) {
    const minutes = Math.floor(seconds / 60);
    return `${minutes} minute${minutes > 1 ? "s" : ""} (${seconds} seconds)`;
  }
  return `${seconds} seconds`;
}

module.exports = checkAPITokenLifetime;

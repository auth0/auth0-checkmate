/*
{
  attackProtection: {
    bruteForceProtection: {
      "enabled": true,
      "shields": [
        "block",
        "user_notification"
      ],
      "mode": "count_per_identifier_and_ip",
      "allowlist": [],
      "max_attempts": 3
  }
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

// Validation Rules
function validateBruteForceSettings(config) {
  const report = [];
  if (_.isEmpty(config)) {
    return report;
  }
  // Check if brute force protection is enabled
  if (config.enabled) {
    report.push({
      field: "enabled",
      status: CONSTANTS.SUCCESS,
    });
  } else {
    report.push({
      field: "disabled",
      status: CONSTANTS.FAIL,
    });
  }

  // Validate shields
  const requiredShields = ["block", "user_notification"];
  const requiredModes = ["count_per_identifier"];
  const missingShields = requiredShields.filter(
    (shield) => !config.shields.includes(shield),
  );
  if (missingShields.length === 0) {
    report.push({
      field: "shieldsConfigured",
      status: CONSTANTS.SUCCESS,
    });
  } else {
    report.push({
      field: "shieldsMissing",
      status: CONSTANTS.FAIL,
      value: missingShields.join(", "),
    });
  }

  // Check allowlist
  if (config.allowlist.length > 0) {
    report.push({
      field: "allowlistPresent",
      status: CONSTANTS.FAIL,
      value: config.allowlist.join(", "),
    });
  } else {
    report.push({
      field: "allowlistEmpty",
      status: CONSTANTS.SUCCESS,
    });
  }
  // validate account lock out mode settings 
  if (config?.mode && !requiredModes.includes(config?.mode)) {
    report.push({
      field: "enableAccountLockout",
      status: CONSTANTS.FAIL,
      value: config?.mode
    });
  }
  // Return the validation report
  return report;
}
function checkBruteForce(options) {
  const { bruteForceProtection } = options.attackProtection || {};
  return executeCheck("checkBruteForce", (callback) => {
    return callback(validateBruteForceSettings(bruteForceProtection));
  });
}

module.exports = checkBruteForce;

/*
{
  attackProtection: {
    suspiciousIpThrottling: {
      "enabled": true,
      "shields": [
        "admin_notification",
        "block"
      ],
      "allowlist": [],
      "stage": {
        "pre-login": {
          "max_attempts": 100,
          "rate": 864000
        },
        "pre-user-registration": {
          "max_attempts": 50,
          "rate": 1200
        }
      }
  }
}
  */
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

// Validation Rules
function validateSettings(config) {
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
  const requiredShields = ["block", "admin_notification"];
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

  // Return the validation report
  return report;
}
function checkSuspiciousIPThrottling(options) {
  const { suspiciousIpThrottling } = options.attackProtection || {};
  return executeCheck("checkSuspiciousIPThrottling", (callback) => {
    return callback(validateSettings(suspiciousIpThrottling));
  });
}

module.exports = checkSuspiciousIPThrottling;

/*
{
  attackProtection: {
    breachedPasswordDetection: {
  "enabled": true,
  "shields": [
    "user_notification",
    "admin_notification",
    "block"
  ],
  "admin_notification_frequency": [
    "daily",
    "monthly",
    "weekly",
    "immediately"
  ],
  "method": "standard|enhanced",
  "stage": {
    "pre-user-registration": {
      "shields": [
        "block",
        "admin_notification"
      ]
    },
    "pre-change-password": {
      "shields": [
        "block"
      ]
    }
  }
}
  }
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

// Expected values
const validShields = ["user_notification", "admin_notification", "block"];
const validFrequencies = ["daily", "monthly", "weekly", "immediately"];
const validMethods = ["standard", "enhanced"];

// Function to validate configuration
function validateBreachedPasswordConfig(config) {
  const report = [];
  if (_.isEmpty(config)) {
    return report;
  }
  // Validate "enabled"
  if (config.enabled) {
    report.push({ field: "enabled", status: CONSTANTS.SUCCESS });
  } else {
    report.push({ field: "disabled", status: CONSTANTS.FAIL });
  }

  // Validate "shields"
  if (config.shields && config.shields.length > 0) {
    if (config.shields.some((shield) => !validShields.includes(shield))) {
      report.push({ field: "shields_invalid_values", status: CONSTANTS.FAIL });
    } else {
      report.push({
        field: "shields_values",
        value: config.shields.length > 0 ? config.shields.join(", ") : "empty",
        status: CONSTANTS.SUCCESS,
      });
    }
  }
  if (!config.shields.includes("block")) {
    report.push({
      field: "stage_login_shields_block_not_configured",
      status: CONSTANTS.FAIL,
    });
  }

  if (config.stage["pre-user-registration"] && !config.stage["pre-user-registration"].shields.includes("block")) {
    report.push({
      field: "stage_pre_user_shields_block_not_configured",
      status: CONSTANTS.FAIL,
    });
  }

  if (
    config.stage["pre-change-password"] &&
    !config.stage["pre-change-password"].shields.includes("block")
  ) {
    report.push({
      field: "stage_pre_change_password_shields_block_not_configured",
      status: CONSTANTS.FAIL,
    });
  }
  // Validate "admin_notification_frequency"
  if (
    config.admin_notification_frequency &&
    config.admin_notification_frequency.length > 0
  ) {
    if (
      config.admin_notification_frequency.some(
        (freq) => !validFrequencies.includes(freq),
      )
    ) {
      report.push({
        field: "admin_frequency_invalid_values",
        value: config.admin_notification_frequency.join(", "),
        status: CONSTANTS.FAIL,
      });
    } else {
      report.push({
        field: "admin_frequency_values",
        value: config.admin_notification_frequency.join(", "),
        status: CONSTANTS.SUCCESS,
      });
    }
  }

  // Validate "method"
  if (!validMethods.includes(config.method)) {
    report.push({ field: "method_invalid_value", status: CONSTANTS.FAIL });
  } else {
    report.push({
      field: "method_value",
      value: config.method,
      status: CONSTANTS.SUCCESS,
    });
  }

  if (config.enabled && config.shields.length === 0) {
    report.push({ field: "monitoring_mode", status: CONSTANTS.FAIL });
  }
  return report;
}

function checkBreachedPassword(options) {
  const { breachedPasswordDetection } = options.attackProtection || {};
  return executeCheck("checkBreachedPassword", (callback) => {
    return callback(validateBreachedPasswordConfig(breachedPasswordDetection));
  });
}

module.exports = checkBreachedPassword;

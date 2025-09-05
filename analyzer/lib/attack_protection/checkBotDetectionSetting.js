/*
{
    "selected": "auth0_v2",
    "policy": "off",
    "passwordless_policy": "always_on",
    "password_reset_policy": "off",
    "providers": {
    },
    "allowlist": []
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function validateBotDetectionSettings(config) {
  const report = [];
  if (_.isEmpty(config)) {
    return report;
  }
  if (config.policy !== "off") {
    report.push({
      field: "policy_enabled",
      status: CONSTANTS.SUCCESS,
    });
  } else {
    report.push({
      field: "policy_disabled",
      status: CONSTANTS.FAIL,
    });
  }
  if (config.passwordless_policy !== "off") {
    report.push({
      field: "passwordless_policy_enabled",
      status: CONSTANTS.SUCCESS,
    });
  } else {
    report.push({
      field: "passwordless_policy_disabled",
      status: CONSTANTS.FAIL,
    });
  }
  if (config.password_reset_policy !== "off") {
    report.push({
      field: "password_reset_policy_enabled",
      status: CONSTANTS.SUCCESS,
    });
  } else {
    report.push({
      field: "password_reset_policy_disabled",
      status: CONSTANTS.FAIL,
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
function checkBotDetectionSetting(options) {
  const { botDetection } = options.attackProtection || {};
  return executeCheck("checkBotDetectionSetting", (callback) => {
    return callback(validateBotDetectionSettings(botDetection));
  });
}
module.exports = checkBotDetectionSetting;

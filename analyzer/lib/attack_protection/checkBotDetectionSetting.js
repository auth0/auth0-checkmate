/*
Merged from the public API endpoints /attack-protection/bot-detection and
/attack-protection/captcha (previously the single /anomaly/captchas object):
{
    "active_provider_id": "auth_challenge",
    "bot_detection_level": "high",
    "challenge_password_policy": "when_risky",
    "challenge_passwordless_policy": "always",
    "challenge_password_reset_policy": "never",
    "allowlist": [],
    "monitoring_mode_enabled": false
}
The three challenge_*_policy fields are a "never" | "when_risky" | "always"
enum; "never" is the only disabled state, so both "when_risky" and "always"
count as enabled.
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function validateBotDetectionSettings(config) {
  const report = [];
  if (_.isEmpty(config)) {
    return report;
  }
  if (config.challenge_password_policy !== "never") {
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
  if (config.challenge_passwordless_policy !== "never") {
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
  if (config.challenge_password_reset_policy !== "never") {
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
  if ((config.allowlist || []).length > 0) {
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

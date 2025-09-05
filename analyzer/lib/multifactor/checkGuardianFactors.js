/*
[
  {
    "name": "sms",
    "enabled": false,
    "trial_expired": false
  },
  {
    "name": "push-notification",
    "enabled": false,
    "trial_expired": false
  },
  {
    "name": "otp",
    "enabled": true,
    "trial_expired": false
  },
  {
    "name": "email",
    "enabled": false,
    "trial_expired": false
  },
  {
    "name": "duo",
    "enabled": false,
    "trial_expired": false
  },
  {
    "name": "webauthn-roaming",
    "enabled": false,
    "trial_expired": false
  },
  {
    "name": "webauthn-platform",
    "enabled": false,
    "trial_expired": false
  },
  {
    "name": "recovery-code",
    "enabled": false,
    "trial_expired": false
  }
]
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");
function checkGuardianFactors(options) {
  const { guardianFactors } = options || {};
  return executeCheck("checkGuardianFactors", (callback) => {
    const report = [];
    const enabledFactors = _.map(
      _.filter(guardianFactors, { enabled: true }),
      "name",
    );
    if (_.isEmpty(enabledFactors)) {
      report.push({
        field: "mfa_factors_not_enabled",
        status: CONSTANTS.FAIL,
      });
    } else {
      report.push({
        field: "mfa_factors_enabled",
        value: enabledFactors.join(""),
        status: CONSTANTS.SUCCESS,
      });
    }
    return callback(report);
  });
}

module.exports = checkGuardianFactors;

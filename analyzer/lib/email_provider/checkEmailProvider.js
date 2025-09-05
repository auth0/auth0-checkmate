/*
{
  "name": "sendgrid",
  "enabled": true
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkEmailProvider(options) {
  const { emailProvider } = options || {};
  return executeCheck("checkEmailProvider", (callback) => {
    const report = [];
    if (_.isEmpty(emailProvider)) {
      report.push({
        field: "email_provider_not_configured",
        status: CONSTANTS.FAIL,
      });
    } else if (emailProvider.enabled) {
      report.push({
        field: "email_provider_enabled",
        status: CONSTANTS.SUCCESS,
        value: emailProvider.name,
      });
    } else {
      report.push({
        field: "email_provider_disabled",
        status: CONSTANTS.FAIL,
        value: emailProvider.name,
      });
    }
    return callback(report);
  });
}

module.exports = checkEmailProvider;

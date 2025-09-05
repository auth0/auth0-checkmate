/*
[
  {
    "id": "test",
    "name": "test",
    "script": "",
        "dependencies": {},
        "enabled": true,
        "triggerId": "post-user-registration"
      }
    ]
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function validateHooks(config) {
  const report = [];
  if (_.isEmpty(config)) {
    report.push({
      field: "no_enabled_hooks",
      status: CONSTANTS.SUCCESS,
    });
    return report;
  }
  config.forEach((hook) => {
    report.push({
      name: hook.name,
      value: hook.triggerId,
      field: "enabled_hooks",
      status: hook.enabled ? CONSTANTS.FAIL : CONSTANTS.SUCCESS,
    });
  });
  // Return the validation report
  return report;
}
function checkHooks(options) {
  const { hooks } = options || [];
  return executeCheck("checkHooks", (callback) => {
    return callback(validateHooks(hooks));
  });
}
module.exports = checkHooks;

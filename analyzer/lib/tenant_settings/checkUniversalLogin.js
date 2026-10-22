/*
prompts (GET /api/v2/prompts):
{
  "universal_login_experience": "new",
  "identifier_first": true,
  "webauthn_platform_first_factor": false
}

globalClient (GET /api/v2/clients?is_global=true&fields=client_id,name,global,custom_login_page_on):
{
  "client_id": "ZmVkYzY0NjUtOTJmOS00YzE1LWEyNjMtNjk4YWQ0ZjQ5ZDBj",
  "name": "All Applications",
  "global": true,
  "custom_login_page_on": false
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkUniversalLogin(options) {
  const { prompts, globalClient } = options || {};
  return executeCheck("checkUniversalLogin", (callback) => {
    const report = [];

    // null/empty means the settings could not be retrieved; don't report on unknowns
    if (!_.isEmpty(prompts)) {
      const experience = prompts.universal_login_experience || "classic";
      report.push({
        field:
          experience === "new"
            ? "new_universal_login_enabled"
            : "classic_universal_login_enabled",
        value: experience,
        status: experience === "new" ? CONSTANTS.SUCCESS : CONSTANTS.WARN,
      });
    }

    if (!_.isEmpty(globalClient)) {
      report.push({
        field: globalClient.custom_login_page_on
          ? "custom_login_page_enabled"
          : "custom_login_page_disabled",
        value: String(!!globalClient.custom_login_page_on),
        status: globalClient.custom_login_page_on
          ? CONSTANTS.WARN
          : CONSTANTS.SUCCESS,
      });
    }

    return callback(report);
  });
}

module.exports = checkUniversalLogin;

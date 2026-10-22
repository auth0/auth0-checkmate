/*
prompts (GET /api/v2/prompts):
{
  "universal_login_experience": "new",
  "identifier_first": true,
  "webauthn_platform_first_factor": false
}
*/
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

// When the tenant uses New Universal Login, recommend blocking signups made
// directly against the Authentication API so they can't bypass it
function checkUniversalLogin(options) {
  const { prompts } = options || {};
  return executeCheck("checkUniversalLogin", (callback) => {
    const report = [];
    if (prompts?.universal_login_experience === "new") {
      report.push({
        field: "block_signup_via_api",
        value: prompts.universal_login_experience,
        // WARN so the recommendation is kept in the summary; severity is Info
        status: CONSTANTS.WARN,
      });
    }
    return callback(report);
  });
}

module.exports = checkUniversalLogin;

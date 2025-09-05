
/*
{
  "allowed_logout_urls": [
    "https://contoso.com"
  ],
  "flags": {
    "allow_changing_enable_sso": true,
    "disable_impersonation": true,
    "enable_dynamic_client_registration": true, // Can be false or undefined
    "enable_sso": true,
    "universal_login": true,
    "revoke_refresh_token_grant": false,
    "disable_clickjack_protection_headers": false
  },
  "default_redirection_uri": "https://contoso.com/login",
  "support_email": "",
  "support_url": "",
  "sandbox_version": "22",
  "sandbox_versions_available": [
    "22",
    "18",
    "16",
    "12"
  ]
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkEnabledDynamicClientRegistration(options) {
  const { tenant } = options || {};
  return executeCheck("checkEnabledDynamicClientRegistration", (callback) => {
    const report = [];
    if (_.isEmpty(tenant)) {
      report.push({
        field: "tenant_setting_missing",
        status: CONSTANTS.FAIL,
      });
      return callback(report);
    }
    const { flags } = tenant;

    if (flags?.enable_dynamic_client_registration) {
      report.push({
        field: "enabled_dynamic_client_registration",
        status: CONSTANTS.FAIL, //to surface this configuration in the report
      });
    } else {
      report.push({
        field: "enable_dynamic_client_registration",
        status: CONSTANTS.FAIL,
      });
    }
    return callback(report);
  });
}

module.exports = checkEnabledDynamicClientRegistration;


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
  "idle_session_lifetime": 72, //default
  "session_lifetime": 168, //default
  "oidc_logout": {
    "rp_logout_end_session_endpoint_discovery": true
  },
  "session_cookie": {
    "mode": "persistent" //default
  },
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

function checkSessionLifetime(options) {
  const { tenant } = options || {};
  return executeCheck("checkSessionLifetime", (callback) => {
    const report = [];
    if (_.isEmpty(tenant)) {
      report.push({
        field: "tenant_setting_missing",
        status: CONSTANTS.FAIL,
      });
      return callback(report);
    }
    const { idle_session_lifetime, session_lifetime, session_cookie  } = tenant;
    if (_.isEmpty(idle_session_lifetime)) {
      report.push({
        field: "idle_session_lifetime",
        value: CONSTANTS.DEFAULT_IDLE_SESSION_LIFETIME,
        status: CONSTANTS.FAIL, //to surface this configuration in the report
      });         
    } else {
      report.push({
        field: "idle_session_lifetime",
        value: `${idle_session_lifetime}h`,
        status: CONSTANTS.FAIL, //to surface this configuration in the report
      }); 
    }
    if (_.isEmpty(session_lifetime)) {
      report.push({
        field: "session_lifetime",
        value: CONSTANTS.DEFAULT_SESSION_LIFETIME,
        status: CONSTANTS.FAIL, //to surface this configuration in the report
      });          
    } else {
      report.push({
        field: "session_lifetime",
        value: `${session_lifetime}h`,
        status: CONSTANTS.FAIL, //to surface this configuration in the report
      });         
    }
    if (_.isEmpty(session_cookie)) {
      report.push({
        field: "session_cookie_mode",
        value: CONSTANTS.DEFAULT_SESSION_COOKIE_MODE,
        status: CONSTANTS.FAIL, //to surface this configuration in the report
      });          
    } else {
      report.push({
        field: "session_cookie_mode",
        value: session_cookie?.mode,
        status: CONSTANTS.FAIL, //to surface this configuration in the report
      });         
    }
    return callback(report);
  });
}

module.exports = checkSessionLifetime;

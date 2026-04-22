
/*
{
  "enabled_locales": [
    "en"
  ],
  "flags": {
    "allow_changing_enable_sso": false,
    "disable_impersonation": true,
    "enable_sso": true,
    "universal_login": true,
    "revoke_refresh_token_grant": false,
    "improved_signup_bot_detection_in_classic": true,
    "disable_clickjack_protection_headers": false
  },
  "idle_session_lifetime": 1,
  "ephemeral_session_lifetime": 4,
  "idle_ephemeral_session_lifetime": 2,
  "sandbox_version": "22",
  "session_lifetime": 3,
  "oidc_logout": {
    "rp_logout_end_session_endpoint_discovery": true
  },
  "session_cookie": {
    "mode": "non-persistent"
  },
  "sandbox_versions_available": [
    "22",
    "18"
  ],
  "resource_parameter_profile": "audience"
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
    const {
      idle_session_lifetime,
      session_lifetime,
      idle_ephemeral_session_lifetime,
      ephemeral_session_lifetime,
      session_cookie
    } = tenant;

    // Determine session cookie mode
    const sessionCookieMode = session_cookie?.mode || CONSTANTS.DEFAULT_SESSION_COOKIE_MODE;

    // Select the appropriate values based on session cookie mode
    let idleValue, lifetimeValue;

    if (sessionCookieMode === "non-persistent") {
      // Non-persistent mode: use ephemeral session settings
      idleValue = (idle_ephemeral_session_lifetime == null)
        ? CONSTANTS.DEFAULT_IDLE_SESSION_LIFETIME
        : `${idle_ephemeral_session_lifetime}h`;

      lifetimeValue = (ephemeral_session_lifetime == null)
        ? CONSTANTS.DEFAULT_SESSION_LIFETIME
        : `${ephemeral_session_lifetime}h`;
    } else {
      // Persistent mode: use regular session settings
      idleValue = (idle_session_lifetime == null)
        ? CONSTANTS.DEFAULT_IDLE_SESSION_LIFETIME
        : `${idle_session_lifetime}h`;

      lifetimeValue = (session_lifetime == null)
        ? CONSTANTS.DEFAULT_SESSION_LIFETIME
        : `${session_lifetime}h`;
    }

    // Report with consistent field names
    report.push({
      field: "idle_session_lifetime",
      value: idleValue,
      status: CONSTANTS.FAIL, //to surface this configuration in the report
    });

    report.push({
      field: "session_lifetime",
      value: lifetimeValue,
      status: CONSTANTS.FAIL, //to surface this configuration in the report
    });

    report.push({
      field: "session_cookie_mode",
      value: sessionCookieMode,
      status: CONSTANTS.FAIL, //to surface this configuration in the report
    });

    return callback(report);
  });
}

module.exports = checkSessionLifetime;

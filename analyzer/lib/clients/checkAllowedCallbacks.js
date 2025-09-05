/*
{
  clients: [
  {
    "tenant": "contos0",
    "global": false,
    "is_token_endpoint_ip_header_trusted": false,
    "name": "Default App",
    "is_first_party": true,
    "oidc_conformant": true,
    "sso_disabled": false,
    "cross_origin_auth": false,
    "refresh_token": {
      "expiration_type": "expiring",
      "leeway": 0,
      "token_lifetime": 2592000,
      "idle_token_lifetime": 1296000,
      "infinite_token_lifetime": false,
      "infinite_idle_token_lifetime": false,
      "rotation_type": "rotating"
    },
    "allowed_clients": [],
    "allowed_logout_urls": [
      "http://localhost:3000"
    ],
    "callbacks": [
      "http://localhost:3000"
    ],
    "native_social_login": {
      "apple": {
        "enabled": false
      },
      "facebook": {
        "enabled": false
      }
    },
    "client_id": "client_id",
    "callback_url_template": false,
    "jwt_configuration": {
      "alg": "RS256",
      "lifetime_in_seconds": 36000,
      "secret_encoded": false
    },
    "client_aliases": [],
    "token_endpoint_auth_method": "none",
    "app_type": "spa",
    "grant_types": [
      "authorization_code",
      "implicit",
      "refresh_token"
    ],
    "web_origins": [
      "http://localhost:3000"
    ],
    "custom_login_page_on": true
  }  
  ]
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

// Function to check callback URLs for insecure patterns (localhost, http, 127.0.0.1)
function checkCallbackURLsForApp(app) {
  const callbackUrls = app.callbacks || [];
  const report = [];
  const insecurePatterns = ["localhost", "http://", "127.0.0.1"];
  if (callbackUrls.length === 0 && app.app_type !== "non_interactive") {
    report.push({
      name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
      client_id: app.client_id || app.name,
      field: "missing_callbacks",
      url: "",
      status: CONSTANTS.SUCCESS,
      app_type: app.app_type,
    });
  }
  callbackUrls.forEach((url) => {
    const subArr = insecurePatterns.filter((str) => url.includes(str));
    if (subArr.length > 0) {
      report.push({
        name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
        client_id: app.client_id || app.name,
        field: "insecure_callbacks",
        value: url,
        status: CONSTANTS.FAIL,
        app_type: app.app_type,
        is_first_party: app.is_first_party
      });
    }
  });
  return report;
}

function checkAllowedCallbacks(options) {
  return executeCheck("checkAllowedCallbacks", (callback) => {
    const { clients } = options;
    const reports = [];
    if (_.isEmpty(clients)) {
      return callback(reports);
    }
    clients.forEach((client) => {
      var report = checkCallbackURLsForApp(client);
      if (report.length === 0) {
        report.push({
          name: client.name,
          client_id: client.client_id || client.name,
          field: "secure_callbacks",
          status: CONSTANTS.SUCCESS,
          value: client.callbacks ? client.callbacks.join(", ") : "",
          app_type: client.app_type || "unknown",
          is_first_party: client.is_first_party
        });
      }
      reports.push({ name: client.name.concat(` (${client.client_id})`), report: report });
    });
    return callback(reports);
  });
}

module.exports = checkAllowedCallbacks;

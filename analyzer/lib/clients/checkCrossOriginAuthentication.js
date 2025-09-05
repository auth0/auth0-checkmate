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
    "cross_origin_authentication": false,
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

function checkCrossOriginAuthentication(options) {
  return executeCheck("checkCrossOriginAuthentication", (callback) => {
    const { clients } = options;
    const reports = [];
    if (_.isEmpty(clients)) {
      return callback(reports);
    }
    // https://community.auth0.com/t/action-required-update-applications-that-use-cross-origin-authentication/132819
    clients.forEach((client) => {
      var report = [];
      report.push({
        name: client.client_id
          ? client.name.concat(` (${client.client_id})`)
          : client.name,
        client_id: client.client_id || client.name,
        field: client.cross_origin_authentication ? "cross_origin_authentication_enabled" : "cross_origin_authentication_disabled",
        status: client.cross_origin_authentication ? CONSTANTS.FAIL : CONSTANTS.SUCCESS,
        app_type: client.app_type || "unknown",
        is_first_party: client.is_first_party
      });
      reports.push({ name: client.name.concat(` (${client.client_id})`), report: report });
    });
    return callback(reports);
  });
}

module.exports = checkCrossOriginAuthentication;

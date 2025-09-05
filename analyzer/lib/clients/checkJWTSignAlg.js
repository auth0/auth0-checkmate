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

function checkJWTSignAlg(options) {
  return executeCheck("checkJWTSignAlg", (callback) => {
    const { clients } = options;
    const reports = [];
    if (_.isEmpty(clients)) {
      return callback(reports);
    }
    // If a client does not have a jwtConfiguration, it will use the default configuration of RS256
    // Clients created via API will have an empty jwtConfiguration
    clients.forEach((client) => {
      var report = [];
      if (!client.jwt_configuration) {
        report.push({
          name: client.client_id
            ? client.name.concat(` (${client.client_id})`)
            : client.name,
          client_id: client.client_id || client.name,
          field: "missing_jwt_alg",
          status: CONSTANTS.SUCCESS,
          value: "RS256",
          is_first_party: client.is_first_party
        });
        reports.push({ name: client.name, report: report });
        return;
      }
      if (client.jwt_configuration.alg !== "HS256") {
        report.push({
          name: client.client_id
            ? client.name.concat(` (${client.client_id})`)
            : client.name,
          client_id: client.client_id || client.name,
          field: "using_asymmetric_alg",
          status: CONSTANTS.SUCCESS,
          value: client.jwt_configuration.alg,
          is_first_party: client.is_first_party
        });
      } else {
        report.push({
          name: client.client_id
            ? client.name.concat(` (${client.client_id})`)
            : client.name,
          client_id: client.client_id || client.name,
          field: "not_using_asymmetric_alg",
          status: CONSTANTS.FAIL,
          value: client.jwt_configuration.alg,
          is_first_party: client.is_first_party
        });
      }
      reports.push({ name: client.name.concat(` (${client.client_id})`), report: report });
    });
    return callback(reports);
  });
}

module.exports = checkJWTSignAlg;

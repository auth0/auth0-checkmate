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

function validateGrantTypesForApp(app) {
  const enabledGrantTypes = app.grant_types || [];
  const appType = app.app_type || "unknown";
  const report = [];
  let requiredGrantTypes = [];

  // Define expected grant types based on appType (OAuth2.0 best practices)
  switch (appType) {
    case "regular_web":
      requiredGrantTypes = [
        "authorization_code",
        "refresh_token",
        "client_credentials",
      ]; // Authorization Code with PKCE and Refresh Tokens
      break;
    case "spa":
      requiredGrantTypes = ["authorization_code", "refresh_token"]; // Implicit (only for older apps) or Authorization Code with PKCE
      break;
    case "native":
      requiredGrantTypes = [
        "authorization_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
      ]; // Authorization Code with PKCE and Refresh Tokens, Device Code, this abou thow to skip this if extended granty_type is used
      break;
    case "non_interactive":
      requiredGrantTypes = ["client_credentials"]; // Client Credentials (no user involvement)
      break;
    default:
      requiredGrantTypes = [
        "authorization_code",
        "refresh_token"
      ]; // Authorization Code with PKCE and Refresh Tokens
      break;
  }

  // Optionally, check for any additional unexpected grant types
  var unexpectedGrantTypes = [];
  enabledGrantTypes.forEach((grantType) => {
    if (!requiredGrantTypes.includes(grantType)) {
      unexpectedGrantTypes.push(grantType);
    }
  });
  if (!_.isEmpty(unexpectedGrantTypes)) {
    report.push({
      name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
      client_id: app.client_id,
      field: "unexpected_grant_type_for_app_type",
      value: unexpectedGrantTypes.join(", "),
      status: CONSTANTS.FAIL,
      app_type: appType,
      is_first_party: app.is_first_party
    });
  }
  return report;
}

function checkGrantTypes(options) {
  return executeCheck("checkGrantTypes", (callback) => {
    const { clients } = options || [];
    const reports = [];
    if (_.isEmpty(clients)) {
      return callback(reports);
    }
    clients.forEach((client) => {
      var report = validateGrantTypesForApp(client);
      var name = client.name.concat(` (${client.client_id})`);
      // removed old code
      reports.push({ name: name, report: report });
    });
    return callback(reports);
  });
}

module.exports = checkGrantTypes;

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

function validateRTGrantTypesForApp(app) {
    const enabledGrantTypes = app.grant_types || [];
    const appType = app.app_type || "unknown";
    const report = [];
    //let requiredGrantTypes = [];

    // Define expected grant types based on appType (OAuth2.0 best practices)
    switch (appType) {
        case "regular_web":
        case "spa":
        case "native":
            //requiredGrantTypes = [
            //    "refresh_token",
            //];
            break;
        default:
            break;
    }
    if (enabledGrantTypes.includes('refresh_token') && app?.refresh_token?.rotation_type && app?.refresh_token?.rotation_type !== 'rotating') {
        // check refresh token configuration
        report.push({
            name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
            client_id: app.client_id,
            field: "use_rotating_refresh_token",
            status: app?.refresh_token?.expiration_type !== 'expiring' ? CONSTANTS.FAIL : CONSTANTS.SUCCESS,
            value: app.refresh_token.rotation_type,
            is_first_party: app.is_first_party
        });
    }
    return report;
}

function checkRefreshToken(options) {
    return executeCheck("checkRefreshToken", (callback) => {
        const { clients } = options || [];
        const reports = [];
        if (_.isEmpty(clients)) {
            return callback(reports);
        }
        clients.forEach((client) => {
            var report = validateRTGrantTypesForApp(client);
            var name = client.name.concat(` (${client.client_id})`);
            reports.push({ name: name, report: report });
        });
        return callback(reports);
    });
}

module.exports = checkRefreshToken;

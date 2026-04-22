/*
{
  clients: [
  {
    "tenant": "contoso",
    "global": false,
    "name": "privateKeyJWT",
    "client_id": "client_id",
    "app_type": "non_interactive",
    "grant_types": [
      "client_credentials"
    ],
    "client_authentication_methods": {
      "private_key_jwt": {
        "credentials": [
          {
            "id": "cred_n844DfTC736dYMqyUGEP9Z"
          }
        ]
      }
    }
  }
  ]
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function validatePrivateKeyJWTForApp(app) {
    const report = [];

    const credentials =
        app.client_authentication_methods?.private_key_jwt?.credentials || [];

    if (credentials.length === 0) {
        report.push({
            name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
            client_id: app.client_id,
            field: "client_authentication_methods.private_key_jwt",
            status: CONSTANTS.FAIL,
            value: "not_configured",
            is_first_party: app.is_first_party,
        });
    } else {
        report.push({
            name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
            client_id: app.client_id,
            field: "client_authentication_methods.private_key_jwt",
            status: CONSTANTS.SUCCESS,
            value: "configured",
            is_first_party: app.is_first_party,
        });
    }

    return report;
}

function checkPrivateKeyJWT(options) {
    return executeCheck("checkPrivateKeyJWT", (callback) => {
        const { clients } = options || [];
        const reports = [];

        if (_.isEmpty(clients)) {
            return callback(reports);
        }

        clients.forEach((client) => {
            // Skip global/system clients
            if (client.global) {
                return;
            }

            // Skip public clients (SPAs, native apps that use no client authentication)
            if (client.token_endpoint_auth_method === "none") {
                return;
            }

            // Skip clients with token sender constraining enabled (mTLS handles client auth)
            if (client.require_proof_of_possession === true) {
                return;
            }

            const report = validatePrivateKeyJWTForApp(client);
            const name = client.name.concat(` (${client.client_id})`);
            reports.push({ name: name, report: report });
        });

        return callback(reports);
    });
}

module.exports = checkPrivateKeyJWT;

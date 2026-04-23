/*
{
  clients: [
  {
    "tenant": "contoso",
    "global": false,
    "name": "HRI Demo - CIC Bank",
    "client_id": "client_id",
    "app_type": "regular_web",
    "grant_types": [
      "authorization_code",
      "refresh_token"
    ],
    "require_pushed_authorization_requests": true
  }
  ]
}

PAR is only supported for confidential clients. Auth0's pushed_authorization_endpoint
rejects public clients (SPAs and native apps) with an error. A client is treated as
public when token_endpoint_auth_method is "none" or app_type is "spa" or "native".
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

const PAR_RELEVANT_GRANT_TYPES = [
    "authorization_code",
];

const PUBLIC_CLIENT_APP_TYPES = ["spa", "native"];

function isPublicClient(app) {
    if (app.token_endpoint_auth_method === "none") return true;
    if (PUBLIC_CLIENT_APP_TYPES.includes(app.app_type)) return true;
    return false;
}

function validatePARForApp(app) {
    const enabledGrantTypes = app.grant_types || [];
    const report = [];

    if (isPublicClient(app)) {
        return report;
    }

    const hasPARRelevantGrant = PAR_RELEVANT_GRANT_TYPES.some((g) =>
        enabledGrantTypes.includes(g)
    );

    if (hasPARRelevantGrant && app.require_pushed_authorization_requests !== true) {
        report.push({
            name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
            client_id: app.client_id,
            field: "require_pushed_authorization_requests",
            status: CONSTANTS.FAIL,
            value: app.require_pushed_authorization_requests ?? false,
            is_first_party: app.is_first_party
        });
    }

    return report;
}

function checkPAR(options) {
    return executeCheck("checkPAR", (callback) => {
        const { clients } = options || [];
        const reports = [];
        if (_.isEmpty(clients)) {
            return callback(reports);
        }
        clients.forEach((client) => {
            var report = validatePARForApp(client);
            var name = client.name.concat(` (${client.client_id})`);
            reports.push({ name: name, report: report });
        });
        return callback(reports);
    });
}

module.exports = checkPAR;

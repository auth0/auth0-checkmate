/*
{
  clients: [
  {
    "tenant": "contos0",
    "global": false,
    "name": "Default App",
    "is_first_party": true,
    "client_id": "client_id",
    "app_type": "
    ",
    "grant_types": [
      "authorization_code",
      "refresh_token"
    ],
    "require_proof_of_possession": true
  }
  ]
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

const TOKEN_SENDER_CONSTRAINING_RELEVANT_GRANT_TYPES = [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "password",
    "urn:ietf:params:oauth:grant-type:device_code",
];

function validateTokenSenderConstrainingForApp(app) {
    const enabledGrantTypes = app.grant_types || [];
    const report = [];

    const hasTokenSenderConstrainingRelevantGrant = TOKEN_SENDER_CONSTRAINING_RELEVANT_GRANT_TYPES.some((g) =>
        enabledGrantTypes.includes(g)
    );

    if (hasTokenSenderConstrainingRelevantGrant && app.require_proof_of_possession !== true) {
        report.push({
            name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
            client_id: app.client_id,
            field: "require_proof_of_possession",
            status: CONSTANTS.FAIL,
            value: app.require_proof_of_possession ?? false,
            is_first_party: app.is_first_party
        });
    }

    return report;
}

function checkAppTokenSenderConstraining(options) {
    return executeCheck("checkAppTokenSenderConstraining", (callback) => {
        const { clients } = options || [];
        const reports = [];
        if (_.isEmpty(clients)) {
            return callback(reports);
        }
        clients.forEach((client) => {
            var report = validateTokenSenderConstrainingForApp(client);
            var name = client.name.concat(` (${client.client_id})`);
            reports.push({ name: name, report: report });
        });
        return callback(reports);
    });
}

module.exports = checkAppTokenSenderConstraining;

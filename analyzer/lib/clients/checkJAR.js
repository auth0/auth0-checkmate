/*
{
  clients: [
  {
    "tenant": "contoso",
    "global": false,
    "name": "HRI",
    "client_id": "client_id",
    "app_type": "spa",
    "grant_types": [
      "authorization_code",
      "implicit",
      "refresh_token"
    ],
    "signed_request_object": {
      "required": true,
      "credentials": [
        {
          "id": "cred_eoBSAwVdfLa6ZC6m3nrPrw"
        }
      ]
    }
  }
  ]
}

JAR is only supported for confidential clients. Auth0's JAR validation
rejects public clients (SPAs and native apps). A client is treated as
public when token_endpoint_auth_method is "none" or app_type is "spa" or "native".
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

const JAR_RELEVANT_GRANT_TYPES = [
    "authorization_code",
    "implicit",
];

const PUBLIC_CLIENT_APP_TYPES = ["spa", "native"];

function isPublicClient(app) {
    if (app.token_endpoint_auth_method === "none") return true;
    if (PUBLIC_CLIENT_APP_TYPES.includes(app.app_type)) return true;
    return false;
}

function validateJARForApp(app) {
    const enabledGrantTypes = app.grant_types || [];
    const report = [];

    if (isPublicClient(app)) {
        return report;
    }

    const hasJARRelevantGrant = JAR_RELEVANT_GRANT_TYPES.some((g) =>
        enabledGrantTypes.includes(g)
    );

    if (!hasJARRelevantGrant) {
        return report;
    }

    const signedRequestObject = app.signed_request_object || {};

    if (signedRequestObject.required !== true) {
        report.push({
            name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
            client_id: app.client_id,
            field: "signed_request_object.required",
            status: CONSTANTS.FAIL,
            value: signedRequestObject.required ?? false,
            is_first_party: app.is_first_party
        });
        return report;
    }

    const credentials = signedRequestObject.credentials || [];
    if (credentials.length === 0) {
        report.push({
            name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
            client_id: app.client_id,
            field: "signed_request_object.credentials",
            status: CONSTANTS.FAIL,
            value: "not_configured",
            is_first_party: app.is_first_party
        });
    }

    return report;
}

function checkJAR(options) {
    return executeCheck("checkJAR", (callback) => {
        const { clients } = options || [];
        const reports = [];
        if (_.isEmpty(clients)) {
            return callback(reports);
        }
        clients.forEach((client) => {
            var report = validateJARForApp(client);
            var name = client.name.concat(` (${client.client_id})`);
            reports.push({ name: name, report: report });
        });
        return callback(reports);
    });
}

module.exports = checkJAR;

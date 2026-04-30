/*
{
  clients: [
  {
    "tenant": "contoso",
    "global": false,
    "name": "backchannellogout",
    "client_id": "client_id",
    "app_type": "regular_web",
    "grant_types": [
      "authorization_code",
      "refresh_token"
    ],
    "oidc_backchannel_logout": {
      "backchannel_logout_initiators": {
        "mode": "all"
      },
      "backchannel_logout_urls": [
        "https://example.com/backchannel-logout"
      ]
    }
  }
  ]
}

Back-Channel Logout is only relevant for applications that maintain server-side sessions
and can receive back-channel communications. It is applicable to regular_web apps.
SPAs and native apps use front-channel logout and cannot receive back-channel requests.
Non-interactive (M2M) clients do not have user sessions and are not relevant.
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

const BACKCHANNEL_LOGOUT_APP_TYPES = ["regular_web"];

function validateBackchannelLogoutForApp(app) {
    const report = [];

    // Check both oidc_backchannel_logout and oidc_logout fields
    const backchannelConfig = app.oidc_backchannel_logout || app.oidc_logout;
    const backchannelUrls =
        backchannelConfig?.backchannel_logout_urls || [];

    if (!backchannelConfig || backchannelUrls.length === 0) {
        report.push({
            name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
            client_id: app.client_id,
            field: "oidc_backchannel_logout.backchannel_logout_urls",
            status: CONSTANTS.FAIL,
            value: "not_configured",
            is_first_party: app.is_first_party,
        });
    } else {
        report.push({
            name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
            client_id: app.client_id,
            field: "oidc_backchannel_logout.backchannel_logout_urls",
            status: CONSTANTS.SUCCESS,
            value: backchannelUrls.join(", "),
            is_first_party: app.is_first_party,
        });
    }

    return report;
}

function checkBackchannelLogout(options) {
    return executeCheck("checkBackchannelLogout", (callback) => {
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

            // Only check app types that support back-channel logout
            if (!BACKCHANNEL_LOGOUT_APP_TYPES.includes(client.app_type)) {
                return;
            }

            const report = validateBackchannelLogoutForApp(client);
            const name = client.name.concat(` (${client.client_id})`);
            reports.push({ name: name, report: report });
        });

        return callback(reports);
    });
}

module.exports = checkBackchannelLogout;

/*
{
  clients: [ { client_id, grant_types, require_pushed_authorization_requests, global } ],
  resourceServers: [ { id, name, identifier, is_system, authorization_details } ],
  clientGrants: [ { client_id, audience } ]
}

Checks whether APIs accessed by PAR+AuthCode or CIBA clients have RAR configured.
Skips system RSes. Skips RSes not linked to any PAR/CIBA client.
Emits INFO when authorization_details is absent or empty.
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

const CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";

function isRARCapableClient(client) {
    if (client.global) return false;
    const grants = client.grant_types || [];
    const hasPARWithAuthCode =
        client.require_pushed_authorization_requests === true &&
        grants.includes("authorization_code");
    const hasCIBA = grants.includes(CIBA_GRANT_TYPE);
    return hasPARWithAuthCode || hasCIBA;
}

function checkRAR(options) {
    return executeCheck("checkRAR", (callback) => {
        const { clients, resourceServers, clientGrants } = options || {};
        const reports = [];

        if (_.isEmpty(clients) || _.isEmpty(resourceServers)) {
            return callback(reports);
        }

        // Step 1: collect client_ids of RAR-capable clients
        const rarClientIds = new Set(
            (clients || [])
                .filter(isRARCapableClient)
                .map((c) => c.client_id)
        );

        if (rarClientIds.size === 0) {
            return callback(reports);
        }

        // Step 2: collect RS identifiers authorized for those clients
        // If clientGrants is empty/unavailable, skip entirely (no false positives)
        if (_.isEmpty(clientGrants)) {
            return callback(reports);
        }

        const authorizedAudiences = new Set(
            (clientGrants || [])
                .filter((g) => rarClientIds.has(g.client_id))
                .map((g) => g.audience)
        );

        // Step 3: check each non-system RS in that set for authorization_details
        (resourceServers || []).forEach((rs) => {
            if (rs.is_system) return;
            if (!authorizedAudiences.has(rs.identifier)) return;

            const name = rs.name || rs.identifier;
            const displayName = rs.identifier ? `${name} (${rs.identifier})` : name;

            const hasRAR =
                Array.isArray(rs.authorization_details) &&
                rs.authorization_details.length > 0;

            const report = [];
            if (!hasRAR) {
                report.push({
                    name: displayName,
                    identifier: rs.identifier,
                    field: "authorization_details",
                    status: CONSTANTS.FAIL,
                    value: "not_configured",
                });
            }
            reports.push({ name: displayName, report });
        });

        return callback(reports);
    });
}

module.exports = checkRAR;

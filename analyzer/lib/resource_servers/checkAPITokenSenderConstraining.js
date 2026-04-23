/*
{
  resourceServers: [
    {
      "id": "rs_abc123",
      "name": "My API",
      "identifier": "https://my-api.example.com",
      "is_system": false,
      "proof_of_possession": {
        "mechanism": "dpop",
        "required": true,
        "required_for": "all_clients"
      }
    }
  ]
}

proof_of_possession.mechanism values:
  "dpop"  => DPoP (Demonstrating Proof of Possession)
  "mtls"  => Mutual TLS

When proof_of_possession is absent from the API response, token sender
constraining is not configured for that resource server.
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

const VALID_MECHANISMS = ["dpop", "mtls"];

function validateDPoPForResourceServer(rs) {
    const report = [];

    const name = rs.name || rs.identifier;
    const displayName = rs.identifier ? `${name} (${rs.identifier})` : name;
    const pop = rs.proof_of_possession;

    // If proof_of_possession is absent the Management API has confirmed that
    // token sender constraining is not configured for this resource server.
    if (!pop) {
        report.push({
            name: displayName,
            identifier: rs.identifier,
            field: "proof_of_possession",
            status: CONSTANTS.FAIL,
            value: "not_configured",
        });
        return report;
    }

    if (!VALID_MECHANISMS.includes(pop.mechanism)) {
        report.push({
            name: displayName,
            identifier: rs.identifier,
            field: "proof_of_possession.mechanism",
            status: CONSTANTS.FAIL,
            value: pop.mechanism ?? "not_set",
        });
    }

    return report;
}

function checkTokenConstrainingResourceServer(options) {
    return executeCheck("checkTokenConstrainingResourceServer", (callback) => {
        const { resourceServers } = options || {};
        const reports = [];
        if (_.isEmpty(resourceServers)) {
            return callback(reports);
        }
        resourceServers.forEach((rs) => {
            if (rs.is_system) {
                return;
            }
            const report = validateDPoPForResourceServer(rs);
            const name = rs.name || rs.identifier;
            const displayName = rs.identifier ? `${name} (${rs.identifier})` : name;
            reports.push({ name: displayName, report: report });
        });
        return callback(reports);
    });
}

module.exports = checkTokenConstrainingResourceServer;

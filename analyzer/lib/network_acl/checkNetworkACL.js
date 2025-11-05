/*
[
  {
    "description": "string",
    "active": true,
    "priority": 1,
    "rule": {
      "match": {
        "ipv4_cidrs": [
          "198.51.100.42",
          "10.0.0.0/24"
        ]
      },
      "scope": "management",
      "action": {
        "block": true
      }
    },
    "created_at": "2025-11-03T22:09:30.550Z",
    "updated_at": "2025-11-03T22:09:30.550Z",
    "id": "acl_pgqBXvEP4qRBohnqxqj2yP"
  }
]
*/

const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkNetworkACL(options) {
  const { networkAcl } = options || [];
  return executeCheck("checkNetworkACL", (callback) => {
    const report = [];
    const hasInsufficientScope = _.some(networkAcl, {
      errorCode: "insufficient_scope",
    });
    if (hasInsufficientScope) {
      return callback(report);
    }
    if (_.isEmpty(networkAcl)) {
      report.push({
        field: "no_network_acl",
        name: "Tenant Access Control List",
        status: CONSTANTS.FAIL,
      });
    } else {
        networkAcl.forEach((acl) => {
        if (!acl.active) {
          const description = acl.description || acl.name || acl.acl_id;
          report.push({
            field: "network_acl_inactive",
            name: `${description}(${acl.acl_id})`,
            status: CONSTANTS.FAIL,
          });
        }
      });
    }
    return callback(report);
  });
}

module.exports = checkNetworkACL;

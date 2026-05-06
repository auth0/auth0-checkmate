/*
{
  "description": "Allow management API from office IPs",
  "active": true,
  "priority": 1,
  "rule": {
    "match": {
      "ipv4_cidrs": [
        "203.0.113.0/24"
      ]
    },
    "scope": "management",
    "action": {
      "allow": true
    }
  }
}
*/

const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkManagementAPIACL(options) {
  const { networkAcl } = options || [];

  return executeCheck("checkManagementAPIACL", (callback) => {
    const report = [];

    const hasInsufficientScope = _.some(networkAcl, {
      errorCode: "insufficient_scope",
    });
    if (hasInsufficientScope) {
      return callback(report);
    }

    const managementRules = _.filter(networkAcl, (acl) => {
      return (
        acl.active &&
        acl.rule &&
        acl.rule.scope === "management"
      );
    });

    const hasAllowlist = _.some(managementRules, (acl) => {
      const { match, action } = acl.rule;
      const hasIpMatch = match &&
        (match.ipv4_cidrs?.length > 0 || match.ipv6_cidrs?.length > 0);
      const isAllowAction = action && action.allow === true;

      return hasIpMatch && isAllowAction;
    });

    if (!hasAllowlist) {
      report.push({
        field: "no_management_api_allowlist",
        name: "Management API Access Control",
        status: CONSTANTS.WARN,
      });
    }

    return callback(report);
  });
}

module.exports = checkManagementAPIACL;

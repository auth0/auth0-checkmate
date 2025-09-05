/*
[
  "all-applications"
]
 */
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");
function checkGuardianPolicy(options) {
  const { guardianPolicies } = options || { policies: [] };
  return executeCheck("checkGuardianPolicy", (callback) => {
    const report = [];
    if (_.isEmpty(guardianPolicies)) {
      report.push({
        field: "mfa_policy_set_to_never",
        value: CONSTANTS.MULTIFACTOR_POLICY["empty"],
        status: CONSTANTS.FAIL,
      });
      return callback(report);
    }
    const policies = guardianPolicies.policies || [];
    if (_.isEmpty(policies)) {
      policies.push("empty");
      report.push({
        field: "mfa_policy_set_to_never",
        value: CONSTANTS.MULTIFACTOR_POLICY[policies.join("")],
        status: CONSTANTS.FAIL,
      });
    } else {
      report.push({
        field: "mfa_policy_set",
        value: CONSTANTS.MULTIFACTOR_POLICY[policies.join("")],
        status: CONSTANTS.SUCCESS,
      });
    }
    return callback(report);
  });
}

module.exports = checkGuardianPolicy;

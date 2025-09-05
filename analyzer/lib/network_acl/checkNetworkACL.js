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
        status: CONSTANTS.FAIL,
      });
    } else {
        networkAcl.forEach((acl) => {
        if (!acl.active) {
          report.push({
            field: "network_acl_inactive",
            name: acl.description.concat(`(${acl.acl_id})`),
            status: CONSTANTS.FAIL,
          });
        }
      });
    }
    return callback(report);
  });
}

module.exports = checkNetworkACL;

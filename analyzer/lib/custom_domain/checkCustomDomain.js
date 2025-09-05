/*
  customDomains: [
    {
      domain: 'apac-tam-team.oauth101.net',
      primary: true,
      status: 'ready',
      tls_policy: 'recommended',
      type: 'auth0_managed_certs',
      verification: [Object]
    }
  ]
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkCustomDomain(options) {
  const { customDomains } = options;
  return executeCheck("checkCustomDomain", (callback) => {
    const report = [];
    if (_.isEmpty(customDomains)) {
      report.push({
        field: "not_configured",
        status: CONSTANTS.FAIL,
      });
    } else if (customDomains.some((domain) => domain.status === "ready")) {
      report.push({
        field: "ready",
        status: CONSTANTS.SUCCESS,
        value: customDomains
          .map((d) => {
            return d.domain;
          })
          .join(","),
      });
    } else if (
      customDomains.some((domain) => domain.status === "pending_verification")
    ) {
      report.push({
        field: "pending_verification",
        status: CONSTANTS.FAIL,
        value: customDomains
          .map((d) => {
            return d.domain;
          })
          .join(","),
      });
    }
    return callback(report);
  });
}

module.exports = checkCustomDomain;

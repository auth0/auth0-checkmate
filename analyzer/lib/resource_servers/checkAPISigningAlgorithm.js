/*
Resource Server (API) - Signing Algorithm Check

Validates that APIs use RS256 (asymmetric) signing algorithm instead of HS256 (symmetric).
RS256 is recommended because:
- Only Auth0 can sign tokens (private key is not shared)
- Easier key rotation without redeploying applications
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkAPISigningAlgorithm(options) {
  return executeCheck("checkAPISigningAlgorithm", (callback) => {
    const { resourceServers } = options;
    const reports = [];

    if (_.isEmpty(resourceServers)) {
      return callback(reports);
    }

    resourceServers.forEach((api) => {
      // Skip the Auth0 Management API (system API)
      if (api.is_system) {
        return;
      }

      const report = [];
      const apiDisplayName = api.identifier
        ? `${api.name} (${api.identifier})`
        : api.name;

      if (api.signing_alg === "HS256") {
        report.push({
          name: apiDisplayName,
          api_name: api.name,
          field: "using_symmetric_alg",
          status: CONSTANTS.FAIL,
          value: api.signing_alg,
          identifier: api.identifier,
        });
      } else {
        report.push({
          name: apiDisplayName,
          api_name: api.name,
          field: "using_asymmetric_alg",
          status: CONSTANTS.SUCCESS,
          value: api.signing_alg || "RS256",
          identifier: api.identifier,
        });
      }

      if (report.length > 0) {
        reports.push({ name: apiDisplayName, report: report });
      }
    });

    return callback(reports);
  });
}

module.exports = checkAPISigningAlgorithm;

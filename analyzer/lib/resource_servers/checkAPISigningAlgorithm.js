/*
  {
    "id": "xxxxxxxxxxxx",
    "name": "test wrong alg",
    "identifier": "test1",
    "allow_offline_access": false,
    "skip_consent_for_verifiable_first_party_clients": true,
    "subject_type_authorization": {
      "user": {
        "policy": "require_client_grant"
      },
      "client": {
        "policy": "require_client_grant"
      }
    },
    "token_lifetime": 86400,
    "token_lifetime_for_web": 7200,
    "signing_alg": "HS256",
    "signing_secret": "xxxxxxxxxxxxxxxxxx",
    "token_dialect": "access_token"
  }
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

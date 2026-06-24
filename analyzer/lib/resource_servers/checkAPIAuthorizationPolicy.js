/*
  {
    "id": "xxxxxxxxxxxx",
    "name": "My API",
    "identifier": "https://api.example.com",
    "is_system": false,
    "subject_type_authorization": {
      "user": {
        "policy": "allow_all"          // any application can mint a user token for this API
      },
      "client": {
        "policy": "require_client_grant"
      }
    }
  }

  When the user policy is not "require_client_grant", every application in the
  tenant is allowed to request a user access token for this API's audience. As
  described in https://www.elttam.com/blog/exploiting-auth0-defaults-in-xss-attacks
  this lets an XSS bug in any first-party application obtain tokens for an
  unrelated API (e.g. an Admin API) - particularly dangerous when the back-end
  does not validate the authorized party (`azp`) claim. Restricting API access to
  approved applications (`require_client_grant`) and validating `azp` server-side
  contains the blast radius of a single compromised application.
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function getUserPolicy(api) {
  return _.get(api, "subject_type_authorization.user.policy");
}

function checkAPIAuthorizationPolicy(options) {
  return executeCheck("checkAPIAuthorizationPolicy", (callback) => {
    const { resourceServers } = options || {};
    const reports = [];

    if (_.isEmpty(resourceServers)) {
      return callback(reports);
    }

    resourceServers.forEach((api) => {
      // The Auth0 Management API is covered by checkManagementAPIUserAccess.
      if (api.is_system) {
        return;
      }

      const apiDisplayName = api.identifier
        ? `${api.name} (${api.identifier})`
        : api.name;
      const report = [];

      if (getUserPolicy(api) === "require_client_grant") {
        report.push({
          name: apiDisplayName,
          api_name: api.name,
          field: "api_access_restricted",
          status: CONSTANTS.SUCCESS,
          value: api.name,
          identifier: api.identifier,
        });
      } else {
        report.push({
          name: apiDisplayName,
          api_name: api.name,
          field: "api_access_unrestricted",
          status: CONSTANTS.WARN,
          value: api.name,
          identifier: api.identifier,
        });
      }

      reports.push({ name: apiDisplayName, report: report });
    });

    return callback(reports);
  });
}

module.exports = checkAPIAuthorizationPolicy;

/*
  The Auth0 Management API is exposed as a system resource server, e.g.:
  {
    "id": "xxxxxxxxxxxx",
    "name": "Auth0 Management API",
    "identifier": "https://your-tenant.us.auth0.com/api/v2/",
    "is_system": true,
    "subject_type_authorization": {
      "user": {
        "policy": "allow_all"          // permissive default -> any app's users can call /api/v2/
      },
      "client": {
        "policy": "require_client_grant"
      }
    }
  }

  When the user policy is "allow_all" (the historical default), users of ANY
  application in the tenant can obtain a Management API access token carrying
  `{action}:current_user_{resource}` scopes. As described in
  https://www.elttam.com/blog/exploiting-auth0-defaults-in-xss-attacks an
  attacker who lands XSS in any first-party app can socially-engineer consent to
  `update:current_user_identities` and link an attacker-controlled account to the
  victim, gaining persistent access. Restricting user access to
  `require_client_grant` and handling profile / account-linking through a
  back-end machine-to-machine flow removes this vector.
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function getUserPolicy(api) {
  return _.get(api, "subject_type_authorization.user.policy");
}

function checkManagementAPIUserAccess(options) {
  return executeCheck("checkManagementAPIUserAccess", (callback) => {
    const { resourceServers } = options || {};
    const report = [];

    if (_.isEmpty(resourceServers)) {
      return callback(report);
    }

    const managementApi = _.find(
      resourceServers,
      (api) =>
        api.is_system &&
        typeof api.identifier === "string" &&
        api.identifier.endsWith("/api/v2/"),
    );

    if (!managementApi) {
      return callback(report);
    }

    const name = managementApi.name || "Auth0 Management API";

    if (getUserPolicy(managementApi) === "require_client_grant") {
      report.push({
        field: "management_api_user_access_restricted",
        name: name,
        status: CONSTANTS.SUCCESS,
      });
    } else {
      report.push({
        field: "management_api_user_access_allowed",
        name: name,
        status: CONSTANTS.FAIL,
      });
    }

    return callback(report);
  });
}

module.exports = checkManagementAPIUserAccess;

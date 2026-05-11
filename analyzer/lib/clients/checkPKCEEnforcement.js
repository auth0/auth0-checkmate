/*
{
  clients: [
  {
    "tenant": "contoso",
    "global": false,
    "name": "My SPA App",
    "client_id": "client_spa",
    "app_type": "spa",
    "is_first_party": true,
    "grant_types": [
      "authorization_code",
      "refresh_token"
    ]
  }
  ],
  actions: {
    actions: [
      {
        "id": "action_id",
        "name": "Enforce PKCE",
        "supported_triggers": [{ "id": "post-login", "version": "v3" }],
        "code": "exports.onExecutePostLogin = async (event, api) => { if (!event.request.query.code_challenge) { api.access.deny('PKCE required'); } };"
      }
    ]
  }
}

For SPA and native app types using the authorization_code grant, PKCE must be enforced.
Auth0 does not natively block non-PKCE authorization code requests for public clients,
so enforcement must be implemented via a post-login Action that checks for the presence
of event.request.query.code_challenge and calls api.access.deny when it is absent.

Reference: https://support.auth0.com/center/s/article/Enforce-PKCE-with-Actions
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");
const acorn = require("acorn");
const walk = require("estree-walker").walk;

const PKCE_APPLICABLE_GRANT_TYPES = ["authorization_code"];
const PKCE_APPLICABLE_APP_TYPES = ["spa", "native"];

function isPKCEApplicableClient(client) {
  const grantTypes = client.grant_types || [];
  const appType = client.app_type;
  return (
    PKCE_APPLICABLE_APP_TYPES.includes(appType) &&
    grantTypes.some((g) => PKCE_APPLICABLE_GRANT_TYPES.includes(g))
  );
}

function getMemberExpressionPath(expr) {
  if (expr.type === "Identifier") return expr.name;
  if (expr.type === "MemberExpression") {
    const obj = getMemberExpressionPath(expr.object);
    const prop = expr.property.name;
    return obj ? `${obj}.${prop}` : prop;
  }
  return null;
}

/**
 * Scans an Action's code for both event.request.query.code_challenge access
 * and an api.access.deny call, which together indicate PKCE enforcement.
 */
function hasPKCEEnforcement(code, scriptName) {
  let hasCodeChallenge = false;
  let hasAccessDeny = false;

  let ast;
  try {
    ast = acorn.parse(code || "", {
      ecmaVersion: "latest",
      locations: true,
    });
  } catch (e) {
    if (e instanceof SyntaxError) {
      console.error(
        `[ACORN PARSE ERROR] Skipping script "${scriptName}" due to malformed code`
      );
      return false;
    }
    throw e;
  }

  walk(ast, {
    enter(node) {
      if (node.type === "MemberExpression") {
        // Match direct access (event.request.query.code_challenge) or
        // indirect access via intermediate variable (query.code_challenge,
        // codeChallenge = query && query.code_challenge, etc.)
        if (node.property.name === "code_challenge") {
          hasCodeChallenge = true;
        }
      }
      if (node.type === "CallExpression") {
        const path = getMemberExpressionPath(node.callee);
        if (path === "api.access.deny") {
          hasAccessDeny = true;
        }
      }
    },
  });

  return hasCodeChallenge && hasAccessDeny;
}

function checkPKCEEnforcement(options) {
  return executeCheck("checkPKCEEnforcement", (callback) => {
    const { clients, actions } = options || {};
    const reports = [];

    if (_.isEmpty(clients)) {
      return callback(reports);
    }

    const pkceApplicableClients = clients.filter(isPKCEApplicableClient);

    if (_.isEmpty(pkceApplicableClients)) {
      return callback(reports);
    }

    const actionsList = _.isArray(actions)
      ? actions
      : (actions && actions.actions) || [];

    const hasPKCEAction = actionsList.some((action) => {
      const triggers = action.supported_triggers || [];
      const isPostLogin = triggers.some((t) => t.id === "post-login");
      if (!isPostLogin) return false;
      if (action.status !== "built") return false;

      try {
        return hasPKCEEnforcement(action.code, action.name);
      } catch (e) {
        console.error(
          `[CHECK ERROR] Skipping Action "${action.name}" due to error: ${e.message}`
        );
        return false;
      }
    });

    pkceApplicableClients.forEach((client) => {
      const name = client.name.concat(` (${client.client_id})`);
      const report = [];

      if (!hasPKCEAction) {
        report.push({
          name: name,
          client_id: client.client_id,
          field: "pkce_enforcement_action_missing",
          status: CONSTANTS.FAIL,
          value: client.app_type,
          is_first_party: client.is_first_party,
        });
      }

      reports.push({ name: name, report: report });
    });

    return callback(reports);
  });
}

module.exports = checkPKCEEnforcement;

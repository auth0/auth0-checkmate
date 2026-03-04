const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");
const acorn = require("acorn");
const walk = require("estree-walker").walk;

/**
 * Scans the Action code for calls to MFA challenge methods.
 * Returns boolean if challenge is found.
 */
function hasMFAChallenge(code, scriptName) {
  let challengeFound = false;
  let ast;

  try {
    ast = acorn.parse(code || "", {
      ecmaVersion: "latest",
      locations: true,
    });
  } catch (e) {
    if (e instanceof SyntaxError) {
      console.error(`[ACORN PARSE ERROR] Skipping script "${scriptName}" due to malformed code`);
      return [];
    }
    throw e;
  }

  walk(ast, {
    enter(node) {
      if (node.type === "CallExpression") {
        const callee = node.callee;
        
        function getMemberExpressionPath(expr) {
          if (expr.type === "Identifier") return expr.name;
          if (expr.type === "MemberExpression") {
            const obj = getMemberExpressionPath(expr.object);
            const prop = expr.property.name;
            return obj ? `${obj}.${prop}` : prop;
          }
          return null;
        }

        const path = getMemberExpressionPath(callee);
        if (path === "api.authentication.challengeWith" || path === "api.authentication.challengeWithAny") {
          challengeFound = true;
        }
      }
    },
  });

  return challengeFound;
}

/**
 * Main validator for Actions targeting the password-reset trigger.
 */
function checkPasswordResetMFA(options) {
  const { actions, databases } = options || {};
  
  return executeCheck("checkPasswordResetMFA", (callback) => {
    // 1. Check for Active Password DBs (Same as before)
    const hasActivePasswordDb = _.some(databases, (db) => {
      const authMethods = db.options?.authentication_methods;
      return db.strategy === "auth0" && (!authMethods || authMethods.password?.enabled !== false);
    });

    if (!hasActivePasswordDb) return callback([]); 

    const actionsList = _.isArray(actions) ? actions : actions.actions;
    if (_.isEmpty(actionsList)) {
      return callback([{ name: "Actions", report: [{ field: "no_actions_configured", status: CONSTANTS.WARN }] }]);
    }

    // 2. Aggregate scan across ALL relevant actions
    let passwordResetActionsFound = [];
    let anyActionHasMFA = false;

    for (const action of actionsList) {
      const triggers = action.supported_triggers || [];
      const isPassReset = triggers.some(t => t.id === "password-reset-post-challenge");
      if (isPassReset) { // deployed_version.deployed
        passwordResetActionsFound.push(action.name);
        if (hasMFAChallenge(action.code, action.name)) {
          anyActionHasMFA = true;
        }
      }
    }

    const reports = [];
    const flowName = "Password Reset Flow";

    // 3. Logic for the single finding report
    if (passwordResetActionsFound.length === 0) {
      reports.push({ 
        name: "Password Reset Flow", 
        report: [{ 
            scriptName: flowName,
            name: flowName, 
            status: CONSTANTS.WARN,
            variableName: "api.authentication.challengeWith",
            line: "N/A",
            column: "N/A",
            field: "no_password_reset_action",
        }] 
      });
    } else if (!anyActionHasMFA) {
      // NONE of the password reset actions had MFA
      reports.push({ 
        name: "Password Reset Flow", 
        report: [{ 
          scriptName: `${passwordResetActionsFound.join(", ")}`, 
          status: CONSTANTS.WARN,
          name: flowName,
          variableName: "api.authentication.challengeWith",
          line: "N/A",
          column: "N/A",
          field: "missing_mfa_step",
        }]      
      });
    } else {
        // found an MFA challenge on password reset
    }

    return callback(reports);
  });
}

module.exports = checkPasswordResetMFA;

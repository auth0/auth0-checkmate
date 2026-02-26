const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");
const acorn = require("acorn");
const walk = require("estree-walker").walk;

/**
 * Scans the Action code for calls to api.access.deny()
 * to warn about potential user enumeration vulnerabilities.
 */
function detectAccessDeny(code, scriptName) {
  const findings = [];

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
        
        // Helper function to reconstruct the property chain (e.g., "api.access.deny")
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

        // This will now catch api.access.deny regardless of how Acorn nests the objects
        if (path === "api.access.deny") {
            findings.push({
            scriptName: scriptName,
            field: "user_enumeration_vulnerability",
            status: CONSTANTS.WARN,
            line: node.loc?.start?.line || "N/A",
            column: node.loc?.start?.column || "N/A",
            // We add this to match the grouping logic in report.js
            variableName: "api.access.deny" 
            });
        }
        }
    },
    });

  return findings;
}

/**
 * Main validator for Actions targeting the pre-user-registration trigger.
 */
function checkPreRegistrationUserEnumeration(options) {
  const { actions } = options || [];
  
  return executeCheck("checkPreRegistrationUserEnumeration", (callback) => {
    const actionsList = _.isArray(actions) ? actions : actions.actions;
    const reports = [];

    if (_.isEmpty(actionsList)) {
      return callback(reports);
    }

    for (const action of actionsList) {
      const triggers = action.supported_triggers || [];
   
      const isPreReg = triggers.some(t => t.id === "pre-user-registration");
      // Only scan if the action is part of the pre-user-registration trigger
      if (!isPreReg) continue;

      const actionName = `${action.name} (pre-user-registration)`;

      try {
        const findings = detectAccessDeny(action.code, actionName);
        if (findings.length > 0) {
          reports.push({ name: actionName, report: findings });
        }
      } catch (e) {
        console.error(`[CHECK ERROR] Skipping Actions due to error: ${actionName}`);
        continue;
      }
    }
    return callback(reports);
  });
}

module.exports = checkPreRegistrationUserEnumeration;
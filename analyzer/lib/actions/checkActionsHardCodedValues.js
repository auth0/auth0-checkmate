/*
{
  "actions": [
    {
      "id": "0cdb84c6-9faf-4344-b1c5-affa9db5a63f",
      "name": "Custom Phone Provider",
      "supported_triggers": [
        {
          "id": "custom-phone-provider",
          "version": "v1"
        }
      ],
      "created_at": "2024-12-05T03:14:55.811465959Z",
      "updated_at": "2024-12-05T03:14:55.831277001Z",
      "code": "exports.onExecuteCustomPhoneProvider = async (event, api) => {\n  // Code goes here\n  return;\n};",
        "dependencies": [],
        "runtime": "node18",
        "status": "built",
        "secrets": [],
        "all_changes_deployed": false
      },
      {
        "id": "89df9e29-d521-43f4-9b80-8a8f9623ad39",
        "name": "Console Log",
        "supported_triggers": [
          {
            "id": "post-login",
            "version": "v3"
          }
        ],
        "created_at": "2024-12-05T03:48:52.546705182Z",
        "updated_at": "2025-02-05T04:33:20.935611754Z",
        "code": "exports.onExecutePostLogin = async (event, api) => {\n  const PASSWORD = \"abcd1234\";\n  console.log(JSON.stringify(event.user, null, 2));\n};",
        "dependencies": [
          {
            "name": "aws-sdk",
            "version": "2.1448.0"
          }
        ],
        "runtime": "node18-actions",
        "status": "built",
        "secrets": [],
        "all_changes_deployed": true
      },
      {
        "id": "7d24512b-aa56-4ddc-8b51-68583110c5fa",
        "name": "action example 1",
        "supported_triggers": [
          {
            "id": "post-login",
            "version": "v3"
          }
        ],
        "created_at": "2025-02-05T03:03:04.643668771Z",
        "updated_at": "2025-02-05T03:03:04.666046787Z",
        "code": "exports.onExecutePostLogin = async (event, api) => {\n};",
        "dependencies": [],
        "runtime": "node22",
        "status": "built",
        "secrets": [],
        "all_changes_deployed": false
      }
    ],
    "total": 3
  }
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");
const acorn = require("acorn");
const walk = require("estree-walker").walk;

function detectHardcodedValues(code, scriptName) {

  const hardcodedValues = [];

  let processedCode = String(code || '').replace(/(?!\w+#)\b#(\w+)/g, "_$1");
  
  let ast;
    try {
      ast = acorn.parse(processedCode, {
        ecmaVersion: "latest",
        locations: true,
      });
    } catch (e) {
      if (e instanceof SyntaxError) {
        console.error(`[ACORN PARSE ERROR] Skipping script "${scriptName}" due to malformed code: ${e.message}`);
        // Return an empty array so the main loop can continue
        return []; 
      }
      throw e; // Re-throw other unexpected errors
    }

  // Walk through the AST
  walk(ast, {
    enter(node) {
      // Check for variable assignments with hardcoded literals
      if (node.type === "VariableDeclaration") {
        
        node.declarations.forEach((declaration) => {
          if (
            declaration.init &&
            declaration.init.type === "Literal" &&
            typeof declaration.init.value === "string"
          ) {
            // Add the variable name and the type of the hardcoded literal
            const value = declaration.init.value;
            
            hardcodedValues.push({
              scriptName: scriptName,
              variableName: declaration.id.name,
              field: "hard_coded_value_detected",
              status: CONSTANTS.FAIL,
              type: typeof declaration.init.value,
              line: declaration.loc?.start?.line || 'N/A', 
              column: declaration.loc?.start?.column || 'N/A',
              value: value, 
            });
          }
        });
      }
    },
  });

  return hardcodedValues.filter(
    (entry) =>
      !isCommonException(entry.value) && !isConstantDeclaration(this.parent),
  );
}

// Helper functions
function isCommonException(value) {
  const exceptions = [
    /^[0-1]$/, // Allow 0 and 1
    /^[a-z]$/i, // Single letters
    /^\s*$/, // Whitespace-only
    /^[{}()[]<>]+$/, // Common brackets
  ];
  return exceptions.some((regex) => regex.test(String(value)));
}

function isConstantDeclaration(node) {
  return node?.type === "VariableDeclarator" && node.parent?.kind === "const";
}

function checkActionsHardCodedValues(options) {
  const { actions } = options || [];
  return executeCheck("checkActionsHardCodedValues", (callback) => {
    const actionsList = _.isArray(actions) ? actions : actions.actions;
    const reports = [];
    if (_.isEmpty(actionsList)) {
      return callback(reports);
    }
    for (const action of actionsList) {
      var actionName = action.name.concat(
        ` (${action.supported_triggers[0].id})`,
      );
      try {
        var report = detectHardcodedValues(action.code, actionName);
        if (report.length === 0) {
          console.log("Stage1")
          continue; 
        }
        if (report.length > 0) {
          console.log("Stage2")
          reports.push({ name: actionName, report: report });
        }
      } catch (e) {
        if (e instanceof SyntaxError) {
          console.error(`[CHECK ERROR] Skipping malformed Actions: ${actionName}`);
          continue; // Skip to the next action in the loop
        }
        throw e; 
      }
    }
    console.log("Stage3")
    return callback(reports);
  });
}

module.exports = checkActionsHardCodedValues;

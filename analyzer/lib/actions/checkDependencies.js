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
const { getActionDependencies } = require("../../tools/helpers");
const CONSTANTS = require("../constants");

async function checkDependencies(options) {
  const { actions } = options || [];
  return executeCheck("checkDependencies", async (callback) => {
    const report = [];
    if (_.isEmpty(actions)) {
      return callback(report);
    }
    const actionsList = _.isArray(actions) ? actions : actions.actions;
    if (_.isEmpty(actionsList)) {
      return callback(report);
    }
    var actionDependencyVulnList = await getActionDependencies(actionsList);
    for (let i = 0; i < actionDependencyVulnList.length; i++) {
      var actionDependencyVuln = actionDependencyVulnList[i];

      if (!_.isEmpty(actionDependencyVulnList[i])) {
        const vulnFindings = actionDependencyVuln.vulnFindings.filter(
          (item) => item.severity === "high" || item.severity === "critical",
        );
        if (vulnFindings.length > 0) {
          report.push({
            name: actionDependencyVuln.actionName.concat(
              ` (${actionDependencyVuln.trigger}-action)`,
            ),
            field: "dependency_with_vuln",
            status: CONSTANTS.FAIL,
            vulnFindings: vulnFindings,
            value:
              actionDependencyVuln.name +
              " version " +
              actionDependencyVuln.version,
          });
        }
      }
    }
    return callback(report);
  });
}

module.exports = checkDependencies;

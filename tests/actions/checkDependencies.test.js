const { expect } = require("chai");
const checkDependencies = require("../../analyzer/lib/actions/checkDependencies");
const CONSTANTS = require("../../analyzer/lib/constants");

// Directly mock the getActionDependencies function
describe("checkDependencies", function () {
  let originalGetActionDependencies;

  // Save the original method to restore after each test
  beforeEach(function () {
    // Mock the getActionDependencies function
    originalGetActionDependencies =
      require("../../analyzer/tools/helpers").getActionDependencies;
  });

  afterEach(function () {
    // Restore the original function after each test
    require("../../analyzer/tools/helpers").getActionDependencies =
      originalGetActionDependencies;
  });

  it("should return an empty report if no actions are provided", async function () {
    const callback = (report) => {
      // Assert that the report is empty
      expect(report).to.be.an("array").that.is.empty;
    };
    await checkDependencies({ actions: [] }, callback);
  });

  it("should return an empty report if actions list is empty", async function () {
    const callback = (report) => {
      // Assert that the report is empty
      expect(report).to.be.an("array").that.is.empty;
    };
    await checkDependencies({ actions: { actions: [] } }, callback);
  });

  it("should return a report with dependency vulnerabilities when high or critical vulnerabilities are found", async function () {
    // Mocking the getActionDependencies to simulate vulnerabilities in dependencies
    require("../../analyzer/tools/auth0").getActionDependencies = async () => [
      {
        actionName: "Custom Phone Provider",
        trigger: "custom-phone-provider",
        vulnFindings: [
          { severity: "high", name: "aws-sdk", version: "2.1448.0" },
          { severity: "low", name: "lodash", version: "4.17.21" },
        ],
      },
    ];

    const callback = (report) => {
      expect(report.details).to.have.lengthOf(1);
      expect(report.details[0]).to.deep.equal({
        name: "Custom Phone Provider (custom-phone-provider-action)",
        field: "dependency_with_vuln",
        status: CONSTANTS.FAIL,
        value: "aws-sdk version 2.1448.0",
      });
    };

    await checkDependencies(
      {
        actions: {
          actions: [
            {
              id: "0cdb84c6",
              name: "Custom Phone Provider",
              dependencies: [
                {
                  name: "aws-sdk",
                  version: "2.1448.0",
                },
              ],
              supported_triggers: [
                {
                  id: "custom-phone-provider",
                  version: "v1",
                },
              ],
            },
          ],
        },
      },
      callback,
    );
  });

  it("should not return any vulnerabilities if no high or critical vulnerabilities are found", async function () {
    // Mocking the getActionDependencies to simulate no critical or high vulnerabilities
    require("../../analyzer/tools/auth0").getActionDependencies = async () => [
      {
        actionName: "Console Log",
        trigger: "post-login",
        vulnFindings: [
          { severity: "low", name: "aws-sdk", version: "2.1448.0" },
        ],
      },
    ];

    const callback = (report) => {
      // The report should be empty (no high/critical vulnerabilities)
      expect(report.details).to.be.an("array").that.is.empty;
    };

    await checkDependencies(
      {
        actions: {
          actions: [
            {
              id: "89df9e29",
              name: "Console Log",
              dependencies: [
                {
                  name: "aws-sdk",
                  version: "2.1448.0",
                },
              ],
              supported_triggers: [
                {
                  id: "post-login",
                  version: "v1",
                },
              ],
            },
          ],
        },
      },
      callback,
    );
  });
});

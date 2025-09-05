const chai = require("chai");
const expect = chai.expect;
const checkActionsHardCodedValues = require("../../analyzer/lib/actions/checkActionsHardCodedValues"); // Import your function
const CONSTANTS = require("../../analyzer/lib/constants"); // Assuming constants file is required

describe("checkActionsHardCodedValues", function () {
  it("should return an empty array when no actions have hardcoded values", async function () {
    const input = {
      actions: {
        actions: [
          {
            id: "0cdb84c6-9faf-4344-b1c5-affa9db5a63f",
            name: "Custom Phone Provider",
            supported_triggers: [
              { id: "custom-phone-provider", version: "v1" },
            ],
            created_at: "2024-12-05T03:14:55.811465959Z",
            updated_at: "2024-12-05T03:14:55.831277001Z",
            code: "exports.onExecuteCustomPhoneProvider = async (event, api) => {\n  // Code goes here\n  return;\n};",
            dependencies: [],
            runtime: "node18",
            status: "built",
            secrets: [],
            all_changes_deployed: false,
          },
        ],
      },
    };

    const reports = await checkActionsHardCodedValues(input);
    expect(reports.details).to.be.an("array").that.is.empty;
  });

  it("should detect hardcoded values in action code", async function () {
    const input = {
      actions: {
        actions: [
          {
            id: "89df9e29-d521-43f4-9b80-8a8f9623ad39",
            name: "Console Log",
            supported_triggers: [{ id: "post-login", version: "v3" }],
            created_at: "2024-12-05T03:48:52.546705182Z",
            updated_at: "2025-02-05T04:33:20.935611754Z",
            code: 'exports.onExecutePostLogin = async (event, api) => {\n  const PASSWORD = "abcd1234";\n  console.log(JSON.stringify(event.user, null, 2));\n};',
            dependencies: [{ name: "aws-sdk", version: "2.1448.0" }],
            runtime: "node18-actions",
            status: "built",
            secrets: [],
            all_changes_deployed: true,
          },
        ],
        total: 1,
      },
    };

    const reports = await checkActionsHardCodedValues(input);
    expect(reports.details).to.have.lengthOf(1);
    const report = reports.details[0];
    expect(report.name).to.equal("Console Log (post-login)");
    expect(report.report).to.have.lengthOf(1);
    expect(report.report[0].variableName).to.equal("PASSWORD");
    expect(report.report[0].type).to.equal("string");
    expect(report.report[0].field).to.equal("hard_coded_value_detected");
    expect(report.report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("should flag multiple hardcoded values in action code", async function () {
    const input = {
      actions: {
        actions: [
          {
            id: "0cdb84c6-9faf-4344-b1c5-affa9db5a63f",
            name: "Custom Phone Provider",
            supported_triggers: [
              { id: "custom-phone-provider", version: "v1" },
            ],
            created_at: "2024-12-05T03:14:55.811465959Z",
            updated_at: "2024-12-05T03:14:55.831277001Z",
            code: 'exports.onExecuteCustomPhoneProvider = async (event, api) => {\n  const PHONE_NUMBER = "123-456-7890";\n  const USERNAME = "user123";\n  return;\n};',
            dependencies: [],
            runtime: "node18",
            status: "built",
            secrets: [],
            all_changes_deployed: false,
          },
        ],
        total: 1,
      },
    };

    const reports = await checkActionsHardCodedValues(input);
    expect(reports.details).to.have.lengthOf(1);
    const report = reports.details[0];
    expect(report.name).to.equal(
      "Custom Phone Provider (custom-phone-provider)",
    );
    expect(report.report).to.have.lengthOf(2);

    // Check for each of the hardcoded values
    expect(report.report[0].variableName).to.equal("PHONE_NUMBER");
    expect(report.report[0].type).to.equal("string");

    expect(report.report[1].variableName).to.equal("USERNAME");
    expect(report.report[1].type).to.equal("string");
  });
});

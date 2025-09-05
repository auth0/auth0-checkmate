const chai = require("chai");
const expect = chai.expect;

const checkActionsRuntime = require("../../analyzer/lib/actions/checkActionsRuntime");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkActionsRuntime", function () {
  it("should not return a report when no actions are provided", function () {
    const options = {};

    checkActionsRuntime(options, (report) => {
      expect(report).to.deep.equal([]);
    });
  });

  it("should return a failure report for actions with outdated Node.js versions", function () {
    const options = {
      actions: {
        actions: [
          {
            id: "0cdb84c6-9faf-4344-b1c5-affa9db5a63f",
            name: "Custom Phone Provider",
            runtime: "node16", // Outdated version
            supported_triggers: [
              { id: "custom-phone-provider", version: "v1" },
            ],
          },
          {
            id: "89df9e29-d521-43f4-9b80-8a8f9623ad39",
            name: "Console Log",
            runtime: "node22", // Valid version
            supported_triggers: [{ id: "post-login", version: "v3" }],
          },
        ],
      },
    };

    checkActionsRuntime(options, (report) => {
      expect(report).to.deep.equal([
        {
          name: "Custom Phone Provider (custom-phone-provider)",
          field: "old_node_version",
          status: CONSTANTS.FAIL,
          value: 16,
        },
      ]);
    });
  });

  it("should not return a report for actions with valid Node.js versions", function () {
    const options = {
      actions: {
        actions: [
          {
            id: "0cdb84c6-9faf-4344-b1c5-affa9db5a63f",
            name: "Custom Phone Provider",
            runtime: "node22", // Valid version
            supported_triggers: [
              { id: "custom-phone-provider", version: "v1" },
            ],
          },
          {
            id: "89df9e29-d521-43f4-9b80-8a8f9623ad39",
            name: "Console Log",
            runtime: "node22", // Valid version
            supported_triggers: [{ id: "post-login", version: "v3" }],
          },
        ],
      },
    };

    checkActionsRuntime(options, (report) => {
      expect(report).to.deep.equal([]);
    });
  });

  it("should return a failure report for actions with outdated Node.js versions and correct trigger names", function () {
    const options = {
      actions: {
        actions: [
          {
            id: "7d24512b-aa56-4ddc-8b51-68583110c5fa",
            name: "action example 1",
            runtime: "node17", // Outdated version
            supported_triggers: [{ id: "post-login", version: "v3" }],
          },
        ],
      },
    };

    checkActionsRuntime(options, (report) => {
      expect(report).to.deep.equal([
        {
          name: "action example 1 (post-login)",
          field: "old_node_version",
          status: CONSTANTS.FAIL,
          value: 17,
        },
      ]);
    });
  });
});

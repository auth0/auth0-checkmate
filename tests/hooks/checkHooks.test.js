const chai = require("chai");
const expect = chai.expect;

const checkHooks = require("../../analyzer/lib/hooks/checkHooks");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkHooks", function () {
  it("should return success when no hooks are provided", function () {
    const options = {};

    checkHooks(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "no_enabled_hooks",
          status: CONSTANTS.SUCCESS,
        },
      ]);
    });
  });

  it("should return fail for an enabled hook", function () {
    const options = {
      hooks: [
        {
          id: "test",
          name: "test",
          script: "",
          dependencies: {},
          enabled: true,
          triggerId: "post-user-registration",
        },
      ],
    };

    checkHooks(options, (report) => {
      expect(report).to.deep.equal([
        {
          name: "test",
          value: "post-user-registration",
          field: "enabled_hooks",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return success for a disabled hook", function () {
    const options = {
      hooks: [
        {
          id: "test",
          name: "test",
          script: "",
          dependencies: {},
          enabled: false,
          triggerId: "post-user-registration",
        },
      ],
    };

    checkHooks(options, (report) => {
      expect(report).to.deep.equal([
        {
          name: "test",
          value: "post-user-registration",
          field: "enabled_hooks",
          status: CONSTANTS.SUCCESS,
        },
      ]);
    });
  });

  it("should handle multiple hooks with mixed enabled/disabled states", function () {
    const options = {
      hooks: [
        {
          id: "test1",
          name: "test1",
          script: "",
          dependencies: {},
          enabled: true,
          triggerId: "post-user-registration",
        },
        {
          id: "test2",
          name: "test2",
          script: "",
          dependencies: {},
          enabled: false,
          triggerId: "pre-user-registration",
        },
      ],
    };

    checkHooks(options, (report) => {
      expect(report).to.deep.equal([
        {
          name: "test1",
          value: "post-user-registration",
          field: "enabled_hooks",
          status: CONSTANTS.FAIL,
        },
        {
          name: "test2",
          value: "pre-user-registration",
          field: "enabled_hooks",
          status: CONSTANTS.SUCCESS,
        },
      ]);
    });
  });
});

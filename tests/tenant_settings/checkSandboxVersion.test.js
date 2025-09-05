const chai = require("chai");
const expect = chai.expect;

const checkSandboxVersion = require("../../analyzer/lib/tenant_settings/checkSandboxVersion");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkSandboxVersion", function () {
  it("should return a failure report for sandbox version below minimum required version", function () {
    const options = {
      tenant: {
        sandbox_version: "16", // Below the minimum required version
      },
    };

    checkSandboxVersion(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "sandbox_version",
          attr: "sandbox_version",
          value: 16,
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should not return a report for sandbox version equal to or above the minimum required version", function () {
    const options = {
      tenant: {
        sandbox_version: "18", // Minimum required version
      },
    };

    checkSandboxVersion(options, (report) => {
      expect(report).to.deep.equal([]);
    });
  });

  it("should not return a report for sandbox version above the minimum required version", function () {
    const options = {
      tenant: {
        sandbox_version: "22", // Above the minimum required version
      },
    };

    checkSandboxVersion(options, (report) => {
      expect(report).to.deep.equal([]);
    });
  });
});

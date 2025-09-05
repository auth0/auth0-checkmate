const chai = require("chai");
const expect = chai.expect;

const checkDefaultDirectory = require("../../analyzer/lib/tenant_settings/checkDefaultDirectory");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkDefaultDirectory", function () {
  it("should return an info report when default_directory is not set (null or empty)", function () {
    const options = {
      tenant: {
        default_directory: null, // default_directory is null
      },
    };

    checkDefaultDirectory(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "no_default_directory",
          attr: "default_directory",
          status: CONSTANTS.INFO,
        },
      ]);
    });
  });

  it("should return an info report when default_directory is an empty string", function () {
    const options = {
      tenant: {
        default_directory: "", // default_directory is an empty string
      },
    };

    checkDefaultDirectory(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "no_default_directory",
          attr: "default_directory",
          status: CONSTANTS.INFO,
        },
      ]);
    });
  });

  it("should return an info report when default_directory is set to a non-empty value", function () {
    const options = {
      tenant: {
        default_directory: "my-directory", // default_directory is set to a non-empty string
      },
    };

    checkDefaultDirectory(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "default_directory",
          attr: "default_directory",
          value: "my-directory",
          status: CONSTANTS.INFO,
        },
      ]);
    });
  });
});

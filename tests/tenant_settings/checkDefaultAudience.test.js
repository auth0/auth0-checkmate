const chai = require("chai");
const expect = chai.expect;

const checkDefaultAudience = require("../../analyzer/lib/tenant_settings/checkDefaultAudience");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkDefaultAudience", function () {
  it("should return an info report when default_audience is not set (null or empty)", function () {
    const options = {
      tenant: {
        default_audience: null, // default_audience is null
      },
    };

    checkDefaultAudience(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "no_default_audience",
          attr: "default_audience",
          status: CONSTANTS.INFO,
        },
      ]);
    });
  });

  it("should return an info report when default_audience is an empty string", function () {
    const options = {
      tenant: {
        default_audience: "", // default_audience is an empty string
      },
    };

    checkDefaultAudience(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "no_default_audience",
          attr: "default_audience",
          status: CONSTANTS.INFO,
        },
      ]);
    });
  });

  it("should return a fail report when default_audience is set to a non-empty value", function () {
    const options = {
      tenant: {
        default_audience: "audience1", // default_audience is set to a non-empty string
      },
    };

    checkDefaultAudience(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "default_audience",
          attr: "default_audience",
          value: "audience1",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });
});

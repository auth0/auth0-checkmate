const chai = require("chai");
const expect = chai.expect;

const checkSupportUrl = require("../../analyzer/lib/tenant_settings/checkSupportUrl");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkSupportUrl", function () {
  it("should return a fail report when tenant is missing or empty", function () {
    const options = {
      tenant: {}, // Empty tenant object
    };

    checkSupportUrl(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "tenant_setting_missing",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return a success report when support_url is provided", function () {
    const options = {
      tenant: {
        support_url: "https://support.contoso.com", // support_url is provided
      },
    };

    checkSupportUrl(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "support_url",
          attr: "support_url",
          value: "https://support.contoso.com",
          status: CONSTANTS.SUCCESS,
        },
      ]);
    });
  });

  it("should return a fail report when support_url is not provided (empty string)", function () {
    const options = {
      tenant: {
        support_url: "", // support_url is an empty string
      },
    };

    checkSupportUrl(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "no_support_url",
          attr: "support_url",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return a fail report when support_url is not provided (null)", function () {
    const options = {
      tenant: {
        support_url: null, // support_url is null
      },
    };

    checkSupportUrl(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "no_support_url",
          attr: "support_url",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });
});

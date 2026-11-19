const chai = require("chai");
const expect = chai.expect;

const checkSupportEmail = require("../../analyzer/lib/tenant_settings/checkSupportEmail");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkSupportEmail", function () {
  it("should return a fail report when tenant is missing or empty", async function () {
    const options = {
      tenant: {}, // Empty tenant object
    };

    const { details: report } = await checkSupportEmail(options);
    expect(report).to.deep.equal([
      {
        field: "tenant_setting_missing",
        status: CONSTANTS.FAIL,
      },
    ]);
  });

  it("should return a success report when support_email is provided", async function () {
    const options = {
      tenant: {
        support_email: "support@contoso.com", // support_email is provided
      },
    };

    const { details: report } = await checkSupportEmail(options);
    expect(report).to.deep.equal([
      {
        field: "support_email",
        attr: "support_email",
        value: "support@contoso.com",
        status: CONSTANTS.SUCCESS,
      },
    ]);
  });

  it("should return a fail report when support_email is not provided (empty string)", async function () {
    const options = {
      tenant: {
        support_email: "", // support_email is an empty string
      },
    };

    const { details: report } = await checkSupportEmail(options);
    expect(report).to.deep.equal([
      {
        field: "no_support_email",
        attr: "support_email",
        status: CONSTANTS.FAIL,
      },
    ]);
  });

  it("should return a fail report when support_email is not provided (null)", async function () {
    const options = {
      tenant: {
        support_email: null, // support_email is null
      },
    };

    const { details: report } = await checkSupportEmail(options);
    expect(report).to.deep.equal([
      {
        field: "no_support_email",
        attr: "support_email",
        status: CONSTANTS.FAIL,
      },
    ]);
  });
});

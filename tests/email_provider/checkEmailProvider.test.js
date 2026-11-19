const chai = require("chai");
const expect = chai.expect;

const checkEmailProvider = require("../../analyzer/lib/email_provider/checkEmailProvider");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkEmailProvider", function () {
  it("should return fail when no email provider is provided", async function () {
    const options = {};

    const { details: report } = await checkEmailProvider(options);
    expect(report).to.deep.equal([
      {
        field: "email_provider_not_configured",
        status: CONSTANTS.FAIL,
      },
    ]);
  });

  it("should return success for an enabled email provider", async function () {
    const options = {
      emailProvider: {
        name: "sendgrid",
        enabled: true,
      },
    };

    const { details: report } = await checkEmailProvider(options);
    expect(report).to.deep.equal([
      {
        field: "email_provider_enabled",
        status: CONSTANTS.SUCCESS,
        value: "sendgrid",
      },
    ]);
  });

  it("should return fail for a disabled email provider", async function () {
    const options = {
      emailProvider: {
        name: "sendgrid",
        enabled: false,
      },
    };

    const { details: report } = await checkEmailProvider(options);
    expect(report).to.deep.equal([
      {
        field: "email_provider_disabled",
        status: CONSTANTS.FAIL,
        value: "sendgrid",
      },
    ]);
  });
});

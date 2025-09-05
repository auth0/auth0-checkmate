const chai = require("chai");
const expect = chai.expect;

const checkEmailProvider = require("../../analyzer/lib/email_provider/checkEmailProvider");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkEmailProvider", function () {
  it("should return fail when no email provider is provided", function () {
    const options = {};

    checkEmailProvider(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "email_provider_not_configured",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return success for an enabled email provider", function () {
    const options = {
      emailProvider: {
        name: "sendgrid",
        enabled: true,
      },
    };

    checkEmailProvider(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "email_provider_enabled",
          status: CONSTANTS.SUCCESS,
          value: "sendgrid",
        },
      ]);
    });
  });

  it("should return fail for a disabled email provider", function () {
    const options = {
      emailProvider: {
        name: "sendgrid",
        enabled: false,
      },
    };

    checkEmailProvider(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "email_provider_disabled",
          status: CONSTANTS.FAIL,
          value: "sendgrid",
        },
      ]);
    });
  });
});

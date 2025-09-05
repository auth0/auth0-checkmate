const chai = require("chai");
const expect = chai.expect;

const checkEmailTemplates = require("../../analyzer/lib/email_templates/checkEmailTemplates");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkEmailTemplates", function () {
  it("should return fail when no email templates are provided", function () {
    const options = {};

    checkEmailTemplates(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "email_templates_not_configured",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return fail for email templates without configuration", function () {
    const options = {
      emailTemplates: [
        {
          name: "Verification Email (Link)",
          template: { template: "verify_email", enabled: true },
        },
        { name: "Verification Email (Code)", template: null },
        { name: "Welcome Email", template: null },
      ],
    };

    checkEmailTemplates(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "email_template_enabled",
          status: CONSTANTS.SUCCESS,
          attr: "verify_email",
          value: "verify_email",
        },
        {
          field: "email_template_not_configured",
          status: CONSTANTS.FAIL,
          attr: "Verification Email (Code)",
          value: "Verification Email (Code)",
        },
        {
          field: "email_template_not_configured",
          status: CONSTANTS.FAIL,
          attr: "Welcome Email",
          value: "Welcome Email",
        },
      ]);
    });
  });

  it("should return success for enabled email templates", function () {
    const options = {
      emailTemplates: [
        {
          name: "Verification Email (Link)",
          template: { template: "verify_email", enabled: true },
        },
        {
          name: "Verification Email (Code)",
          template: { template: "verify_code", enabled: true },
        },
      ],
    };

    checkEmailTemplates(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "email_template_enabled",
          status: CONSTANTS.SUCCESS,
          attr: "verify_email",
          value: "verify_email",
        },
        {
          field: "email_template_enabled",
          status: CONSTANTS.SUCCESS,
          attr: "verify_code",
          value: "verify_code",
        },
      ]);
    });
  });

  it("should return fail for disabled email templates", function () {
    const options = {
      emailTemplates: [
        {
          name: "Verification Email (Link)",
          template: { template: "verify_email", enabled: false },
        },
        {
          name: "Verification Email (Code)",
          template: { template: "verify_code", enabled: false },
        },
      ],
    };

    checkEmailTemplates(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "email_template_not_enabled",
          status: CONSTANTS.FAIL,
          attr: "Verification Email (Link)",
          value: "Verification Email (Link)",
        },
        {
          field: "email_template_not_enabled",
          status: CONSTANTS.FAIL,
          attr: "Verification Email (Code)",
          value: "Verification Email (Code)",
        },
      ]);
    });
  });
});

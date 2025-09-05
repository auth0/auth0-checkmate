const chai = require("chai");
const expect = chai.expect;

const customDomainConfigured = require("../../analyzer/lib/custom_domain/checkCustomDomain"); // Adjust the path accordingly
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkCustomDomain", function () {
  it("should return fail when customDomains is empty", function () {
    const options = { customDomains: [] };

    customDomainConfigured(options, (report) => {
      expect(report.checkName).to.equal("checkCustomDomain");
      expect(report.result).to.equal("fail");
      expect(report.timestamp).to.be.ok;
      expect(report.details).to.deep.equal([
        {
          field: "not_configured",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return success when a domain is ready", function () {
    const options = {
      customDomains: [
        {
          domain: "apac-tam-team.oauth101.net",
          primary: true,
          status: "ready",
          tls_policy: "recommended",
          type: "auth0_managed_certs",
          verification: {},
        },
      ],
    };

    customDomainConfigured(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "ready",
          status: CONSTANTS.SUCCESS,
          value: "auth.contoso.com",
        },
      ]);
    });
  });

  it("should return fail when a domain is pending verification", function () {
    const options = {
      customDomains: [
        {
          domain: "auth.contoso.com",
          primary: true,
          status: "pending_verification",
          tls_policy: "recommended",
          type: "auth0_managed_certs",
          verification: {},
        },
      ],
    };

    customDomainConfigured(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "pending_verification",
          status: CONSTANTS.FAIL,
          value: "auth.contoso.com",
        },
      ]);
    });
  });
});

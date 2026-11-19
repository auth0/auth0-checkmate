const chai = require("chai");
const expect = chai.expect;

const customDomainConfigured = require("../../analyzer/lib/custom_domain/checkCustomDomain"); // Adjust the path accordingly
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkCustomDomain", function () {
  it("should return fail when customDomains is empty", async function () {
    const options = { customDomains: [] };

    const result = await customDomainConfigured(options);
    expect(result.checkName).to.equal("checkCustomDomain");
    expect(result.timestamp).to.be.ok;
    expect(result.details).to.deep.equal([
      {
        field: "not_configured",
        status: CONSTANTS.FAIL,
      },
    ]);
  });

  it("should return success when a domain is ready", async function () {
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

    const { details: report } = await customDomainConfigured(options);
    expect(report).to.deep.equal([
      {
        field: "ready",
        status: CONSTANTS.SUCCESS,
        value: "apac-tam-team.oauth101.net",
      },
    ]);
  });

  it("should return fail when a domain is pending verification", async function () {
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

    const { details: report } = await customDomainConfigured(options);
    expect(report).to.deep.equal([
      {
        field: "pending_verification",
        status: CONSTANTS.FAIL,
        value: "auth.contoso.com",
      },
    ]);
  });
});

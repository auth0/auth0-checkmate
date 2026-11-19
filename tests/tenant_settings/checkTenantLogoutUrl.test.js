const chai = require("chai");
const expect = chai.expect;

const checkTenantLogoutUrl = require("../../analyzer/lib/tenant_settings/checkTenantLogoutUrl");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkTenantLogoutUrl", function () {
  it("should return a fail report when allowed_logout_urls is empty", async function () {
    const options = {
      tenant: {
        allowed_logout_urls: [], // Empty logout URLs
      },
    };

    const { details: report } = await checkTenantLogoutUrl(options);
    expect(report).to.deep.equal([
      {
        field: "missing_allowed_logout_urls",
        attr: "allowed_logout_urls",
        value: "[]",
        status: CONSTANTS.FAIL,
      },
    ]);
  });

  it("should return a fail report when allowed_logout_urls contains an insecure URL (localhost)", async function () {
    const options = {
      tenant: {
        allowed_logout_urls: ["http://localhost"], // Insecure URL
      },
    };

    const { details: report } = await checkTenantLogoutUrl(options);
    expect(report).to.deep.equal([
      {
        field: "invalid_allowed_logout_urls",
        attr: "allowed_logout_urls",
        value: "http://localhost",
        status: CONSTANTS.FAIL,
      },
    ]);
  });

  it("should return a fail report when allowed_logout_urls contains an insecure URL (http://)", async function () {
    const options = {
      tenant: {
        allowed_logout_urls: ["http://example.com"], // Insecure URL
      },
    };

    const { details: report } = await checkTenantLogoutUrl(options);
    expect(report).to.deep.equal([
      {
        field: "invalid_allowed_logout_urls",
        attr: "allowed_logout_urls",
        value: "http://example.com",
        status: CONSTANTS.FAIL,
      },
    ]);
  });

  it("should return a success report when allowed_logout_urls contains a secure URL", async function () {
    const options = {
      tenant: {
        allowed_logout_urls: ["https://contoso.com"], // Secure URL
      },
    };

    const { details: report } = await checkTenantLogoutUrl(options);
    expect(report).to.deep.equal([]); // Secure URLs are not reported at tenant level
  });

  it("should return both fail and success reports when allowed_logout_urls contains both secure and insecure URLs", async function () {
    const options = {
      tenant: {
        allowed_logout_urls: ["http://localhost", "https://contoso.com"], // Mix of insecure and secure URLs
      },
    };

    const { details: report } = await checkTenantLogoutUrl(options);
    expect(report).to.deep.equal([
      {
        field: "invalid_allowed_logout_urls",
        attr: "allowed_logout_urls",
        value: "http://localhost",
        status: CONSTANTS.FAIL,
      },
    ]); // Secure URLs are not reported at tenant level
  });
});

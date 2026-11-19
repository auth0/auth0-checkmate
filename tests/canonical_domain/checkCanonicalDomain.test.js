const chai = require("chai");
const expect = chai.expect;
const checkCanonicalDomain = require("../../analyzer/lib/canonical_domain/checkCanonicalDomain");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkCanonicalDomain", function () {
  it("should add the hostname to report if logs are not empty but customDomains is empty", async function () {
    const options = {
      log_query: "query",
      customDomains: [], // Empty customDomains
      logs: [
        {
          type: "s",
          hostname: "contoso.us.auth0.com",
          _id: "90020250210004837491441000000000000001223372036874609060",
        },
      ],
    };

    const { details: report } = await checkCanonicalDomain(options);
    // Check that the report contains the hostname from logs
    expect(report).to.have.lengthOf(1);
    expect(report[0].field).to.equal("canonical_domain_used");
    expect(report[0].value).to.equal(
      "<br> query <br> log_id: 90020250210004837491441000000000000001223372036874609060",
    );
    expect(report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("should add the hostname to report if no match is found in customDomains", async function () {
    const options = {
      log_query: "query",
      customDomains: [
        {
          domain: "different.com",
          primary: true,
          status: "ready",
          tls_policy: "recommended",
          type: "auth0_managed_certs",
          verification: {},
        },
      ], // Custom domain is different
      logs: [
        {
          type: "s",
          hostname: "contoso.us.auth0.com",
          _id: "90020250210004837491441000000000000001223372036874609060",
        },
      ],
    };

    const { details: report } = await checkCanonicalDomain(options);
    // Check that the report contains the hostname from logs because there is no match
    expect(report).to.have.lengthOf(1);
    expect(report[0].field).to.equal("canonical_domain_used");
    expect(report[0].value).to.equal(
      "<br> query <br> log_id: 90020250210004837491441000000000000001223372036874609060",
    );
    expect(report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("should return a no-logs failure if logs are empty", async function () {
    const options = {
      log_query: "query",
      customDomains: [
        {
          domain: "contoso.com",
          primary: true,
          status: "ready",
          tls_policy: "recommended",
          type: "auth0_managed_certs",
          verification: {},
        },
      ],
      logs: [], // No logs
    };

    const { details: report } = await checkCanonicalDomain(options);
    expect(report).to.deep.equal([
      {
        field: "canonical_domain_no_logs",
        value: "<br> query",
        status: CONSTANTS.FAIL,
      },
    ]);
  });

  it("should return a no-logs failure if customDomains are empty and no logs exist", async function () {
    const options = {
      log_query: "query",
      customDomains: [], // No custom domains
      logs: [], // No logs
    };

    const { details: report } = await checkCanonicalDomain(options);
    expect(report).to.deep.equal([
      {
        field: "canonical_domain_no_logs",
        value: "<br> query",
        status: CONSTANTS.FAIL,
      },
    ]);
  });
});

const chai = require("chai");
const expect = chai.expect;
const checkCanonicalDomain = require("../../analyzer/lib/canonical_domain/checkCanonicalDomain");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkCanonicalDomain", function () {
  it("should add the hostname to report if logs are not empty but customDomains is empty", function () {
    const options = {
      customDomains: [], // Empty customDomains
      logs: [
        {
          type: "s",
          hostname: "contoso.us.auth0.com",
          _id: "90020250210004837491441000000000000001223372036874609060",
        },
      ],
    };

    checkCanonicalDomain(options, (report) => {
      // Check that the report contains the hostname from logs
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("canonical_domain_used");
      expect(report[0].value).to.equal(
        "log_id: 90020250210004837491441000000000000001223372036874609060",
      );
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
    });
  });

  it("should add the hostname to report if no match is found in customDomains", function () {
    const options = {
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

    checkCanonicalDomain(options, (report) => {
      // Check that the report contains the hostname from logs because there is no match
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("canonical_domain_used");
      expect(report[0].value).to.equal(
        "log_id: 90020250210004837491441000000000000001223372036874609060",
      );
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
    });
  });

  it("should return an empty report if logs are empty", function () {
    const options = {
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

    checkCanonicalDomain(options, (report) => {
      // Check that the report is empty
      expect(report).to.be.an("array").that.is.empty;
    });
  });

  it("should not add anything to the report if customDomains are empty and no logs exist", function () {
    const options = {
      customDomains: [], // No custom domains
      logs: [], // No logs
    };

    checkCanonicalDomain(options, (report) => {
      // Check that the report is empty
      expect(report).to.be.an("array").that.is.empty;
    });
  });
});

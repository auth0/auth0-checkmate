const chai = require("chai");
const expect = chai.expect;

const checkTenantLoginUrl = require("../../analyzer/lib/tenant_settings/checkTenantLoginUrl");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkTenantLoginUrl", function () {
  it("should return a fail report when default_redirection_uri is empty", function () {
    const options = {
      tenant: {
        default_redirection_uri: "", // Empty redirection URI
      },
    };

    checkTenantLoginUrl(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "no_default_redirection_uri",
          attr: "default_redirection_uri",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return a fail report when default_redirection_uri contains an insecure URL (localhost)", function () {
    const options = {
      tenant: {
        default_redirection_uri: "http://localhost", // Insecure URL
      },
    };

    checkTenantLoginUrl(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "invalid_default_redirection_uri",
          attr: "default_redirection_uri",
          value: "http://localhost",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return a fail report when default_redirection_uri contains an insecure URL (http://)", function () {
    const options = {
      tenant: {
        default_redirection_uri: "http://example.com", // Insecure URL
      },
    };

    checkTenantLoginUrl(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "invalid_default_redirection_uri",
          attr: "default_redirection_uri",
          value: "http://example.com",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return a success report when default_redirection_uri contains a secure URL", function () {
    const options = {
      tenant: {
        default_redirection_uri: "https://contoso.com/login", // Secure URL
      },
    };

    checkTenantLoginUrl(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "default_redirection_uri",
          attr: "default_redirection_uri",
          value: "https://contoso.com/login",
          status: CONSTANTS.SUCCESS,
        },
      ]);
    });
  });
});

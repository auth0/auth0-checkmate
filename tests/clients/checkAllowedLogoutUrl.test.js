const chai = require("chai");
const expect = chai.expect;

const checkAllowedLogoutUrl = require("../../analyzer/lib/clients/checkAllowedLogoutUrl");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkAllowedLogoutUrl", function () {
  it("should return an empty report when there are no clients", function () {
    const options = {
      clients: [], // No clients
    };

    checkAllowedLogoutUrl(options, (reports) => {
      expect(reports).to.deep.equal([]); // No reports expected
    });
  });

  it("should return a fail report when client has no allowed logout URLs and app_type is not non_interactive", function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // Not non_interactive
          allowed_logout_urls: [], // No allowed logout URLs
        },
      ],
    };

    checkAllowedLogoutUrl(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "missing_allowed_logout_urls",
              url: "missing_allowed_logout_urls",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return a fail report when client has insecure allowed logout URLs (http://localhost)", function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          allowed_logout_urls: ["http://localhost:3000"], // Insecure logout URL
          app_type: "spa",
        },
      ],
    };

    checkAllowedLogoutUrl(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "insecure_allowed_logout_urls",
              url: "http://localhost:3000",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return a success report when client has secure allowed logout URLs (https://contoso.com)", function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          allowed_logout_urls: ["https://contoso.com"], // Secure logout URL
          app_type: "spa",
        },
      ],
    };

    checkAllowedLogoutUrl(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "secure_allowed_logout_urls",
              status: CONSTANTS.SUCCESS,
              url: "https://contoso.com",
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return both fail and success reports when client has both insecure and secure allowed logout URLs", function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          allowed_logout_urls: ["http://localhost:3000", "https://contoso.com"], // Mix of insecure and secure URLs
          app_type: "spa",
        },
      ],
    };

    checkAllowedLogoutUrl(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "insecure_allowed_logout_urls",
              url: "http://localhost:3000",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
            {
              name: "Test App",
              client_id: "client_id",
              field: "secure_allowed_logout_urls",
              status: CONSTANTS.SUCCESS,
              url: "https://contoso.com",
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });
});

const chai = require("chai");
const expect = chai.expect;

const checkWebOrigins = require("../../analyzer/lib/clients/checkWebOrigins");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkWebOrigins", function () {
  it("should return an empty report when there are no clients", function () {
    const options = {
      clients: [], // No clients
    };

    checkWebOrigins(options, (reports) => {
      expect(reports).to.deep.equal([]); // No reports expected
    });
  });

  it("should return a empty report when client has no web origins URLs and app_type is not non_interactive and native", function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // Not non_interactive
          web_origins: [], // No allowed logout URLs
        },
      ],
    };

    checkWebOrigins(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [],
        },
      ]);
    });
  });

  it("should return a fail report when client has insecure web origin URLs (http://localhost)", function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          web_origins: ["http://localhost:3000"], // Insecure logout URL
          app_type: "spa",
        },
      ],
    };

    checkWebOrigins(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "insecure_web_origins_urls",
              url: "http://localhost:3000",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return a success report when client has secure aweb origin URLs (https://contoso.com)", function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          web_origins: ["https://contoso.com"], // Secure logout URL
          app_type: "spa",
        },
      ],
    };

    checkWebOrigins(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "secure_web_origins_urls",
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
          web_origins: ["http://localhost:3000", "https://contoso.com"], // Mix of insecure and secure URLs
          app_type: "spa",
        },
      ],
    };

    checkWebOrigins(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "insecure_web_originst_urls",
              url: "http://localhost:3000",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
            {
              name: "Test App",
              client_id: "client_id",
              field: "secure_web_originst_urls",
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

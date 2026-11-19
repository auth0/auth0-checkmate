const chai = require("chai");
const expect = chai.expect;

const checkWebOrigins = require("../../analyzer/lib/clients/checkWebOrigins");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkWebOrigins", function () {
  it("should return an empty report when there are no clients", async function () {
    const options = {
      clients: [], // No clients
    };

    const { details: reports } = await checkWebOrigins(options);
    expect(reports).to.deep.equal([]); // No reports expected
  });

  it("should return a empty report when client has no web origins URLs and app_type is not non_interactive and native", async function () {
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

    const { details: reports } = await checkWebOrigins(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App",
            client_id: "client_id",
            field: "secure_web_origins",
            status: CONSTANTS.SUCCESS,
            value: "",
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });

  it("should return a fail report when client has insecure web origin URLs (http://localhost)", async function () {
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

    const { details: reports } = await checkWebOrigins(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App (client_id)",
            client_id: "client_id",
            field: "insecure_web_origins_urls",
            value: "http://localhost:3000",
            status: CONSTANTS.FAIL,
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });

  it("should return a success report when client has secure aweb origin URLs (https://contoso.com)", async function () {
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

    const { details: reports } = await checkWebOrigins(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App",
            client_id: "client_id",
            field: "secure_web_origins",
            status: CONSTANTS.SUCCESS,
            value: "https://contoso.com",
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });

  it("should return both fail and success reports when client has both insecure and secure allowed logout URLs", async function () {
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

    const { details: reports } = await checkWebOrigins(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App (client_id)",
            client_id: "client_id",
            field: "insecure_web_origins_urls",
            value: "http://localhost:3000",
            status: CONSTANTS.FAIL,
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });
});

const chai = require("chai");
const expect = chai.expect;

const checkAllowedCallbacks = require("../../analyzer/lib/clients/checkAllowedCallbacks");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkAllowedCallbacks", function () {
  it("should return an empty report when there are no clients", async function () {
    const options = {
      clients: [], // No clients
    };

    const { details: reports } = await checkAllowedCallbacks(options);
    expect(reports).to.deep.equal([]); // No reports expected
  });

  it("should return a fail report when client has no callbacks and app_type is not non_interactive", async function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // Not non_interactive
          callbacks: [], // No callbacks
        },
      ],
    };

    const { details: reports } = await checkAllowedCallbacks(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App (client_id)",
            client_id: "client_id",
            field: "missing_callbacks",
            url: "",
            status: CONSTANTS.SUCCESS,
            app_type: "spa",
          },
        ],
      },
    ]);
  });

  it("should return a fail report when client has insecure callbacks (http://localhost)", async function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          callbacks: ["http://localhost:3000"], // Insecure callback URL
          app_type: "spa",
        },
      ],
    };

    const { details: reports } = await checkAllowedCallbacks(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App (client_id)",
            client_id: "client_id",
            field: "insecure_callbacks",
            value: "http://localhost:3000",
            status: CONSTANTS.FAIL,
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });

  it("should return a success report when client has secure callbacks (https://contoso.com)", async function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          callbacks: ["https://contoso.com"], // Secure callback URL
          app_type: "spa",
        },
      ],
    };

    const { details: reports } = await checkAllowedCallbacks(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App",
            client_id: "client_id",
            field: "secure_callbacks",
            status: CONSTANTS.SUCCESS,
            value: "https://contoso.com",
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });

  it("should return both fail and success reports when client has both insecure and secure callbacks", async function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          callbacks: ["http://localhost:3000", "https://contoso.com"], // Mix of insecure and secure URLs
          app_type: "spa",
        },
      ],
    };

    const { details: reports } = await checkAllowedCallbacks(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App (client_id)",
            client_id: "client_id",
            field: "insecure_callbacks",
            value: "http://localhost:3000",
            status: CONSTANTS.FAIL,
            app_type: "spa",
            is_first_party: undefined,
          },
          // No success entry: secure URLs are only reported when nothing failed
        ],
      },
    ]);
  });
});

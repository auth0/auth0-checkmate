const chai = require("chai");
const expect = chai.expect;

const checkApplicationLoginUri = require("../../analyzer/lib/clients/checkApplicationLoginUri");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkApplicationLoginUri", function () {
  it("should return an empty report when there are no clients", async function () {
    const options = {
      clients: [], // No clients
    };

    const { details: reports } = await checkApplicationLoginUri(options);
    expect(reports).to.deep.equal([]); // No reports expected
  });

  it("should return a fail report when client has missing initiate_login_uri for spa app type", async function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // spa app type
          initiate_login_uri: "", // Missing initiate_login_uri
        },
      ],
    };

    const { details: reports } = await checkApplicationLoginUri(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App (client_id)",
            client_id: "client_id",
            field: "missing_initiate_login_uri",
            value: "missing_initiate_login_uri",
            status: CONSTANTS.FAIL,
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });

  it("should return a fail report when client has insecure initiate_login_uri containing localhost", async function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // spa app type
          initiate_login_uri: "http://localhost:3000", // Insecure URI (localhost)
        },
      ],
    };

    const { details: reports } = await checkApplicationLoginUri(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App (client_id)",
            client_id: "client_id",
            field: "insecure_initiate_login_uri",
            value: "http://localhost:3000",
            status: CONSTANTS.FAIL,
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });

  it("should return a fail report when client has insecure initiate_login_uri containing http://", async function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // spa app type
          initiate_login_uri: "http://example.com", // Insecure URI (http://)
        },
      ],
    };

    const { details: reports } = await checkApplicationLoginUri(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App (client_id)",
            client_id: "client_id",
            field: "insecure_initiate_login_uri",
            value: "http://example.com",
            status: CONSTANTS.FAIL,
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });

  it("should return a success report when client has a secure initiate_login_uri", async function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // spa app type
          initiate_login_uri: "https://secure-example.com", // Secure URI
        },
      ],
    };

    const { details: reports } = await checkApplicationLoginUri(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App",
            client_id: "client_id",
            field: "secure_initiate_login_uri",
            status: CONSTANTS.SUCCESS,
            value: "https://secure-example.com",
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });

  it("should return both missing and insecure initiate_login_uri reports for a client with both issues", async function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // spa app type
          initiate_login_uri: "http://localhost:3000", // Insecure URI and missing URI issue
        },
      ],
    };

    const { details: reports } = await checkApplicationLoginUri(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          // A non-empty URI cannot also be "missing", so only the insecure issue is reported
          {
            name: "Test App (client_id)",
            client_id: "client_id",
            field: "insecure_initiate_login_uri",
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

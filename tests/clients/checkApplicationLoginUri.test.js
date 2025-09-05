const chai = require("chai");
const expect = chai.expect;

const checkApplicationLoginUri = require("../../analyzer/lib/clients/checkApplicationLoginUri");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkApplicationLoginUri", function () {
  it("should return an empty report when there are no clients", function () {
    const options = {
      clients: [], // No clients
    };

    checkApplicationLoginUri(options, (reports) => {
      expect(reports).to.deep.equal([]); // No reports expected
    });
  });

  it("should return a fail report when client has missing initiate_login_uri for spa app type", function () {
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

    checkApplicationLoginUri(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "missing_initiate_login_uri",
              url: "missing_initiate_login_uri",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return a fail report when client has insecure initiate_login_uri containing localhost", function () {
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

    checkApplicationLoginUri(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "insecure_initiate_login_uri",
              url: "http://localhost:3000",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return a fail report when client has insecure initiate_login_uri containing http://", function () {
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

    checkApplicationLoginUri(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "insecure_initiate_login_uri",
              url: "http://example.com",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return a success report when client has a secure initiate_login_uri", function () {
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

    checkApplicationLoginUri(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "secure_initiate_login_uri",
              status: CONSTANTS.SUCCESS,
              url: "https://secure-example.com",
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return both missing and insecure initiate_login_uri reports for a client with both issues", function () {
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

    checkApplicationLoginUri(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "missing_initiate_login_uri",
              url: "missing_initiate_login_uri",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
            {
              name: "Test App",
              client_id: "client_id",
              field: "insecure_initiate_login_uri",
              url: "http://localhost:3000",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });
});

const chai = require("chai");
const expect = chai.expect;

const checkAllowedCallbacks = require("../../analyzer/lib/clients/checkAllowedCallbacks");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkAllowedCallbacks", function () {
  it("should return an empty report when there are no clients", function () {
    const options = {
      clients: [], // No clients
    };

    checkAllowedCallbacks(options, (reports) => {
      expect(reports).to.deep.equal([]); // No reports expected
    });
  });

  it("should return a fail report when client has no callbacks and app_type is not non_interactive", function () {
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

    checkAllowedCallbacks(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "missing_callbacks",
              url: "",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return a fail report when client has insecure callbacks (http://localhost)", function () {
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

    checkAllowedCallbacks(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "insecure_callbacks",
              url: "http://localhost:3000",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return a success report when client has secure callbacks (https://contoso.com)", function () {
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

    checkAllowedCallbacks(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "secure_callbacks",
              status: CONSTANTS.SUCCESS,
              url: "https://contoso.com",
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return both fail and success reports when client has both insecure and secure callbacks", function () {
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

    checkAllowedCallbacks(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "insecure_callbacks",
              url: "http://localhost:3000",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
            {
              name: "Test App",
              client_id: "client_id",
              field: "secure_callbacks",
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

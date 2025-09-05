const chai = require("chai");
const expect = chai.expect;

const checkGrantTypes = require("../../analyzer/lib/clients/checkGrantTypes");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkGrantTypes", function () {
  it("should return an empty report when there are no clients", function () {
    const options = {
      clients: [], // No clients
    };

    checkGrantTypes(options, (reports) => {
      expect(reports).to.deep.equal([]); // No reports expected
    });
  });

  it("should return a fail report when client has missing grant types for spa app type", function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // spa app type
          grant_types: ["authorization_code"], // Missing refresh_token
        },
      ],
    };

    checkGrantTypes(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "missing_grant_type_for_app_type",
              grant_type: "refresh_token",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return a fail report when client has unexpected grant types for spa app type", function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // spa app type
          grant_types: [
            "authorization_code",
            "implicit",
            "refresh_token",
            "client_credentials",
          ], // Unexpected client_credentials
        },
      ],
    };

    checkGrantTypes(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "unexpected_grant_type_for_app_type",
              grant_type: "client_credentials",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return a success report when client has the correct grant types for spa app type", function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // spa app type
          grant_types: ["authorization_code", "refresh_token"], // Correct grant types for spa
        },
      ],
    };

    checkGrantTypes(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "grant_types_passed",
              status: CONSTANTS.SUCCESS,
              grant_type: "authorization_code, refresh_token",
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });

  it("should return both missing and unexpected grant type reports for a client with both issues", function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // spa app type
          grant_types: ["authorization_code", "client_credentials"], // Missing refresh_token and unexpected client_credentials
        },
      ],
    };

    checkGrantTypes(options, (reports) => {
      expect(reports).to.deep.equal([
        {
          name: "Test App",
          report: [
            {
              name: "Test App",
              client_id: "client_id",
              field: "missing_grant_type_for_app_type",
              grant_type: "refresh_token",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
            {
              name: "Test App",
              client_id: "client_id",
              field: "unexpected_grant_type_for_app_type",
              grant_type: "client_credentials",
              status: CONSTANTS.FAIL,
              app_type: "spa",
            },
          ],
        },
      ]);
    });
  });
});

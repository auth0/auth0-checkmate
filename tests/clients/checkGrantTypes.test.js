const chai = require("chai");
const expect = chai.expect;

const checkGrantTypes = require("../../analyzer/lib/clients/checkGrantTypes");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkGrantTypes", function () {
  it("should return an empty report when there are no clients", async function () {
    const options = {
      clients: [], // No clients
    };

    const { details: reports } = await checkGrantTypes(options);
    expect(reports).to.deep.equal([]); // No reports expected
  });

  it("should return an empty report when client has missing grant types for spa app type", async function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // spa app type
          grant_types: ["authorization_code"], // Missing refresh_token (no longer reported)
        },
      ],
    };

    const { details: reports } = await checkGrantTypes(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [],
      },
    ]);
  });

  it("should return a fail report when client has unexpected grant types for spa app type", async function () {
    const options = {
      clients: [
        {
          name: "Test App",
          client_id: "client_id",
          app_type: "spa", // spa app type
          grant_types: ["authorization_code", "implicit", "refresh_token", "client_credentials"], // implicit and client_credentials are unexpected for spa
        },
      ],
    };

    const { details: reports } = await checkGrantTypes(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App (client_id)",
            client_id: "client_id",
            field: "unexpected_grant_type_for_app_type",
            value: "implicit, client_credentials",
            status: CONSTANTS.FAIL,
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });

  it("should return an empty report when client has the correct grant types for spa app type", async function () {
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

    const { details: reports } = await checkGrantTypes(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [],
      },
    ]);
  });

  it("should only report unexpected grant types for a client with missing and unexpected grant types", async function () {
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

    const { details: reports } = await checkGrantTypes(options);
    expect(reports).to.deep.equal([
      {
        name: "Test App (client_id)",
        report: [
          {
            name: "Test App (client_id)",
            client_id: "client_id",
            field: "unexpected_grant_type_for_app_type",
            value: "client_credentials",
            status: CONSTANTS.FAIL,
            app_type: "spa",
            is_first_party: undefined,
          },
        ],
      },
    ]);
  });
});

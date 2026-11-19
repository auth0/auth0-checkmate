const chai = require("chai");
const expect = chai.expect;
const checkAuthenticationMethods = require("../../analyzer/lib/databases/checkAuthenticationMethods");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkAuthenticationMethods", function () {
  it("should return a failure report when no database connections are found", async function () {
    const options = { databases: [] }; // No databases provided
    const { details: report } = await checkAuthenticationMethods(options);
    expect(report).to.be.an("array").that.has.lengthOf(1);
    expect(report[0]).to.deep.equal({
      field: "no_database_connections_found",
      status: CONSTANTS.FAIL,
    });
  });

  it("should return a failure report when authentication methods are missing", async function () {
    const options = {
      databases: [
        {
          name: "Username-Password-Authentication",
          options: {
            authentication_methods: {},
          },
        },
      ],
    };
    const { details: report } = await checkAuthenticationMethods(options);
    expect(report).to.be.an("array").that.has.lengthOf(1);
    expect(report[0]).to.deep.equal({
      name: "Username-Password-Authentication",
      status: CONSTANTS.FAIL,
      field: "only_password_method",
    });
  });

  it("should return a failure report when password is enabled but passkey is missing", async function () {
    const options = {
      databases: [
        {
          name: "Username-Password-Authentication",
          options: {
            authentication_methods: {
              password: { enabled: true },
              passkey: { enabled: false },
            },
          },
        },
      ],
    };
    const { details: report } = await checkAuthenticationMethods(options);
    expect(report).to.be.an("array").that.has.lengthOf(1);
    expect(report[0]).to.deep.equal({
      name: "Username-Password-Authentication",
      status: CONSTANTS.FAIL,
      field: "only_password_method",
    });
  });

  it("should return a success report when passkey is enabled", async function () {
    const options = {
      databases: [
        {
          name: "Username-Password-Authentication",
          options: {
            authentication_methods: {
              password: { enabled: false },
              passkey: { enabled: true },
            },
          },
        },
      ],
    };
    const { details: report } = await checkAuthenticationMethods(options);
    expect(report).to.be.an("array").that.has.lengthOf(1);
    expect(report[0]).to.deep.equal({
      name: "Username-Password-Authentication",
      status: CONSTANTS.SUCCESS,
      field: "passkey_enabled",
    });
  });

  it("should handle multiple databases correctly", async function () {
    const options = {
      databases: [
        {
          name: "Username-Password-Authentication",
          options: {
            authentication_methods: {
              password: { enabled: true },
              passkey: { enabled: false },
            },
          },
        },
        {
          name: "Another-Authentication",
          options: {
            authentication_methods: {
              password: { enabled: false },
              passkey: { enabled: true },
            },
          },
        },
      ],
    };
    const { details: report } = await checkAuthenticationMethods(options);
    expect(report).to.be.an("array").that.has.lengthOf(2);
    expect(report[0]).to.deep.equal({
      name: "Username-Password-Authentication",
      status: CONSTANTS.FAIL,
      field: "only_password_method",
    });
    expect(report[1]).to.deep.equal({
      name: "Another-Authentication",
      status: CONSTANTS.SUCCESS,
      field: "passkey_enabled",
    });
  });
});

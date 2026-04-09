const chai = require("chai");
const expect = chai.expect;

const checkAPITokenLifetime = require("../../analyzer/lib/resource_servers/checkAPITokenLifetime");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkAPITokenLifetime", function () {
  it("should return an empty report when resourceServers is empty", async function () {
    const options = { resourceServers: [] };

    const result = await checkAPITokenLifetime(options);
    expect(result.details).to.deep.equal([]);
  });

  it("should return an empty report when resourceServers is undefined", async function () {
    const options = { resourceServers: undefined };

    const result = await checkAPITokenLifetime(options);
    expect(result.details).to.deep.equal([]);
  });

  it("should skip system APIs (Auth0 Management API)", async function () {
    const options = {
      resourceServers: [
        {
          id: "system_api",
          name: "Auth0 Management API",
          identifier: "https://tenant.auth0.com/api/v2/",
          is_system: true,
          token_lifetime: 86400,
        },
      ],
    };

    const result = await checkAPITokenLifetime(options);
    expect(result.details).to.deep.equal([]);
  });

  it("should return fail for API with token lifetime >= 7 days", async function () {
    const options = {
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
          token_lifetime: 604800, // 7 days
        },
      ],
    };

    const result = await checkAPITokenLifetime(options);
    const report = result.details[0].report;

    expect(report).to.have.lengthOf(1);
    expect(report[0].field).to.equal("token_lifetime_too_long");
    expect(report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("should return fail for API with token lifetime at maximum (30 days)", async function () {
    const options = {
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
          token_lifetime: 2592000, // 30 days (max)
        },
      ],
    };

    const result = await checkAPITokenLifetime(options);
    const report = result.details[0].report;

    expect(report[0].field).to.equal("token_lifetime_too_long");
    expect(report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("should return warn for API with token lifetime > 24 hours but < 7 days", async function () {
    const options = {
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
          token_lifetime: 172800, // 2 days
        },
      ],
    };

    const result = await checkAPITokenLifetime(options);
    const report = result.details[0].report;

    expect(report).to.have.lengthOf(1);
    expect(report[0].field).to.equal("token_lifetime_extended");
    expect(report[0].status).to.equal(CONSTANTS.WARN);
  });

  it("should return success for API with token lifetime <= 24 hours", async function () {
    const options = {
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
          token_lifetime: 86400, // 24 hours (default)
        },
      ],
    };

    const result = await checkAPITokenLifetime(options);
    const report = result.details[0].report;

    expect(report).to.have.lengthOf(1);
    expect(report[0].field).to.equal("token_lifetime_appropriate");
    expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
  });

  it("should return success for API with short token lifetime (1 hour)", async function () {
    const options = {
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
          token_lifetime: 3600, // 1 hour
        },
      ],
    };

    const result = await checkAPITokenLifetime(options);
    const report = result.details[0].report;

    expect(report[0].field).to.equal("token_lifetime_appropriate");
    expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
  });

  it("should use default token lifetime (24h) when not specified", async function () {
    const options = {
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
        },
      ],
    };

    const result = await checkAPITokenLifetime(options);
    const report = result.details[0].report;

    expect(report[0].field).to.equal("token_lifetime_appropriate");
    expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
    expect(report[0].value).to.include("86400");
  });

  it("should format duration correctly in the value field", async function () {
    const options = {
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
          token_lifetime: 172800, // 2 days
        },
      ],
    };

    const result = await checkAPITokenLifetime(options);
    const report = result.details[0].report;

    expect(report[0].value).to.include("2 days");
    expect(report[0].value).to.include("172800 seconds");
  });
});

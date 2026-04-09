const chai = require("chai");
const expect = chai.expect;

const checkAPISigningAlgorithm = require("../../analyzer/lib/resource_servers/checkAPISigningAlgorithm");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkAPISigningAlgorithm", function () {
  it("should return an empty report when resourceServers is empty", async function () {
    const options = { resourceServers: [] };

    const result = await checkAPISigningAlgorithm(options);
    expect(result.details).to.deep.equal([]);
  });

  it("should return an empty report when resourceServers is undefined", async function () {
    const options = { resourceServers: undefined };

    const result = await checkAPISigningAlgorithm(options);
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
          signing_alg: "RS256",
        },
      ],
    };

    const result = await checkAPISigningAlgorithm(options);
    expect(result.details).to.deep.equal([]);
  });

  it("should return fail for API using HS256 signing algorithm", async function () {
    const options = {
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
          signing_alg: "HS256",
        },
      ],
    };

    const result = await checkAPISigningAlgorithm(options);
    const report = result.details[0].report;

    expect(report).to.have.lengthOf(1);
    expect(report[0].field).to.equal("using_symmetric_alg");
    expect(report[0].status).to.equal(CONSTANTS.FAIL);
    expect(report[0].value).to.equal("HS256");
  });

  it("should return success for API using RS256 signing algorithm", async function () {
    const options = {
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
          signing_alg: "RS256",
        },
      ],
    };

    const result = await checkAPISigningAlgorithm(options);
    const report = result.details[0].report;

    expect(report).to.have.lengthOf(1);
    expect(report[0].field).to.equal("using_asymmetric_alg");
    expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
    expect(report[0].value).to.equal("RS256");
  });

  it("should default to RS256 when signing_alg is not specified", async function () {
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

    const result = await checkAPISigningAlgorithm(options);
    const report = result.details[0].report;

    expect(report[0].field).to.equal("using_asymmetric_alg");
    expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
    expect(report[0].value).to.equal("RS256");
  });

  it("should handle multiple APIs with different signing algorithms", async function () {
    const options = {
      resourceServers: [
        {
          id: "api_1",
          name: "Secure API",
          identifier: "https://secure.api.com",
          is_system: false,
          signing_alg: "RS256",
        },
        {
          id: "api_2",
          name: "Legacy API",
          identifier: "https://legacy.api.com",
          is_system: false,
          signing_alg: "HS256",
        },
      ],
    };

    const result = await checkAPISigningAlgorithm(options);
    expect(result.details).to.have.lengthOf(2);

    const secureApiReport = result.details.find((d) => d.name.includes("Secure API"));
    expect(secureApiReport.report[0].status).to.equal(CONSTANTS.SUCCESS);

    const legacyApiReport = result.details.find((d) => d.name.includes("Legacy API"));
    expect(legacyApiReport.report[0].status).to.equal(CONSTANTS.FAIL);
  });
});

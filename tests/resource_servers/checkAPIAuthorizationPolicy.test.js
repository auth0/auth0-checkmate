const chai = require("chai");
const expect = chai.expect;

const checkAPIAuthorizationPolicy = require("../../analyzer/lib/resource_servers/checkAPIAuthorizationPolicy");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkAPIAuthorizationPolicy", function () {
  it("should return an empty report when resourceServers is empty", async function () {
    const result = await checkAPIAuthorizationPolicy({ resourceServers: [] });
    expect(result.details).to.deep.equal([]);
  });

  it("should return an empty report when resourceServers is undefined", async function () {
    const result = await checkAPIAuthorizationPolicy({
      resourceServers: undefined,
    });
    expect(result.details).to.deep.equal([]);
  });

  it("should skip the system Management API", async function () {
    const result = await checkAPIAuthorizationPolicy({
      resourceServers: [
        {
          id: "system_api",
          name: "Auth0 Management API",
          identifier: "https://tenant.us.auth0.com/api/v2/",
          is_system: true,
          subject_type_authorization: { user: { policy: "allow_all" } },
        },
      ],
    });
    expect(result.details).to.deep.equal([]);
  });

  it("should warn when API user access policy is allow_all", async function () {
    const result = await checkAPIAuthorizationPolicy({
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
          subject_type_authorization: {
            user: { policy: "allow_all" },
            client: { policy: "require_client_grant" },
          },
        },
      ],
    });
    const report = result.details[0].report;
    expect(report).to.have.lengthOf(1);
    expect(report[0].field).to.equal("api_access_unrestricted");
    expect(report[0].status).to.equal(CONSTANTS.WARN);
  });

  it("should warn when the user policy is absent (permissive default)", async function () {
    const result = await checkAPIAuthorizationPolicy({
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
        },
      ],
    });
    expect(result.details[0].report[0].field).to.equal("api_access_unrestricted");
    expect(result.details[0].report[0].status).to.equal(CONSTANTS.WARN);
  });

  it("should pass when the user policy is require_client_grant", async function () {
    const result = await checkAPIAuthorizationPolicy({
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
          subject_type_authorization: {
            user: { policy: "require_client_grant" },
            client: { policy: "require_client_grant" },
          },
        },
      ],
    });
    expect(result.details[0].report[0].field).to.equal("api_access_restricted");
    expect(result.details[0].report[0].status).to.equal(CONSTANTS.SUCCESS);
  });

  it("should handle multiple APIs independently", async function () {
    const result = await checkAPIAuthorizationPolicy({
      resourceServers: [
        {
          id: "api_1",
          name: "Restricted API",
          identifier: "https://restricted.api.com",
          is_system: false,
          subject_type_authorization: { user: { policy: "require_client_grant" } },
        },
        {
          id: "api_2",
          name: "Open API",
          identifier: "https://open.api.com",
          is_system: false,
          subject_type_authorization: { user: { policy: "allow_all" } },
        },
      ],
    });
    expect(result.details).to.have.lengthOf(2);

    const restricted = result.details.find((d) => d.name.includes("Restricted API"));
    expect(restricted.report[0].status).to.equal(CONSTANTS.SUCCESS);

    const open = result.details.find((d) => d.name.includes("Open API"));
    expect(open.report[0].status).to.equal(CONSTANTS.WARN);
  });
});

const chai = require("chai");
const expect = chai.expect;

const checkManagementAPIUserAccess = require("../../analyzer/lib/resource_servers/checkManagementAPIUserAccess");
const CONSTANTS = require("../../analyzer/lib/constants");

const MGMT_IDENTIFIER = "https://tenant.us.auth0.com/api/v2/";

describe("checkManagementAPIUserAccess", function () {
  it("should return an empty report when resourceServers is empty", async function () {
    const result = await checkManagementAPIUserAccess({ resourceServers: [] });
    expect(result.details).to.deep.equal([]);
  });

  it("should return an empty report when resourceServers is undefined", async function () {
    const result = await checkManagementAPIUserAccess({
      resourceServers: undefined,
    });
    expect(result.details).to.deep.equal([]);
  });

  it("should return an empty report when the Management API is not present", async function () {
    const result = await checkManagementAPIUserAccess({
      resourceServers: [
        {
          id: "api_1",
          name: "My API",
          identifier: "https://api.example.com",
          is_system: false,
        },
      ],
    });
    expect(result.details).to.deep.equal([]);
  });

  it("should fail when Management API user access policy is allow_all", async function () {
    const result = await checkManagementAPIUserAccess({
      resourceServers: [
        {
          id: "system_api",
          name: "Auth0 Management API",
          identifier: MGMT_IDENTIFIER,
          is_system: true,
          subject_type_authorization: {
            user: { policy: "allow_all" },
            client: { policy: "require_client_grant" },
          },
        },
      ],
    });
    const report = result.details;
    expect(report).to.have.lengthOf(1);
    expect(report[0].field).to.equal("management_api_user_access_allowed");
    expect(report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("should fail when the user policy is absent (permissive default)", async function () {
    const result = await checkManagementAPIUserAccess({
      resourceServers: [
        {
          id: "system_api",
          name: "Auth0 Management API",
          identifier: MGMT_IDENTIFIER,
          is_system: true,
        },
      ],
    });
    expect(result.details[0].field).to.equal(
      "management_api_user_access_allowed",
    );
    expect(result.details[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("should pass when the user policy is require_client_grant", async function () {
    const result = await checkManagementAPIUserAccess({
      resourceServers: [
        {
          id: "system_api",
          name: "Auth0 Management API",
          identifier: MGMT_IDENTIFIER,
          is_system: true,
          subject_type_authorization: {
            user: { policy: "require_client_grant" },
            client: { policy: "require_client_grant" },
          },
        },
      ],
    });
    expect(result.details[0].field).to.equal(
      "management_api_user_access_restricted",
    );
    expect(result.details[0].status).to.equal(CONSTANTS.SUCCESS);
  });
});

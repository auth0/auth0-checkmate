const { expect } = require("chai");
const checkNetworkACL = require("../../analyzer/lib/network_acl/checkNetworkACL");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkNetworkACL", function () {
  // Happy path - should return populated array with issues found
  it("should return populated array when inactive ACLs are found", async function () {
    const input = {
      networkAcl: [
        {
          acl_id: "acl_pgqBXvEP4qRBohnqxqj2yP",
          active: false,
          description: "Disabled ACL",
        },
      ],
    };

    const result = await checkNetworkACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("network_acl_inactive");
    expect(result.details[0].name).to.equal("Disabled ACL(acl_pgqBXvEP4qRBohnqxqj2yP)");
    expect(result.details[0].status).to.equal(CONSTANTS.FAIL);
  });

  // Sad path - should return empty array when no issues
  it("should return empty array when all ACLs are active", async function () {
    const input = {
      networkAcl: [
        {
          acl_id: "acl_pgqBXvEP4qRBohnqxqj2yP",
          active: true,
          description: "Production ACL",
        },
      ],
    };

    const result = await checkNetworkACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });

  // Edge case - handle null/undefined description gracefully
  it("should handle ACL with null description", async function () {
    const input = {
      networkAcl: [
        {
          acl_id: "acl_456",
          active: false,
          description: null,
        },
      ],
    };

    const result = await checkNetworkACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].name).to.match(/acl_456/);
  });

  // Edge case - insufficient scope
  it("should return empty array when insufficient_scope error", async function () {
    const input = {
      networkAcl: [
        {
          errorCode: "insufficient_scope",
        },
      ],
    };

    const result = await checkNetworkACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });

  // Test case for no network ACL defined
  it("should return proper details when no network ACL is defined", async function () {
    const input = {
      networkAcl: [],
    };

    const result = await checkNetworkACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("no_network_acl");
    expect(result.details[0].name).to.equal("Tenant Access Control List");
    expect(result.details[0].status).to.equal(CONSTANTS.FAIL);
  });
});

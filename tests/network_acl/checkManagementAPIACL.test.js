const { expect } = require("chai");
const checkManagementAPIACL = require("../../analyzer/lib/network_acl/checkManagementAPIACL");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkManagementAPIACL", function () {
  it("should return warning when no management API allowlist is configured", async function () {
    const input = {
      networkAcl: [],
    };

    const result = await checkManagementAPIACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("no_management_api_allowlist");
    expect(result.details[0].status).to.equal(CONSTANTS.WARN);
  });

  it("should return empty array when management API allowlist is configured with IPv4", async function () {
    const input = {
      networkAcl: [
        {
          acl_id: "acl_123",
          active: true,
          description: "Allow management from office",
          rule: {
            match: {
              ipv4_cidrs: ["203.0.113.0/24"],
            },
            scope: "management",
            action: {
              allow: true,
            },
          },
        },
      ],
    };

    const result = await checkManagementAPIACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });

  it("should return empty array when management API allowlist is configured with IPv6", async function () {
    const input = {
      networkAcl: [
        {
          acl_id: "acl_456",
          active: true,
          description: "Allow management from office IPv6",
          rule: {
            match: {
              ipv6_cidrs: ["2001:db8::/32"],
            },
            scope: "management",
            action: {
              allow: true,
            },
          },
        },
      ],
    };

    const result = await checkManagementAPIACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });

  it("should return warning when only block rules exist for management API", async function () {
    const input = {
      networkAcl: [
        {
          acl_id: "acl_789",
          active: true,
          description: "Block malicious IPs",
          rule: {
            match: {
              ipv4_cidrs: ["192.0.2.0/24"],
            },
            scope: "management",
            action: {
              block: true,
            },
          },
        },
      ],
    };

    const result = await checkManagementAPIACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("no_management_api_allowlist");
    expect(result.details[0].status).to.equal(CONSTANTS.WARN);
  });

  it("should return warning when management API allowlist rule is inactive", async function () {
    const input = {
      networkAcl: [
        {
          acl_id: "acl_inactive",
          active: false,
          description: "Disabled management allowlist",
          rule: {
            match: {
              ipv4_cidrs: ["203.0.113.0/24"],
            },
            scope: "management",
            action: {
              allow: true,
            },
          },
        },
      ],
    };

    const result = await checkManagementAPIACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("no_management_api_allowlist");
  });

  it("should ignore authentication scope rules", async function () {
    const input = {
      networkAcl: [
        {
          acl_id: "acl_auth",
          active: true,
          description: "Auth allowlist",
          rule: {
            match: {
              ipv4_cidrs: ["203.0.113.0/24"],
            },
            scope: "authentication",
            action: {
              allow: true,
            },
          },
        },
      ],
    };

    const result = await checkManagementAPIACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("no_management_api_allowlist");
  });

  it("should return empty array when insufficient_scope error", async function () {
    const input = {
      networkAcl: [
        {
          errorCode: "insufficient_scope",
        },
      ],
    };

    const result = await checkManagementAPIACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });

  it("should handle undefined networkAcl gracefully", async function () {
    const input = {};

    const result = await checkManagementAPIACL(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("no_management_api_allowlist");
  });
});

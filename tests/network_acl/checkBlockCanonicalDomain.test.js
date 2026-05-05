const { expect } = require("chai");
const checkBlockCanonicalDomain = require("../../analyzer/lib/network_acl/checkBlockCanonicalDomain");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkBlockCanonicalDomain", function () {
  const canonicalDomain = "example-tenant.us.auth0app.com";
  const customDomain = "auth.example.com";

  it("should return empty array when custom domain exists and canonical domain is blocked", async function () {
    const input = {
      customDomains: [
        {
          domain: customDomain,
          primary: true,
          status: "ready",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [
        {
          description: "Block canonical domain",
          active: true,
          priority: 1,
          rule: {
            match: {
              hostnames: [canonicalDomain],
            },
            scope: "authentication",
            action: {
              block: true,
            },
          },
          id: "acl_12345",
        },
      ],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });

  it("should return warning when custom domain exists but canonical domain is not blocked", async function () {
    const input = {
      customDomains: [
        {
          domain: customDomain,
          primary: true,
          status: "ready",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [
        {
          description: "Some other ACL",
          active: true,
          priority: 1,
          rule: {
            match: {
              ipv4_cidrs: ["192.168.1.0/24"],
            },
            scope: "management",
            action: {
              block: true,
            },
          },
          id: "acl_67890",
        },
      ],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("canonical_domain_not_blocked");
    expect(result.details[0].status).to.equal(CONSTANTS.WARN);
    expect(result.details[0].value).to.equal(canonicalDomain);
    expect(result.details[0].customDomains).to.equal(customDomain);
  });

  // no custom domain configured (skip check)
  it("should return empty array when no custom domain is configured", async function () {
    const input = {
      customDomains: [],
      networkAcl: [],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });

  // custom domain pending verification (skip check)
  it("should return empty array when custom domain is pending verification", async function () {
    const input = {
      customDomains: [
        {
          domain: customDomain,
          primary: true,
          status: "pending_verification",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });

  it("should return empty array when insufficient_scope error", async function () {
    const input = {
      customDomains: [
        {
          domain: customDomain,
          primary: true,
          status: "ready",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [
        {
          errorCode: "insufficient_scope",
        },
      ],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });

  // ACL rule exists but is inactive
  it("should return warning when ACL rule exists but is inactive", async function () {
    const input = {
      customDomains: [
        {
          domain: customDomain,
          primary: true,
          status: "ready",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [
        {
          description: "Block canonical domain",
          active: false, // Inactive!
          priority: 1,
          rule: {
            match: {
              hostnames: [canonicalDomain],
            },
            scope: "authentication",
            action: {
              block: true,
            },
          },
          id: "acl_12345",
        },
      ],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("canonical_domain_not_blocked");
    expect(result.details[0].status).to.equal(CONSTANTS.WARN);
  });

  // Edge case - ACL rule has wrong scope (management instead of authentication)
  it("should return warning when ACL rule has management scope instead of authentication", async function () {
    const input = {
      customDomains: [
        {
          domain: customDomain,
          primary: true,
          status: "ready",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [
        {
          description: "Block canonical domain",
          active: true,
          priority: 1,
          rule: {
            match: {
              hostnames: [canonicalDomain],
            },
            scope: "management", // Wrong scope!
            action: {
              block: true,
            },
          },
          id: "acl_12345",
        },
      ],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("canonical_domain_not_blocked");
    expect(result.details[0].status).to.equal(CONSTANTS.WARN);
  });

  // Edge case - ACL rule has block: false (monitoring mode)
  it("should return warning when ACL rule has block: false", async function () {
    const input = {
      customDomains: [
        {
          domain: customDomain,
          primary: true,
          status: "ready",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [
        {
          description: "Block canonical domain",
          active: true,
          priority: 1,
          rule: {
            match: {
              hostnames: [canonicalDomain],
            },
            scope: "authentication",
            action: {
              block: false, // Monitoring mode, not blocking!
            },
          },
          id: "acl_12345",
        },
      ],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("canonical_domain_not_blocked");
    expect(result.details[0].status).to.equal(CONSTANTS.WARN);
  });

  // Happy path - wildcard *.auth0.com pattern
  it("should pass when using wildcard *.auth0.com pattern", async function () {
    const input = {
      customDomains: [
        {
          domain: customDomain,
          primary: true,
          status: "ready",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [
        {
          description: "Block all canonical domains",
          active: true,
          priority: 1,
          rule: {
            match: {
              hostnames: ["*.auth0.com"],
            },
            scope: "authentication",
            action: {
              block: true,
            },
          },
          id: "acl_12345",
        },
      ],
      canonicalDomain: "example-tenant.us.auth0.com",
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });

  // Happy path - wildcard *.auth0app.com pattern
  it("should pass when using wildcard *.auth0app.com pattern", async function () {
    const input = {
      customDomains: [
        {
          domain: customDomain,
          primary: true,
          status: "ready",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [
        {
          description: "Block all canonical domains",
          active: true,
          priority: 1,
          rule: {
            match: {
              hostnames: ["*.auth0app.com"],
            },
            scope: "authentication",
            action: {
              block: true,
            },
          },
          id: "acl_12345",
        },
      ],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });

  // Edge case - multiple custom domains, one ready, one pending
  it("should check when at least one custom domain is ready", async function () {
    const input = {
      customDomains: [
        {
          domain: "pending.example.com",
          primary: false,
          status: "pending_verification",
          type: "auth0_managed_certs",
        },
        {
          domain: "ready.example.com",
          primary: true,
          status: "ready",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("canonical_domain_not_blocked");
    expect(result.details[0].customDomains).to.equal("ready.example.com");
  });

  // Edge case - ACL rule exists but doesn't have hostnames field
  it("should return warning when ACL rule exists but has no hostnames", async function () {
    const input = {
      customDomains: [
        {
          domain: customDomain,
          primary: true,
          status: "ready",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [
        {
          description: "IP-based ACL only",
          active: true,
          priority: 1,
          rule: {
            match: {
              ipv4_cidrs: ["192.168.1.0/24"],
            },
            scope: "authentication",
            action: {
              block: true,
            },
          },
          id: "acl_12345",
        },
      ],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].field).to.equal("canonical_domain_not_blocked");
  });

  // Happy path - multiple ACL rules, one of them blocks canonical domain
  it("should pass when one of multiple ACL rules blocks canonical domain", async function () {
    const input = {
      customDomains: [
        {
          domain: customDomain,
          primary: true,
          status: "ready",
          type: "auth0_managed_certs",
        },
      ],
      networkAcl: [
        {
          description: "Management API protection",
          active: true,
          priority: 1,
          rule: {
            match: {
              ipv4_cidrs: ["192.168.1.0/24"],
            },
            scope: "management",
            action: {
              block: true,
            },
          },
          id: "acl_11111",
        },
        {
          description: "Block canonical domain",
          active: true,
          priority: 2,
          rule: {
            match: {
              hostnames: [canonicalDomain],
            },
            scope: "authentication",
            action: {
              block: true,
            },
          },
          id: "acl_22222",
        },
      ],
      canonicalDomain: canonicalDomain,
    };

    const result = await checkBlockCanonicalDomain(input);
    expect(result.details).to.be.an("array");
    expect(result.details).to.have.lengthOf(0);
  });
});

const chai = require("chai");
const expect = chai.expect;
const checkPKCEEnforcement = require("../../analyzer/lib/clients/checkPKCEEnforcement");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkPKCEEnforcement", function () {
  const pkceEnforcingAction = {
    id: "pkce-action",
    name: "Enforce PKCE",
    status: "built",
    supported_triggers: [{ id: "post-login", version: "v3" }],
    code: `exports.onExecutePostLogin = async (event, api) => {
      if (!event.request.query.code_challenge) {
        api.access.deny("PKCE required");
      }
    };`,
  };

  it("should return empty details when no clients are provided", async function () {
    const input = { clients: [] };
    const result = await checkPKCEEnforcement(input);
    expect(result.details).to.be.an("array").that.is.empty;
  });

  it("should return empty details when no applicable clients exist (regular_web only)", async function () {
    const input = {
      clients: [
        {
          name: "Web App",
          client_id: "client_web",
          app_type: "regular_web",
          grant_types: ["authorization_code", "refresh_token"],
        },
      ],
      actions: { actions: [pkceEnforcingAction] },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details).to.be.an("array").that.is.empty;
  });

  it("should return empty details when no applicable clients exist (non_interactive only)", async function () {
    const input = {
      clients: [
        {
          name: "M2M App",
          client_id: "client_m2m",
          app_type: "non_interactive",
          grant_types: ["client_credentials"],
        },
      ],
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details).to.be.an("array").that.is.empty;
  });

  it("should FAIL a SPA client with authorization_code grant when no PKCE-enforcing action exists", async function () {
    const input = {
      clients: [
        {
          name: "My SPA",
          client_id: "client_spa",
          app_type: "spa",
          is_first_party: true,
          grant_types: ["authorization_code", "refresh_token"],
        },
      ],
      actions: { actions: [] },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].name).to.equal("My SPA (client_spa)");
    expect(result.details[0].report).to.have.lengthOf(1);
    expect(result.details[0].report[0]).to.include({
      field: "pkce_enforcement_action_missing",
      status: CONSTANTS.FAIL,
      value: "spa",
    });
  });

  it("should FAIL a native client with authorization_code grant when no PKCE-enforcing action exists", async function () {
    const input = {
      clients: [
        {
          name: "Mobile App",
          client_id: "client_native",
          app_type: "native",
          is_first_party: true,
          grant_types: ["authorization_code", "refresh_token"],
        },
      ],
      actions: { actions: [] },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].report[0]).to.include({
      field: "pkce_enforcement_action_missing",
      status: CONSTANTS.FAIL,
      value: "native",
    });
  });

  it("should pass (empty report) when a valid PKCE-enforcing post-login action exists", async function () {
    const input = {
      clients: [
        {
          name: "My SPA",
          client_id: "client_spa",
          app_type: "spa",
          is_first_party: true,
          grant_types: ["authorization_code", "refresh_token"],
        },
      ],
      actions: { actions: [pkceEnforcingAction] },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details).to.have.lengthOf(1);
    expect(result.details[0].report).to.be.an("array").that.is.empty;
  });

  it("should pass when code_challenge is accessed via an intermediate variable", async function () {
    const input = {
      clients: [
        {
          name: "My SPA",
          client_id: "client_spa",
          app_type: "spa",
          grant_types: ["authorization_code"],
        },
      ],
      actions: {
        actions: [
          {
            id: "pkce-indirect",
            name: "Enforce PKCE Indirect",
            status: "built",
            supported_triggers: [{ id: "post-login", version: "v3" }],
            code: `exports.onExecutePostLogin = async (event, api) => {
              const query = event.request && event.request.query;
              const codeChallenge = query && query.code_challenge;
              if (!codeChallenge) {
                api.access.deny("PKCE required");
              }
            };`,
          },
        ],
      },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details[0].report).to.be.an("array").that.is.empty;
  });

  it("should FAIL when action checks code_challenge but has no api.access.deny call", async function () {
    const input = {
      clients: [
        {
          name: "My SPA",
          client_id: "client_spa",
          app_type: "spa",
          grant_types: ["authorization_code"],
        },
      ],
      actions: {
        actions: [
          {
            id: "partial-action",
            name: "Partial PKCE",
            supported_triggers: [{ id: "post-login", version: "v3" }],
            code: `exports.onExecutePostLogin = async (event, api) => {
              const challenge = event.request.query.code_challenge;
              console.log(challenge);
            };`,
          },
        ],
      },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details[0].report[0].field).to.equal("pkce_enforcement_action_missing");
    expect(result.details[0].report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("should FAIL when action calls api.access.deny but does not check code_challenge", async function () {
    const input = {
      clients: [
        {
          name: "My SPA",
          client_id: "client_spa",
          app_type: "spa",
          grant_types: ["authorization_code"],
        },
      ],
      actions: {
        actions: [
          {
            id: "deny-only-action",
            name: "Deny Only",
            supported_triggers: [{ id: "post-login", version: "v3" }],
            code: `exports.onExecutePostLogin = async (event, api) => {
              api.access.deny("blocked");
            };`,
          },
        ],
      },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details[0].report[0].field).to.equal("pkce_enforcement_action_missing");
    expect(result.details[0].report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("should FAIL when the PKCE action is on the wrong trigger type (not post-login)", async function () {
    const input = {
      clients: [
        {
          name: "My SPA",
          client_id: "client_spa",
          app_type: "spa",
          grant_types: ["authorization_code"],
        },
      ],
      actions: {
        actions: [
          {
            id: "pre-reg-action",
            name: "Pre-Registration PKCE",
            supported_triggers: [{ id: "pre-user-registration", version: "v1" }],
            code: `exports.onExecutePreUserRegistration = async (event, api) => {
              if (!event.request.query.code_challenge) {
                api.access.deny("PKCE required");
              }
            };`,
          },
        ],
      },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details[0].report[0].field).to.equal("pkce_enforcement_action_missing");
    expect(result.details[0].report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("should FAIL all applicable clients when no PKCE enforcement action exists", async function () {
    const input = {
      clients: [
        {
          name: "SPA One",
          client_id: "client_spa_1",
          app_type: "spa",
          grant_types: ["authorization_code"],
        },
        {
          name: "SPA Two",
          client_id: "client_spa_2",
          app_type: "spa",
          grant_types: ["authorization_code"],
        },
        {
          name: "Native App",
          client_id: "client_native_1",
          app_type: "native",
          grant_types: ["authorization_code"],
        },
      ],
      actions: { actions: [] },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details).to.have.lengthOf(3);
    result.details.forEach((detail) => {
      expect(detail.report[0].field).to.equal("pkce_enforcement_action_missing");
      expect(detail.report[0].status).to.equal(CONSTANTS.FAIL);
    });
  });

  it("should pass all applicable clients when a PKCE-enforcing action exists", async function () {
    const input = {
      clients: [
        {
          name: "SPA One",
          client_id: "client_spa_1",
          app_type: "spa",
          grant_types: ["authorization_code"],
        },
        {
          name: "Native App",
          client_id: "client_native_1",
          app_type: "native",
          grant_types: ["authorization_code"],
        },
      ],
      actions: { actions: [pkceEnforcingAction] },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details).to.have.lengthOf(2);
    result.details.forEach((detail) => {
      expect(detail.report).to.be.an("array").that.is.empty;
    });
  });

  it("should FAIL when the PKCE-enforcing action exists but is not deployed (status !== built)", async function () {
    const input = {
      clients: [
        {
          name: "My SPA",
          client_id: "client_spa",
          app_type: "spa",
          grant_types: ["authorization_code"],
        },
      ],
      actions: {
        actions: [
          {
            ...pkceEnforcingAction,
            status: "draft",
          },
        ],
      },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details[0].report[0].field).to.equal("pkce_enforcement_action_missing");
    expect(result.details[0].report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("should pass when the PKCE-enforcing action has status built", async function () {
    const input = {
      clients: [
        {
          name: "My SPA",
          client_id: "client_spa",
          app_type: "spa",
          grant_types: ["authorization_code"],
        },
      ],
      actions: {
        actions: [
          {
            ...pkceEnforcingAction,
            status: "built",
          },
        ],
      },
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details[0].report).to.be.an("array").that.is.empty;
  });

  it("should accept actions as a flat array (not wrapped in actions object)", async function () {
    const input = {
      clients: [
        {
          name: "My SPA",
          client_id: "client_spa",
          app_type: "spa",
          grant_types: ["authorization_code"],
        },
      ],
      actions: [pkceEnforcingAction],
    };
    const result = await checkPKCEEnforcement(input);
    expect(result.details[0].report).to.be.an("array").that.is.empty;
  });

  it("should FAIL a SPA that only uses implicit grant (no authorization_code)", async function () {
    const input = {
      clients: [
        {
          name: "Legacy SPA",
          client_id: "client_implicit",
          app_type: "spa",
          grant_types: ["implicit"],
        },
      ],
      actions: { actions: [] },
    };
    const result = await checkPKCEEnforcement(input);
    // implicit-only SPAs do not use authorization_code, so not applicable
    expect(result.details).to.be.an("array").that.is.empty;
  });
});

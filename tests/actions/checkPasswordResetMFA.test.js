const chai = require("chai");
const expect = chai.expect;
const checkPasswordResetMFA = require("../../analyzer/lib/actions/checkPasswordResetMFA"); 

describe("checkPasswordResetMFA", function () {
  // Mock Database Connection to trigger the validator's logic
  const mockDbConnections = [{ id: "con_1", strategy: "auth0", name: "Username-Password-Authentication" }];
  // Mock Social Connection only
  const mockSocialConnections = [{ id: "con_2", strategy: "google-oauth2", name: "google" }];

  it("should return SUCCESS when a password-reset-post-challenge action correctly implements MFA challenges", async function () {
    const input = {
      databases: mockDbConnections, 
      actions: {
        actions: [
          {
            id: "pw-reset-mfa-ok",
            name: "Secure Reset",
            supported_triggers: [{ id: "password-reset-post-challenge", version: "v1" }],
            code: `exports.onExecutePostChallenge = async (event, api) => {
              api.authentication.challengeWithAny();
            };`,
          },
        ],
      },
    };

    const reports = await checkPasswordResetMFA(input);
    expect(reports.details).to.have.lengthOf(0);
  });

  it("should return WARN when a password-reset-post-challenge action exists but is missing the MFA challenge", async function () {
    const input = {
      databases: mockDbConnections, 
      actions: {
        actions: [
          {
            id: "pw-reset-weak",
            name: "Weak Reset",
            supported_triggers: [{ id: "password-reset-post-challenge", version: "v1" }],
            code: `exports.onExecutePostChallenge = async (event, api) => { return; };`,
          },
        ],
      },
    };

    const reports = await checkPasswordResetMFA(input);
    expect(reports.details).to.have.lengthOf(1);
    expect(reports.details[0].report[0].field).to.equal("missing_mfa_step");
  });

  it("should return NO FINDINGS for a Social-Only tenant (Passwordless)", async function () {
    const input = {
      databases: mockSocialConnections, // Only Social
      actions: {
        actions: [
          {
            id: "action-1",
            name: "Some Action",
            supported_triggers: [{ id: "password-reset-post-challenge", version: "v1" }],
            code: `exports.onExecutePostChallenge = async (event, api) => { return; };`,
          },
        ],
      },
    };

    const reports = await checkPasswordResetMFA(input);
    // Should be empty because password reset doesn't apply to Social-only tenants
    expect(reports.details).to.be.an("array").that.is.empty;
  });

  it("should ignore MFA challenges in actions that are NOT part of the password-reset flow", async function () {
    const input = {
      databases: mockDbConnections, 
      actions: {
        actions: [
          {
            id: "login-mfa",
            name: "Login MFA",
            supported_triggers: [{ id: "post-login", version: "v3" }],
            code: 'exports.onExecutePostLogin = async (event, api) => { api.authentication.challengeWithAny(); };',
          },
        ],
      },
    };

    const reports = await checkPasswordResetMFA(input);
    expect(reports.details).to.have.lengthOf(1);
    expect(reports.details[0].report[0].field).to.equal("no_password_reset_action");
  });

  it("should detect alternate challenge methods like challengeWith", async function () {
    const input = {
      databases: mockDbConnections, 
      actions: {
        actions: [
          {
            id: "pw-reset-otp",
            name: "OTP Reset",
            supported_triggers: [{ id: "password-reset-post-challenge", version: "v1" }],
            code: `exports.onExecutePostChallenge = async (event, api) => {
              api.authentication.challengeWith({ type: 'otp' });
            };`,
          },
        ],
      },
    };

    const reports = await checkPasswordResetMFA(input);
    expect(reports.details).to.have.lengthOf(0);
  });

  it("should return a warning if the actions list is entirely empty but DB connections exist", async function () {
    const input = { 
      databases: mockDbConnections, 
      actions: { actions: [] } 
    };
    const reports = await checkPasswordResetMFA(input);
    
    expect(reports.details[0].report[0].field).to.equal("no_actions_configured");
  });
});
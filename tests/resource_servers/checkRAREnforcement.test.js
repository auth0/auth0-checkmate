const chai = require("chai");
const expect = chai.expect;

const checkRAREnforcement = require("../../analyzer/lib/resource_servers/checkRAREnforcement");
const CONSTANTS = require("../../analyzer/lib/constants");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRS(overrides) {
    return Object.assign(
        {
            id: "rs1",
            name: "Banking API",
            identifier: "https://bank.api.com",
            is_system: false,
            authorization_details: [{ type: "payment_initiation" }],
        },
        overrides
    );
}

function makeAction(codeOverride, overrides) {
    return Object.assign(
        {
            id: "action1",
            name: "RAR Step-Up",
            supported_triggers: [{ id: "post-login", version: "v3" }],
            status: "built",
            all_changes_deployed: true,
            code: codeOverride,
        },
        overrides
    );
}

const RAR_REF = "event.transaction.requested_authorization_details";

// A minimal action body that references RAR and performs a step-up challenge.
const ENFORCING_CODE_CHALLENGE_WITH = `
exports.onExecutePostLogin = async (event, api) => {
  const details = ${RAR_REF};
  if (details && details.length > 0) {
    api.authentication.challengeWith({ type: "otp" });
  }
};`;

const ENFORCING_CODE_CHALLENGE = `
exports.onExecutePostLogin = async (event, api) => {
  const details = ${RAR_REF};
  if (details) { api.authentication.challenge(); }
};`;

const ENFORCING_CODE_MFA_ENABLE = `
exports.onExecutePostLogin = async (event, api) => {
  const req = ${RAR_REF};
  if (req) { api.multifactor.enable("any"); }
};`;

const ENFORCING_CODE_REDIRECT = `
exports.onExecutePostLogin = async (event, api) => {
  const req = ${RAR_REF};
  if (req) {
    api.redirect.sendUserTo("https://step-up.example.com");
  }
};
exports.onContinuePostLogin = async (event, api) => {
  await api.redirect.validateToken({ secret: "s3cr3t" });
};`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("checkRAREnforcement", function () {

    // 1. consent_policy covers the RS → no finding
    it("RS with consent_policy=transactional-authorization-with-mfa → no finding", async function () {
        const options = {
            resourceServers: [
                makeRS({ consent_policy: "transactional-authorization-with-mfa" }),
            ],
            actions: { actions: [], total: 0 },
        };

        const result = await checkRAREnforcement(options);
        expect(result.details).to.have.lengthOf(1);
        expect(result.details[0].report).to.have.lengthOf(0);
    });

    // 2. Deployed post-login action using api.authentication.challengeWith → no finding
    it("deployed post-login action with challengeWith + RAR reference → no finding", async function () {
        const options = {
            resourceServers: [makeRS()],
            actions: {
                actions: [makeAction(ENFORCING_CODE_CHALLENGE_WITH)],
                total: 1,
            },
        };

        const result = await checkRAREnforcement(options);
        expect(result.details).to.have.lengthOf(1);
        expect(result.details[0].report).to.have.lengthOf(0);
    });

    // 3. api.authentication.challenge (older API) + RAR reference → no finding
    it("deployed post-login action with challenge() + RAR reference → no finding", async function () {
        const options = {
            resourceServers: [makeRS()],
            actions: {
                actions: [makeAction(ENFORCING_CODE_CHALLENGE)],
                total: 1,
            },
        };

        const result = await checkRAREnforcement(options);
        expect(result.details[0].report).to.have.lengthOf(0);
    });

    // 4. api.multifactor.enable + RAR reference → no finding
    it("deployed post-login action with multifactor.enable() + RAR reference → no finding", async function () {
        const options = {
            resourceServers: [makeRS()],
            actions: {
                actions: [makeAction(ENFORCING_CODE_MFA_ENABLE)],
                total: 1,
            },
        };

        const result = await checkRAREnforcement(options);
        expect(result.details[0].report).to.have.lengthOf(0);
    });

    // 5. Redirect-based step-up (sendUserTo + validateToken) + RAR reference → no finding
    it("deployed post-login action with redirect step-up + RAR reference → no finding", async function () {
        const options = {
            resourceServers: [makeRS()],
            actions: {
                actions: [makeAction(ENFORCING_CODE_REDIRECT)],
                total: 1,
            },
        };

        const result = await checkRAREnforcement(options);
        expect(result.details[0].report).to.have.lengthOf(0);
    });

    // 6. Action has step-up call but NO RAR reference → still a finding (enforcement not RAR-aware)
    it("action has step-up call but no RAR reference → WARN finding", async function () {
        const noRarRefCode = `
exports.onExecutePostLogin = async (event, api) => {
  api.authentication.challengeWith({ type: "otp" });
};`;

        const options = {
            resourceServers: [makeRS()],
            actions: {
                actions: [makeAction(noRarRefCode)],
                total: 1,
            },
        };

        const result = await checkRAREnforcement(options);
        expect(result.details).to.have.lengthOf(1);
        const report = result.details[0].report;
        expect(report).to.have.lengthOf(1);
        expect(report[0].status).to.equal(CONSTANTS.WARN);
        expect(report[0].field).to.equal("rar_enforcement");
    });

    // 7. Action references RAR but has NO step-up call → still a finding (reads but doesn't enforce)
    it("action references RAR but has no step-up call → WARN finding", async function () {
        const noStepUpCode = `
exports.onExecutePostLogin = async (event, api) => {
  const details = ${RAR_REF};
  console.log(details);
};`;

        const options = {
            resourceServers: [makeRS()],
            actions: {
                actions: [makeAction(noStepUpCode)],
                total: 1,
            },
        };

        const result = await checkRAREnforcement(options);
        const report = result.details[0].report;
        expect(report).to.have.lengthOf(1);
        expect(report[0].status).to.equal(CONSTANTS.WARN);
    });

    // 8. No consent_policy, no actions → WARN finding
    it("RS has RAR but no consent_policy and empty actions list → WARN finding", async function () {
        const options = {
            resourceServers: [makeRS()],
            actions: { actions: [], total: 0 },
        };

        const result = await checkRAREnforcement(options);
        const report = result.details[0].report;
        expect(report).to.have.lengthOf(1);
        expect(report[0].status).to.equal(CONSTANTS.WARN);
        expect(report[0].value).to.equal("not_enforced");
    });

    // 9. Action has correct code but all_changes_deployed is false → not in use, finding expected
    it("action with enforcing code but all_changes_deployed=false → WARN finding", async function () {
        const options = {
            resourceServers: [makeRS()],
            actions: {
                actions: [
                    makeAction(ENFORCING_CODE_CHALLENGE_WITH, {
                        all_changes_deployed: false,
                    }),
                ],
                total: 1,
            },
        };

        const result = await checkRAREnforcement(options);
        const report = result.details[0].report;
        expect(report).to.have.lengthOf(1);
        expect(report[0].status).to.equal(CONSTANTS.WARN);
    });

    // 10. Action has correct code but status !== "built" → not compiled, finding expected
    it("action with enforcing code but status=pending → WARN finding", async function () {
        const options = {
            resourceServers: [makeRS()],
            actions: {
                actions: [
                    makeAction(ENFORCING_CODE_CHALLENGE_WITH, { status: "pending" }),
                ],
                total: 1,
            },
        };

        const result = await checkRAREnforcement(options);
        const report = result.details[0].report;
        expect(report).to.have.lengthOf(1);
        expect(report[0].status).to.equal(CONSTANTS.WARN);
    });

    // 11. Enforcing action has non-post-login trigger → ignored, finding expected
    it("action with enforcing code but wrong trigger (pre-user-registration) → WARN finding", async function () {
        const options = {
            resourceServers: [makeRS()],
            actions: {
                actions: [
                    makeAction(ENFORCING_CODE_CHALLENGE_WITH, {
                        supported_triggers: [{ id: "pre-user-registration", version: "v2" }],
                    }),
                ],
                total: 1,
            },
        };

        const result = await checkRAREnforcement(options);
        const report = result.details[0].report;
        expect(report).to.have.lengthOf(1);
        expect(report[0].status).to.equal(CONSTANTS.WARN);
    });

    // 12. RS without authorization_details → skipped entirely
    it("RS without authorization_details → not included in details", async function () {
        const options = {
            resourceServers: [makeRS({ authorization_details: undefined })],
            actions: { actions: [], total: 0 },
        };

        const result = await checkRAREnforcement(options);
        expect(result.details).to.deep.equal([]);
    });

    // 13. RS with empty authorization_details array → skipped (no RAR configured)
    it("RS with empty authorization_details array → not included in details", async function () {
        const options = {
            resourceServers: [makeRS({ authorization_details: [] })],
            actions: { actions: [], total: 0 },
        };

        const result = await checkRAREnforcement(options);
        expect(result.details).to.deep.equal([]);
    });

    // 14. System RS with RAR configured → always skipped
    it("system RS with RAR configured → skipped", async function () {
        const options = {
            resourceServers: [makeRS({ is_system: true })],
            actions: { actions: [], total: 0 },
        };

        const result = await checkRAREnforcement(options);
        expect(result.details).to.deep.equal([]);
    });

    // 15. Only sendUserTo without validateToken → not a complete redirect step-up, finding expected
    it("action with only sendUserTo (no validateToken) + RAR reference → WARN finding", async function () {
        const incompleteRedirect = `
exports.onExecutePostLogin = async (event, api) => {
  const req = ${RAR_REF};
  api.redirect.sendUserTo("https://step-up.example.com");
};`;

        const options = {
            resourceServers: [makeRS()],
            actions: {
                actions: [makeAction(incompleteRedirect)],
                total: 1,
            },
        };

        const result = await checkRAREnforcement(options);
        const report = result.details[0].report;
        expect(report).to.have.lengthOf(1);
        expect(report[0].status).to.equal(CONSTANTS.WARN);
    });

    // 16. Actions passed as raw array (not wrapped in { actions: [] }) → handled correctly
    it("actions passed as plain array (not wrapped object) → processed correctly", async function () {
        const options = {
            resourceServers: [makeRS()],
            actions: [makeAction(ENFORCING_CODE_CHALLENGE_WITH)],
        };

        const result = await checkRAREnforcement(options);
        expect(result.details[0].report).to.have.lengthOf(0);
    });

    // 17. Mixed batch: one RS with consent_policy, one without enforcement, system RS
    it("mixed batch: only RS without enforcement is flagged", async function () {
        const options = {
            resourceServers: [
                makeRS({
                    id: "rs1",
                    name: "Payments API",
                    identifier: "https://pay.api.com",
                    consent_policy: "transactional-authorization-with-mfa",
                }),
                makeRS({
                    id: "rs2",
                    name: "Account API",
                    identifier: "https://account.api.com",
                    // no consent_policy
                }),
                makeRS({
                    id: "sys",
                    name: "Auth0 Management API",
                    identifier: "https://tenant.auth0.com/api/v2/",
                    is_system: true,
                }),
                makeRS({
                    id: "rs3",
                    name: "No-RAR API",
                    identifier: "https://legacy.api.com",
                    authorization_details: undefined,
                }),
            ],
            actions: { actions: [], total: 0 },
        };

        const result = await checkRAREnforcement(options);

        const paymentsEntry = result.details.find((d) => d.name.includes("Payments API"));
        expect(paymentsEntry, "Payments API should be in details").to.exist;
        expect(paymentsEntry.report).to.have.lengthOf(0);

        const accountEntry = result.details.find((d) => d.name.includes("Account API"));
        expect(accountEntry, "Account API should be in details").to.exist;
        expect(accountEntry.report[0].status).to.equal(CONSTANTS.WARN);

        const systemEntry = result.details.find((d) => d.name.includes("Management API"));
        expect(systemEntry, "System RS should not appear").to.not.exist;

        const noRarEntry = result.details.find((d) => d.name.includes("No-RAR API"));
        expect(noRarEntry, "RS without RAR should not appear").to.not.exist;
    });
});

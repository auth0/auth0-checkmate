/*
{
  resourceServers: [ { id, name, identifier, is_system, authorization_details, consent_policy } ],
  actions: { actions: [ { id, name, code, status, all_changes_deployed, supported_triggers } ] }
}

For each Resource Server that has RAR configured (authorization_details non-empty), checks
that at least one enforcement mechanism is present:

  1. consent_policy === "transactional-authorization-with-mfa"  (Auth0 built-in enforcement)
  2. OR a deployed post-login Action whose code both:
       a. references  event.transaction.requested_authorization_details  (reads RAR context)
       b. calls one of the recognised step-up authentication APIs

Step-up patterns detected:
  api.authentication.challengeWith(  – explicit factor challenge (primary RAR enforcement API)
  api.authentication.challenge(      – generic challenge (older API, still in use)
  api.multifactor.enable(            – programmatic MFA enforcement
  api.redirect.sendUserTo( … api.redirect.validateToken(  – redirect-based step-up flow

Skips system RSes. Emits WARN when RAR is configured but no enforcement is found.
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

const TRANSACTIONAL_MFA_POLICY = "transactional-authorization-with-mfa";

// Patterns that signal step-up / MFA enforcement inside an action.
// Ordered from most specific to most general.
const STEP_UP_PATTERNS = [
    /api\.authentication\.challengeWith\s*\(/,
    /api\.authentication\.challenge\s*\(/,
    /api\.multifactor\.enable\s*\(/,
];

// Redirect-based step-up requires BOTH sendUserTo and validateToken in the same action.
function hasRedirectStepUp(code) {
    return (
        /api\.redirect\.sendUserTo\s*\(/.test(code) &&
        /api\.redirect\.validateToken\s*\(/.test(code)
    );
}

function hasStepUpCall(code) {
    return (
        STEP_UP_PATTERNS.some((re) => re.test(code)) ||
        hasRedirectStepUp(code)
    );
}

function isEnforcingPostLoginAction(action) {
    // Must target the post-login trigger
    const isPostLogin = (action.supported_triggers || []).some(
        (t) => t.id === "post-login"
    );
    if (!isPostLogin) return false;

    // Must be deployed: built and all current changes pushed to the flow
    if (action.status !== "built" || !action.all_changes_deployed) return false;

    const code = action.code || "";

    // Must read the RAR context from the event
    if (!code.includes("event.transaction.requested_authorization_details")) {
        return false;
    }

    // Must perform a step-up / MFA challenge
    return hasStepUpCall(code);
}

function checkRAREnforcement(options) {
    return executeCheck("checkRAREnforcement", (callback) => {
        const { resourceServers, actions } = options || {};
        const reports = [];

        if (_.isEmpty(resourceServers)) {
            return callback(reports);
        }

        // Normalise actions regardless of whether the caller passed the raw array
        // or the Management API wrapper object { actions: [], total: N }
        const actionsList = Array.isArray(actions)
            ? actions
            : (actions?.actions || []);

        // Pre-compute: does any deployed post-login action enforce RAR step-up?
        const hasEnforcingAction = actionsList.some(isEnforcingPostLoginAction);

        resourceServers.forEach((rs) => {
            if (rs.is_system) return;

            // Only examine RSes that have RAR configured
            const hasRAR =
                Array.isArray(rs.authorization_details) &&
                rs.authorization_details.length > 0;
            if (!hasRAR) return;

            const name = rs.name || rs.identifier;
            const displayName = rs.identifier ? `${name} (${rs.identifier})` : name;

            const hasTransactionalMFA =
                rs.consent_policy === TRANSACTIONAL_MFA_POLICY;

            const report = [];
            if (!hasTransactionalMFA && !hasEnforcingAction) {
                report.push({
                    name: displayName,
                    identifier: rs.identifier,
                    field: "rar_enforcement",
                    status: CONSTANTS.WARN,
                    value: "not_enforced",
                });
            }

            reports.push({ name: displayName, report });
        });

        return callback(reports);
    });
}

module.exports = checkRAREnforcement;

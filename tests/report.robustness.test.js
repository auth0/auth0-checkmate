const { expect } = require("chai");
const i18n = require("i18n");
const CONSTANTS = require("../analyzer/lib/constants");
const { generateReport } = require("../analyzer/report");
const checkUserEnumeration = require("../analyzer/lib/actions/checkUserEnumeration");
const checkActionsHardCodedValues = require("../analyzer/lib/actions/checkActionsHardCodedValues");
const checkPasswordResetMFA = require("../analyzer/lib/actions/checkPasswordResetMFA");
const checkWebOrigins = require("../analyzer/lib/clients/checkWebOrigins");

describe("report robustness", function () {
  describe("generateReport", function () {
    it("keeps the rest of the report when one check throws", async function () {
      // A breached-password response without `stage`/`shields` makes
      // checkBreachedPassword throw; the other validator must still report.
      const tenantConfig = {
        customDomains: [],
        attackProtection: { breachedPasswordDetection: { enabled: true } },
      };
      const report = await generateReport("en", tenantConfig, {
        auth0Domain: "example.auth0.com",
        selectedValidators: ["checkBreachedPassword", "checkCustomDomain"],
      });

      expect(report.full_report).to.have.lengthOf(2);
      const byName = Object.fromEntries(
        report.full_report.map((r) => [r.name, r]),
      );
      expect(byName.checkBreachedPassword.details).to.deep.equal([]);
      expect(byName.checkCustomDomain.details).to.be.an("array").that.is.not
        .empty;
    });
  });

  describe("REQUIRED_SCOPES", function () {
    it("covers every scope a validator declares as required", function () {
      const requested = CONSTANTS.REQUIRED_SCOPES.split(" ");
      const declared = i18n
        .__("list_of_validators")
        .flatMap((v) => (v.required_scope ? v.required_scope.split(" ") : []));

      expect(declared).to.include("read:rules");
      expect(declared).to.include("read:hooks");
      declared.forEach((scope) => expect(requested).to.include(scope));
    });
  });

  describe("checks without an actions list", function () {
    it("checkPreRegistrationUserEnumeration does not throw", async function () {
      const { details } = await checkUserEnumeration({});
      expect(details).to.deep.equal([]);
    });

    it("checkActionsHardCodedValues does not throw", async function () {
      const { details } = await checkActionsHardCodedValues({});
      expect(details).to.deep.equal([]);
    });

    it("checkPasswordResetMFA does not throw", async function () {
      const { details } = await checkPasswordResetMFA({
        databases: [{ strategy: "auth0", options: {} }],
      });
      expect(details).to.be.an("array");
    });
  });

  describe("checkWebOrigins", function () {
    it("returns no findings when there are no clients", async function () {
      const { details } = await checkWebOrigins({});
      expect(details).to.deep.equal([]);
    });
  });
});

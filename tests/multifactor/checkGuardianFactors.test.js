const chai = require("chai");
const expect = chai.expect;

const checkGuardianFactors = require("../../analyzer/lib/multifactor/checkGuardianFactors");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkGuardianFactors", function () {
  it("should return fail when no MFA factors are enabled", function () {
    const options = {
      guardianFactors: [
        { name: "sms", enabled: false, trial_expired: false },
        { name: "push-notification", enabled: false, trial_expired: false },
        { name: "otp", enabled: false, trial_expired: false },
        { name: "email", enabled: false, trial_expired: false },
        { name: "duo", enabled: false, trial_expired: false },
        { name: "webauthn-roaming", enabled: false, trial_expired: false },
        { name: "webauthn-platform", enabled: false, trial_expired: false },
        { name: "recovery-code", enabled: false, trial_expired: false },
      ],
    };

    checkGuardianFactors(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "mfa_factors_not_enabled",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return success when one MFA factor is enabled", function () {
    const options = {
      guardianFactors: [
        { name: "sms", enabled: false, trial_expired: false },
        { name: "push-notification", enabled: false, trial_expired: false },
        { name: "otp", enabled: true, trial_expired: false }, // enabled factor
        { name: "email", enabled: false, trial_expired: false },
        { name: "duo", enabled: false, trial_expired: false },
        { name: "webauthn-roaming", enabled: false, trial_expired: false },
        { name: "webauthn-platform", enabled: false, trial_expired: false },
        { name: "recovery-code", enabled: false, trial_expired: false },
      ],
    };

    checkGuardianFactors(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "mfa_factors_enabled",
          value: "otp",
          status: CONSTANTS.SUCCESS,
        },
      ]);
    });
  });

  it("should return success when multiple MFA factors are enabled", function () {
    const options = {
      guardianFactors: [
        { name: "sms", enabled: true, trial_expired: false },
        { name: "push-notification", enabled: false, trial_expired: false },
        { name: "otp", enabled: true, trial_expired: false }, // enabled factor
        { name: "email", enabled: false, trial_expired: false },
        { name: "duo", enabled: false, trial_expired: false },
        { name: "webauthn-roaming", enabled: false, trial_expired: false },
        { name: "webauthn-platform", enabled: false, trial_expired: false },
        { name: "recovery-code", enabled: false, trial_expired: false },
      ],
    };

    checkGuardianFactors(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "mfa_factors_enabled",
          value: "smsotp", // concatenated list of enabled factors
          status: CONSTANTS.SUCCESS,
        },
      ]);
    });
  });

  it("should return fail when no guardianFactors are provided", function () {
    const options = {};

    checkGuardianFactors(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "mfa_factors_not_enabled",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });
});

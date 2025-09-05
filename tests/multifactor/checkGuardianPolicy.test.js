const chai = require("chai");
const expect = chai.expect;

const checkGuardianPolicy = require("../../analyzer/lib/multifactor/checkGuardianPolicy");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkGuardianPolicy", function () {
  it("should return fail when guardianPolicies.policies is empty", function () {
    const options = { guardianPolicies: { policies: [] } };

    checkGuardianPolicy(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "mfa_policy_set_to_never",
          value: "never",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return success when guardianPolicies.policies has a value", function () {
    const options = { guardianPolicies: { policies: ["all-applications"] } };

    checkGuardianPolicy(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "mfa_policy_set",
          value: "enabled",
          status: CONSTANTS.SUCCESS,
        },
      ]);
    });
  });

  it("should return fail when guardianPolicies is not provided", function () {
    const options = {};

    checkGuardianPolicy(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "mfa_policy_set_to_never",
          value: "never",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });
});

const chai = require("chai");
const expect = chai.expect;

const checkGuardianPolicy = require("../../analyzer/lib/multifactor/checkGuardianPolicy");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkGuardianPolicy", function () {
  it("should return fail when guardianPolicies.policies is empty", async function () {
    const options = { guardianPolicies: [] };

    const { details: report } = await checkGuardianPolicy(options);
    expect(report).to.deep.equal([
      {
        field: "mfa_policy_set_to_never",
        value: "Never",
        status: CONSTANTS.FAIL,
      },
    ]);
  });

  it("should return success when guardianPolicies.policies has a value", async function () {
    const options = { guardianPolicies: ["all-applications"] };

    const { details: report } = await checkGuardianPolicy(options);
    expect(report).to.deep.equal([
      {
        field: "mfa_policy_set",
        value: "Always",
        status: CONSTANTS.SUCCESS,
      },
    ]);
  });

  it("should return fail when guardianPolicies is not provided", async function () {
    const options = {};

    const { details: report } = await checkGuardianPolicy(options);
    expect(report).to.deep.equal([
      {
        field: "mfa_policy_set_to_never",
        value: "Never",
        status: CONSTANTS.FAIL,
      },
    ]);
  });
});

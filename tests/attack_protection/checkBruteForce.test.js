const { expect } = require("chai");
const checkBruteForce = require("../../analyzer/lib/attack_protection/checkBruteForce");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkBruteForce", function () {
  it("should return success when brute force protection is enabled and correctly configured", async function () {
    const options = {
      attackProtection: {
        bruteForceProtection: {
          enabled: true,
          shields: ["block", "user_notification"],
          mode: "count_per_identifier_and_ip",
          allowlist: [],
          max_attempts: 3,
        },
      },
    };

    const { details: report } = await checkBruteForce(options);
    // Check if the report contains expected success statuses
    expect(report).to.deep.include({
      field: "enabled",
      status: CONSTANTS.SUCCESS,
    });
    expect(report).to.deep.include({
      field: "shieldsConfigured",
      status: CONSTANTS.SUCCESS,
    });
    expect(report).to.deep.include({
      field: "allowlistEmpty",
      status: CONSTANTS.SUCCESS,
    });
  });

  // BUG: stageMaxAttempts report entry not implemented in check (fix in PR 4)
  it.skip("should report the configured max_attempts when brute force protection is enabled", async function () {
    const options = {
      attackProtection: {
        bruteForceProtection: {
          enabled: true,
          shields: ["block", "user_notification"],
          mode: "count_per_identifier_and_ip",
          allowlist: [],
          max_attempts: 3,
        },
      },
    };

    const { details: report } = await checkBruteForce(options);
    expect(report).to.deep.include({
      field: "stageMaxAttempts",
      status: CONSTANTS.SUCCESS,
      value: 3,
    });
  });

  it("should return failure when brute force protection is disabled", async function () {
    const options = {
      attackProtection: {
        bruteForceProtection: {
          enabled: false,
          shields: ["block"],
          mode: "count_per_identifier_and_ip",
          allowlist: [],
          max_attempts: 3,
        },
      },
    };

    const { details: report } = await checkBruteForce(options);
    expect(report).to.deep.include({
      field: "disabled",
      status: CONSTANTS.FAIL,
    });
  });

  it("should return failure when shields have missing values", async function () {
    const options = {
      attackProtection: {
        bruteForceProtection: {
          enabled: true,
          shields: ["block"], // Missing "user_notification"
          mode: "count_per_identifier_and_ip",
          allowlist: [],
          max_attempts: 3,
        },
      },
    };

    const { details: report } = await checkBruteForce(options);
    expect(report).to.deep.include({
      field: "shieldsMissing",
      status: CONSTANTS.FAIL,
      value: "user_notification",
    });
  });

  it("should return failure when allowlist is not empty", async function () {
    const options = {
      attackProtection: {
        bruteForceProtection: {
          enabled: true,
          shields: ["block", "user_notification"],
          mode: "count_per_identifier_and_ip",
          allowlist: ["127.0.0.1"],
          max_attempts: 3,
        },
      },
    };

    const { details: report } = await checkBruteForce(options);
    expect(report).to.deep.include({
      field: "allowlistPresent",
      status: CONSTANTS.FAIL,
      value: "127.0.0.1",
    });
  });

  // BUG: stage max_attempts/rate validation (stageMaxAttemptsInvalid, stageRateInvalid, stageRate) not implemented in check (fix in PR 4)
  it.skip("should return failure when max_attempts is less than or equal to 0", async function () {
    const options = {
      attackProtection: {
        bruteForceProtection: {
          enabled: true,
          shields: ["block", "user_notification"],
          mode: "count_per_identifier_and_ip",
          allowlist: [],
          max_attempts: 0, // Invalid value
        },
      },
    };

    const { details: report } = await checkBruteForce(options);
    expect(report).to.deep.include({
      field: "stageMaxAttemptsInvalid",
      status: CONSTANTS.FAIL,
      value: 0,
    });
  });

  // BUG: stage max_attempts/rate validation (stageMaxAttemptsInvalid, stageRateInvalid, stageRate) not implemented in check (fix in PR 4)
  it.skip("should return failure when rate is less than or equal to 0", async function () {
    const options = {
      attackProtection: {
        bruteForceProtection: {
          enabled: true,
          shields: ["block", "user_notification"],
          mode: "count_per_identifier_and_ip",
          allowlist: [],
          max_attempts: 3,
          stage: {
            "pre-user-registration": {
              rate: 0, // Invalid value
            },
          },
        },
      },
    };

    const { details: report } = await checkBruteForce(options);
    expect(report).to.deep.include({
      field: "stageRateInvalid",
      status: CONSTANTS.FAIL,
      value: 0,
    });
  });

  // BUG: stage max_attempts/rate validation (stageMaxAttemptsInvalid, stageRateInvalid, stageRate) not implemented in check (fix in PR 4)
  it.skip("should return success when rate is valid", async function () {
    const options = {
      attackProtection: {
        bruteForceProtection: {
          enabled: true,
          shields: ["block", "user_notification"],
          mode: "count_per_identifier_and_ip",
          allowlist: [],
          max_attempts: 3,
          stage: {
            "pre-user-registration": {
              rate: 5, // Valid value
            },
          },
        },
      },
    };

    const { details: report } = await checkBruteForce(options);
    expect(report).to.deep.include({
      field: "stageRate",
      status: CONSTANTS.SUCCESS,
      value: 5,
    });
  });
});

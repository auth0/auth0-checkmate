const { expect } = require("chai");
const checkBruteForce = require("../../analyzer/lib/attack_protection/checkBruteForce");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkBruteForce", function () {
  it("should return success when brute force protection is enabled and correctly configured", function () {
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

    checkBruteForce(options, (report) => {
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
      expect(report).to.deep.include({
        field: "stageMaxAttempts",
        status: CONSTANTS.SUCCESS,
        value: 3,
      });
    });
  });

  it("should return failure when brute force protection is disabled", function () {
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

    checkBruteForce(options, (report) => {
      expect(report).to.deep.include({
        field: "disabled",
        status: CONSTANTS.FAIL,
      });
    });
  });

  it("should return failure when shields have missing values", function () {
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

    checkBruteForce(options, (report) => {
      expect(report).to.deep.include({
        field: "shieldsMissing",
        status: CONSTANTS.FAIL,
        value: "user_notification",
      });
    });
  });

  it("should return failure when allowlist is not empty", function () {
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

    checkBruteForce(options, (report) => {
      expect(report).to.deep.include({
        field: "allowlistPresent",
        status: CONSTANTS.FAIL,
        value: "127.0.0.1",
      });
    });
  });

  it("should return failure when max_attempts is less than or equal to 0", function () {
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

    checkBruteForce(options, (report) => {
      expect(report).to.deep.include({
        field: "stageMaxAttemptsInvalid",
        status: CONSTANTS.FAIL,
        value: 0,
      });
    });
  });

  it("should return failure when rate is less than or equal to 0", function () {
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

    checkBruteForce(options, (report) => {
      expect(report).to.deep.include({
        field: "stageRateInvalid",
        status: CONSTANTS.FAIL,
        value: 0,
      });
    });
  });

  it("should return success when rate is valid", function () {
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

    checkBruteForce(options, (report) => {
      expect(report).to.deep.include({
        field: "stageRate",
        status: CONSTANTS.SUCCESS,
        value: 5,
      });
    });
  });
});

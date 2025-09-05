const { expect } = require("chai");
const checkSuspiciousIPThrottling = require("../../analyzer/lib/attack_protection/checkSuspiciousIPThrottling");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkSuspiciousIPThrottling", function () {
  it("should return success when suspicious IP throttling is enabled and correctly configured", function () {
    const options = {
      attackProtection: {
        suspiciousIpThrottling: {
          enabled: true,
          shields: ["admin_notification", "block"],
          allowlist: [],
          stage: {
            "pre-login": {
              max_attempts: 100,
              rate: 864000,
            },
            "pre-user-registration": {
              max_attempts: 50,
              rate: 1200,
            },
          },
        },
      },
    };

    checkSuspiciousIPThrottling(options, (report) => {
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
  });

  it("should return failure when suspicious IP throttling is disabled", function () {
    const options = {
      attackProtection: {
        suspiciousIpThrottling: {
          enabled: false,
          shields: ["block"],
          allowlist: [],
          stage: {
            "pre-login": {
              max_attempts: 100,
              rate: 864000,
            },
            "pre-user-registration": {
              max_attempts: 50,
              rate: 1200,
            },
          },
        },
      },
    };

    checkSuspiciousIPThrottling(options, (report) => {
      expect(report).to.deep.include({
        field: "disabled",
        status: CONSTANTS.FAIL,
      });
    });
  });

  it("should return failure when shields are missing values", function () {
    const options = {
      attackProtection: {
        suspiciousIpThrottling: {
          enabled: true,
          shields: ["block"], // Missing "admin_notification"
          allowlist: [],
          stage: {
            "pre-login": {
              max_attempts: 100,
              rate: 864000,
            },
            "pre-user-registration": {
              max_attempts: 50,
              rate: 1200,
            },
          },
        },
      },
    };

    checkSuspiciousIPThrottling(options, (report) => {
      expect(report).to.deep.include({
        field: "shieldsMissing",
        status: CONSTANTS.FAIL,
        value: "admin_notification",
      });
    });
  });

  it("should return failure when allowlist is not empty", function () {
    const options = {
      attackProtection: {
        suspiciousIpThrottling: {
          enabled: true,
          shields: ["block", "admin_notification"],
          allowlist: ["192.168.0.1"],
          stage: {
            "pre-login": {
              max_attempts: 100,
              rate: 864000,
            },
            "pre-user-registration": {
              max_attempts: 50,
              rate: 1200,
            },
          },
        },
      },
    };

    checkSuspiciousIPThrottling(options, (report) => {
      expect(report).to.deep.include({
        field: "allowlistPresent",
        status: CONSTANTS.FAIL,
        value: "192.168.0.1",
      });
    });
  });

  it("should return failure when max_attempts is less than or equal to 0", function () {
    const options = {
      attackProtection: {
        suspiciousIpThrottling: {
          enabled: true,
          shields: ["block", "admin_notification"],
          allowlist: [],
          stage: {
            "pre-login": {
              max_attempts: 0, // Invalid value
              rate: 864000,
            },
            "pre-user-registration": {
              max_attempts: 50,
              rate: 1200,
            },
          },
        },
      },
    };

    checkSuspiciousIPThrottling(options, (report) => {
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
        suspiciousIpThrottling: {
          enabled: true,
          shields: ["block", "admin_notification"],
          allowlist: [],
          stage: {
            "pre-login": {
              max_attempts: 100,
              rate: 0, // Invalid value
            },
            "pre-user-registration": {
              max_attempts: 50,
              rate: 1200,
            },
          },
        },
      },
    };

    checkSuspiciousIPThrottling(options, (report) => {
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
        suspiciousIpThrottling: {
          enabled: true,
          shields: ["block", "admin_notification"],
          allowlist: [],
          stage: {
            "pre-login": {
              max_attempts: 100,
              rate: 864000, // Valid value
            },
            "pre-user-registration": {
              max_attempts: 50,
              rate: 1200,
            },
          },
        },
      },
    };

    checkSuspiciousIPThrottling(options, (report) => {
      expect(report).to.deep.include({
        field: "stageRate",
        status: CONSTANTS.SUCCESS,
        value: 864000,
      });
    });
  });
});

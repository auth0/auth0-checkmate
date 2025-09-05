const { expect } = require("chai");
const checkBreachedPassword = require("../../analyzer/lib/attack_protection/checkBreachedPassword");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkBreachedPassword", function () {
  it("should return a success when breachedPasswordDetection is enabled and correctly configured", function () {
    const options = {
      attackProtection: {
        breachedPasswordDetection: {
          enabled: true,
          shields: ["user_notification", "admin_notification", "block"],
          admin_notification_frequency: ["daily", "weekly"],
          method: "standard",
          stage: {
            "pre-user-registration": {
              shields: ["block", "admin_notification"],
            },
            "pre-change-password": {
              shields: ["block"],
            },
          },
        },
      },
    };

    checkBreachedPassword(options, (report) => {
      // Check if the report contains the expected success statuses for all fields
      expect(report).to.deep.include({
        field: "enabled",
        status: CONSTANTS.SUCCESS,
      });
      expect(report).to.deep.include({
        field: "shields_values",
        status: CONSTANTS.SUCCESS,
      });
      expect(report).to.deep.include({
        field: "admin_frequency_values",
        status: CONSTANTS.SUCCESS,
      });
      expect(report).to.deep.include({
        field: "method_value",
        status: CONSTANTS.SUCCESS,
      });
      expect(report).to.deep.include({
        field: "stage_pre_user_shields",
        status: CONSTANTS.SUCCESS,
      });
      expect(report).to.deep.include({
        field: "stage_pre_change_password_shields",
        status: CONSTANTS.SUCCESS,
      });
    });
  });

  it("should return failure when breachedPasswordDetection is disabled", function () {
    const options = {
      attackProtection: {
        breachedPasswordDetection: {
          enabled: false,
          shields: ["user_notification"],
          admin_notification_frequency: ["daily"],
          method: "standard",
          stage: {
            "pre-user-registration": {
              shields: ["block"],
            },
            "pre-change-password": {
              shields: ["block"],
            },
          },
        },
      },
    };

    checkBreachedPassword(options, (report) => {
      expect(report).to.deep.include({
        field: "disabled",
        status: CONSTANTS.FAIL,
      });
    });
  });

  it("should return failure when shields have invalid values", function () {
    const options = {
      attackProtection: {
        breachedPasswordDetection: {
          enabled: true,
          shields: ["user_notification", "invalid_shield"],
          admin_notification_frequency: ["daily"],
          method: "standard",
          stage: {
            "pre-user-registration": {
              shields: ["block"],
            },
          },
        },
      },
    };

    checkBreachedPassword(options, (report) => {
      expect(report).to.deep.include({
        field: "shields_invalid_values",
        status: CONSTANTS.FAIL,
      });
    });
  });

  it("should return failure when admin_notification_frequency has invalid values", function () {
    const options = {
      attackProtection: {
        breachedPasswordDetection: {
          enabled: true,
          shields: ["user_notification"],
          admin_notification_frequency: ["invalid_frequency"],
          method: "standard",
          stage: {
            "pre-user-registration": {
              shields: ["block"],
            },
          },
        },
      },
    };

    checkBreachedPassword(options, (report) => {
      expect(report).to.deep.include({
        field: "admin_frequency_invalid_values",
        status: CONSTANTS.FAIL,
      });
    });
  });

  it("should return failure when method is invalid", function () {
    const options = {
      attackProtection: {
        breachedPasswordDetection: {
          enabled: true,
          shields: ["user_notification"],
          admin_notification_frequency: ["daily"],
          method: "invalid_method",
          stage: {
            "pre-user-registration": {
              shields: ["block"],
            },
          },
        },
      },
    };

    checkBreachedPassword(options, (report) => {
      expect(report).to.deep.include({
        field: "method_invalid_value",
        status: CONSTANTS.FAIL,
      });
    });
  });

  it("should return failure when pre-user-registration stage is missing or incorrectly configured", function () {
    const options = {
      attackProtection: {
        breachedPasswordDetection: {
          enabled: true,
          shields: ["user_notification"],
          admin_notification_frequency: ["daily"],
          method: "standard",
          stage: {},
        },
      },
    };

    checkBreachedPassword(options, (report) => {
      expect(report).to.deep.include({
        field: "stage_pre_user_missing",
        status: CONSTANTS.FAIL,
      });
    });
  });

  it("should return failure when pre-user-registration shields are not configured", function () {
    const options = {
      attackProtection: {
        breachedPasswordDetection: {
          enabled: true,
          shields: ["user_notification"],
          admin_notification_frequency: ["daily"],
          method: "standard",
          stage: {
            "pre-user-registration": {
              shields: [],
            },
          },
        },
      },
    };

    checkBreachedPassword(options, (report) => {
      expect(report).to.deep.include({
        field: "stage_pre_user_shields_not_configured",
        status: CONSTANTS.FAIL,
      });
    });
  });

  it("should return failure when pre-change-password shields are not configured", function () {
    const options = {
      attackProtection: {
        breachedPasswordDetection: {
          enabled: true,
          shields: ["user_notification"],
          admin_notification_frequency: ["daily"],
          method: "standard",
          stage: {
            "pre-change-password": {
              shields: [],
            },
          },
        },
      },
    };

    checkBreachedPassword(options, (report) => {
      expect(report).to.deep.include({
        field: "stage_pre_change_password_shields_not_configured",
        status: CONSTANTS.FAIL,
      });
    });
  });

  it("should return failure if shields are empty but monitoring mode is enabled", function () {
    const options = {
      attackProtection: {
        breachedPasswordDetection: {
          enabled: true,
          shields: [],
          admin_notification_frequency: ["daily"],
          method: "standard",
          stage: {
            "pre-user-registration": {
              shields: ["block"],
            },
          },
        },
      },
    };

    checkBreachedPassword(options, (report) => {
      expect(report).to.deep.include({
        field: "monitoring_mode",
        status: CONSTANTS.FAIL,
      });
    });
  });
});

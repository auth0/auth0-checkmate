const { expect } = require("chai");
const checkBreachedPassword = require("../../analyzer/lib/attack_protection/checkBreachedPassword");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkBreachedPassword", function () {
  it("should return a success when breachedPasswordDetection is enabled and correctly configured", async function () {
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

    const { details: report } = await checkBreachedPassword(options);
    // Check if the report contains the expected success statuses for all fields
    expect(report).to.deep.include({
      field: "enabled",
      status: CONSTANTS.SUCCESS,
    });
    expect(report).to.deep.include({
      field: "shields_values",
      value: "user_notification, admin_notification, block",
      status: CONSTANTS.SUCCESS,
    });
    expect(report).to.deep.include({
      field: "admin_frequency_values",
      value: "daily, weekly",
      status: CONSTANTS.SUCCESS,
    });
    expect(report).to.deep.include({
      field: "method_value",
      value: "standard",
      status: CONSTANTS.SUCCESS,
    });
    // Correctly configured stages produce no failures
    expect(report.filter((r) => r.status === CONSTANTS.FAIL)).to.be.empty;
  });

  it("should return failure when breachedPasswordDetection is disabled", async function () {
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

    const { details: report } = await checkBreachedPassword(options);
    expect(report).to.deep.include({
      field: "disabled",
      status: CONSTANTS.FAIL,
    });
  });

  it("should return failure when shields have invalid values", async function () {
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

    const { details: report } = await checkBreachedPassword(options);
    expect(report).to.deep.include({
      field: "shields_invalid_values",
      status: CONSTANTS.FAIL,
    });
  });

  it("should return failure when admin_notification_frequency has invalid values", async function () {
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

    const { details: report } = await checkBreachedPassword(options);
    expect(report).to.deep.include({
      field: "admin_frequency_invalid_values",
      value: "invalid_frequency",
      status: CONSTANTS.FAIL,
    });
  });

  it("should return failure when method is invalid", async function () {
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

    const { details: report } = await checkBreachedPassword(options);
    expect(report).to.deep.include({
      field: "method_invalid_value",
      status: CONSTANTS.FAIL,
    });
  });

  it("should not report pre-user-registration failures when the stage is missing", async function () {
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

    const { details: report } = await checkBreachedPassword(options);
    expect(report.map((r) => r.field)).to.not.include.members([
      "stage_pre_user_missing",
      "stage_pre_user_shields_block_not_configured",
    ]);
  });

  it("should return failure when pre-user-registration shields do not include block", async function () {
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

    const { details: report } = await checkBreachedPassword(options);
    expect(report).to.deep.include({
      field: "stage_pre_user_shields_block_not_configured",
      status: CONSTANTS.FAIL,
    });
  });

  it("should return failure when pre-change-password shields do not include block", async function () {
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

    const { details: report } = await checkBreachedPassword(options);
    expect(report).to.deep.include({
      field: "stage_pre_change_password_shields_block_not_configured",
      status: CONSTANTS.FAIL,
    });
  });

  it("should return failure if shields are empty but monitoring mode is enabled", async function () {
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

    const { details: report } = await checkBreachedPassword(options);
    expect(report).to.deep.include({
      field: "monitoring_mode",
      status: CONSTANTS.FAIL,
    });
  });
});

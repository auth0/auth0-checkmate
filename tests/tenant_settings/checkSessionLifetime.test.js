const { expect } = require("chai");
const checkSessionLifetime = require("../../analyzer/lib/tenant_settings/checkSessionLifetime");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkSessionLifetime", () => {

  it("should report all fields with proper values", () => {
    const options = {
      tenant: {
        idle_session_lifetime: 72,
        session_lifetime: 168,
        session_cookie: {
          mode: "persistent",
        },
      },
    };

    checkSessionLifetime(options, (report) => {
      expect(report).to.deep.include.members([
        {
          field: "idle_session_lifetime",
          value: "72h",
          status: CONSTANTS.FAIL,
        },
        {
          field: "session_lifetime",
          value: "168h",
          status: CONSTANTS.FAIL,
        },
        {
          field: "session_cookie_mode",
          value: "persistent",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return fail if tenant is missing", () => {
    checkSessionLifetime({}, (report) => {
      expect(report).to.deep.equal([
        {
          field: "tenant_setting_missing",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should report default values if idle_session_lifetime and session_lifetime are missing", () => {
    const options = {
      tenant: {
        session_cookie: {
          mode: "persistent",
        },
      },
    };

    checkSessionLifetime(options, (report) => {
      expect(report).to.deep.include.members([
        {
          field: "idle_session_lifetime",
          value: CONSTANTS.DEFAULT_IDLE_SESSION_LIFETIME,
          status: CONSTANTS.FAIL,
        },
        {
          field: "session_lifetime",
          value: CONSTANTS.DEFAULT_SESSION_LIFETIME,
          status: CONSTANTS.FAIL,
        },
        {
          field: "session_cookie_mode",
          value: "persistent",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should report default session_cookie_mode if session_cookie is missing", () => {
    const options = {
      tenant: {
        idle_session_lifetime: 24,
        session_lifetime: 48,
      },
    };

    checkSessionLifetime(options, (report) => {
      expect(report).to.deep.include.members([
        {
          field: "session_cookie_mode",
          value: CONSTANTS.DEFAULT_SESSION_COOKIE_MODE,
          status: CONSTANTS.FAIL,
        },
        {
          field: "idle_session_lifetime",
          value: "24h",
          status: CONSTANTS.FAIL,
        },
        {
          field: "session_lifetime",
          value: "48h",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });
});

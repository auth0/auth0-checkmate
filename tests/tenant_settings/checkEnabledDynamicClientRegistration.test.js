const chai = require("chai");
const expect = chai.expect;

const checkReg = require("../../analyzer/lib/tenant_settings/checkEnabledDynamicClientRegistration");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkReg", function () {
    it("should return fail when input is not set (null or empty)", function () {
        const options = {
            tenant: {
            },
        };

        checkReg(options, (report) => {
            expect(report).to.deep.equal([
                {
                    field: "tenant_setting_missing",
                    status: CONSTANTS.FAIL,
                },
            ]);
        });
    });

    it("should return fail when flag.enable_dynamic_client_registration attribute not present", function () {
        const options = {
            tenant: {
                "flags": {
                    "allow_changing_enable_sso": true,
                    "disable_impersonation": true,
                    "enable_sso": true,
                    "universal_login": true,
                    "revoke_refresh_token_grant": false,
                    "disable_clickjack_protection_headers": false
                },
            },
        };

        checkReg(options, (report) => {
            expect(report).to.deep.equal([
                {
                    field: "enable_dynamic_client_registration",
                    status: CONSTANTS.FAIL,
                },
            ]);
        });
    });

    it("should return fail when flag.enable_dynamic_client_registration attribute is present with false ", function () {
        const options = {
            tenant: {
                "flags": {
                    "allow_changing_enable_sso": true,
                    "disable_impersonation": true,
                    "enable_sso": true,
                    "universal_login": true,
                    "enable_dynamic_client_registration": false,
                    "revoke_refresh_token_grant": false,
                    "disable_clickjack_protection_headers": false
                },
            },
        };

        checkReg(options, (report) => {
            expect(report).to.deep.equal([
                {
                    field: "enable_dynamic_client_registration",
                    status: CONSTANTS.FAIL,
                },
            ]);
        });
    });

    it("should return success when flag.enable_dynamic_client_registration attribute is present with true", function () {
        const options = {
            tenant: {
                "flags": {
                    "allow_changing_enable_sso": true,
                    "disable_impersonation": true,
                    "enable_sso": true,
                    "universal_login": true,
                    "enable_dynamic_client_registration": true,
                    "revoke_refresh_token_grant": false,
                    "disable_clickjack_protection_headers": false
                },
            },
        };

        checkReg(options, (report) => {
            expect(report).to.deep.equal([
                {
                    field: "enabled_dynamic_client_registration",
                    status: CONSTANTS.SUCCESS,
                },
            ]);
        });
    });
});

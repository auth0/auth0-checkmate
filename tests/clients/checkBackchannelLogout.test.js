const chai = require("chai");
const expect = chai.expect;

const checkBackchannelLogout = require("../../analyzer/lib/clients/checkBackchannelLogout");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkBackchannelLogout", function () {

    it("should return an empty report when no clients are provided", function () {
        const options = { clients: [] };
        checkBackchannelLogout(options).then((result) => {
            expect(result.details).to.be.an("array").that.is.empty;
        });
    });

    it("should skip global clients", function () {
        const options = {
            clients: [{
                name: "All Applications",
                client_id: "global_client",
                global: true,
                app_type: "regular_web",
                is_first_party: true,
            }],
        };

        checkBackchannelLogout(options).then((result) => {
            expect(result.details).to.be.an("array").that.is.empty;
        });
    });

    it("should skip SPA clients", function () {
        const options = {
            clients: [{
                name: "SPA App",
                client_id: "client_spa",
                global: false,
                is_first_party: true,
                app_type: "spa",
                grant_types: ["authorization_code", "refresh_token"],
            }],
        };

        checkBackchannelLogout(options).then((result) => {
            expect(result.details).to.be.an("array").that.is.empty;
        });
    });

    it("should skip native clients", function () {
        const options = {
            clients: [{
                name: "Mobile App",
                client_id: "client_native",
                global: false,
                is_first_party: true,
                app_type: "native",
                grant_types: ["authorization_code", "refresh_token"],
            }],
        };

        checkBackchannelLogout(options).then((result) => {
            expect(result.details).to.be.an("array").that.is.empty;
        });
    });

    it("should skip non_interactive (M2M) clients", function () {
        const options = {
            clients: [{
                name: "M2M App",
                client_id: "client_m2m",
                global: false,
                is_first_party: true,
                app_type: "non_interactive",
                grant_types: ["client_credentials"],
            }],
        };

        checkBackchannelLogout(options).then((result) => {
            expect(result.details).to.be.an("array").that.is.empty;
        });
    });

    it("should report failure for a regular_web app without back-channel logout configured", function () {
        const options = {
            clients: [{
                name: "Web App",
                client_id: "client_web",
                global: false,
                is_first_party: true,
                app_type: "regular_web",
                grant_types: ["authorization_code", "refresh_token"],
            }],
        };

        checkBackchannelLogout(options).then((result) => {
            expect(result.details).to.be.an("array").with.lengthOf(1);
            expect(result.details[0].name).to.equal("Web App (client_web)");
            expect(result.details[0].report).to.be.an("array").with.lengthOf(1);
            expect(result.details[0].report[0]).to.include({
                field: "oidc_backchannel_logout.backchannel_logout_urls",
                status: CONSTANTS.FAIL,
                value: "not_configured",
            });
        });
    });

    it("should report success for a regular_web app with oidc_backchannel_logout configured", function () {
        const options = {
            clients: [{
                name: "backchannellogout",
                client_id: "client_bcl",
                global: false,
                is_first_party: true,
                app_type: "regular_web",
                grant_types: ["authorization_code", "refresh_token"],
                oidc_backchannel_logout: {
                    backchannel_logout_initiators: { mode: "all" },
                    backchannel_logout_urls: ["https://example.com/backchannel-logout"],
                },
            }],
        };

        checkBackchannelLogout(options).then((result) => {
            expect(result.details).to.be.an("array").with.lengthOf(1);
            expect(result.details[0].name).to.equal("backchannellogout (client_bcl)");
            expect(result.details[0].report[0]).to.include({
                field: "oidc_backchannel_logout.backchannel_logout_urls",
                status: CONSTANTS.SUCCESS,
            });
        });
    });

    it("should report success for a regular_web app with oidc_logout configured", function () {
        const options = {
            clients: [{
                name: "Web App OIDC Logout",
                client_id: "client_oidc_logout",
                global: false,
                is_first_party: true,
                app_type: "regular_web",
                grant_types: ["authorization_code", "refresh_token"],
                oidc_logout: {
                    backchannel_logout_initiators: { mode: "all" },
                    backchannel_logout_urls: ["https://example.com/backchannel-logout"],
                },
            }],
        };

        checkBackchannelLogout(options).then((result) => {
            expect(result.details).to.be.an("array").with.lengthOf(1);
            expect(result.details[0].report[0]).to.include({
                field: "oidc_backchannel_logout.backchannel_logout_urls",
                status: CONSTANTS.SUCCESS,
            });
        });
    });

    it("should report failure when oidc_backchannel_logout has empty backchannel_logout_urls", function () {
        const options = {
            clients: [{
                name: "Partial Config App",
                client_id: "client_partial",
                global: false,
                is_first_party: true,
                app_type: "regular_web",
                grant_types: ["authorization_code"],
                oidc_backchannel_logout: {
                    backchannel_logout_initiators: { mode: "all" },
                    backchannel_logout_urls: [],
                },
            }],
        };

        checkBackchannelLogout(options).then((result) => {
            expect(result.details).to.be.an("array").with.lengthOf(1);
            expect(result.details[0].report[0]).to.include({
                field: "oidc_backchannel_logout.backchannel_logout_urls",
                status: CONSTANTS.FAIL,
                value: "not_configured",
            });
        });
    });

    it("should handle a mix of regular_web and non-eligible clients correctly", function () {
        const options = {
            clients: [
                {
                    name: "SPA",
                    client_id: "client_spa",
                    global: false,
                    is_first_party: true,
                    app_type: "spa",
                    grant_types: ["authorization_code"],
                },
                {
                    name: "Web App",
                    client_id: "client_web",
                    global: false,
                    is_first_party: true,
                    app_type: "regular_web",
                    grant_types: ["authorization_code", "refresh_token"],
                    oidc_backchannel_logout: {
                        backchannel_logout_initiators: { mode: "all" },
                        backchannel_logout_urls: ["https://example.com/backchannel-logout"],
                    },
                },
            ],
        };

        checkBackchannelLogout(options).then((result) => {
            // Only the regular_web client should appear
            expect(result.details).to.be.an("array").with.lengthOf(1);
            expect(result.details[0].name).to.equal("Web App (client_web)");
            expect(result.details[0].report[0]).to.include({
                status: CONSTANTS.SUCCESS,
            });
        });
    });
});

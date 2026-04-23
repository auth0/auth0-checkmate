const chai = require("chai");
const expect = chai.expect;

const checkPAR = require("../../analyzer/lib/clients/checkPAR");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkPAR", function() {

    it("should report failure if authorization_code grant is used and PAR is not required", function() {
        const options = {
            clients: [{
                name: "Web App",
                client_id: "client_web",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["authorization_code"],
                require_pushed_authorization_requests: false,
            }]
        };

        checkPAR(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].name).to.equal("Web App (client_web)");
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                name: "Web App (client_web)",
                client_id: "client_web",
                field: "require_pushed_authorization_requests",
                status: CONSTANTS.FAIL,
                value: false,
            });
        });
    });

    it("should report failure if require_pushed_authorization_requests field is absent", function() {
        const options = {
            clients: [{
                name: "HRI App",
                client_id: "client_hri",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["authorization_code", "refresh_token"],
            }]
        };

        checkPAR(options, (result) => {
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                field: "require_pushed_authorization_requests",
                status: CONSTANTS.FAIL,
                value: false,
            });
        });
    });

    it("should return empty report if PAR is required", function() {
        const options = {
            clients: [{
                name: "Secure HRI App",
                client_id: "client_secure",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["authorization_code", "refresh_token"],
                require_pushed_authorization_requests: true,
            }]
        };

        checkPAR(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].name).to.equal("Secure HRI App (client_secure)");
            expect(result[0].report).to.be.an("array").that.is.empty;
        });
    });

    it("should not flag SPA clients because public clients are not supported on the PAR endpoint", function() {
        const options = {
            clients: [{
                name: "SPA App",
                client_id: "client_spa",
                app_type: "spa",
                is_first_party: true,
                grant_types: ["authorization_code", "implicit", "refresh_token"],
                require_pushed_authorization_requests: false,
            }]
        };

        checkPAR(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].report).to.be.an("array").that.is.empty;
        });
    });

    it("should not flag native clients because public clients are not supported on the PAR endpoint", function() {
        const options = {
            clients: [{
                name: "Mobile App",
                client_id: "client_native",
                app_type: "native",
                is_first_party: true,
                grant_types: ["authorization_code", "refresh_token"],
                require_pushed_authorization_requests: false,
            }]
        };

        checkPAR(options, (result) => {
            expect(result[0].report).to.be.an("array").that.is.empty;
        });
    });

    it("should not flag clients with token_endpoint_auth_method of none (public client)", function() {
        const options = {
            clients: [{
                name: "Public Client App",
                client_id: "client_public",
                app_type: "regular_web",
                is_first_party: true,
                token_endpoint_auth_method: "none",
                grant_types: ["authorization_code"],
                require_pushed_authorization_requests: false,
            }]
        };

        checkPAR(options, (result) => {
            expect(result[0].report).to.be.an("array").that.is.empty;
        });
    });

    it("should not flag clients using only client_credentials grant", function() {
        const options = {
            clients: [{
                name: "M2M App",
                client_id: "client_m2m",
                app_type: "non_interactive",
                is_first_party: true,
                grant_types: ["client_credentials"],
                require_pushed_authorization_requests: false,
            }]
        };

        checkPAR(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].report).to.be.an("array").that.is.empty;
        });
    });

    it("should not flag clients using only refresh_token grant", function() {
        const options = {
            clients: [{
                name: "Refresh Only App",
                client_id: "client_refresh",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["refresh_token"],
                require_pushed_authorization_requests: false,
            }]
        };

        checkPAR(options, (result) => {
            expect(result[0].report).to.be.an("array").that.is.empty;
        });
    });

    it("should return empty result if no clients are provided", function() {
        const options = { clients: [] };
        checkPAR(options, (result) => {
            expect(result).to.be.an("array").that.is.empty;
        });
    });
});

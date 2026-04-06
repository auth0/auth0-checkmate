const chai = require("chai");
const expect = chai.expect;

const checkDPoP = require("../../analyzer/lib/clients/checkDPoP");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkDPoP", function() {

    it("should report failure if authorization_code grant is used and DPoP is not required", function() {
        const options = {
            clients: [{
                name: "Web App",
                client_id: "client_web",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["authorization_code"],
                require_proof_of_possession: false,
            }]
        };

        checkDPoP(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].name).to.equal("Web App (client_web)");
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                name: "Web App (client_web)",
                client_id: "client_web",
                field: "require_proof_of_possession",
                status: CONSTANTS.FAIL,
                value: false,
            });
        });
    });

    it("should report failure if refresh_token grant is used and DPoP is not required", function() {
        const options = {
            clients: [{
                name: "SPA App",
                client_id: "client_spa",
                app_type: "spa",
                is_first_party: true,
                grant_types: ["authorization_code", "refresh_token"],
                require_proof_of_possession: false,
            }]
        };

        checkDPoP(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                field: "require_proof_of_possession",
                status: CONSTANTS.FAIL,
            });
        });
    });

    it("should report failure if require_proof_of_possession is absent", function() {
        const options = {
            clients: [{
                name: "Legacy App",
                client_id: "client_legacy",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["authorization_code"],
            }]
        };

        checkDPoP(options, (result) => {
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                field: "require_proof_of_possession",
                status: CONSTANTS.FAIL,
                value: false,
            });
        });
    });

    it("should return empty report if DPoP is required", function() {
        const options = {
            clients: [{
                name: "Secure App",
                client_id: "client_secure",
                app_type: "spa",
                is_first_party: true,
                grant_types: ["authorization_code", "refresh_token"],
                require_proof_of_possession: true,
            }]
        };

        checkDPoP(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].name).to.equal("Secure App (client_secure)");
            expect(result[0].report).to.be.an("array").that.is.empty;
        });
    });

    it("should not flag clients without DPoP-relevant grant types", function() {
        const options = {
            clients: [{
                name: "M2M App",
                client_id: "client_m2m",
                app_type: "non_interactive",
                is_first_party: true,
                grant_types: ["client_credentials"],
                require_proof_of_possession: false,
            }]
        };

        checkDPoP(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].report).to.be.an("array").that.is.empty;
        });
    });

    it("should return empty result if no clients are provided", function() {
        const options = { clients: [] };
        checkDPoP(options, (result) => {
            expect(result).to.be.an("array").that.is.empty;
        });
    });
});

const chai = require("chai");
const expect = chai.expect;

const checkDPoP = require("../../analyzer/lib/clients/checkDPoP");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkDPoP", function() {

    it("should report failure if authorization_code grant is used and Token Sender-Constraining is not enabled", function() {
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

    it("should report failure if refresh_token grant is used and Token Sender-Constraining is not enabled", function() {
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

    it("should report failure if Token Sender-Constraining is absent", function() {
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

    it("should return empty report if Token Sender-Constraining is enabled", function() {
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

    it("should report failure if client_credentials grant is used and Token Sender-Constraining is not enabled", function() {
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
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                field: "require_proof_of_possession",
                status: CONSTANTS.FAIL,
                value: false,
            });
        });
    });

    it("should report failure if password grant is used and Token Sender-Constraining is not enabled", function() {
        const options = {
            clients: [{
                name: "ROPC App",
                client_id: "client_ropc",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["password"],
                require_proof_of_possession: false,
            }]
        };

        checkDPoP(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                field: "require_proof_of_possession",
                status: CONSTANTS.FAIL,
                value: false,
            });
        });
    });

    it("should report failure if device_code grant is used and Token Sender-Constraining is not enabled", function() {
        const options = {
            clients: [{
                name: "Device App",
                client_id: "client_device",
                app_type: "native",
                is_first_party: true,
                grant_types: ["urn:ietf:params:oauth:grant-type:device_code"],
                require_proof_of_possession: false,
            }]
        };

        checkDPoP(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                field: "require_proof_of_possession",
                status: CONSTANTS.FAIL,
                value: false,
            });
        });
    });

    it("should not flag clients with only implicit grant type", function() {
        const options = {
            clients: [{
                name: "Legacy SPA",
                client_id: "client_implicit",
                app_type: "spa",
                is_first_party: true,
                grant_types: ["implicit"],
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

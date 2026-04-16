const chai = require("chai");
const expect = chai.expect;

const checkDPoPResourceServer = require("../../analyzer/lib/resource_servers/checkDPoPResourceServer");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkDPoPResourceServer", function() {

    it("should report failure when proof_of_possession is absent (not configured)", function() {
        const options = {
            resourceServers: [{
                id: "rs1",
                name: "Legacy API",
                identifier: "https://legacy-api.example.com",
                is_system: false,
            }]
        };

        checkDPoPResourceServer(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].name).to.equal("Legacy API (https://legacy-api.example.com)");
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                field: "proof_of_possession",
                status: CONSTANTS.FAIL,
                value: "not_configured",
            });
        });
    });

    it("should report failure when proof_of_possession mechanism is invalid", function() {
        const options = {
            resourceServers: [{
                id: "rs2",
                name: "Invalid Mechanism API",
                identifier: "https://invalid-mechanism-api.example.com",
                is_system: false,
                proof_of_possession: {
                    mechanism: "unknown",
                    required: true,
                    required_for: "all_clients",
                },
            }]
        };

        checkDPoPResourceServer(options, (result) => {
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                field: "proof_of_possession.mechanism",
                status: CONSTANTS.FAIL,
                value: "unknown",
            });
        });
    });

    it("should report failure when proof_of_possession mechanism is missing", function() {
        const options = {
            resourceServers: [{
                id: "rs3",
                name: "No Mechanism API",
                identifier: "https://no-mechanism-api.example.com",
                is_system: false,
                proof_of_possession: {
                    required: true,
                    required_for: "all_clients",
                },
            }]
        };

        checkDPoPResourceServer(options, (result) => {
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                field: "proof_of_possession.mechanism",
                status: CONSTANTS.FAIL,
                value: "not_set",
            });
        });
    });

    it("should return empty report when mechanism is dpop, required true, required_for all_clients", function() {
        const options = {
            resourceServers: [{
                id: "rs4",
                name: "DPOP",
                identifier: "https://dpop",
                is_system: false,
                proof_of_possession: {
                    mechanism: "dpop",
                    required: true,
                    required_for: "all_clients",
                },
            }]
        };

        checkDPoPResourceServer(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].name).to.equal("DPOP (https://dpop)");
            expect(result[0].report).to.be.an("array").that.is.empty;
        });
    });

    it("should return empty report when mechanism is mtls, required true, required_for all_clients", function() {
        const options = {
            resourceServers: [{
                id: "rs5",
                name: "mTLS API",
                identifier: "https://mtls-api.example.com",
                is_system: false,
                proof_of_possession: {
                    mechanism: "mtls",
                    required: true,
                    required_for: "all_clients",
                },
            }]
        };

        checkDPoPResourceServer(options, (result) => {
            expect(result[0].report).to.be.an("array").that.is.empty;
        });
    });

    it("should return empty report when mechanism is dpop, required false, required_for public_clients", function() {
        const options = {
            resourceServers: [{
                id: "rs6",
                name: "Public DPoP API",
                identifier: "https://public-dpop-api.example.com",
                is_system: false,
                proof_of_possession: {
                    mechanism: "dpop",
                    required: false,
                    required_for: "public_clients",
                },
            }]
        };

        checkDPoPResourceServer(options, (result) => {
            expect(result[0].report).to.be.an("array").that.is.empty;
        });
    });

    it("should skip system resource servers entirely", function() {
        const options = {
            resourceServers: [{
                id: "rs_system",
                name: "Auth0 Management API",
                identifier: "https://tenant.auth0.com/api/v2/",
                is_system: true,
            }]
        };

        checkDPoPResourceServer(options, (result) => {
            expect(result).to.be.an("array").that.is.empty;
        });
    });

    it("should process multiple resource servers and report failures only for unconfigured ones", function() {
        const options = {
            resourceServers: [
                {
                    id: "rs_system",
                    name: "Auth0 Management API",
                    identifier: "https://tenant.auth0.com/api/v2/",
                    is_system: true,
                },
                {
                    id: "rs_dpop",
                    name: "DPOP",
                    identifier: "https://dpop",
                    is_system: false,
                    proof_of_possession: {
                        mechanism: "dpop",
                        required: true,
                        required_for: "all_clients",
                    },
                },
                {
                    id: "rs_bare",
                    name: "api",
                    identifier: "https://api",
                    is_system: false,
                },
            ]
        };

        checkDPoPResourceServer(options, (result) => {
            // system RS is skipped; 2 non-system RSes are included
            expect(result).to.be.an("array").with.lengthOf(2);

            const dpopEntry = result.find(r => r.name === "DPOP (https://dpop)");
            expect(dpopEntry.report).to.be.an("array").that.is.empty;

            const bareEntry = result.find(r => r.name === "api (https://api)");
            expect(bareEntry.report).to.be.an("array").with.lengthOf(1);
            expect(bareEntry.report[0]).to.include({
                field: "proof_of_possession",
                status: CONSTANTS.FAIL,
                value: "not_configured",
            });
        });
    });

    it("should return empty result if no resource servers are provided", function() {
        const options = { resourceServers: [] };
        checkDPoPResourceServer(options, (result) => {
            expect(result).to.be.an("array").that.is.empty;
        });
    });
});

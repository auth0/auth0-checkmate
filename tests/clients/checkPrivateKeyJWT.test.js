const chai = require("chai");
const expect = chai.expect;

const checkPrivateKeyJWT = require("../../analyzer/lib/clients/checkPrivateKeyJWT");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkPrivateKeyJWT", function () {

    it("should return an empty report when no clients are provided", async function () {
        const options = { clients: [] };
        const result = await checkPrivateKeyJWT(options);
          expect(result.details).to.be.an("array").that.is.empty;
    });

    it("should skip global clients", async function () {
        const options = {
            clients: [{
                name: "All Applications",
                client_id: "global_client",
                global: true,
                is_first_party: true,
                grant_types: ["client_credentials"],
            }],
        };

        const result = await checkPrivateKeyJWT(options);
          expect(result.details).to.be.an("array").that.is.empty;
    });

    it("should skip public clients with token_endpoint_auth_method none", async function () {
        const options = {
            clients: [{
                name: "SPA App",
                client_id: "client_spa",
                global: false,
                is_first_party: true,
                app_type: "spa",
                token_endpoint_auth_method: "none",
                grant_types: ["authorization_code", "refresh_token"],
            }],
        };

        const result = await checkPrivateKeyJWT(options);
          expect(result.details).to.be.an("array").that.is.empty;
    });

    it("should report failure for a confidential client without private_key_jwt configured", async function () {
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

        const result = await checkPrivateKeyJWT(options);
          expect(result.details).to.be.an("array").with.lengthOf(1);
          expect(result.details[0].name).to.equal("M2M App (client_m2m)");
          expect(result.details[0].report).to.be.an("array").with.lengthOf(1);
          expect(result.details[0].report[0]).to.include({
              field: "client_authentication_methods.private_key_jwt",
              status: CONSTANTS.FAIL,
              value: "not_configured",
          });
    });

    it("should report failure when client_authentication_methods is present but private_key_jwt has no credentials", async function () {
        const options = {
            clients: [{
                name: "Web App",
                client_id: "client_web",
                global: false,
                is_first_party: true,
                app_type: "regular_web",
                grant_types: ["authorization_code", "client_credentials"],
                client_authentication_methods: {
                    private_key_jwt: {
                        credentials: [],
                    },
                },
            }],
        };

        const result = await checkPrivateKeyJWT(options);
          expect(result.details).to.be.an("array").with.lengthOf(1);
          expect(result.details[0].report[0]).to.include({
              field: "client_authentication_methods.private_key_jwt",
              status: CONSTANTS.FAIL,
              value: "not_configured",
          });
    });

    it("should report success for a confidential client with private_key_jwt configured", async function () {
        const options = {
            clients: [{
                name: "privateKeyJWT",
                client_id: "client_pkjwt",
                global: false,
                is_first_party: true,
                app_type: "non_interactive",
                grant_types: ["client_credentials"],
                client_authentication_methods: {
                    private_key_jwt: {
                        credentials: [
                            { id: "cred_n844DfTC736dYMqyUGEP9Z" },
                        ],
                    },
                },
            }],
        };

        const result = await checkPrivateKeyJWT(options);
          expect(result.details).to.be.an("array").with.lengthOf(1);
          expect(result.details[0].name).to.equal("privateKeyJWT (client_pkjwt)");
          expect(result.details[0].report).to.be.an("array").with.lengthOf(1);
          expect(result.details[0].report[0]).to.include({
              field: "client_authentication_methods.private_key_jwt",
              status: CONSTANTS.SUCCESS,
              value: "configured",
          });
    });

    it("should report failure for a regular_web app without private_key_jwt", async function () {
        const options = {
            clients: [{
                name: "Web Backend",
                client_id: "client_backend",
                global: false,
                is_first_party: true,
                app_type: "regular_web",
                grant_types: ["authorization_code", "refresh_token"],
            }],
        };

        const result = await checkPrivateKeyJWT(options);
          expect(result.details).to.be.an("array").with.lengthOf(1);
          expect(result.details[0].report[0]).to.include({
              field: "client_authentication_methods.private_key_jwt",
              status: CONSTANTS.FAIL,
              value: "not_configured",
          });
    });

    it("should skip clients with token sender constraining enabled", async function () {
        const options = {
            clients: [{
                name: "mTLS App",
                client_id: "client_mtls",
                global: false,
                is_first_party: true,
                app_type: "non_interactive",
                grant_types: ["client_credentials"],
                require_proof_of_possession: true,
            }],
        };

        const result = await checkPrivateKeyJWT(options);
          expect(result.details).to.be.an("array").that.is.empty;
    });

    it("should handle a mix of public and confidential clients correctly", async function () {
        const options = {
            clients: [
                {
                    name: "SPA",
                    client_id: "client_spa",
                    global: false,
                    is_first_party: true,
                    app_type: "spa",
                    token_endpoint_auth_method: "none",
                    grant_types: ["authorization_code"],
                },
                {
                    name: "M2M",
                    client_id: "client_m2m",
                    global: false,
                    is_first_party: true,
                    app_type: "non_interactive",
                    grant_types: ["client_credentials"],
                    client_authentication_methods: {
                        private_key_jwt: {
                            credentials: [{ id: "cred_abc123" }],
                        },
                    },
                },
            ],
        };

        const result = await checkPrivateKeyJWT(options);
          // Only the M2M confidential client should be in the report
          expect(result.details).to.be.an("array").with.lengthOf(1);
          expect(result.details[0].name).to.equal("M2M (client_m2m)");
          expect(result.details[0].report[0]).to.include({
              status: CONSTANTS.SUCCESS,
          });
    });
});

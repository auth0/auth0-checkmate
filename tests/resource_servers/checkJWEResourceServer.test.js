const chai = require("chai");
const expect = chai.expect;

const checkJWEResourceServer = require("../../analyzer/lib/resource_servers/checkJWEResourceServer");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkJWEResourceServer", function() {

    it("should emit advisory finding when token_encryption is not present in the API response", async function () {
        const options = {
            resourceServers: [{
                id: "rs1",
                name: "My API",
                identifier: "https://my-api.example.com",
                is_system: false,
            }]
        };

        const { details: result } = await checkJWEResourceServer(options);
          expect(result[0].report).to.be.an("array").with.lengthOf(1);
          expect(result[0].report[0]).to.include({
              field: "token_encryption",
              status: CONSTANTS.FAIL,
              value: "not_verifiable",
          });
    });

    it("should report failure if token_encryption.format is invalid", async function () {
        const options = {
            resourceServers: [{
                id: "rs2",
                name: "Invalid Format API",
                identifier: "https://invalid-format-api.example.com",
                is_system: false,
                token_encryption: {
                    format: "unknown-format",
                    encryption_key: {
                        name: "TestKey",
                        alg: "RSA-OAEP-256",
                    }
                }
            }]
        };

        const { details: result } = await checkJWEResourceServer(options);
          expect(result[0].report).to.be.an("array").with.lengthOf(1);
          expect(result[0].report[0]).to.include({
              field: "token_encryption.format",
              status: CONSTANTS.FAIL,
              value: "unknown-format",
          });
    });

    it("should report failure if token_encryption.format is not set", async function () {
        const options = {
            resourceServers: [{
                id: "rs3",
                name: "No Format API",
                identifier: "https://no-format-api.example.com",
                is_system: false,
                token_encryption: {
                    encryption_key: {
                        name: "TestKey",
                        alg: "RSA-OAEP-256",
                    }
                }
            }]
        };

        const { details: result } = await checkJWEResourceServer(options);
          expect(result[0].report).to.be.an("array").with.lengthOf(1);
          expect(result[0].report[0]).to.include({
              field: "token_encryption.format",
              status: CONSTANTS.FAIL,
              value: "not_set",
          });
    });

    it("should report failure if token_encryption.encryption_key is missing", async function () {
        const options = {
            resourceServers: [{
                id: "rs4",
                name: "No Key API",
                identifier: "https://no-key-api.example.com",
                is_system: false,
                token_encryption: {
                    format: "compact-nested-jwe",
                }
            }]
        };

        const { details: result } = await checkJWEResourceServer(options);
          expect(result[0].report).to.be.an("array").with.lengthOf(1);
          expect(result[0].report[0]).to.include({
              field: "token_encryption.encryption_key",
              status: CONSTANTS.FAIL,
              value: "not_configured",
          });
    });

    it("should return empty report if token_encryption is fully configured with RSA-OAEP-256", async function () {
        const options = {
            resourceServers: [{
                id: "rs5",
                name: "Secure Banking API",
                identifier: "https://secure.bank.ciam.rocks",
                is_system: false,
                token_encryption: {
                    format: "compact-nested-jwe",
                    encryption_key: {
                        name: "ApiPubKey",
                        alg: "RSA-OAEP-256",
                        thumbprint_sha256: "0TAjxEoZw-DEsXzzaSXHDof6_IJfxpK8JXTMvewQmlU"
                    }
                }
            }]
        };

        const { details: result } = await checkJWEResourceServer(options);
          expect(result).to.be.an("array").with.lengthOf(1);
          expect(result[0].name).to.equal("Secure Banking API (https://secure.bank.ciam.rocks)");
          expect(result[0].report).to.be.an("array").that.is.empty;
    });

    it("should return empty report if token_encryption is fully configured with RSA-OAEP-512", async function () {
        const options = {
            resourceServers: [{
                id: "rs6",
                name: "JWEAPITest",
                identifier: "https://jweapitest",
                is_system: false,
                token_encryption: {
                    format: "compact-nested-jwe",
                    encryption_key: {
                        alg: "RSA-OAEP-512",
                        name: "JWEPEM",
                        kid: "jwekeyid",
                        thumbprint_sha256: "forcr5qZ_jjtnTiBfTqwMuZPNf-BmAjVBnglsGxoIbA"
                    }
                }
            }]
        };

        const { details: result } = await checkJWEResourceServer(options);
          expect(result[0].report).to.be.an("array").that.is.empty;
    });

    it("should skip system resource servers entirely", async function () {
        const options = {
            resourceServers: [{
                id: "rs_system",
                name: "Auth0 Management API",
                identifier: "https://tenant.auth0.com/api/v2/",
                is_system: true,
            }]
        };

        const { details: result } = await checkJWEResourceServer(options);
          expect(result).to.be.an("array").that.is.empty;
    });

    it("should return empty result if no resource servers are provided", async function () {
        const options = { resourceServers: [] };
        const { details: result } = await checkJWEResourceServer(options);
          expect(result).to.be.an("array").that.is.empty;
    });
});

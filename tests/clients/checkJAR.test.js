const chai = require("chai");
const expect = chai.expect;

const checkJAR = require("../../analyzer/lib/clients/checkJAR");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkJAR", function() {

    it("should report failure if authorization_code grant is used and JAR is not required", async function () {
        const options = {
            clients: [{
                name: "Web App",
                client_id: "client_web",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["authorization_code"],
                signed_request_object: {
                    required: false,
                },
            }]
        };

        const { details: result } = await checkJAR(options);
          expect(result).to.be.an("array").with.lengthOf(1);
          expect(result[0].name).to.equal("Web App (client_web)");
          expect(result[0].report).to.be.an("array").with.lengthOf(1);
          expect(result[0].report[0]).to.include({
              name: "Web App (client_web)",
              client_id: "client_web",
              field: "signed_request_object.required",
              status: CONSTANTS.FAIL,
              value: false,
          });
    });

    it("should skip public SPA clients (app_type spa)", async function () {
        const options = {
            clients: [{
                name: "Legacy SPA",
                client_id: "client_legacy",
                app_type: "spa",
                is_first_party: true,
                grant_types: ["implicit"],
            }]
        };

        const { details: result } = await checkJAR(options);
          expect(result).to.be.an("array").with.lengthOf(1);
          expect(result[0].report).to.be.an("array").that.is.empty;
    });

    it("should skip public native clients (app_type native)", async function () {
        const options = {
            clients: [{
                name: "Native App",
                client_id: "client_native",
                app_type: "native",
                is_first_party: true,
                grant_types: ["authorization_code"],
            }]
        };

        const { details: result } = await checkJAR(options);
          expect(result).to.be.an("array").with.lengthOf(1);
          expect(result[0].report).to.be.an("array").that.is.empty;
    });

    it("should skip clients with token_endpoint_auth_method none", async function () {
        const options = {
            clients: [{
                name: "Public Web App",
                client_id: "client_public",
                app_type: "regular_web",
                is_first_party: true,
                token_endpoint_auth_method: "none",
                grant_types: ["authorization_code"],
            }]
        };

        const { details: result } = await checkJAR(options);
          expect(result).to.be.an("array").with.lengthOf(1);
          expect(result[0].report).to.be.an("array").that.is.empty;
    });

    it("should report failure if signed_request_object field is absent", async function () {
        const options = {
            clients: [{
                name: "HRI App",
                client_id: "client_hri",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["authorization_code", "refresh_token"],
            }]
        };

        const { details: result } = await checkJAR(options);
          expect(result[0].report).to.be.an("array").with.lengthOf(1);
          expect(result[0].report[0]).to.include({
              field: "signed_request_object.required",
              status: CONSTANTS.FAIL,
              value: false,
          });
    });

    it("should report failure if JAR is required but no credentials are configured", async function () {
        const options = {
            clients: [{
                name: "Misconfigured HRI App",
                client_id: "client_misconfig",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["authorization_code"],
                signed_request_object: {
                    required: true,
                    credentials: [],
                },
            }]
        };

        const { details: result } = await checkJAR(options);
          expect(result).to.be.an("array").with.lengthOf(1);
          expect(result[0].report).to.be.an("array").with.lengthOf(1);
          expect(result[0].report[0]).to.include({
              field: "signed_request_object.credentials",
              status: CONSTANTS.FAIL,
              value: "not_configured",
          });
    });

    it("should return empty report if JAR is required and credentials are configured", async function () {
        const options = {
            clients: [{
                name: "Secure HRI App",
                client_id: "client_secure",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["authorization_code", "refresh_token"],
                signed_request_object: {
                    required: true,
                    credentials: [
                        { id: "cred_eoBSAwVdfLa6ZC6m3nrPrw" }
                    ],
                },
            }]
        };

        const { details: result } = await checkJAR(options);
          expect(result).to.be.an("array").with.lengthOf(1);
          expect(result[0].name).to.equal("Secure HRI App (client_secure)");
          expect(result[0].report).to.be.an("array").that.is.empty;
    });

    it("should not flag clients using only client_credentials grant", async function () {
        const options = {
            clients: [{
                name: "M2M App",
                client_id: "client_m2m",
                app_type: "non_interactive",
                is_first_party: true,
                grant_types: ["client_credentials"],
            }]
        };

        const { details: result } = await checkJAR(options);
          expect(result).to.be.an("array").with.lengthOf(1);
          expect(result[0].report).to.be.an("array").that.is.empty;
    });

    it("should report failure if credentials are present but required is not set to true", async function () {
        const options = {
            clients: [{
                name: "HRI Demo - CIC Bank",
                client_id: "client_cic",
                app_type: "regular_web",
                is_first_party: true,
                grant_types: ["authorization_code"],
                signed_request_object: {
                    credentials: [
                        { id: "cred_mP3XfLgdZ525CzCRtk87mk" }
                    ],
                },
            }]
        };

        const { details: result } = await checkJAR(options);
          expect(result[0].report).to.be.an("array").with.lengthOf(1);
          expect(result[0].report[0]).to.include({
              field: "signed_request_object.required",
              status: CONSTANTS.FAIL,
          });
    });

    it("should return empty result if no clients are provided", async function () {
        const options = { clients: [] };
        const { details: result } = await checkJAR(options);
          expect(result).to.be.an("array").that.is.empty;
    });
});

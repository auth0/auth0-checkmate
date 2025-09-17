const chai = require("chai");
const expect = chai.expect;

const checkRefreshToken = require("../../analyzer/lib/clients/checkRefreshToken");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkRefreshToken", function() {

    it("should report failure if refresh_token is used but rotation_type is not rotating", function() {
        const options = {
            clients: [{
                name: "Default App",
                client_id: "client_id",
                app_type: "spa",
                grant_types: ["authorization_code", "refresh_token"],
                refresh_token: {
                    rotation_type: "non-rotating",
                },
            }]
        };;

        checkRefreshToken(options, (result) => {
            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].name).to.equal("Default App (client_id)");
            expect(result[0].report).to.be.an("array").with.lengthOf(1);
            expect(result[0].report[0]).to.include({
                name: "Default App (client_id)",
                client_id: "client_id",
                field: "use_rotating_refresh_token",
                status: CONSTANTS.FAIL,
                value: "non-rotating",
            });
        });
    });

    it("should return an empty report if refresh_token uses rotating", function() {
        const options = {
            clients: [{
                name: "Secure App",
                client_id: "client_secure",
                app_type: "spa",
                grant_types: ["authorization_code", "refresh_token"],
                refresh_token: {
                    rotation_type: "rotating",
                },
            }]
        };;

        checkRefreshToken(options, (result) => {

            expect(result).to.be.an("array").with.lengthOf(1);
            expect(result[0].name).to.equal("Secure App (client_secure)");
            expect(result[0].report).to.be.an("array").that.is.empty;
        })
    });

    it("should return empty result if no clients are provided", function() {
        const options = {clients: []};
        checkRefreshToken(options, (result) => {
            expect(result).to.be.an("array").that.is.empty;
        });
    });
});
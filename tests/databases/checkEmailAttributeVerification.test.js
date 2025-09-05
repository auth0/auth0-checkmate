const chai = require("chai");
const expect = chai.expect;
const checkEmailAttributeVerification = require("../../analyzer/lib/databases/checkEmailAttributeVerification");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkEmailAttributeVerification", function () {
    it("should return a failure report when no database connections are found", function () {
        const options = { databases: [] }; // No databases provided
        checkEmailAttributeVerification(options, (report) => {
            expect(report).to.be.an("array").that.has.lengthOf(1);
            expect(report[0]).to.deep.equal({
                field: "no_database_connections_found",
                status: CONSTANTS.FAIL,
            });
        });
    });

    it("should return a failure report when attributes are missing", function () {
        const options = {
            databases: [
                {
                    name: "Username-Password-Authentication",
                    options: {
                        authentication_methods: {},
                    },
                },
            ],
        };
        checkEmailAttributeVerification(options, (report) => {
            expect(report).to.be.an("array").that.has.lengthOf(1);
            expect(report[0]).to.deep.equal({
                name: "Username-Password-Authentication",
                status: CONSTANTS.FAIL,
                field: "flexible_identifiers_disabled",
            });
        });
    });

    it("should return a failure report when verification_method is not otp", function () {
        const options = {
            databases: [
                {
                    name: "Username-Password-Authentication",
                    options: {
                        attributes: {
                            email: { verification_method: "link" },
                        },
                    },
                },
            ],
        };
        checkEmailAttributeVerification(options, (report) => {
            expect(report).to.be.an("array").that.has.lengthOf(1);
            expect(report[0]).to.deep.equal({
                name: "Username-Password-Authentication",
                status: CONSTANTS.FAIL,
                field: "verification_by_link_method",
            });
        });
    });

    it("should return a success report when verification_method is otp", function () {
        const options = {
            databases: [
                {
                    name: "Username-Password-Authentication",
                    options: {
                        attributes: {
                            email: { verification_method: "otp" },
                        },
                    },
                },
            ],
        };
        checkEmailAttributeVerification(options, (report) => {
            expect(report).to.be.an("array").that.has.lengthOf(0);
        });
    });
});

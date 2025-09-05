const chai = require("chai");
const expect = chai.expect;
const checkEnabledDatabaseCustomization = require("../../analyzer/lib/databases/checkEnabledDatabaseCustomization");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkEnabledDatabaseCustomization", function () {
  it("should return a failure report when no database connections are found", function () {
    const options = { databases: [] }; // No databases provided
    checkEnabledDatabaseCustomization(options, (report) => {
      expect(report).to.be.an("array").that.has.lengthOf(1);
      expect(report[0]).to.deep.equal({
        field: "no_database_connections_found",
        status: CONSTANTS.FAIL,
      });
    });
  });

  it("should return a failure report when import_mode is false and enabledDatabaseCustomization is true", function () {
    const options = {
      databases: [
        {
          name: "Username-Password-Authentication",
          options: {
            import_mode: false,
            enabledDatabaseCustomization: true
          },
        },
      ],
    };
    checkEnabledDatabaseCustomization(options, (report) => {
      expect(report).to.be.an("array").that.has.lengthOf(1);
      expect(report[0]).to.deep.equal({
        name: "Username-Password-Authentication",
        status: CONSTANTS.FAIL,
        field: "external_user_store",
      });
    });
  });

  it("should handle multiple databases correctly", function () {
    const options = {
      databases: [
        {
          name: "Username-Password-Authentication",
          options: {
            import_mode: false,
            enabledDatabaseCustomization: true
          },
        },
        {
          name: "Another-Authentication",
          options: {
            import_mode: false,
            enabledDatabaseCustomization: false
          },
        },
      ],
    };
    checkEnabledDatabaseCustomization(options, (report) => {
      expect(report).to.be.an("array").that.has.lengthOf(1);
      expect(report[0]).to.deep.equal({
        name: "Username-Password-Authentication",
        status: CONSTANTS.FAIL,
        field: "external_user_store",
      });
    });
  });
});

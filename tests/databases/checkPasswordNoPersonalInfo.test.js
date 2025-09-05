const { expect } = require("chai");
const checkPasswordNoPersonalInfo = require("../../analyzer/lib/databases/checkPasswordNoPersonalInfo");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkPasswordNoPersonalInfo", function () {
  it("should return failure if no databases are provided", function () {
    const options = {
      databases: [], // Empty databases array
    };

    checkPasswordNoPersonalInfo(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("no_database_connections_found");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
    });
  });

  it("should return failure if password_no_personal_info is disabled", function () {
    const options = {
      databases: [
        {
          name: "Default DB",
          options: {
            password_no_personal_info: {
              enable: false, // Personal info disallowed is disabled
            },
          },
        },
      ],
    };

    checkPasswordNoPersonalInfo(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_no_personal_info_disabled");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
    });
  });

  it("should return success if password_no_personal_info is enabled", function () {
    const options = {
      databases: [
        {
          name: "Default DB",
          options: {
            password_no_personal_info: {
              enable: true, // Personal info disallowed is enabled
            },
          },
        },
      ],
    };

    checkPasswordNoPersonalInfo(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_no_personal_info_enable");
      expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
    });
  });

  it("should handle multiple databases with different personal info configurations", function () {
    const options = {
      databases: [
        {
          name: "DB 1",
          options: {
            password_no_personal_info: {
              enable: false, // Personal info disallowed is disabled (failure case)
            },
          },
        },
        {
          name: "DB 2",
          options: {
            password_no_personal_info: {
              enable: true, // Personal info disallowed is enabled (success case)
            },
          },
        },
      ],
    };

    checkPasswordNoPersonalInfo(options, (report) => {
      expect(report).to.have.lengthOf(2);

      // DB 1: Personal info disallowed is disabled, should fail
      expect(report[0].field).to.equal("password_no_personal_info_disabled");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);

      // DB 2: Personal info disallowed is enabled, should succeed
      expect(report[1].field).to.equal("password_no_personal_info_enable");
      expect(report[1].status).to.equal(CONSTANTS.SUCCESS);
    });
  });
});

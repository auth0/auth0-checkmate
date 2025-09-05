const { expect } = require("chai");
const checkPasswordComplexity = require("../../analyzer/lib/databases/checkPasswordComplexity");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkPasswordComplexity", function () {
  it("should return failure if no databases are provided", function () {
    const options = {
      databases: [], // Empty databases array
    };

    checkPasswordComplexity(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("no_database_connections_found");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
    });
  });

  it("should return failure if password complexity is not configured", function () {
    const options = {
      databases: [
        {
          name: "Default DB",
          options: {
            password_complexity_options: {}, // Empty password_complexity_options
          },
        },
      ],
    };

    checkPasswordComplexity(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_complexity_not_configured");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
    });
  });

  it("should return failure if password minimum length is less than 12", function () {
    const options = {
      databases: [
        {
          name: "Default DB",
          options: {
            password_complexity_options: {
              min_length: 8, // Password min length is 8 (which is less than 12)
            },
          },
        },
      ],
    };

    checkPasswordComplexity(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_min_length_fail");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
      expect(report[0].value).to.equal(8);
    });
  });

  it("should return success if password minimum length is 12 or greater", function () {
    const options = {
      databases: [
        {
          name: "Default DB",
          options: {
            password_complexity_options: {
              min_length: 12, // Password min length is 12 (which meets the minimum requirement)
            },
          },
        },
      ],
    };

    checkPasswordComplexity(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_min_length_success");
      expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
      expect(report[0].value).to.equal(12);
    });
  });

  it("should handle multiple databases with different password complexity configurations", function () {
    const options = {
      databases: [
        {
          name: "DB 1",
          options: {
            password_complexity_options: {
              min_length: 8, // Password min length is 8 (failure case)
            },
          },
        },
        {
          name: "DB 2",
          options: {
            password_complexity_options: {
              min_length: 14, // Password min length is 14 (success case)
            },
          },
        },
        {
          name: "DB 3",
          options: {
            password_complexity_options: {}, // No password complexity configured (failure case)
          },
        },
      ],
    };

    checkPasswordComplexity(options, (report) => {
      expect(report).to.have.lengthOf(3);

      // DB 1: Password min length is less than 12, should fail
      expect(report[0].field).to.equal("password_min_length_fail");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
      expect(report[0].value).to.equal(8);

      // DB 2: Password min length is 14, should succeed
      expect(report[1].field).to.equal("password_min_length_success");
      expect(report[1].status).to.equal(CONSTANTS.SUCCESS);
      expect(report[1].value).to.equal(14);

      // DB 3: Password complexity not configured, should fail
      expect(report[2].field).to.equal("password_complexity_not_configured");
      expect(report[2].status).to.equal(CONSTANTS.FAIL);
    });
  });
});

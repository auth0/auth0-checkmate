const { expect } = require("chai");
const checkPasswordHistory = require("../../analyzer/lib/databases/checkPasswordHistory");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkPasswordHistory", function () {
  it("should return failure if no databases are provided", function () {
    const options = {
      databases: [], // Empty databases array
    };

    checkPasswordHistory(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("no_database_connections_found");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
    });
  });

  it("should return failure if password history is disabled", function () {
    const options = {
      databases: [
        {
          name: "Default DB",
          options: {
            password_history: {
              enable: false, // Password history is disabled
              size: 5,
            },
          },
        },
      ],
    };

    checkPasswordHistory(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_history_disabled");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
    });
  });

  it("should return success if password history is enabled", function () {
    const options = {
      databases: [
        {
          name: "Default DB",
          options: {
            password_history: {
              enable: true, // Password history is enabled
              size: 5,
            },
          },
        },
      ],
    };

    checkPasswordHistory(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_history_enabled");
      expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
      expect(report[0].value).to.equal(5);
    });
  });

  it("should handle multiple databases with different password history configurations", function () {
    const options = {
      databases: [
        {
          name: "DB 1",
          options: {
            password_history: {
              enable: false, // Password history is disabled (failure case)
              size: 5,
            },
          },
        },
        {
          name: "DB 2",
          options: {
            password_history: {
              enable: true, // Password history is enabled (success case)
              size: 10,
            },
          },
        },
      ],
    };

    checkPasswordHistory(options, (report) => {
      expect(report).to.have.lengthOf(2);

      // DB 1: Password history disabled, should fail
      expect(report[0].field).to.equal("password_history_disabled");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);

      // DB 2: Password history enabled, should succeed
      expect(report[1].field).to.equal("password_history_enabled");
      expect(report[1].status).to.equal(CONSTANTS.SUCCESS);
      expect(report[1].value).to.equal(10);
    });
  });
});

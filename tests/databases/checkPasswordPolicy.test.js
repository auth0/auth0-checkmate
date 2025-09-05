const { expect } = require("chai");
const checkPasswordPolicy = require("../../analyzer/lib/databases/checkPasswordPolicy");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkPasswordPolicy", function () {
  it("should return failure if no databases are provided", function () {
    const options = {
      databases: [], // Empty databases array
    };

    checkPasswordPolicy(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("no_database_connections_found");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
    });
  });

  it('should return failure if passwordPolicy is "none"', function () {
    const options = {
      databases: [
        {
          name: "DB 1",
          options: {
            passwordPolicy: "none", // Password policy is "none"
          },
        },
      ],
    };

    checkPasswordPolicy(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_policy");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
      expect(report[0].value).to.equal("none");
    });
  });

  it('should return failure if passwordPolicy is "low"', function () {
    const options = {
      databases: [
        {
          name: "DB 2",
          options: {
            passwordPolicy: "low", // Password policy is "low"
          },
        },
      ],
    };

    checkPasswordPolicy(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_policy");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
      expect(report[0].value).to.equal("low");
    });
  });

  it('should return failure if passwordPolicy is "fair"', function () {
    const options = {
      databases: [
        {
          name: "DB 3",
          options: {
            passwordPolicy: "fair", // Password policy is "fair"
          },
        },
      ],
    };

    checkPasswordPolicy(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_policy");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
      expect(report[0].value).to.equal("fair");
    });
  });

  it('should return success if passwordPolicy is "good"', function () {
    const options = {
      databases: [
        {
          name: "DB 4",
          options: {
            passwordPolicy: "good", // Password policy is "good"
          },
        },
      ],
    };

    checkPasswordPolicy(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_policy");
      expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
      expect(report[0].value).to.equal("good");
    });
  });

  it('should return success if passwordPolicy is "excellent"', function () {
    const options = {
      databases: [
        {
          name: "DB 5",
          options: {
            passwordPolicy: "excellent", // Password policy is "excellent"
          },
        },
      ],
    };

    checkPasswordPolicy(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("password_policy");
      expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
      expect(report[0].value).to.equal("excellent");
    });
  });

  it("should handle multiple databases with different password policies", function () {
    const options = {
      databases: [
        {
          name: "DB 1",
          options: {
            passwordPolicy: "none", // Password policy is "none"
          },
        },
        {
          name: "DB 2",
          options: {
            passwordPolicy: "low", // Password policy is "low"
          },
        },
        {
          name: "DB 3",
          options: {
            passwordPolicy: "good", // Password policy is "good"
          },
        },
      ],
    };

    checkPasswordPolicy(options, (report) => {
      expect(report).to.have.lengthOf(3);

      // DB 1: Password policy "none", should fail
      expect(report[0].field).to.equal("password_policy");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
      expect(report[0].value).to.equal("none");

      // DB 2: Password policy "low", should fail
      expect(report[1].field).to.equal("password_policy");
      expect(report[1].status).to.equal(CONSTANTS.FAIL);
      expect(report[1].value).to.equal("low");

      // DB 3: Password policy "good", should succeed
      expect(report[2].field).to.equal("password_policy");
      expect(report[2].status).to.equal(CONSTANTS.SUCCESS);
      expect(report[2].value).to.equal("good");
    });
  });
});

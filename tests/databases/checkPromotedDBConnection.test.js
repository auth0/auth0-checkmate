const { expect } = require("chai");
const checkPromotedDBConnection = require("../../analyzer/lib/databases/checkPromotedDBConnection");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkPromotedDBConnection", function () {
  it("should return failure if no databases are provided", function () {
    const options = {
      databases: [], // Empty databases array
    };

    checkPromotedDBConnection(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("no_database_connections_found");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
    });
  });

  it('should return no_connection if no any prmoted domain connection', function () {
    const options = {
      databases: [
        {
          name: "DB 1",
          is_domain_connection: false,
        },
        {
          name: "DB 2",
          is_domain_connection: false,
        }
      ],
    };

    checkPromotedDBConnection(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("NO_PRMOTED_DOMAIN_CONNECTION");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
      expect(report[0].value).to.equal("no_database_connections_found");
    });
  });

  it('should return promoted_domain_connection name if is_domain_connection is true', function () {
    const options = {
      databases: [
        {
          name: "DB 1",
          is_domain_connection: false,
        },
        {
          name: "DB 2",
          is_domain_connection: true,
        }
      ],
    };

    checkPromotedDBConnection(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("DB 2");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
      expect(report[0].value).to.equal("with_promoted_database_connections");
    });
  });

});
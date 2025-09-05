const { expect } = require("chai");
const checkJWTSignAlg = require("../../analyzer/lib/clients/checkJWTSignAlg");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkJWTSignAlg", function () {
  it("should return RS256 when no jwt_configuration is provided", function () {
    const options = {
      clients: [
        {
          name: "Default App",
          client_id: "client_id",
          jwt_configuration: undefined, // No jwt_configuration provided, defaults to RS256
        },
      ],
    };

    checkJWTSignAlg(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("missing_jwt_alg");
      expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
      expect(report[0].alg).to.equal("RS256");
    });
  });

  it("should return success for clients using an asymmetric algorithm (e.g., RS512)", function () {
    const options = {
      clients: [
        {
          name: "Default App",
          client_id: "client_id",
          jwt_configuration: {
            alg: "RS512", // Custom asymmetric algorithm
          },
        },
      ],
    };

    checkJWTSignAlg(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("using_asymmetric_alg");
      expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
      expect(report[0].alg).to.equal("RS512");
    });
  });

  it("should return fail for clients using HS256 (symmetric algorithm)", function () {
    const options = {
      clients: [
        {
          name: "Default App",
          client_id: "client_id",
          jwt_configuration: {
            alg: "HS256", // Symmetric algorithm, flagged as an issue
          },
        },
      ],
    };

    checkJWTSignAlg(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0].field).to.equal("not_using_asymmetric_alg");
      expect(report[0].status).to.equal(CONSTANTS.FAIL);
      expect(report[0].alg).to.equal("HS256");
    });
  });

  it("should return an empty report when no clients are provided", function () {
    const options = {
      clients: [], // Empty clients list
    };

    checkJWTSignAlg(options, (report) => {
      expect(report).to.have.lengthOf(0); // No reports should be generated
    });
  });

  it("should handle multiple clients with different JWT configurations", function () {
    const options = {
      clients: [
        {
          name: "Client 1",
          client_id: "client_1_id",
          jwt_configuration: undefined, // No jwt_configuration provided, defaults to RS256
        },
        {
          name: "Client 2",
          client_id: "client_2_id",
          jwt_configuration: {
            alg: "RS256",
          },
        },
        {
          name: "Client 3",
          client_id: "client_3_id",
          jwt_configuration: {
            alg: "HS256",
          },
        },
      ],
    };

    checkJWTSignAlg(options, (report) => {
      expect(report).to.have.lengthOf(3);

      // Client 1: Missing JWT configuration, defaults to RS256
      expect(report[0].field).to.equal("missing_jwt_alg");
      expect(report[0].status).to.equal(CONSTANTS.SUCCESS);
      expect(report[0].alg).to.equal("RS256");

      // Client 2: Uses RS256 (asymmetric)
      expect(report[1].field).to.equal("using_asymmetric_alg");
      expect(report[1].status).to.equal(CONSTANTS.SUCCESS);
      expect(report[1].alg).to.equal("RS256");

      // Client 3: Uses HS256 (symmetric)
      expect(report[2].field).to.equal("not_using_asymmetric_alg");
      expect(report[2].status).to.equal(CONSTANTS.FAIL);
      expect(report[2].alg).to.equal("HS256");
    });
  });
});

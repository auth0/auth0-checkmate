const chai = require("chai");
const expect = chai.expect;

const checkDASHardCodedValues = require("../../analyzer/lib/databases/checkDASHardCodedValues");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkDASHardCodedValues", () => {

    it("should detect hardcoded values in login script", async () => {
        const mockData = {
            databases: [
                {
                    name: "Username-Password-Authentication",
                    options: {
                        enabledDatabaseCustomization: true,
                        customScripts: {
                            login: `
                function login(identifierValue, password, callback) {
                  const mysql = require('mysql');
                  const connection = mysql.createConnection({
                    host: 'localhost',
                    user: 'admin',
                    password: 'secret',
                    database: 'users_db'
                  });
                  connection.connect();
                  const query = 'SELECT * FROM users WHERE email = ?';
                  connection.query(query, [ identifierValue ], callback);
                }
              `,
                        },
                    },
                },
            ],
        };

        const result = await checkDASHardCodedValues(mockData);
        expect(result.details).to.have.lengthOf(1);
        const report = result.details[0];
        expect(report.report).to.have.lengthOf(5);
        expect(report.report[0].scriptName).to.equal("login");
        expect(report.report[0].type).to.equal("string");
        expect(report.report[0].field).to.equal("hard_coded_value_detected");
        expect(report.report[0].status).to.equal(CONSTANTS.FAIL);

        const findings = report.report.map((r) => r.variableName);
        expect(findings).to.include.members(["host", "user", "password", "database", "query"]);
    });

    it("should return no findings if customization is disabled", async () => {
        const mockData = {
            databases: [
                {
                    name: "NoCustomization",
                    options: {
                        enabledDatabaseCustomization: false,
                        customScripts: {
                            login: "function login() { return; }",
                        },
                    },
                },
            ],
        };

        const result = await checkDASHardCodedValues(mockData);
        expect(result.details).to.be.an("array").that.is.empty;
    });

    it("should return failure if no databases are present", async () => {
        const report = await checkDASHardCodedValues({ databases: [] });
        expect(report.details).to.be.an("array").that.has.lengthOf(1);
        expect(report.details[0]).to.deep.equal({
            field: "no_database_connections_found",
            status: CONSTANTS.FAIL,
        });
    });
});

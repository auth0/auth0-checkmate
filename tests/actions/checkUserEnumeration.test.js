const chai = require("chai");
const expect = chai.expect;
const checkPreRegistrationUserEnumeration = require("../../analyzer/lib/actions/checkUserEnumeration"); 
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkPreRegistrationUserEnumeration", function () {
  it("should return an empty array when no pre-registration actions use api.access.deny", async function () {
    const input = {
      actions: {
        actions: [
          {
            id: "12345",
            name: "Safe Action",
            supported_triggers: [{ id: "pre-user-registration", version: "v1" }],
            code: "exports.onExecutePreUserRegistration = async (event, api) => { return; };",
          },
        ],
      },
    };

    const reports = await checkPreRegistrationUserEnumeration(input);
    expect(reports.details).to.be.an("array").that.is.empty;
  });

  it("should ignore api.access.deny in actions that are NOT pre-user-registration", async function () {
    const input = {
      actions: {
        actions: [
          {
            id: "67890",
            name: "Post Login Deny",
            supported_triggers: [{ id: "post-login", version: "v3" }],
            code: 'exports.onExecutePostLogin = async (event, api) => { api.access.deny("Access Denied"); };',
          },
        ],
      },
    };

    const reports = await checkPreRegistrationUserEnumeration(input);
    expect(reports.details).to.be.an("array").that.is.empty;
  });

  it("should detect api.access.deny in pre-user-registration action code", async function () {
    const input = {
      actions: {
        actions: [
          {
            id: "auth0-vulnerability-test",
            name: "User Check",
            supported_triggers: [{ id: "pre-user-registration", version: "v1" }],
            code: `exports.onExecutePreUserRegistration = async (event, api) => {
              if(event.user.email === "test@example.com") {
                api.access.deny("User already exists", "Testing user enumeration vuln");
              }
            };`,
          },
        ],
      },
    };

    const reports = await checkPreRegistrationUserEnumeration(input);
    
    expect(reports.details).to.have.lengthOf(1);
    const detail = reports.details[0];
    
    expect(detail.name).to.equal("User Check (pre-user-registration)");
    expect(detail.report).to.have.lengthOf(1);
    
    const finding = detail.report[0];
    expect(finding.variableName).to.equal("api.access.deny");
    expect(finding.field).to.equal("user_enumeration_vulnerability");
    expect(finding.status).to.equal(CONSTANTS.WARN);
    // Line 3 is where the call starts in the template string above
    expect(finding.line).to.equal(3); 
  });

  it("should flag multiple occurrences of api.access.deny in the same action", async function () {
    const input = {
      actions: {
        actions: [
          {
            id: "multi-deny",
            name: "Strict Validation",
            supported_triggers: [{ id: "pre-user-registration", version: "v1" }],
            code: `exports.onExecutePreUserRegistration = async (event, api) => {
              if (!event.user.email) api.access.deny("duplicate emaill");
              if (event.user.name === 'admin') api.access.deny("high risk");
            };`,
          },
        ],
      },
    };

    const reports = await checkPreRegistrationUserEnumeration(input);
    
    expect(reports.details).to.have.lengthOf(1);
    const reportList = reports.details[0].report;
    expect(reportList).to.have.lengthOf(2);
    expect(reportList[0].variableName).to.equal("api.access.deny");
    expect(reportList[1].variableName).to.equal("api.access.deny");
  });
});
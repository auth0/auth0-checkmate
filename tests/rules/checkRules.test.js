const chai = require("chai");
const expect = chai.expect;

const checkRules = require("../../analyzer/lib/rules/checkRules");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkRules", function () {
  it("should return success when no rules are provided", function () {
    const options = {};

    checkRules(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "no_enabled_rules",
          status: CONSTANTS.SUCCESS,
        },
      ]);
    });
  });

  it("should return fail for an enabled rule", function () {
    const options = {
      rules: [
        {
          id: "rul_YFDdYGJSIwMPzsZR",
          enabled: true,
          name: "Override SAML Certificate",
          order: 14,
          stage: "login_success",
        },
      ],
    };

    checkRules(options, (report) => {
      expect(report).to.deep.equal([
        {
          name: "Override SAML Certificate",
          value: "rul_YFDdYGJSIwMPzsZR",
          field: "enabled_rules",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return empty for disabled rules", function () {
    const options = {
      rules: [
        {
          id: "rul_IYlu62iBa6K52fBi",
          enabled: false,
          name: "Dump Rule",
          order: 1,
          stage: "login_success",
        },
        {
          id: "rul_RFtsxXcHptdfNytp",
          enabled: false,
          name: "auth0-account-link-extension",
          order: 7,
          stage: "login_success",
        },
      ],
    };

    checkRules(options, (report) => {
      expect(report).to.deep.equal([]);
    });
  });

  it("should return fail for only rules with enabled state", function () {
    const options = {
      rules: [
        {
          id: "rul_YFDdYGJSIwMPzsZR",
          enabled: true,
          name: "Override SAML Certificate",
          order: 14,
          stage: "login_success",
        },
        {
          id: "rul_IYlu62iBa6K52fBi",
          enabled: false,
          name: "Dump Rule",
          order: 1,
          stage: "login_success",
        },
      ],
    };

    checkRules(options, (report) => {
      expect(report).to.deep.equal([
        {
          name: "Override SAML Certificate",
          value: "rul_YFDdYGJSIwMPzsZR",
          field: "enabled_rules",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });
});

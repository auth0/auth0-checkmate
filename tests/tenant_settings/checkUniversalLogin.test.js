const chai = require("chai");
const expect = chai.expect;
const checkUniversalLogin = require("../../analyzer/lib/tenant_settings/checkUniversalLogin");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkUniversalLogin", function () {
  it("should pass when New Universal Login is used without a custom login page", async function () {
    const result = await checkUniversalLogin({
      prompts: { universal_login_experience: "new", identifier_first: true },
      globalClient: { client_id: "global", global: true, custom_login_page_on: false },
    });

    expect(result.details).to.deep.equal([
      { field: "new_universal_login_enabled", value: "new", status: CONSTANTS.SUCCESS },
      { field: "custom_login_page_disabled", value: "false", status: CONSTANTS.SUCCESS },
    ]);
  });

  it("should warn when the tenant uses Classic Universal Login", async function () {
    const result = await checkUniversalLogin({
      prompts: { universal_login_experience: "classic" },
      globalClient: { custom_login_page_on: false },
    });

    expect(result.details[0]).to.deep.equal({
      field: "classic_universal_login_enabled",
      value: "classic",
      status: CONSTANTS.WARN,
    });
  });

  it("should treat a missing universal_login_experience as Classic", async function () {
    const result = await checkUniversalLogin({
      prompts: { identifier_first: false },
      globalClient: null,
    });

    expect(result.details).to.deep.equal([
      { field: "classic_universal_login_enabled", value: "classic", status: CONSTANTS.WARN },
    ]);
  });

  it("should warn when the login page is customized", async function () {
    const result = await checkUniversalLogin({
      prompts: { universal_login_experience: "new" },
      globalClient: { custom_login_page_on: true },
    });

    expect(result.details[1]).to.deep.equal({
      field: "custom_login_page_enabled",
      value: "true",
      status: CONSTANTS.WARN,
    });
  });

  it("should not report when the settings could not be retrieved", async function () {
    const result = await checkUniversalLogin({ prompts: null, globalClient: null });
    expect(result.details).to.be.an("array").that.is.empty;
  });

  it("should not throw when called without options", async function () {
    const result = await checkUniversalLogin();
    expect(result.details).to.be.an("array").that.is.empty;
  });
});

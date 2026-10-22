const chai = require("chai");
const expect = chai.expect;
const checkUniversalLogin = require("../../analyzer/lib/tenant_settings/checkUniversalLogin");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkUniversalLogin", function () {
  it("should recommend blocking signups via API when New Universal Login is used", async function () {
    const result = await checkUniversalLogin({
      prompts: { universal_login_experience: "new", identifier_first: true },
    });

    expect(result.details).to.deep.equal([
      { field: "block_signup_via_api", value: "new", status: CONSTANTS.WARN },
    ]);
  });

  it("should not report when the tenant uses Classic Universal Login", async function () {
    const result = await checkUniversalLogin({
      prompts: { universal_login_experience: "classic" },
    });

    expect(result.details).to.be.an("array").that.is.empty;
  });

  it("should not report when universal_login_experience is not set", async function () {
    const result = await checkUniversalLogin({ prompts: { identifier_first: false } });
    expect(result.details).to.be.an("array").that.is.empty;
  });

  it("should not report when the prompts settings could not be retrieved", async function () {
    const result = await checkUniversalLogin({ prompts: null });
    expect(result.details).to.be.an("array").that.is.empty;
  });

  it("should not throw when called without options", async function () {
    const result = await checkUniversalLogin();
    expect(result.details).to.be.an("array").that.is.empty;
  });
});

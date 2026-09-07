const { expect } = require("chai");
const Handlebars = require("handlebars");
const fs = require("fs");

// Register the same helpers that report.js registers
Handlebars.registerHelper("chooseFont", function (locale) {
  if (locale === "ja") return "Noto Sans JP, sans-serif";
  if (locale === "ko") return "Noto Sans KR, sans-serif";
  return "DM Sans, sans-serif";
});
Handlebars.registerHelper("replace", function (str, search, replace) {
  return str.replace(search, replace);
});
Handlebars.registerHelper("and", (a, b) => a && b);
Handlebars.registerHelper("inc", (a) => parseInt(a) + 1);

// A tenant configuration that satisfies every validator, so tests exercise
// validator selection rather than missing-data handling.
function buildTenantConfig() {
  return {
    customDomains: [{ domain: "custom.example.com", status: "ready" }],
    clients: [],
    databases: [],
    attackProtection: {
      breachedPasswordDetection: { enabled: false, shields: [], stage: {} },
      bruteForceProtection: { enabled: false, shields: [], allowlist: [] },
      suspiciousIpThrottling: { enabled: false, shields: [], allowlist: [] },
    },
    emailProvider: {},
    logStreams: [],
    emailTemplates: [],
    errorPageTemplate: {},
    tenant: {
      friendly_name: "Test Tenant",
      support_email: "support@test.com",
      support_url: "https://support.test.com",
    },
    guardianFactors: [],
    guardianPolicies: [],
    rules: [],
    hooks: [],
    actions: [],
    logs: [],
    log_query: "",
    networkAcl: [],
    eventStreams: [],
    resourceServers: [],
  };
}

describe("report.js", function () {
  describe("Handlebars helpers", function () {
    describe("chooseFont", function () {
      it("should return default font for en locale", function () {
        const result = Handlebars.helpers.chooseFont("en");
        expect(result).to.equal("DM Sans, sans-serif");
      });

      it("should return default font for unknown locale", function () {
        const result = Handlebars.helpers.chooseFont("fr");
        expect(result).to.equal("DM Sans, sans-serif");
      });

      it("should return default font for undefined locale", function () {
        const result = Handlebars.helpers.chooseFont(undefined);
        expect(result).to.equal("DM Sans, sans-serif");
      });
    });

    describe("replace", function () {
      it("should replace a substring", function () {
        const result = Handlebars.helpers.replace("hello world", "world", "test");
        expect(result).to.equal("hello test");
      });

      it("should replace first occurrence only", function () {
        const result = Handlebars.helpers.replace("foo foo foo", "foo", "bar");
        expect(result).to.equal("bar foo foo");
      });

      it("should return original string if search not found", function () {
        const result = Handlebars.helpers.replace("hello world", "xyz", "test");
        expect(result).to.equal("hello world");
      });

      it("should handle empty replacement", function () {
        const result = Handlebars.helpers.replace("hello world", "world", "");
        expect(result).to.equal("hello ");
      });
    });

    describe("and", function () {
      it("should return true when both are true", function () {
        const result = Handlebars.helpers.and(true, true);
        expect(result).to.equal(true);
      });

      it("should return false when first is false", function () {
        const result = Handlebars.helpers.and(false, true);
        expect(result).to.equal(false);
      });

      it("should return false when second is false", function () {
        const result = Handlebars.helpers.and(true, false);
        expect(result).to.equal(false);
      });

      it("should return false when both are false", function () {
        const result = Handlebars.helpers.and(false, false);
        expect(result).to.equal(false);
      });

      it("should handle truthy values", function () {
        const result = Handlebars.helpers.and("truthy", 1);
        expect(result).to.equal(1);
      });

      it("should handle falsy values", function () {
        const result = Handlebars.helpers.and("truthy", 0);
        expect(result).to.equal(0);
      });
    });

    describe("inc", function () {
      it("should increment a number", function () {
        const result = Handlebars.helpers.inc(5);
        expect(result).to.equal(6);
      });

      it("should increment zero", function () {
        const result = Handlebars.helpers.inc(0);
        expect(result).to.equal(1);
      });

      it("should increment a string number", function () {
        const result = Handlebars.helpers.inc("10");
        expect(result).to.equal(11);
      });

      it("should handle negative numbers", function () {
        const result = Handlebars.helpers.inc(-1);
        expect(result).to.equal(0);
      });
    });
  });

  describe("generateHtml", function () {
    let originalReadFileSync;

    before(function () {
      originalReadFileSync = fs.readFileSync;
    });

    after(function () {
      fs.readFileSync = originalReadFileSync;
    });

    it("should generate HTML with report data", function () {
      const minimalTemplate = `
        <html>
          <head><title>{{data.report.report_title}}</title></head>
          <body>
            <div class="domain">{{data.auth0Domain}}</div>
            <div class="date">{{data.today}}</div>
            <div class="locale">{{data.locale}}</div>
          </body>
        </html>
      `;

      fs.readFileSync = function (filePath, encoding) {
        if (filePath.includes("pdf_cli_report.handlebars")) {
          return minimalTemplate;
        }
        return originalReadFileSync(filePath, encoding);
      };

      delete require.cache[require.resolve("../analyzer/report.js")];
      const { generateHtml } = require("../analyzer/report.js");

      const mockReport = {
        report_title: "Test Report",
        preamble: { intro: "Test intro" },
        summary: { total: 10 },
        full_report: [],
        list_of_validators: [],
      };

      return generateHtml(mockReport, "test.auth0.com", "en").then((html) => {
        expect(html).to.be.a("string");
        expect(html).to.include("test.auth0.com");
        expect(html).to.include("Test Report");
      });
    });

    it("should default to en locale when not specified", function () {
      const minimalTemplate = `<div class="locale">{{data.locale}}</div>`;

      fs.readFileSync = function (filePath, encoding) {
        if (filePath.includes("pdf_cli_report.handlebars")) {
          return minimalTemplate;
        }
        return originalReadFileSync(filePath, encoding);
      };

      delete require.cache[require.resolve("../analyzer/report.js")];
      const { generateHtml } = require("../analyzer/report.js");

      const mockReport = {
        preamble: {},
      };

      return generateHtml(mockReport, "test.auth0.com").then((html) => {
        expect(html).to.include("en");
      });
    });
  });

  describe("generateReport", function () {
    let originalReadFileSync;

    before(function () {
      originalReadFileSync = fs.readFileSync;
      fs.readFileSync = function (filePath, encoding) {
        if (filePath.includes("pdf_cli_report.handlebars")) {
          return "<html></html>";
        }
        return originalReadFileSync(filePath, encoding);
      };
    });

    after(function () {
      fs.readFileSync = originalReadFileSync;
    });

    it("should generate report with pre-populated tenantConfig", async function () {
      this.timeout(10000); 

      delete require.cache[require.resolve("../analyzer/report.js")];
      const { generateReport } = require("../analyzer/report.js");

      const tenantConfig = {
        customDomains: [],
        clients: [],
        databases: [],
        attackProtection: {
          breachedPasswordDetection: { enabled: false },
          bruteForceProtection: { enabled: false },
          suspiciousIpThrottling: { enabled: false },
        },
        emailProvider: {},
        logStreams: [],
        emailTemplates: [],
        errorPageTemplate: {},
        tenant: {
          friendly_name: "Test Tenant",
          support_email: "support@test.com",
          support_url: "https://support.test.com",
        },
        guardianFactors: [],
        guardianPolicies: [],
        rules: [],
        hooks: [],
        actions: [],
        logs: [],
        log_query: "",
        networkAcl: [],
        eventStreams: [],
        resourceServers: [],
      };

      const config = {
        auth0Domain: "test.auth0.com",
        selectedValidators: ["checkCustomDomain"], // run only one validator
      };

      const report = await generateReport("en", tenantConfig, config);

      expect(report).to.be.an("object");
      expect(report).to.have.property("report_title");
      expect(report).to.have.property("summary");
      expect(report).to.have.property("full_report");
      expect(report).to.have.property("list_of_validators");
      expect(report).to.have.property("tenantConfig");
      expect(report.tenantConfig).to.equal(tenantConfig);
    });

    it("should filter validators based on selectedValidators config", async function () {
      this.timeout(10000);

      delete require.cache[require.resolve("../analyzer/report.js")];
      const { generateReport } = require("../analyzer/report.js");

      const tenantConfig = {
        customDomains: [{ domain: "custom.example.com", status: "ready" }],
        clients: [],
        databases: [],
        attackProtection: {
          breachedPasswordDetection: { enabled: false },
          bruteForceProtection: { enabled: false },
          suspiciousIpThrottling: { enabled: false },
        },
        emailProvider: {},
        logStreams: [],
        emailTemplates: [],
        errorPageTemplate: {},
        tenant: {},
        guardianFactors: [],
        guardianPolicies: [],
        rules: [],
        hooks: [],
        actions: [],
        logs: [],
        log_query: "",
        networkAcl: [],
        eventStreams: [],
        resourceServers: [],
      };

      const config = {
        auth0Domain: "test.auth0.com",
        selectedValidators: ["checkCustomDomain"], 
      };

      const report = await generateReport("en", tenantConfig, config);

      expect(report).to.be.an("object");
      expect(report.full_report).to.be.an("array");

      const customDomainResult = report.full_report.find(
        (r) => r.name === "checkCustomDomain"
      );
      expect(customDomainResult).to.exist;
      expect(customDomainResult).to.have.property("title");
      expect(customDomainResult).to.have.property("description");
    });

    it("should not execute validators that were not selected", async function () {
      this.timeout(10000);

      delete require.cache[require.resolve("../analyzer/lib/listOfAnalyser.js")];
      delete require.cache[require.resolve("../analyzer/report.js")];

      // Wrap every check so we can observe which ones actually get invoked.
      const listOfAnalyser = require("../analyzer/lib/listOfAnalyser.js");
      const executed = [];
      const originalChecks = listOfAnalyser.checks;
      listOfAnalyser.checks = originalChecks.map((check) => {
        const wrapped = (tenant) => {
          executed.push(check.name);
          return check(tenant);
        };
        Object.defineProperty(wrapped, "name", { value: check.name });
        return wrapped;
      });

      try {
        const { generateReport } = require("../analyzer/report.js");
        const report = await generateReport("en", buildTenantConfig(), {
          auth0Domain: "test.auth0.com",
          selectedValidators: ["checkCustomDomain"],
        });

        expect(executed).to.deep.equal(["checkCustomDomain"]);
        expect(report.full_report).to.have.lengthOf(1);
        expect(report.full_report[0].name).to.equal("checkCustomDomain");
      } finally {
        listOfAnalyser.checks = originalChecks;
        delete require.cache[require.resolve("../analyzer/lib/listOfAnalyser.js")];
        delete require.cache[require.resolve("../analyzer/report.js")];
      }
    });

    it("should run every validator when no selection is provided", async function () {
      this.timeout(20000);

      delete require.cache[require.resolve("../analyzer/report.js")];
      const { generateReport } = require("../analyzer/report.js");
      const { checks } = require("../analyzer/lib/listOfAnalyser.js");

      const report = await generateReport("en", buildTenantConfig(), {
        auth0Domain: "test.auth0.com",
        selectedValidators: [],
      });

      expect(report.full_report).to.have.lengthOf(checks.length);
      expect(report.summary).to.be.an("array");
    });

    it("should report scope and totals for the selected validators only", async function () {
      this.timeout(10000);

      delete require.cache[require.resolve("../analyzer/report.js")];
      const { generateReport } = require("../analyzer/report.js");

      const report = await generateReport("en", buildTenantConfig(), {
        auth0Domain: "test.auth0.com",
        selectedValidators: ["checkCustomDomain", "checkRules"],
      });

      expect(report.list_of_validators).to.deep.equal([
        { title: "Custom Domains", items: [] },
        { title: "Rules", items: [] },
      ]);
      expect(report.validator_summary).to.include("<b>2</b>");
    });

    it("should reject a selection containing unknown validator names", async function () {
      delete require.cache[require.resolve("../analyzer/report.js")];
      const { generateReport } = require("../analyzer/report.js");

      try {
        await generateReport("en", buildTenantConfig(), {
          auth0Domain: "test.auth0.com",
          selectedValidators: ["checkcustomdomain"],
        });
        throw new Error("expected generateReport to reject unknown validators");
      } catch (error) {
        expect(error.message).to.include("checkcustomdomain");
        expect(error.message).to.include("checkCustomDomain");
      }
    });
  });

  describe("getValidatorNames", function () {
    it("should list every available validator name", function () {
      delete require.cache[require.resolve("../analyzer/report.js")];
      const { getValidatorNames } = require("../analyzer/report.js");
      const { checks } = require("../analyzer/lib/listOfAnalyser.js");

      const names = getValidatorNames();

      expect(names).to.have.lengthOf(checks.length);
      expect(names).to.include("checkCustomDomain");
      expect(names).to.deep.equal(checks.map((check) => check.name));
    });
  });

  describe("parseValidatorSelection", function () {
    it("should return an empty selection when unset or blank", function () {
      delete require.cache[require.resolve("../analyzer/report.js")];
      const { parseValidatorSelection } = require("../analyzer/report.js");

      expect(parseValidatorSelection(undefined)).to.deep.equal([]);
      expect(parseValidatorSelection("")).to.deep.equal([]);
      expect(parseValidatorSelection("   ")).to.deep.equal([]);
    });

    it("should split a comma-separated list", function () {
      delete require.cache[require.resolve("../analyzer/report.js")];
      const { parseValidatorSelection } = require("../analyzer/report.js");

      expect(
        parseValidatorSelection("checkCustomDomain,checkRules"),
      ).to.deep.equal(["checkCustomDomain", "checkRules"]);
    });

    it("should tolerate whitespace and trailing commas", function () {
      delete require.cache[require.resolve("../analyzer/report.js")];
      const { parseValidatorSelection } = require("../analyzer/report.js");

      expect(
        parseValidatorSelection(" checkCustomDomain , checkRules , "),
      ).to.deep.equal(["checkCustomDomain", "checkRules"]);
    });

    it("should reject unknown names so the CLI can fail fast", function () {
      delete require.cache[require.resolve("../analyzer/report.js")];
      const { parseValidatorSelection } = require("../analyzer/report.js");

      expect(() => parseValidatorSelection("checkRules,bogus")).to.throw(
        /bogus/,
      );
    });
  });

  describe("resolveSelectedValidators", function () {
    it("should return all checks when nothing is selected", function () {
      delete require.cache[require.resolve("../analyzer/report.js")];
      const { resolveSelectedValidators } = require("../analyzer/report.js");
      const { checks } = require("../analyzer/lib/listOfAnalyser.js");

      expect(resolveSelectedValidators([])).to.have.lengthOf(checks.length);
      expect(resolveSelectedValidators(undefined)).to.have.lengthOf(checks.length);
    });

    it("should return only the selected checks, preserving selection order", function () {
      delete require.cache[require.resolve("../analyzer/report.js")];
      const { resolveSelectedValidators } = require("../analyzer/report.js");

      const resolved = resolveSelectedValidators([
        "checkRules",
        "checkCustomDomain",
      ]);

      expect(resolved.map((check) => check.name)).to.deep.equal([
        "checkRules",
        "checkCustomDomain",
      ]);
    });

    it("should throw listing unknown names and a suggestion", function () {
      delete require.cache[require.resolve("../analyzer/report.js")];
      const { resolveSelectedValidators } = require("../analyzer/report.js");

      expect(() => resolveSelectedValidators(["checkRules", "nope"])).to.throw(
        /nope/
      );
      expect(() => resolveSelectedValidators(["checkRule"])).to.throw(
        /checkRules/
      );
    });

    it("should ignore surrounding whitespace and duplicates", function () {
      delete require.cache[require.resolve("../analyzer/report.js")];
      const { resolveSelectedValidators } = require("../analyzer/report.js");

      const resolved = resolveSelectedValidators([
        " checkCustomDomain ",
        "checkCustomDomain",
      ]);

      expect(resolved.map((check) => check.name)).to.deep.equal([
        "checkCustomDomain",
      ]);
    });
  });
});

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

describe("report.js", function () {
  describe("Handlebars helpers", function () {
    describe("chooseFont", function () {
      it("should return Japanese font for ja locale", function () {
        const result = Handlebars.helpers.chooseFont("ja");
        expect(result).to.equal("Noto Sans JP, sans-serif");
      });

      it("should return Korean font for ko locale", function () {
        const result = Handlebars.helpers.chooseFont("ko");
        expect(result).to.equal("Noto Sans KR, sans-serif");
      });

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

    it("should handle empty tenantConfig by using config for API calls", async function () {
      delete require.cache[require.resolve("../analyzer/report.js")];
      const { generateReport } = require("../analyzer/report.js");

      const report = await generateReport("en", {}, {
        auth0Domain: "invalid.auth0.com",
        auth0ClientId: "invalid",
        auth0ClientSecret: "invalid",
        selectedValidators: [],
      });

      expect(report).to.deep.equal({});
    });
  });
});

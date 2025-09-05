const { expect } = require("chai");
const axios = require("axios");
const semver = require("semver");
const {
  checkVulnerableVersion,
  checkGitHubAdvisories,
  getActionDependencies
} = require("../../analyzer/tools/helpers");
const logger = require("../../analyzer/lib/logger");

describe("helpers.js", function() {
  let originalAxiosGet;
  let originalLoggerLog;
  let originalSemverSatisfies;

  beforeEach(function() {
    // Store original functions
    originalAxiosGet = axios.get;
    originalLoggerLog = logger.log;
    originalSemverSatisfies = semver.satisfies;

    // Mock logger.log to capture log messages
    logger.log = function() {};
  });

  afterEach(function() {
    // Restore original functions
    axios.get = originalAxiosGet;
    logger.log = originalLoggerLog;
    semver.satisfies = originalSemverSatisfies;
  });

  describe("checkVulnerableVersion", function() {
    it("should return empty array when no vulnerabilities are found", async function() {
      const currentVersion = "1.0.0";
      const advisoryData = [
        {
          cve_id: "CVE-2023-1234",
          html_url: "https://github.com/advisories/CVE-2023-1234",
          summary: "Test vulnerability",
          severity: "high",
          vulnerabilities: [
            {
              vulnerable_version_range: "< 0.5.0"
            }
          ]
        }
      ];

      semver.satisfies = function(version, range) {
        return false; // Not vulnerable
      };

      const result = await checkVulnerableVersion(currentVersion, advisoryData);

      expect(result).to.be.an("array");
      expect(result).to.have.length(0);
    });

    it("should return vulnerability details when version is vulnerable", async function() {
      const currentVersion = "0.4.0";
      const advisoryData = [
        {
          cve_id: "CVE-2023-1234",
          html_url: "https://github.com/advisories/CVE-2023-1234",
          summary: "Critical security vulnerability",
          severity: "critical",
          vulnerabilities: [
            {
              vulnerable_version_range: "< 0.5.0"
            }
          ]
        }
      ];

      semver.satisfies = function(version, range) {
        return version === "0.4.0" && range === "< 0.5.0";
      };

      const result = await checkVulnerableVersion(currentVersion, advisoryData);

      expect(result).to.be.an("array");
      expect(result).to.have.length(1);
      expect(result[0]).to.deep.equal({
        description: "Vulnerable to CVE-2023-1234 (range: < 0.5.0)",
        advisory_url: "https://github.com/advisories/CVE-2023-1234",
        advisory_summary: "Critical security vulnerability",
        severity: "critical"
      });
    });

    it("should handle multiple vulnerabilities in a single advisory", async function() {
      const currentVersion = "1.5.0";
      const advisoryData = [
        {
          cve_id: "CVE-2023-5678",
          html_url: "https://github.com/advisories/CVE-2023-5678",
          summary: "Multiple vulnerabilities",
          severity: "high",
          vulnerabilities: [
            {
              vulnerable_version_range: "< 2.0.0"
            },
            {
              vulnerable_version_range: ">= 1.0.0 < 1.8.0"
            }
          ]
        }
      ];

      semver.satisfies = function(version, range) {
        if (version === "1.5.0") {
          return range === "< 2.0.0" || range === ">= 1.0.0 < 1.8.0";
        }
        return false;
      };

      const result = await checkVulnerableVersion(currentVersion, advisoryData);

      expect(result).to.be.an("array");
      expect(result).to.have.length(2);
      expect(result[0].description).to.contain("CVE-2023-5678");
      expect(result[1].description).to.contain("CVE-2023-5678");
    });

    it("should handle multiple advisories", async function() {
      const currentVersion = "1.0.0";
      const advisoryData = [
        {
          cve_id: "CVE-2023-1111",
          html_url: "https://github.com/advisories/CVE-2023-1111",
          summary: "First vulnerability",
          severity: "medium",
          vulnerabilities: [
            {
              vulnerable_version_range: "<= 1.0.0"
            }
          ]
        },
        {
          cve_id: "CVE-2023-2222",
          html_url: "https://github.com/advisories/CVE-2023-2222",
          summary: "Second vulnerability",
          severity: "low",
          vulnerabilities: [
            {
              vulnerable_version_range: "= 1.0.0"
            }
          ]
        }
      ];

      semver.satisfies = function(version, range) {
        if (version === "1.0.0") {
          return range === "<= 1.0.0" || range === "= 1.0.0";
        }
        return false;
      };

      const result = await checkVulnerableVersion(currentVersion, advisoryData);

      expect(result).to.be.an("array");
      expect(result).to.have.length(2);
      expect(result[0].description).to.contain("CVE-2023-1111");
      expect(result[1].description).to.contain("CVE-2023-2222");
    });

    it("should handle empty advisory data", async function() {
      const currentVersion = "1.0.0";
      const advisoryData = [];

      const result = await checkVulnerableVersion(currentVersion, advisoryData);

      expect(result).to.be.an("array");
      expect(result).to.have.length(0);
    });

    it("should handle advisory with no vulnerabilities", async function() {
      const currentVersion = "1.0.0";
      const advisoryData = [
        {
          cve_id: "CVE-2023-0000",
          html_url: "https://github.com/advisories/CVE-2023-0000",
          summary: "No vulnerabilities",
          severity: "info",
          vulnerabilities: []
        }
      ];

      const result = await checkVulnerableVersion(currentVersion, advisoryData);

      expect(result).to.be.an("array");
      expect(result).to.have.length(0);
    });
  });

  describe("checkGitHubAdvisories", function() {
    it("should return vulnerability findings on successful API call", async function() {
      const mockAdvisoryData = [
        {
          cve_id: "CVE-2023-9999",
          html_url: "https://github.com/advisories/CVE-2023-9999",
          summary: "Test vulnerability from GitHub API",
          severity: "high",
          vulnerabilities: [
            {
              vulnerable_version_range: "< 2.0.0"
            }
          ]
        }
      ];

      axios.get = async function(url, options) {
        expect(url).to.equal("https://api.github.com/advisories?affects=lodash@1.0.0");
        expect(options.headers.Accept).to.equal("application/vnd.github.v3+json");
        return { data: mockAdvisoryData };
      };

      semver.satisfies = function(version, range) {
        return version === "1.0.0" && range === "< 2.0.0";
      };

      const result = await checkGitHubAdvisories("lodash", "1.0.0");

      expect(result).to.be.an("array");
      expect(result).to.have.length(1);
      expect(result[0].description).to.contain("CVE-2023-9999");
    });

    it("should return empty array when no vulnerabilities are found", async function() {
      const mockAdvisoryData = [
        {
          cve_id: "CVE-2023-0001",
          html_url: "https://github.com/advisories/CVE-2023-0001",
          summary: "Non-applicable vulnerability",
          severity: "medium",
          vulnerabilities: [
            {
              vulnerable_version_range: "< 0.5.0"
            }
          ]
        }
      ];

      axios.get = async function(url, options) {
        return { data: mockAdvisoryData };
      };

      semver.satisfies = function(version, range) {
        return false; // Not vulnerable
      };

      const result = await checkGitHubAdvisories("express", "4.18.0");

      expect(result).to.be.an("array");
      expect(result).to.have.length(0);
    });

    it("should handle API errors gracefully and return empty array", async function() {
      let loggedError = null;
      logger.log = function(level, message) {
        if (level === "error") {
          loggedError = message;
        }
      };

      axios.get = async function(url, options) {
        const error = new Error("GitHub API rate limit exceeded");
        error.response = { status: 403 };
        throw error;
      };

      const result = await checkGitHubAdvisories("react", "18.0.0");

      expect(result).to.be.an("array");
      expect(result).to.have.length(0);
      expect(loggedError).to.contain("Failed to get github advisory skipping");
      expect(loggedError).to.contain("GitHub API rate limit exceeded");
    });

    it("should handle network timeout errors", async function() {
      let loggedError = null;
      logger.log = function(level, message) {
        if (level === "error") {
          loggedError = message;
        }
      };

      axios.get = async function(url, options) {
        const error = new Error("timeout of 5000ms exceeded");
        error.code = "ECONNABORTED";
        throw error;
      };

      const result = await checkGitHubAdvisories("moment", "2.29.0");

      expect(result).to.be.an("array");
      expect(result).to.have.length(0);
      expect(loggedError).to.contain("timeout of 5000ms exceeded");
    });

    it("should construct correct API URL with package name and version", async function() {
      let capturedUrl = null;
      
      axios.get = async function(url, options) {
        capturedUrl = url;
        return { data: [] };
      };

      await checkGitHubAdvisories("@types/node", "16.11.0");

      expect(capturedUrl).to.equal("https://api.github.com/advisories?affects=@types/node@16.11.0");
    });

    it("should include correct headers in API request", async function() {
      let capturedHeaders = null;
      
      axios.get = async function(url, options) {
        capturedHeaders = options.headers;
        return { data: [] };
      };

      await checkGitHubAdvisories("chalk", "4.1.2");

      expect(capturedHeaders).to.deep.equal({
        Accept: "application/vnd.github.v3+json"
      });
    });
  });

  describe("getActionDependencies", function() {
    it("should return empty array when no actions are provided", async function() {
      const result = await getActionDependencies([]);

      expect(result).to.be.an("array");
      expect(result).to.have.length(0);
    });

    it("should return empty array when actions have no vulnerable dependencies", async function() {
      const actionsList = [
        {
          name: "Test Action",
          dependencies: [
            { name: "safe-package", version: "1.0.0" }
          ],
          supported_triggers: [{ id: "post-login" }]
        }
      ];

      axios.get = async function(url, options) {
        return { data: [] }; // No vulnerabilities
      };

      const result = await getActionDependencies(actionsList);

      expect(result).to.be.an("array");
      expect(result).to.have.length(0);
    });

    it("should return vulnerability details for actions with vulnerable dependencies", async function() {
      const actionsList = [
        {
          name: "Auth Action",
          dependencies: [
            { name: "vulnerable-package", version: "1.0.0" },
            { name: "safe-package", version: "2.0.0" }
          ],
          supported_triggers: [{ id: "post-login" }]
        }
      ];

      let callCount = 0;
      axios.get = async function(url, options) {
        callCount++;
        if (url.includes("vulnerable-package")) {
          return {
            data: [
              {
                cve_id: "CVE-2023-VULN",
                html_url: "https://github.com/advisories/CVE-2023-VULN",
                summary: "Critical vulnerability",
                severity: "critical",
                vulnerabilities: [
                  { vulnerable_version_range: "<= 1.0.0" }
                ]
              }
            ]
          };
        } else {
          return { data: [] }; // No vulnerabilities for safe-package
        }
      };

      semver.satisfies = function(version, range) {
        return version === "1.0.0" && range === "<= 1.0.0";
      };

      const result = await getActionDependencies(actionsList);

      expect(result).to.be.an("array");
      expect(result).to.have.length(1);
      expect(result[0]).to.deep.include({
        name: "vulnerable-package",
        actionName: "Auth Action",
        version: "1.0.0",
        trigger: "post-login"
      });
      expect(result[0].vulnFindings).to.have.length(1);
      expect(result[0].vulnFindings[0].description).to.contain("CVE-2023-VULN");
      expect(callCount).to.equal(2); // Called for both dependencies
    });

    it("should handle multiple actions with multiple vulnerable dependencies", async function() {
      const actionsList = [
        {
          name: "Action 1",
          dependencies: [
            { name: "vuln-pkg-1", version: "0.5.0" }
          ],
          supported_triggers: [{ id: "post-login" }]
        },
        {
          name: "Action 2",
          dependencies: [
            { name: "vuln-pkg-2", version: "1.2.0" }
          ],
          supported_triggers: [{ id: "pre-user-registration" }]
        }
      ];

      axios.get = async function(url, options) {
        if (url.includes("vuln-pkg-1")) {
          return {
            data: [
              {
                cve_id: "CVE-2023-0001",
                html_url: "https://github.com/advisories/CVE-2023-0001",
                summary: "First vulnerability",
                severity: "high",
                vulnerabilities: [
                  { vulnerable_version_range: "< 1.0.0" }
                ]
              }
            ]
          };
        } else if (url.includes("vuln-pkg-2")) {
          return {
            data: [
              {
                cve_id: "CVE-2023-0002",
                html_url: "https://github.com/advisories/CVE-2023-0002",
                summary: "Second vulnerability",
                severity: "medium",
                vulnerabilities: [
                  { vulnerable_version_range: ">= 1.0.0 < 1.5.0" }
                ]
              }
            ]
          };
        }
        return { data: [] };
      };

      semver.satisfies = function(version, range) {
        return (version === "0.5.0" && range === "< 1.0.0") ||
               (version === "1.2.0" && range === ">= 1.0.0 < 1.5.0");
      };

      const result = await getActionDependencies(actionsList);

      expect(result).to.be.an("array");
      expect(result).to.have.length(2);
      
      expect(result[0].name).to.equal("vuln-pkg-1");
      expect(result[0].actionName).to.equal("Action 1");
      expect(result[0].trigger).to.equal("post-login");
      
      expect(result[1].name).to.equal("vuln-pkg-2");
      expect(result[1].actionName).to.equal("Action 2");
      expect(result[1].trigger).to.equal("pre-user-registration");
    });

    it("should handle actions with no dependencies", async function() {
      const actionsList = [
        {
          name: "Simple Action",
          dependencies: [],
          supported_triggers: [{ id: "post-login" }]
        }
      ];

      const result = await getActionDependencies(actionsList);

      expect(result).to.be.an("array");
      expect(result).to.have.length(0);
    });

    it("should handle API errors during dependency checking", async function() {
      const actionsList = [
        {
          name: "Error Action",
          dependencies: [
            { name: "error-package", version: "1.0.0" }
          ],
          supported_triggers: [{ id: "post-login" }]
        }
      ];

      let loggedErrors = [];
      logger.log = function(level, message) {
        if (level === "error") {
          loggedErrors.push(message);
        }
      };

      axios.get = async function(url, options) {
        throw new Error("API request failed");
      };

      const result = await getActionDependencies(actionsList);

      expect(result).to.be.an("array");
      expect(result).to.have.length(0);
      expect(loggedErrors).to.have.length(1);
      expect(loggedErrors[0]).to.contain("Failed to get github advisory skipping");
    });

    it("should handle actions with mixed vulnerable and safe dependencies", async function() {
      const actionsList = [
        {
          name: "Mixed Action",
          dependencies: [
            { name: "safe-package", version: "2.0.0" },
            { name: "vulnerable-package", version: "0.1.0" },
            { name: "another-safe-package", version: "3.0.0" }
          ],
          supported_triggers: [{ id: "post-change-password" }]
        }
      ];

      axios.get = async function(url, options) {
        if (url.includes("vulnerable-package")) {
          return {
            data: [
              {
                cve_id: "CVE-2023-MIXED",
                html_url: "https://github.com/advisories/CVE-2023-MIXED",
                summary: "Mixed action vulnerability",
                severity: "high",
                vulnerabilities: [
                  { vulnerable_version_range: "< 1.0.0" }
                ]
              }
            ]
          };
        }
        return { data: [] }; // Safe packages have no vulnerabilities
      };

      semver.satisfies = function(version, range) {
        return version === "0.1.0" && range === "< 1.0.0";
      };

      const result = await getActionDependencies(actionsList);

      expect(result).to.be.an("array");
      expect(result).to.have.length(1); // Only the vulnerable package
      expect(result[0].name).to.equal("vulnerable-package");
      expect(result[0].actionName).to.equal("Mixed Action");
      expect(result[0].trigger).to.equal("post-change-password");
    });

    it("should handle actions with multiple supported triggers", async function() {
      const actionsList = [
        {
          name: "Multi-Trigger Action",
          dependencies: [
            { name: "vuln-package", version: "1.0.0" }
          ],
          supported_triggers: [
            { id: "post-login" },
            { id: "pre-user-registration" }
          ]
        }
      ];

      axios.get = async function(url, options) {
        return {
          data: [
            {
              cve_id: "CVE-2023-MULTI",
              html_url: "https://github.com/advisories/CVE-2023-MULTI",
              summary: "Multi-trigger vulnerability",
              severity: "medium",
              vulnerabilities: [
                { vulnerable_version_range: "= 1.0.0" }
              ]
            }
          ]
        };
      };

      semver.satisfies = function(version, range) {
        return version === "1.0.0" && range === "= 1.0.0";
      };

      const result = await getActionDependencies(actionsList);

      expect(result).to.be.an("array");
      expect(result).to.have.length(1);
      expect(result[0].trigger).to.equal("post-login"); // Should use first trigger
    });
  });

  describe("Integration and Edge Cases", function() {
    it("should handle semver edge cases", async function() {
      const currentVersion = "1.0.0-beta.1";
      const advisoryData = [
        {
          cve_id: "CVE-2023-BETA",
          html_url: "https://github.com/advisories/CVE-2023-BETA",
          summary: "Beta version vulnerability",
          severity: "low",
          vulnerabilities: [
            {
              vulnerable_version_range: ">=1.0.0-alpha <1.0.0"
            }
          ]
        }
      ];

      // Use actual semver function to test real behavior
      semver.satisfies = originalSemverSatisfies;

      const result = await checkVulnerableVersion(currentVersion, advisoryData);

      expect(result).to.be.an("array");
      // Beta versions like 1.0.0-beta.1 should satisfy ">=1.0.0-alpha <1.0.0" 
      expect(result).to.have.length(1);
      expect(result[0].description).to.contain("CVE-2023-BETA");
    });

    it("should handle malformed advisory data gracefully", async function() {
      const currentVersion = "1.0.0";
      const malformedAdvisoryData = [
        {
          // Missing required fields
          vulnerabilities: [
            {
              vulnerable_version_range: "< 1.0.0"
            }
          ]
        },
        {
          cve_id: "CVE-2023-GOOD",
          html_url: "https://github.com/advisories/CVE-2023-GOOD",
          summary: "Good advisory",
          severity: "medium",
          vulnerabilities: [
            {
              vulnerable_version_range: "= 1.0.0"
            }
          ]
        }
      ];

      semver.satisfies = function(version, range) {
        return version === "1.0.0" && range === "= 1.0.0";
      };

      const result = await checkVulnerableVersion(currentVersion, malformedAdvisoryData);

      expect(result).to.be.an("array");
      expect(result).to.have.length(1); // Should only process the well-formed advisory
      expect(result[0].description).to.contain("CVE-2023-GOOD");
    });

    it("should handle undefined/null values gracefully", async function() {
      const currentVersion = "1.0.0";
      const advisoryData = null;

      let threwError = false;
      try {
        await checkVulnerableVersion(currentVersion, advisoryData);
      } catch (error) {
        threwError = true;
      }

      expect(threwError).to.be.true; // Should handle gracefully or throw appropriately
    });
  });
});

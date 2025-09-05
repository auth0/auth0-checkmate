const { expect } = require("chai");
const axios = require("axios");
const {
  getAccessToken,
  getCustomDomains,
  getApplications,
  getConnections,
  getEmailProvider,
  getEmailTemplates,
  getErrorPageTemplate,
  getBruteForceProtectionSetting,
  getSuspiciousIpSetting,
  getBreachedPasswordSetting,
  getLogStreams,
  getAttackProtection,
  getTenantSettings,
  getGuardianFactors,
  getGuardianPolicies,
  getBotDetectionSetting,
  getRules,
  getHooks,
  getActions,
  getLogs,
  getNetworkACL,
  getEventStreams
} = require("../../analyzer/tools/auth0");
const logger = require("../../analyzer/lib/logger");
const constants = require("../../analyzer/lib/constants");

describe("auth0.js", function() {
  let originalAxiosPost;
  let originalAxiosGet;
  let originalLoggerLog;
  let originalConsoleError;
  let originalProcessExit;

  beforeEach(function() {
    // Store original functions
    originalAxiosPost = axios.post;
    originalAxiosGet = axios.get;
    originalLoggerLog = logger.log;
    originalConsoleError = console.error;
    originalProcessExit = process.exit;

    // Mock process.exit to prevent test termination
    process.exit = function(code) {
      throw new Error(`process.exit called with code ${code}`);
    };

    // Mock console.error to capture error messages
    console.error = function() {};

    // Mock logger.log to capture log messages
    logger.log = function() {};
  });

  afterEach(function() {
    // Restore original functions
    axios.post = originalAxiosPost;
    axios.get = originalAxiosGet;
    logger.log = originalLoggerLog;
    console.error = originalConsoleError;
    process.exit = originalProcessExit;
  });

  describe("getAccessToken", function() {
    it("should return existing access token when provided", async function() {
      const existingToken = "existing-token-123";
      
      const result = await getAccessToken("test-domain", "client-id", "client-secret", existingToken);

      expect(result).to.equal(existingToken);
    });

    it("should return access token on successful authentication", async function() {
      const mockResponse = {
        data: {
          access_token: "test-access-token",
          token_type: "Bearer",
          expires_in: 3600
        }
      };

      axios.post = async function(url, body, options) {
        expect(url).to.equal("https://test-domain/oauth/token");
        expect(body.grant_type).to.equal("client_credentials");
        expect(body.client_id).to.equal("test-client-id");
        expect(body.client_secret).to.equal("test-client-secret");
        expect(body.audience).to.equal("https://test-domain/api/v2/");
        return mockResponse;
      };

      const result = await getAccessToken("test-domain", "test-client-id", "test-client-secret");

      expect(result).to.equal("test-access-token");
    });

    it("should exit process on authentication failure", async function() {
      axios.post = async function() {
        throw new Error("Authentication failed");
      };

      try {
        await getAccessToken("test-domain", "test-client-id", "wrong-secret");
        expect.fail("Should have thrown an error");
      } catch (error) {
        expect(error.message).to.contain("process.exit called with code 1");
      }
    });
  });

  describe("getCustomDomains", function() {
    it("should return custom domains data on success", async function() {
      const mockDomains = [
        {
          domain_id: "cd_123",
          domain: "auth.example.com",
          status: "ready",
          type: "auth0_managed_certs"
        }
      ];

      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/custom-domains");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockDomains };
      };

      const result = await getCustomDomains("test-domain", "test-token");

      expect(result).to.deep.equal(mockDomains);
    });

    it("should return empty array on API error", async function() {
      axios.get = async function() {
        throw new Error("API Error");
      };

      const result = await getCustomDomains("test-domain", "invalid-token");

      expect(result).to.deep.equal([]);
    });
  });

  describe("getApplications", function() {
    it("should return all applications with pagination", async function() {
      const mockClients = [
        { client_id: "app1", name: "Test App 1" },
        { client_id: "app2", name: "Test App 2" }
      ];

      let callCount = 0;
      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/clients");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        
        callCount++;
        if (callCount === 1) {
          // First page with full results
          return { data: new Array(100).fill().map((_, i) => ({ client_id: `app${i}`, name: `App ${i}` })) };
        } else {
          // Second page with partial results
          return { data: mockClients };
        }
      };

      const result = await getApplications("test-domain", "test-token");

      expect(result.length).to.equal(102); // 100 from first page + 2 from second page
    });

    it("should return empty array on error", async function() {
      axios.get = async function() {
        throw new Error("Network error");
      };

      const result = await getApplications("test-domain", "test-token");

      expect(result).to.deep.equal([]);
    });
  });

  describe("getConnections", function() {
    it("should return database connections on success", async function() {
      const mockConnections = [
        {
          id: "con_123",
          name: "Username-Password-Authentication",
          strategy: "auth0",
          enabled_clients: ["client_123"]
        }
      ];

      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/connections?strategy=auth0");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockConnections };
      };

      const result = await getConnections("test-domain", "test-token");

      expect(result).to.deep.equal(mockConnections);
    });

    it("should return empty array on error", async function() {
      axios.get = async function() {
        throw new Error("Connection error");
      };

      const result = await getConnections("test-domain", "test-token");

      expect(result).to.deep.equal([]);
    });
  });

  describe("getEmailProvider", function() {
    it("should return email provider configuration on success", async function() {
      const mockProvider = {
        name: "sendgrid",
        enabled: true,
        default_from_address: "noreply@example.com",
        credentials: { api_key: "sg.***" }
      };

      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/emails/provider");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockProvider };
      };

      const result = await getEmailProvider("test-domain", "test-token");

      expect(result).to.deep.equal(mockProvider);
    });

    it("should return null on error", async function() {
      axios.get = async function() {
        throw new Error("Provider not configured");
      };

      const result = await getEmailProvider("test-domain", "test-token");

      expect(result).to.be.null;
    });
  });

  describe("getEmailTemplates", function() {
    it("should return all email templates", async function() {
      let callCount = 0;
      const mockTemplates = {
        verify_email: { enabled: true, template: "Verify: {{user.email}}" },
        reset_email: { enabled: true, template: "Reset: {{user.email}}" }
      };

      axios.get = async function(url, options) {
        expect(url).to.match(/https:\/\/test-domain\/api\/v2\/email-templates\/.+/);
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        
        const templateName = url.split('/').pop();
        callCount++;
        
        if (mockTemplates[templateName]) {
          return { data: mockTemplates[templateName] };
        } else {
          return { data: null };
        }
      };

      const result = await getEmailTemplates("test-domain", "test-token");

      expect(result).to.be.an("array");
      expect(result.length).to.equal(constants.EMAIL_TEMPLATES_TYPES.length);
      expect(callCount).to.equal(constants.EMAIL_TEMPLATES_TYPES.length);
    });
  });

  describe("getErrorPageTemplate", function() {
    it("should return error page template on success", async function() {
      const mockResponse = {
        error_page: {
          html: "<html>Error: {{error}}</html>"
        }
      };

      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/tenants/settings");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockResponse };
      };

      const result = await getErrorPageTemplate("test-domain", "test-token");

      expect(result).to.equal("<html>Error: {{error}}</html>");
    });

    it("should return null on error", async function() {
      axios.get = async function() {
        throw new Error("Template not configured");
      };

      const result = await getErrorPageTemplate("test-domain", "test-token");

      expect(result).to.be.null;
    });
  });

  describe("getTenantSettings", function() {
    it("should return tenant settings on success", async function() {
      const mockSettings = {
        friendly_name: "Test Tenant",
        default_audience: "",
        default_directory: "Username-Password-Authentication",
        session_lifetime: 720
      };

      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/tenants/settings");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockSettings };
      };

      const result = await getTenantSettings("test-domain", "test-token");

      expect(result).to.deep.equal(mockSettings);
    });

    it("should return empty object on error", async function() {
      axios.get = async function() {
        throw new Error("Settings not accessible");
      };

      const result = await getTenantSettings("test-domain", "test-token");

      expect(result).to.deep.equal({});
    });
  });

  describe("getGuardianFactors", function() {
    it("should return guardian factors on success", async function() {
      const mockFactors = [
        { name: "sms", enabled: true, trial_expired: false },
        { name: "email", enabled: false, trial_expired: false }
      ];

      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/guardian/factors");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockFactors };
      };

      const result = await getGuardianFactors("test-domain", "test-token");

      expect(result).to.deep.equal(mockFactors);
    });

    it("should return empty object on error", async function() {
      axios.get = async function() {
        throw new Error("MFA not configured");
      };

      const result = await getGuardianFactors("test-domain", "test-token");

      expect(result).to.deep.equal({});
    });
  });

  describe("getGuardianPolicies", function() {
    it("should return guardian policies on success", async function() {
      const mockPolicies = [
        "all-applications",
        "confidence-score"
      ];

      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/guardian/policies");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockPolicies };
      };

      const result = await getGuardianPolicies("test-domain", "test-token");

      expect(result).to.deep.equal(mockPolicies);
    });

    it("should return empty object on error", async function() {
      axios.get = async function() {
        throw new Error("Policies not found");
      };

      const result = await getGuardianPolicies("test-domain", "test-token");

      expect(result).to.deep.equal({});
    });
  });

  describe("getRules", function() {
    it("should return rules on success", async function() {
      const mockRules = [
        {
          id: "rule_123",
          name: "Add roles",
          script: "function(user, context, callback) { callback(null, user, context); }",
          enabled: true
        }
      ];

      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/rules?enabled=true");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockRules };
      };

      const result = await getRules("test-domain", "test-token");

      expect(result).to.deep.equal(mockRules);
    });

    it("should return empty array on error", async function() {
      axios.get = async function() {
        throw new Error("Rules not accessible");
      };

      const result = await getRules("test-domain", "test-token");

      expect(result).to.deep.equal([]);
    });
  });

  describe("getHooks", function() {
    it("should return hooks on success", async function() {
      const mockHooks = [
        {
          id: "hook_123",
          name: "Pre User Registration",
          script: "function(user, context, callback) { callback(null, user); }",
          enabled: true
        }
      ];

      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/hooks?enabled=true");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockHooks };
      };

      const result = await getHooks("test-domain", "test-token");

      expect(result).to.deep.equal(mockHooks);
    });

    it("should return empty array on error", async function() {
      axios.get = async function() {
        throw new Error("Hooks not found");
      };

      const result = await getHooks("test-domain", "test-token");

      expect(result).to.deep.equal([]);
    });
  });

  describe("getActions", function() {
    it("should return actions on success", async function() {
      const mockActions = [
        {
          id: "action_123",
          name: "Custom Action",
          code: "exports.onExecutePostLogin = async (event, api) => {};",
          runtime: "node18"
        }
      ];

      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/actions/actions?installed=false");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockActions };
      };

      const result = await getActions("test-domain", "test-token");

      expect(result).to.deep.equal(mockActions);
    });

    it("should return empty array on error", async function() {
      axios.get = async function() {
        throw new Error("Actions not accessible");
      };

      const result = await getActions("test-domain", "test-token");

      expect(result).to.deep.equal([]);
    });
  });

  describe("getLogStreams", function() {
    it("should return log streams on success", async function() {
      const mockStreams = [
        {
          id: "lst_123",
          name: "Test Stream",
          type: "http",
          status: "active"
        }
      ];

      axios.get = async function(url, options) {
        expect(url).to.equal("https://test-domain/api/v2/log-streams");
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockStreams };
      };

      const result = await getLogStreams("test-domain", "test-token");

      expect(result).to.deep.equal(mockStreams);
    });

    it("should return error response data on error", async function() {
      const errorResponse = { response: { data: { error: "Stream not found" } } };
      
      axios.get = async function() {
        throw errorResponse;
      };

      const result = await getLogStreams("test-domain", "test-token");

      expect(result).to.deep.equal([{ error: "Stream not found" }]);
    });
  });

  describe("Attack Protection Functions", function() {
    describe("getBruteForceProtectionSetting", function() {
      it("should return brute force protection settings on success", async function() {
        const mockSettings = {
          enabled: true,
          shields: ["block", "user_notification"],
          mode: "count_per_identifier_and_ip"
        };

        axios.get = async function(url, options) {
          expect(url).to.equal("https://test-domain/api/v2/attack-protection/brute-force-protection");
          expect(options.headers.Authorization).to.equal("Bearer test-token");
          return { data: mockSettings };
        };

        const result = await getBruteForceProtectionSetting("test-domain", "test-token");

        expect(result).to.deep.equal(mockSettings);
      });

      it("should return empty object on error", async function() {
        axios.get = async function() {
          throw new Error("Settings not found");
        };

        const result = await getBruteForceProtectionSetting("test-domain", "test-token");

        expect(result).to.deep.equal({});
      });
    });

    describe("getSuspiciousIpSetting", function() {
      it("should return suspicious IP settings on success", async function() {
        const mockSettings = {
          enabled: true,
          shields: ["admin_notification", "block"],
          allowlist: [],
          stage: {
            "pre-login": { max_attempts: 100, rate: 864000 }
          }
        };

        axios.get = async function(url) {
          expect(url).to.equal("https://test-domain/api/v2/attack-protection/suspicious-ip-throttling");
          return { data: mockSettings };
        };

        const result = await getSuspiciousIpSetting("test-domain", "test-token");

        expect(result).to.deep.equal(mockSettings);
      });
    });

    describe("getBreachedPasswordSetting", function() {
      it("should return breached password settings on success", async function() {
        const mockSettings = {
          enabled: true,
          shields: ["admin_notification", "block"],
          admin_notification_frequency: ["immediately"],
          method: "standard"
        };

        axios.get = async function(url) {
          expect(url).to.equal("https://test-domain/api/v2/attack-protection/breached-password-detection");
          return { data: mockSettings };
        };

        const result = await getBreachedPasswordSetting("test-domain", "test-token");

        expect(result).to.deep.equal(mockSettings);
      });
    });

    describe("getBotDetectionSetting", function() {
      it("should return bot detection settings on success", async function() {
        const mockSettings = {
          enabled: true,
          provider: "recaptcha_v2"
        };

        axios.get = async function(url) {
          expect(url).to.equal("https://test-domain/api/v2/anomaly/captchas");
          return { data: mockSettings };
        };

        const result = await getBotDetectionSetting("test-domain", "test-token");

        expect(result).to.deep.equal(mockSettings);
      });
    });

    describe("getAttackProtection", function() {
      it("should return combined attack protection settings", async function() {
        const mockBreached = { enabled: true };
        const mockBrute = { enabled: true };
        const mockSuspicious = { enabled: false };
        const mockBot = { enabled: true };

        let callCount = 0;
        axios.get = async function(url) {
          callCount++;
          if (url.includes("breached-password-detection")) {
            return { data: mockBreached };
          } else if (url.includes("brute-force-protection")) {
            return { data: mockBrute };
          } else if (url.includes("suspicious-ip-throttling")) {
            return { data: mockSuspicious };
          } else if (url.includes("captchas")) {
            return { data: mockBot };
          }
        };

        const result = await getAttackProtection("test-domain", "test-token");

        expect(result).to.have.property("breachedPasswordDetection");
        expect(result).to.have.property("bruteForceProtection");
        expect(result).to.have.property("suspiciousIpThrottling");
        expect(result).to.have.property("botDetection");
        expect(callCount).to.equal(4);
      });

      it("should return empty object on error", async function() {
        axios.get = async function() {
          throw new Error("Attack protection not accessible");
        };

        const result = await getAttackProtection("test-domain", "test-token");

        // The actual function returns an object with empty sub-objects, not an empty object
        expect(result).to.have.property("breachedPasswordDetection");
        expect(result).to.have.property("bruteForceProtection");
        expect(result).to.have.property("suspiciousIpThrottling");
        expect(result).to.have.property("botDetection");
        expect(result.breachedPasswordDetection).to.deep.equal({});
        expect(result.bruteForceProtection).to.deep.equal({});
        expect(result.suspiciousIpThrottling).to.deep.equal({});
        expect(result.botDetection).to.deep.equal({});
      });
    });
  });

  describe("getLogs", function() {
    it("should return logs with query on success", async function() {
      const mockLogs = [
        { type: "s", hostname: "test-domain" },
        { type: "f", hostname: "test-domain" }
      ];

      axios.get = async function(url, options) {
        expect(url).to.match(/https:\/\/test-domain\/api\/v2\/logs\?per_page=1&fields=type,hostname&q=type:/);
        expect(options.headers.Authorization).to.equal("Bearer test-token");
        return { data: mockLogs };
      };

      const result = await getLogs("test-domain", "test-token");

      expect(result).to.have.property("log_query");
      expect(result).to.have.property("logs");
      expect(result.logs).to.deep.equal(mockLogs);
    });

    it("should return empty logs array on error", async function() {
      axios.get = async function() {
        throw new Error("Logs not accessible");
      };

      const result = await getLogs("test-domain", "test-token");

      expect(result).to.have.property("log_query");
      expect(result.logs).to.deep.equal([]);
    });
  });

  describe("getNetworkACL", function() {
    it("should return network ACL settings on success", async function() {
      const mockACL = [
        {
          id: "acl_123",
          name: "Test ACL",
          ip_ranges: ["192.168.1.0/24"]
        }
      ];

      axios.get = async function(url) {
        expect(url).to.equal("https://test-domain/api/v2/network-acls");
        return { data: mockACL };
      };

      const result = await getNetworkACL("test-domain", "test-token");

      expect(result).to.deep.equal(mockACL);
    });

    it("should return error response on failure", async function() {
      const errorData = { message: "Feature not available", statusCode: 404 };
      const error = new Error("Not found");
      error.response = { data: errorData };

      axios.get = async function() {
        throw error;
      };

      const result = await getNetworkACL("test-domain", "test-token");

      expect(result).to.deep.equal([errorData]);
    });
  });

  describe("getEventStreams", function() {
    it("should return event streams on success", async function() {
      const mockEventStreams = [
        {
          id: "ev_123",
          name: "User Events Stream",
          type: "http",
          status: "active"
        }
      ];

      axios.get = async function(url) {
        expect(url).to.equal("https://test-domain/api/v2/event-streams");
        return { data: { eventStreams: mockEventStreams } };
      };

      const result = await getEventStreams("test-domain", "test-token");

      expect(result).to.deep.equal(mockEventStreams);
    });

    it("should return error response on failure", async function() {
      const errorData = { error: "Event streams not available" };
      const error = new Error("Service unavailable");
      error.response = { data: errorData };

      axios.get = async function() {
        throw error;
      };

      const result = await getEventStreams("test-domain", "test-token");

      expect(result).to.deep.equal([errorData]);
    });
  });

  describe("Edge cases and error handling", function() {
    it("should handle malformed response data", async function() {
      axios.get = async function() {
        return { data: null };
      };

      const result = await getCustomDomains("test-domain", "test-token");

      expect(result).to.be.null;
    });

    it("should handle network timeouts", async function() {
      axios.get = async function() {
        const error = new Error("timeout of 5000ms exceeded");
        error.code = "ECONNABORTED";
        throw error;
      };

      const result = await getTenantSettings("test-domain", "test-token");

      expect(result).to.deep.equal({});
    });

    it("should handle 401 unauthorized errors", async function() {
      axios.get = async function() {
        const error = new Error("Request failed with status code 401");
        error.response = { status: 401, data: { error: "Unauthorized" } };
        throw error;
      };

      const result = await getEmailProvider("test-domain", "invalid-token");

      expect(result).to.be.null;
    });

    it("should handle 403 forbidden errors", async function() {
      axios.get = async function() {
        const error = new Error("Request failed with status code 403");
        error.response = { status: 403, data: { error: "Insufficient scope" } };
        throw error;
      };

      const result = await getActions("test-domain", "limited-token");

      expect(result).to.deep.equal([]);
    });

    it("should handle 404 not found errors", async function() {
      axios.get = async function() {
        const error = new Error("Request failed with status code 404");
        error.response = { status: 404, data: { error: "Resource not found" } };
        throw error;
      };

      const result = await getErrorPageTemplate("test-domain", "test-token");

      expect(result).to.be.null;
    });
  });
});

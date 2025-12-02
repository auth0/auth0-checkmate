const { expect } = require("chai");
const axios = require("axios");
const logger = require("../../analyzer/lib/logger");
// We need to require the file to ensure the interceptor is attached
require("../../analyzer/tools/auth0");

describe("Auth0 API Retry Logic", function() {
  let originalAdapter;
  let originalLoggerLog;
  let logSpy = [];

  beforeEach(function() {
    originalAdapter = axios.defaults.adapter;
    originalLoggerLog = logger.log;
    logSpy = [];
    logger.log = (level, message) => {
      logSpy.push({ level, message });
    };
  });

  afterEach(function() {
    axios.defaults.adapter = originalAdapter;
    logger.log = originalLoggerLog;
  });

  it("should retry on 429 and eventually succeed", async function() {
    let attempts = 0;
    
    // Mock adapter that fails twice with 429 then succeeds
    axios.defaults.adapter = async (config) => {
      attempts++;
      if (attempts <= 2) {
        const error = new Error("Request failed with status code 429");
        error.config = config; // Attach config to error
        error.response = {
          status: 429,
          headers: { "retry-after": "1" }, // 1 second
          config: config,
          data: {}
        };
        // We need to reject for the interceptor to catch it
        return Promise.reject(error);
      }
      return {
        status: 200,
        statusText: "OK",
        headers: {},
        config: config,
        data: { success: true }
      };
    };

    // Override setTimeout to speed up tests
    const originalSetTimeout = global.setTimeout;
    global.setTimeout = (fn) => fn();

    try {
      const response = await axios.get("https://test.com/api");
      expect(response.data.success).to.be.true;
      expect(attempts).to.equal(3); // Initial + 2 retries
      
      // Verify logs
      const retryLogs = logSpy.filter(l => l.message.includes("Rate limited. Retrying"));
      expect(retryLogs.length).to.equal(2);
    } finally {
      global.setTimeout = originalSetTimeout;
    }
  });

  it("should fail after max retries", async function() {
    let attempts = 0;
    
    axios.defaults.adapter = async (config) => {
      attempts++;
      const error = new Error("Request failed with status code 429");
      error.config = config; // Attach config to error
      error.response = {
        status: 429,
        headers: {}, // No retry-after, use exponential backoff
        config: config,
        data: {}
      };
      return Promise.reject(error);
    };

    // Override setTimeout
    const originalSetTimeout = global.setTimeout;
    global.setTimeout = (fn) => fn();

    try {
      await axios.get("https://test.com/api");
      throw new Error("Should have failed");
    } catch (error) {
      expect(error.response.status).to.equal(429);
      // Initial + 5 retries = 6 attempts
      expect(attempts).to.equal(6);
    } finally {
      global.setTimeout = originalSetTimeout;
    }
  });

  it("should respect Retry-After header", async function() {
    let attempts = 0;
    let delays = [];

    // Mock setTimeout to capture delays
    const originalSetTimeout = global.setTimeout;
    global.setTimeout = (fn, delay) => {
      delays.push(delay);
      fn();
    };

    axios.defaults.adapter = async (config) => {
      attempts++;
      if (attempts === 1) {
        const error = new Error("Request failed with status code 429");
        error.config = config; // Attach config to error
        error.response = {
          status: 429,
          headers: { "retry-after": "2" }, // 2 seconds
          config: config,
          data: {}
        };
        return Promise.reject(error);
      }
      return { status: 200, data: {} };
    };

    try {
      await axios.get("https://test.com/api");
      expect(attempts).to.equal(2);
      // Delay should be around 2000ms + jitter
      expect(delays[0]).to.be.at.least(2000);
      expect(delays[0]).to.be.below(3100); // 2000 + max 1000 jitter
    } finally {
      global.setTimeout = originalSetTimeout;
    }
  });

  it("should handle Date format Retry-After header", async function() {
    let attempts = 0;
    let delays = [];

    // Mock setTimeout to capture delays
    const originalSetTimeout = global.setTimeout;
    global.setTimeout = (fn, delay) => {
      delays.push(delay);
      fn();
    };

    axios.defaults.adapter = async (config) => {
      attempts++;
      if (attempts === 1) {
        const error = new Error("Request failed with status code 429");
        error.config = config; // Attach config to error
        error.response = {
          status: 429,
          headers: { "retry-after": "Wed, 21 Oct 2015 07:28:00 GMT" }, 
          config: config,
          data: {}
        };
        return Promise.reject(error);
      }
      return { status: 200, data: {} };
    };

    try {
      await axios.get("https://test.com/api");
      expect(attempts).to.equal(2);
      // Delay should be default, around 1000ms + jitter
      expect(delays[0]).to.be.at.least(1000);
      expect(delays[0]).to.be.below(2000); // 1000 + max 1000 jitter
    } finally {
      global.setTimeout = originalSetTimeout;
    }
  });

  it("should handle non existent Retry-After header", async function() {
    let attempts = 0;
    let delays = [];

    // Mock setTimeout to capture delays
    const originalSetTimeout = global.setTimeout;
    global.setTimeout = (fn, delay) => {
      delays.push(delay);
      fn();
    };

    axios.defaults.adapter = async (config) => {
      attempts++;
      if (attempts === 1) {
        const error = new Error("Request failed with status code 429");
        error.config = config; // Attach config to error
        error.response = {
          status: 429,
          headers: {}, // No retry-after
          config: config,
          data: {}
        };
        return Promise.reject(error);
      }
      return { status: 200, data: {} };
    };

    try {
      await axios.get("https://test.com/api");
      expect(attempts).to.equal(2);
      // Delay should be default, around 1000ms + jitter
      expect(delays[0]).to.be.at.least(1000);
      expect(delays[0]).to.be.below(2000); // 1000 + max 1000 jitter
    } finally {
      global.setTimeout = originalSetTimeout;
    }
  });
});

const axios = require("axios");
const CONSTANTS = require("../lib/constants");
const logger = require("../lib/logger");
const {
  version: packageVersion,
  name: packageName,
} = require("../../package.json");
const PER_PAGE = 100;
//axios default config
axios.defaults.headers.common["User-Agent"] =
  `${packageName}/${packageVersion}`;

// Add exponential backoff interceptor
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    const config = error.config;

    // Retry on 429 (Too Many Requests)
    if (error.response && error.response.status === 429) {
      config.__retryCount = config.__retryCount || 0;
      const MAX_RETRIES = 5;

      if (config.__retryCount >= MAX_RETRIES) {
        return Promise.reject(error);
      }

      // Calculate delay
      let delayInMs = 1000;
      if (error.response.headers["retry-after"]) {
        //usually Auth0 provides seconds in retry-after header
        const retryAfter = parseInt(error.response.headers["retry-after"], 10);
        if (!isNaN(retryAfter)) {
          delayInMs = retryAfter * 1000;
        }
      } else {
        // In case Auth0 changes retry-after header
        delayInMs = Math.pow(2, config.__retryCount) * 1000;
      }

      // Add some jitter to prevent thundering herd
      delayInMs += Math.random() * 1000;

      logger.log(
        "warn",
        `Rate limited. Retrying in ${Math.round(delayInMs)}ms... 
        (Attempt ${config.__retryCount}/${MAX_RETRIES}) due to ${error.response.status} response`,
      );

      config.__retryCount += 1;
      await new Promise((resolve) => setTimeout(resolve, delayInMs));
      return axios(config);
    }

    return Promise.reject(error);
  }
);

async function getAccessToken(domain, client_id, client_secret, canonicalDomain) {
  logger.log("info", `Getting an access token for client_id ${client_id}`);
  logger.log("info", `Requesting scopes ${CONSTANTS.REQUIRED_SCOPES}`);
  const tokenUrl = `https://${domain}/oauth/token`;
  const headers = {
    "Content-Type": "application/json",
  };
  const body = {
    grant_type: "client_credentials",
    client_id: client_id,
    client_secret: client_secret,
    audience: `https://${canonicalDomain || domain}/api/v2/`,
    scopes: CONSTANTS.REQUIRED_SCOPES,
  };

  try {
    const response = await axios.post(tokenUrl, body, { headers });
    return response.data.access_token;
  } catch (error) {
    logger.log("error", `Error getting access token: ${error.message}`);
    process.exit(1);
  }
}

/**
 * GET a Management API v2 resource. On failure the error is logged and
 * `fallback` (a value, or a function of the error) is returned.
 * `select` extracts the value to return from the response body.
 */
async function mgmtGet(
  domain,
  accessToken,
  path,
  label,
  fallback,
  { select = (data) => data, level = "info" } = {},
) {
  const url = `https://${domain}/api/v2/${path}`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log(level, `Getting ${label}`);
  try {
    const response = await axios.get(url, { headers });
    return select(response.data);
  } catch (error) {
    logger.log("error", `Failed to get ${label} ${error.message}`);
    return typeof fallback === "function" ? fallback(error) : fallback;
  }
}

// The API error body is surfaced to the checks (e.g. insufficient_scope).
const errorBodyOrEmpty = (error) =>
  error.response?.data ? [error.response.data] : [];

async function getCustomDomains(domain, accessToken) {
  return mgmtGet(domain, accessToken, "custom-domains", "custom domains", []);
}

async function fetchClients(url, accessToken, page) {
  try {
    const response = await axios.get(url, {
      params: {
        per_page: PER_PAGE,
        page: page,
        is_global: false,
      },
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    return response.data; // Array of clients
  } catch (error) {
    logger.log("error", `Error fetching clients: ${error.message}`);
    throw error;
  }
}

async function getActions(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "actions/actions?installed=false",
    "actions",
    [],
  );
}

async function getApplications(domain, accessToken) {
  const url = `https://${domain}/api/v2/clients`;
  let allClients = [],
    page = 0;
  logger.log("info", `Getting Applications`);
  try {
    let hasMore = true;

    while (hasMore) {
      const clients = await fetchClients(url, accessToken, page);

      if (clients.length < PER_PAGE) {
        hasMore = false; // No more data to fetch
      } else {
        page++; // Move to the next page
      }

      allClients = allClients.concat(clients); // Add the current page's clients to the list

      // Stop early once past the limit; client validations are skipped anyway
      if (allClients.length > CONSTANTS.MAX_APPLICATIONS) {
        logger.log(
          "info",
          `Stopped fetching applications: tenant has more than ${CONSTANTS.MAX_APPLICATIONS} applications`,
        );
        hasMore = false;
      }
    }

    return allClients;
  } catch (error) {
    logger.log("error", `Failed to get clients ${error.message}`);
    return [];
  }
}

async function getConnections(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "connections?strategy=auth0",
    "database connections",
    [],
  );
}

async function getEmailProvider(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "emails/provider",
    "email provider",
    null,
  );
}

async function getLogStreams(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "log-streams",
    "log streams",
    errorBodyOrEmpty,
  );
}

async function getBruteForceProtectionSetting(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "attack-protection/brute-force-protection",
    "brute force settings",
    {},
  );
}

async function getSuspiciousIpSetting(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "attack-protection/suspicious-ip-throttling",
    "suspicious IP settings",
    {},
  );
}

async function getBreachedPasswordSetting(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "attack-protection/breached-password-detection",
    "breached password settings",
    {},
  );
}

async function getBotDetectionSetting(domain, accessToken) {
  const botDetectionUrl = `https://${domain}/api/v2/attack-protection/bot-detection`;
  const captchaUrl = `https://${domain}/api/v2/attack-protection/captcha`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting bot detection setting`);

  try {
    const [botDetectionResponse, captchaResponse] = await Promise.all([
      axios.get(botDetectionUrl, { headers }),
      axios.get(captchaUrl, { headers }),
    ]);
    return { ...botDetectionResponse.data, ...captchaResponse.data };
  } catch (error) {
    logger.log(
      "error",
      `Failed to get bot detection settings ${error.message}`,
    );
    return {};
  }
}

async function getAttackProtection(domain, accessToken) {
  try {
    const [
      breachedPasswordDetection,
      bruteForceProtection,
      suspiciousIpThrottling,
      botDetection,
    ] = await Promise.all([
      getBreachedPasswordSetting(domain, accessToken),
      getBruteForceProtectionSetting(domain, accessToken),
      getSuspiciousIpSetting(domain, accessToken),
      getBotDetectionSetting(domain, accessToken),
    ]);
    return {
      breachedPasswordDetection,
      bruteForceProtection,
      suspiciousIpThrottling,
      botDetection,
    };
  } catch (error) {
    logger.log(
      "error",
      `Failed to get attack protection settings ${error.message}`,
    );
    return {};
  }
}

async function getEmailTemplate(domain, accessToken, templateName) {
  // Templates that are not configured return an error; treat them as null
  return mgmtGet(
    domain,
    accessToken,
    `email-templates/${templateName}`,
    `email template ${templateName}`,
    null,
    { level: "debug" },
  );
}

async function getErrorPageTemplate(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "tenants/settings",
    "error page template",
    null,
    { select: (settings) => settings.error_page.html },
  );
}

async function getEmailTemplates(domain, accessToken) {
  logger.log("info", `Getting email templates`);
  return Promise.all(
    CONSTANTS.EMAIL_TEMPLATES_TYPES.map(async (templateName) => {
      const template = await getEmailTemplate(
        domain,
        accessToken,
        templateName,
      );
      return { name: CONSTANTS.EMAIL_TEMPLATES_NAMES[templateName], template };
    }),
  );
}

async function getTenantSettings(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "tenants/settings",
    "tenant settings",
    {},
  );
}

// Returns null on failure so callers can tell "not set" from "unknown"
async function getPrompts(domain, accessToken) {
  return mgmtGet(domain, accessToken, "prompts", "prompts settings", null);
}

async function getGuardianFactors(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "guardian/factors",
    "MFA factors",
    {},
  );
}

async function getGuardianPolicies(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "guardian/policies",
    "MFA policies",
    {},
  );
}

// legacy rules and hooks
async function getRules(domain, accessToken) {
  return mgmtGet(domain, accessToken, "rules?enabled=true", "rules", [], {
    level: "warn",
  });
}

async function getHooks(domain, accessToken) {
  return mgmtGet(domain, accessToken, "hooks?enabled=true", "hooks", [], {
    level: "warn",
  });
}

async function getLogs(domain, accessToken, queryDomain) {
  const logTypes = CONSTANTS.LOG_TYPES;
  const fields = "type,hostname";
  const per_page = 1;
  const query = `type: (${logTypes.join(" ")}) AND hostname: ${queryDomain || domain}`;
  return mgmtGet(
    domain,
    accessToken,
    encodeURI(`logs?per_page=${per_page}&fields=${fields}&q=${query}`),
    "logs",
    { log_query: query, logs: [] },
    { select: (logs) => ({ log_query: query, logs }) },
  );
}

// Early Access
async function getNetworkACL(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "network-acls",
    "network ACL",
    errorBodyOrEmpty,
  );
}

// Early Access
async function getEventStreams(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "event-streams",
    "event streams",
    errorBodyOrEmpty,
    { select: (data) => data.eventStreams },
  );
}

async function getResourceServers(domain, accessToken) {
  return mgmtGet(
    domain,
    accessToken,
    "resource-servers",
    "resource servers (APIs)",
    [],
  );
}

module.exports = {
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
  getPrompts,
  getGuardianFactors,
  getGuardianPolicies,
  getBotDetectionSetting,
  getRules,
  getHooks,
  getActions,
  getLogs,
  getNetworkACL,
  getEventStreams,
  getResourceServers,
};

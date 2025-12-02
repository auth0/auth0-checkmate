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

      config.__retryCount += 1;

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

      await new Promise((resolve) => setTimeout(resolve, delayInMs));
      return axios(config);
    }

    return Promise.reject(error);
  }
);

async function getAccessToken(domain, client_id, client_secret, access_token) {
  if (access_token) {
    return access_token;
  }
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
    audience: `https://${domain}/api/v2/`,
    scopes: CONSTANTS.REQUIRED_SCOPES,
  };

  try {
    const response = await axios.post(tokenUrl, body, { headers });
    return response.data.access_token;
  } catch (error) {
    console.error("Error getting access token: %s", error.message);
    process.exit(1);
  }
}

async function getCustomDomains(domain, accessToken) {
  const url = `https://${domain}/api/v2/custom-domains`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting custom domains`);
  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log("error", `Failed to get custom domains ${error.message}`);
    return [];
  }
}

async function fetchClients(url, accessToken, page) {
  try {
    const response = await axios.get(url, {
      params: {
        per_page: PER_PAGE,
        page: page,
        is_global: false,
        //include_fields: false,
        //fields: `client_secret,signing_keys,encryption_key,client_authentication_methods`
      },
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    return response.data; // Array of clients
  } catch (error) {
    console.error("Error fetching clients:", error);
    throw error;
  }
}
async function getActions(domain, accessToken) {
  const url = `https://${domain}/api/v2/actions/actions?installed=false`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting Actions`);
  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log("error", `Failed to get actions ${error.message}`);
    return [];
  }
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
    }

    return allClients;
  } catch (error) {
    logger.log("error", `Failed to get clients ${error.message}`);
    return [];
  }
}

async function getConnections(domain, accessToken) {
  const url = `https://${domain}/api/v2/connections?strategy=auth0`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting database connections`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log("error", `Failed to get database connections ${error.message}`);
    return [];
  }
}

async function getEmailProvider(domain, accessToken) {
  const url = `https://${domain}/api/v2/emails/provider`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting email provider`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log("error", `Failed to get email provider ${error.message}`);
    return null;
  }
}

async function getLogStreams(domain, accessToken) {
  const url = `https://${domain}/api/v2/log-streams`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting log streams`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log("error", `Failed to get log streams ${error.message}`);
    return [error.response.data];
  }
}

async function getBruteForceProtectionSetting(domain, accessToken) {
  const url = `https://${domain}/api/v2/attack-protection/brute-force-protection`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting brute force setting`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log("error", `Failed to get brute force settings ${error.message}`);
    return {};
  }
}
async function getSuspiciousIpSetting(domain, accessToken) {
  const url = `https://${domain}/api/v2/attack-protection/suspicious-ip-throttling`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting suspicious ip throttling`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log(
      "error",
      `Failed to get suspicious IP settings ${error.message}`,
    );
    return {};
  }
}
async function getBreachedPasswordSetting(domain, accessToken) {
  const url = `https://${domain}/api/v2/attack-protection/breached-password-detection`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting breached password setting`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log(
      "error",
      `Failed to get breached password settings ${error.message}`,
    );
    return {};
  }
}

async function getBotDetectionSetting(domain, accessToken) {
  const url = `https://${domain}/api/v2/anomaly/captchas`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting bot detection setting`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
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
    var attackProtection = {};
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
    attackProtection = {
      breachedPasswordDetection,
      bruteForceProtection,
      suspiciousIpThrottling,
      botDetection,
    };
    return attackProtection;
  } catch (error) {
    logger.log(
      "error",
      `Failed to get attack protection settings ${error.message}`,
    );
    return {};
  }
}

async function getEmailTemplate(domain, accessToken, templateName) {
  try {
    const response = await axios.get(
      `https://${domain}/api/v2/email-templates/${templateName}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );
    return response.data;
  } catch (error) {
    logger.log(
      "error",
      `Failed to get email template because it is not configured ${templateName} - ${error.message}`,
    );
    return null; // Return null for templates that may not exist
  }
}

async function getErrorPageTemplate(domain, accessToken) {
  try {
    const response = await axios.get(
      `https://${domain}/api/v2/tenants/settings`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );
    const payload = response.data.error_page.html;
    return payload;
  } catch (error) {
    logger.log(
      "error",
      `Failed to get error page template because it is not configured - ${error.message}`,
    );
    return null; // Return null for templates that may not exist
  }
}

async function getEmailTemplates(domain, accessToken) {
  logger.log("info", `Getting email templates`);
  const emailTemplates = await Promise.all(
    CONSTANTS.EMAIL_TEMPLATES_TYPES.map(async (templateName) => {
      const template = await getEmailTemplate(
        domain,
        accessToken,
        templateName,
      );
      return { name: CONSTANTS.EMAIL_TEMPLATES_NAMES[templateName], template };
    }),
  );
  //const nonEmptyTemplates = emailTemplates.filter((template) => !!template);
  return emailTemplates;
}

async function getTenantSettings(domain, accessToken) {
  const url = `https://${domain}/api/v2/tenants/settings`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting tenant setting`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log("error", `Failed to get tenant settings ${error.message}`);
    return {};
  }
}

async function getGuardianFactors(domain, accessToken) {
  const url = `https://${domain}/api/v2/guardian/factors`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting MFA factors`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log("error", `Failed to get MFA factors ${error.message}`);
    return {};
  }
}
// policies
async function getGuardianPolicies(domain, accessToken) {
  const url = `https://${domain}/api/v2/guardian/policies`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting MFA policy`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log("error", `Failed to get MFA policies ${error.message}`);
    return {};
  }
}
// legacy rules and hooks
async function getRules(domain, accessToken) {
  const url = `https://${domain}/api/v2/rules?enabled=true`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("warn", `Getting rules`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log("error", `Failed to get rules ${error.message}`);
    return [];
  }
}

async function getHooks(domain, accessToken) {
  const url = `https://${domain}/api/v2/hooks?enabled=true`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("warn", `Getting hooks`);

  try {
    const response = await axios.get(url, { headers });
    return response.data;
  } catch (error) {
    logger.log("error", `Failed to get hooks ${error.message}`);
    return [];
  }
}

async function getLogs(domain, accessToken) {
  const logTypes = CONSTANTS.LOG_TYPES;
  const fields = "type,hostname";
  const per_page = 1;
  const query = `type: (${logTypes.join(" ")}) AND hostname: ${domain}`;
  const url = `https://${domain}/api/v2/logs?per_page=${per_page}&fields=${fields}&q=${query}`;
  const encodedUrl = encodeURI(url);
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting logs`);
  try {
    const response = await axios.get(encodedUrl, { headers });
    return { log_query: query, logs: response.data };
  } catch (error) {
    logger.log("error", `Failed to get logs ${error.message}`);
    return { log_query: query, logs: [] };
  }
}
// Early Access
async function getNetworkACL(domain, accessToken) {
    const url = `https://${domain}/api/v2/network-acls`;
    const headers = { Authorization: `Bearer ${accessToken}` };
    logger.log("info", `Getting Network ACL`);
  
    try {
      const response = await axios.get(url, { headers });
      return response.data;
    } catch (error) {
      logger.log("error", `Failed to get network ACL ${error.response.data.message}`);
      return [error.response.data];
    }
}
//Early Access
async function getEventStreams(domain, accessToken) {
  const url = `https://${domain}/api/v2/event-streams`;
  const headers = { Authorization: `Bearer ${accessToken}` };
  logger.log("info", `Getting event streams`);

  try {
    const response = await axios.get(url, { headers });
    return response.data.eventStreams;
  } catch (error) {
    logger.log("error", `Failed to get event streams ${error.message}`);
    return [error.response.data];
  }
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
  getGuardianFactors,
  getGuardianPolicies,
  getBotDetectionSetting,
  getRules,
  getHooks,
  getActions,
  getLogs,
  getNetworkACL,
  getEventStreams,
};

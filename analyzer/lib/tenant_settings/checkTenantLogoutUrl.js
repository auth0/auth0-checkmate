/*
{
  "allowed_logout_urls": [
    "https://contoso.com"
  ],
  "default_redirection_uri": "https://contoso.com/login",
  "support_email": "",
  "support_url": "",
  "sandbox_version": "22",
  "sandbox_versions_available": [
    "22",
    "18",
    "16",
    "12"
  ]
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");
const defaultValues = {
  allowed_logout_urls: [],
  default_redirection_uri: [],
  default_audience: "",
  default_directory: "",
  support_email: null,
  support_url: null,
};
function checkTenantLogoutUrl(options) {
  const { tenant } = options || {};
  return executeCheck("checkTenantLogoutUrl", (callback) => {
    const report = [];
    const { allowed_logout_urls } = _.defaultsDeep({}, tenant, defaultValues);
    // allowed_logout_urls
    const insecurePatterns = CONSTANTS.INSECURE_URL_PATTERN;
    if (allowed_logout_urls.length === 0) {
      report.push({
        field: "missing_allowed_logout_urls",
        attr: "allowed_logout_urls",
        value: ["[]"].join(","),
        status: CONSTANTS.FAIL,
      });
    } else {
      allowed_logout_urls.forEach((url) => {
        const subArr = insecurePatterns.filter((str) => url.includes(str));
        if (subArr.length > 0) {
          report.push({
            field: "invalid_allowed_logout_urls",
            attr: "allowed_logout_urls",
            value: url,
            status: CONSTANTS.FAIL,
          });
        }
      });
    }
    return callback(report);
  });
}

module.exports = checkTenantLogoutUrl;

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
  default_redirection_uri: "",
  default_audience: "",
  default_directory: "",
  support_email: null,
  support_url: null,
};
function checkTenantLoginUrl(options) {
  const { tenant } = options || {};
  return executeCheck("checkTenantLoginUrl", (callback) => {
    const report = [];
    const { default_redirection_uri } = _.defaultsDeep(
      {},
      tenant,
      defaultValues,
    );
    // allowed_logout_urls
    const insecurePatterns = CONSTANTS.INSECURE_URL_PATTERN; //['localhost', 'http://', '127.0.0.1'];
    //default_redirection_uri
    if (_.isEmpty(default_redirection_uri)) {
      report.push({
        field: "no_default_redirection_uri",
        attr: "default_redirection_uri",
        status: CONSTANTS.FAIL,
      });
    } else {
      const subArr = insecurePatterns.filter((str) =>
        default_redirection_uri.includes(str),
      );
      if (subArr.length > 0) {
        report.push({
          field: "invalid_default_redirection_uri",
          attr: "default_redirection_uri",
          value: default_redirection_uri,
          status: CONSTANTS.FAIL,
        });
      } else {
        report.push({
          field: "default_redirection_uri",
          attr: "default_redirection_uri",
          value: default_redirection_uri,
          status: CONSTANTS.SUCCESS,
        });
      }
    }
    return callback(report);
  });
}

module.exports = checkTenantLoginUrl;

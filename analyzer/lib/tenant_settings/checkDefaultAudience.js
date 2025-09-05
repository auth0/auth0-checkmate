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
function checkDefaultAudience(options) {
  const { tenant } = options || {};
  return executeCheck("checkDefaultAudience", (callback) => {
    const report = [];
    const { default_audience } = _.defaultsDeep({}, tenant, defaultValues);
    if (_.isNil(default_audience) || _.isEmpty(default_audience)) {
      report.push({
        field: "no_default_audience",
        attr: "default_audience",
        status: CONSTANTS.INFO,
      });
    } else {
      report.push({
        field: "default_audience",
        attr: "default_audience",
        value: default_audience,
        status: CONSTANTS.FAIL,
      });
    }

    return callback(report);
  });
}

module.exports = checkDefaultAudience;

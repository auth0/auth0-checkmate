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
function checkSupportUrl(options) {
  const { tenant } = options || {};
  return executeCheck("checkSupportUrl", (callback) => {
    const report = [];
    if (_.isEmpty(tenant)) {
      report.push({
        field: "tenant_setting_missing",
        status: CONSTANTS.FAIL,
      });
      return callback(report);
    }
    const { support_url } = _.defaultsDeep({}, tenant, defaultValues);

    if (support_url) {
      report.push({
        field: "support_url",
        attr: "support_url",
        value: support_url,
        status: CONSTANTS.SUCCESS,
      });
    } else {
      report.push({
        field: "no_support_url",
        attr: "support_url",
        status: CONSTANTS.FAIL,
      });
    }
    return callback(report);
  });
}

module.exports = checkSupportUrl;

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
function checkDefaultDirectory(options) {
  const { tenant } = options || {};
  return executeCheck("checkDefaultDirectory", (callback) => {
    const report = [];
    const { default_directory } = _.defaultsDeep({}, tenant, defaultValues);
    report.push({
      field:
        _.isNil(default_directory) || _.isEmpty(default_directory)
          ? "no_default_directory"
          : "default_directory",
      attr: "default_directory",
      value: default_directory,
      status: _.isNil(default_directory) || _.isEmpty(default_directory) ? CONSTANTS.INFO : CONSTANTS.FAIL,
    });
    return callback(report);
  });
}

module.exports = checkDefaultDirectory;

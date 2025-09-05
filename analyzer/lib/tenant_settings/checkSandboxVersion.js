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
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");
function checkSandboxVersion(options) {
  const { tenant } = options || {};
  return executeCheck("checkSandboxVersion", (callback) => {
    const report = [];
    const sandbox_version = Number(tenant.sandbox_version);
    if (sandbox_version < CONSTANTS.MINIMUM_NODE_VERSION) {
      report.push({
        field: "sandbox_version",
        attr: "sandbox_version",
        value: sandbox_version,
        status: CONSTANTS.FAIL,
      });
    }
    return callback(report);
  });
}

module.exports = checkSandboxVersion;

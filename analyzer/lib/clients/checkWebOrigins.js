const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");
// Function to check web origin URLs for insecure patterns (localhost, http, 127.0.0.1)
function checkURLsForApp(app) {
  const web_origins = app.web_origins || [];
  const report = [];
  const insecurePatterns = ["localhost", "http://", "127.0.0.1"];
  if (
    web_origins.length === 0 &&
    (app.app_type !== "non_interactive" || app.app_type !== "native")
  ) {
    return report;
  }
  web_origins.forEach((url) => {
    const subArr = insecurePatterns.filter((str) => url.includes(str));
    if (subArr.length > 0) {
      report.push({
        name: app.client_id ? app.name.concat(` (${app.client_id})`) : app.name,
        client_id: app.client_id || app.name,
        field: "insecure_web_origins_urls",
        value: url,
        status: CONSTANTS.FAIL,
        app_type: app.app_type,
        is_first_party: app.is_first_party
      });
    }
  });
  return report;
}

function checkWebOrigins(options) {
  return executeCheck("checkWebOrigins", (callback) => {
    const { clients } = options;
    const reports = [];

    clients.forEach((client) => {
      var report = checkURLsForApp(client);
      if (report.length === 0) {
        report.push({
          name: client.name,
          client_id: client.client_id || client.name,
          field: "secure_web_origins",
          status: CONSTANTS.SUCCESS,
          value: client.web_origins ? client.web_origins.join(", ") : "",
          app_type: client.app_type || "unknown",
          is_first_party: client.is_first_party
        });
      }
      reports.push({ name: client.name.concat(` (${client.client_id})`), report: report });
    });
    return callback(reports);
  });
}

module.exports = checkWebOrigins;

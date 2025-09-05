/*
{
  customDomains: [
    {
      domain: 'constoso.com',
      primary: true,
      status: 'ready',
      tls_policy: 'recommended',
      type: 'auth0_managed_certs',
      verification: [Object]
    }
  ],
  logs: [
    {
        type: 's',
        hostname: 'contoso.us.auth0.com',
        _id: '90020250210004837491441000000000000001223372036874609060'
    }
  ]
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");
function checkCanonicalDomain(options) {
  const { customDomains, logs, log_query } = options || {
    customDomains: [],
    logs: [],
  };
  return executeCheck("checkCanonicalDomain", (callback) => {
    const report = [];
    if (_.isEmpty(logs)) {
      report.push({
        field: "canonical_domain_no_logs",
        value: `<br> ${log_query}`,
        status: CONSTANTS.FAIL,
      });
      return callback(report);
    }
    if (_.isEmpty(customDomains) && !_.isEmpty(logs)) {
      report.push({
        field: "canonical_domain_used",
        value: `<br> ${log_query} <br> log_id: ${logs[0]._id}`,
        status: CONSTANTS.FAIL,
      });
      return callback(report);
    }
    // Finding a match
    const matchedLog = _.find(logs, (log) => {
      return _.some(customDomains, (domain) => log.hostname === domain.domain);
    });
    if (_.isEmpty(matchedLog)) {
      report.push({
        field: "canonical_domain_used",
        value: `<br> ${log_query} <br> log_id: ${logs[0]._id}`,
        status: CONSTANTS.FAIL,
      });
    }
    return callback(report);
  });
}

module.exports = checkCanonicalDomain;

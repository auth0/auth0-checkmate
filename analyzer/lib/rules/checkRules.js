/*
[
  {
    "id": "rul_IYlu62iBa6K52fBi",
    "enabled": false,
    "name": "Dump Rule",
    "order": 1,
    "stage": "login_success"
  },
  {
    "id": "rul_RFtsxXcHptdfNytp",
    "enabled": false,
    "name": "auth0-account-link-extension",
    "order": 7,
    "stage": "login_success"
  },
  {
    "id": "rul_PUbmUscnlFfvqWEo",
    "enabled": false,
    "name": "Link Accounts with Same Email Address while Merging Metadata",
    "order": 6,
    "stage": "login_success"
  },
  {
    "id": "rul_2UMKolzalvxt4x5k",
    "enabled": false,
    "name": "Link Accounts with Same Email Address while Merging Metadata For FB",
    "order": 11,
    "stage": "login_success"
  },
  {
    "id": "rul_U9tyXS894nPYxHPT",
    "enabled": false,
    "name": "redirect rule rule",
    "order": 9,
    "stage": "login_success"
  },
  {
    "id": "rul_f4K2T8LBE5sdM6sk",
    "enabled": false,
    "name": "Add attributes to a user for facebook connection",
    "order": 10,
    "stage": "login_success"
  },
  {
    "id": "rul_A892yaO7K5dpmzhr",
    "enabled": false,
    "name": "Redirect rule for capturing email",
    "order": 13,
    "stage": "login_success"
  },
  {
    "id": "rul_Wcr19IorVdhsRfnc",
    "enabled": false,
    "name": "MYOB SAML",
    "order": 15,
    "stage": "login_success"
  },
  {
    "id": "rul_YFDdYGJSIwMPzsZR",
    "enabled": true,
    "name": "Override SAML Certificate",
    "order": 14,
    "stage": "login_success"
  }
]
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function validateRules(config) {
  const report = [];
  if (_.isEmpty(config)) {
    report.push({
      field: "no_enabled_rules",
      status: CONSTANTS.SUCCESS,
    });
    return report;
  }
  config.forEach((rule) => {
    if (rule.enabled) {
      report.push({
        name: rule.name,
        value: rule.id,
        field: "enabled_rules",
        status: CONSTANTS.FAIL,
      });
    }
    return;
  });
  // Return the validation report
  return report;
}
function checkRules(options) {
  const { rules } = options || [];
  return executeCheck("checkRules", (callback) => {
    const report = validateRules(rules);
    return callback(report);
  });
}
module.exports = checkRules;

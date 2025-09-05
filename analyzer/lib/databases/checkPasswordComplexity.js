/*
{
    databases: [
  {
    "id": "con_JBv3Nu3wcKQni7Vv",
    "options": {
      "import_mode": false,
      "configuration": {},
      "disable_signup": true,
      "passwordPolicy": "good",
      "passkey_options": {
        "challenge_ui": "both",
        "local_enrollment_enabled": true,
        "progressive_enrollment_enabled": true
      },
      "password_history": {
        "size": 5,
        "enable": false
      },
      "strategy_version": 2,
      "password_dictionary": {
        "enable": false,
        "dictionary": []
      },
      "authentication_methods": {
        "passkey": {
          "enabled": false
        },
        "password": {
          "enabled": true
        }
      },
      "brute_force_protection": true,
      "password_no_personal_info": {
        "enable": false
      },
      "password_complexity_options": {
        "min_length": 8
      },
      "enabledDatabaseCustomization": false
    },
    "strategy": "auth0",
    "name": "Username-Password-Authentication",
    "is_domain_connection": false,
    "realms": [
      "Username-Password-Authentication"
    ],
    "enabled_clients": [
    ]
  }
]    
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkPasswordComplexity(options) {
  const { databases } = options || [];
  return executeCheck("checkPasswordComplexity", (callback) => {
    const report = [];
    if (_.isEmpty(databases)) {
      report.push({
        field: "no_database_connections_found",
        status: CONSTANTS.FAIL,
      });
      return callback(report);
    }
    databases.forEach((connection) => {
      //Check password complexity and minimum length.
      if (!_.isEmpty(connection.options.password_complexity_options)) {
        // Recommend NIST standards
        if (connection.options.password_complexity_options.min_length < 12) {
          report.push({
            name: connection.name,
            field: "password_min_length_fail",
            status: CONSTANTS.FAIL,
            value: connection.options.password_complexity_options.min_length,
          });
        } else {
          report.push({
            name: connection.name,
            status: CONSTANTS.SUCCESS,
            field: "password_min_length_success",
            value: connection.options.password_complexity_options.min_length,
          });
        }
      } else {
        report.push({
          name: connection.name,
          field: "password_complexity_not_configured",
          status: CONSTANTS.FAIL,
        });
      }
    });
    return callback(report);
  });
}

module.exports = checkPasswordComplexity;

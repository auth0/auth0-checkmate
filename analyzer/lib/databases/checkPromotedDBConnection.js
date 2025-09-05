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

function checkPromotedDBConnection(options) {

    const { databases } = options || [];
    return executeCheck("checkPromotedDBConnection", (callback) => {
        const report = [];
        if (_.isEmpty(databases)) {
            report.push({
                field: "no_database_connections_found",
                status: CONSTANTS.FAIL,
            });
            return callback(report);
        }
        promoted_domain_connection = null;
        databases.forEach((connection) => {
            connection.is_domain_connection;
            if (connection.is_domain_connection === true) {
                promoted_domain_connection = connection.name;
                return;
            }
        });
        if (promoted_domain_connection === null) {
            report.push({
                name: "NO_PRMOTED_DOMAIN_CONNECTION",
                status: CONSTANTS.FAIL,
                field: "no_database_connections_found",
            });
        }
        else {
            report.push({
                name: promoted_domain_connection,
                status: CONSTANTS.FAIL,
                field: "with_promoted_database_connections",
            });
        }
        return callback(report);
    });
}

module.exports = checkPromotedDBConnection;

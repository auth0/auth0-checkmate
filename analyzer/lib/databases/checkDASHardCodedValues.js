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
    "customScripts": {
      "login": "function login(identifierValue, password, callback) {\n  const mysql = require('mysql');\n  const bcrypt = require('bcrypt');\n\n  const connection = mysql.createConnection({\n    host: 'localhost',\n    user: 'me',\n    password: 'secret',\n    database: 'mydb'\n  });\n\n  connection.connect();\n\n  const query = 'SELECT id, nickname, email, password FROM users WHERE email = ?';\n\n  connection.query(query, [ identifierValue ], function(err, results) {\n    if (err) return callback(err);\n    if (results.length === 0) return callback(new WrongUsernameOrPasswordError(identifierValue));\n    const user = results[0];\n\n    bcrypt.compare(password, user.password, function(err, isValid) {\n      if (err || !isValid) return callback(err || new WrongUsernameOrPasswordError(identifierValue));\n\n      callback(null, {\n        user_id: user.id.toString(),\n        nickname: user.nickname,\n        email: user.email\n      });\n    });\n  });\n}\n",
      "create": "function create(user, callback) {\n  const mysql = require('mysql');\n  const bcrypt = require('bcrypt');\n\n  const connection = mysql.createConnection({\n    host: 'localhost',\n    user: 'me',\n    password: 'secret',\n    database: 'mydb'\n  });\n\n  connection.connect();\n\n  const query = 'INSERT INTO users SET ?';\n\n  bcrypt.hash(user.password, 10, function(err, hash) {\n    if (err) return callback(err);\n\n    const insert = {\n      password: hash,\n      email: user.email\n    };\n\n    connection.query(query, insert, function(err, results) {\n      if (err) return callback(err);\n      if (results.length === 0) return callback();\n      callback(null);\n    });\n  });\n}\n",
      "delete": "function remove(id, callback) {\n  // This script remove a user from your existing database.\n  // It is executed whenever a user is deleted from the API or Auth0 dashboard.\n  //\n  // There are two ways that this script can finish:\n  // 1. The user was removed successfully:\n  //     callback(null);\n  // 2. Something went wrong while trying to reach your database:\n  //     callback(new Error(\"my error message\"));\n\n  const msg = 'Please implement the Delete script for this database ' +\n    'connection at https://manage.auth0.com/#/connections/database';\n  return callback(new Error(msg));\n}\n",
      "verify": "function verify(email, callback) {\n  const mysql = require('mysql');\n\n  const connection = mysql.createConnection({\n    host: 'localhost',\n    user: 'me',\n    password: 'secret',\n    database: 'mydb'\n  });\n\n  connection.connect();\n\n  const query = 'UPDATE users SET email_Verified = true WHERE email_Verified = false AND email = ?';\n\n  connection.query(query, [ email ], function(err, results) {\n    if (err) return callback(err);\n\n    callback(null, results.length > 0);\n  });\n\n}\n",
      "get_user": "function getUser(identifierValue, callback) {\n  const mysql = require('mysql');\n\n  const connection = mysql.createConnection({\n    host: 'localhost',\n    user: 'me',\n    password: 'secret',\n    database: 'mydb'\n  });\n\n  connection.connect();\n\n  const query = 'SELECT id, nickname, email FROM users WHERE email = ?';\n\n  connection.query(query, [ identifierValue ], function(err, results) {\n    if (err || results.length === 0) return callback(err || null);\n\n    const user = results[0];\n    callback(null, {\n      user_id: user.id.toString(),\n      nickname: user.nickname,\n      email: user.email\n    });\n  });\n}\n",
      "change_password": "function changePassword(email, newPassword, callback) {\n  const mysql = require('mysql');\n  const bcrypt = require('bcrypt');\n\n  const connection = mysql.createConnection({\n    host: 'localhost',\n    user: 'me',\n    password: 'secret',\n    database: 'mydb'\n  });\n\n  connection.connect();\n\n  const query = 'UPDATE users SET password = ? WHERE email = ?';\n\n  bcrypt.hash(newPassword, 10, function(err, hash) {\n    if (err) return callback(err);\n\n    connection.query(query, [ hash, email ], function(err, results) {\n      if (err) return callback(err);\n      callback(null, results.length > 0);\n    });\n  });\n}\n"
    },
      "enabledDatabaseCustomization": true,

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
const acorn = require("acorn");
const walk = require("estree-walker").walk;

function detectHardcodedValues(code, scriptName) {
    let processedCode = code.replace(/(?!\w+#)\b#(\w+)/g, "_$1");
    const ast = acorn.parse(processedCode, {
        ecmaVersion: "latest",
        locations: true,
    });

    const hardcodedValues = [];

    walk(ast, {
        enter(node) {
            // Variable assignments
            if (node.type === "VariableDeclaration") {
                node.declarations.forEach((declaration) => {
                    if (
                        declaration.init &&
                        declaration.init.type === "Literal" &&
                        typeof declaration.init.value === "string" &&
                        !isCommonException(declaration.init.value)
                    ) {
                        hardcodedValues.push({
                            scriptName: scriptName,
                            variableName: declaration.id.name,
                            field: "hard_coded_value_detected",
                            status: CONSTANTS.FAIL,
                            type: typeof declaration.init.value,
                            line: declaration.loc.start.line,
                            column: declaration.loc.start.column,
                        });
                    }
                });
            }

            // Object literals
            if (
                node.type === "Property" &&
                node.value.type === "Literal" &&
                typeof node.value.value === "string" &&
                !isCommonException(node.value.value)
            ) {
                hardcodedValues.push({
                    scriptName: scriptName,
                    variableName: node.key.name || node.key.value,
                    field: "hard_coded_value_detected",
                    status: CONSTANTS.FAIL,
                    type: typeof node.value.value,
                    line: node.loc.start.line,
                    column: node.loc.start.column,
                });
            }
        },
    });

    return hardcodedValues;
}

// Helper functions
function isCommonException(value) {
    const exceptions = [
        /^[0-1]$/, // Allow 0 and 1
        /^[a-z]$/i, // Single letters
        /^\s*$/, // Whitespace-only
        /^[{}()[]<>]+$/, // Common brackets
    ];
    return exceptions.some((regex) => regex.test(String(value)));
}


function checkDASHardCodedValues(options) {
    const { databases } = options || [];
    return executeCheck("checkDASHardCodedValues", (callback) => {
        const reports = [];
        if (_.isEmpty(databases)) {
            reports.push({
                field: "no_database_connections_found",
                status: CONSTANTS.FAIL,
            });
            return callback(reports);
        }
        databases.forEach((connection) => {
            const { enabledDatabaseCustomization, customScripts } = connection.options;
            if (enabledDatabaseCustomization) {
                Object.entries(customScripts).forEach(([scriptName, scriptCode]) => {
                    var report = detectHardcodedValues(scriptCode, scriptName);
                    if (report.length > 0) {
                        reports.push({ name: connection.name, report: report });
                    }
                });
            }
        });
        return callback(reports);
    });
}

module.exports = checkDASHardCodedValues;

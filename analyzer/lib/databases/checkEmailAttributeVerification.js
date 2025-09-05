/*
{
  "id": "con_GVkgEDMhImBiBt2j",
  "options": {
    "mfa": {
      "active": true,
      "return_enroll_settings": true
    },
    "attributes": {
      "email": {
        "signup": {
          "status": "required",
          "verification": {
            "active": true
          }
        },
        "identifier": {
          "active": true
        },
        "profile_required": true,
        "verification_method": "otp" //link
      }
    },
    "import_mode": false,
    "configuration": {},
    "customScripts": {
      "login": "function login(identifierValue, password, callback) {\n  // This script should authenticate a user against the credentials stored in\n  // your database.\n  // It is executed when a user attempts to log in or immediately after signing\n  // up (as a verification that the user was successfully signed up).\n  //\n  // Everything returned by this script will be set as part of the user profile\n  // and will be visible by any of the tenant admins. Avoid adding attributes\n  // with values such as passwords, keys, secrets, etc.\n  //\n  // The `password` parameter of this function is in plain text. It must be\n  // hashed/salted to match whatever is stored in your database. For example:\n  //\n  //     var bcrypt = require('bcrypt@0.8.5');\n  //     bcrypt.compare(password, dbPasswordHash, function(err, res)) { ... }\n  //\n  // There are three ways this script can finish:\n  // 1. The user's credentials are valid. The returned user profile should be in\n  // the following format: https://auth0.com/docs/users/normalized/auth0/normalized-user-profile-schema\n  //     var profile = {\n  //       user_id: ..., // user_id is mandatory\n  //       email: ...,\n  //       [...]\n  //     };\n  //     callback(null, profile);\n  // 2. The user's credentials are invalid\n  //     callback(new WrongUsernameOrPasswordError(email, \"my error message\"));\n  //\n  //    Note: Passing no arguments or a falsey first argument to\n  //    `WrongUsernameOrPasswordError` will result in the error being logged as\n  //    an `fu` event (invalid username/email) with an empty string for a user_id.\n  //    Providing a truthy first argument will result in the error being logged\n  //    as an `fp` event (the user exists, but the password is invalid) with a\n  //    user_id value of \"auth0|<first argument>\". See the `Log Event Type Codes`\n  //    documentation for more information about these event types:\n  //    https://auth0.com/docs/deploy-monitor/logs/log-event-type-codes\n  // 3. Something went wrong while trying to reach your database\n  //     callback(new Error(\"my error message\"));\n  //\n  // A list of Node.js modules which can be referenced is available here:\n  //\n  //    https://tehsis.github.io/webtaskio-canirequire/\n\n  const msg = 'Please implement the Login script for this database connection ' +\n    'at https://manage.auth0.com/#/connections/database';\n  return callback(new Error(msg));\n}\n",
      "create": "function create(user, callback) {\n  // This script should create a user entry in your existing database. It will\n  // be executed when a user attempts to sign up, or when a user is created\n  // through the Auth0 dashboard or API.\n  // When this script has finished executing, the Login script will be\n  // executed immediately afterwards, to verify that the user was created\n  // successfully.\n  //\n  // The user object will always contain the following properties:\n  // * email: the user's email\n  // * password: the password entered by the user, in plain text\n  // * tenant: the name of this Auth0 account\n  // * client_id: the client ID of the application where the user signed up, or\n  //              API key if created through the API or Auth0 dashboard\n  // * connection: the name of this database connection\n  //\n  // There are three ways this script can finish:\n  // 1. A user was successfully created\n  //     callback(null);\n  // 2. This user already exists in your database\n  //     callback(new ValidationError(\"user_exists\", \"my error message\"));\n  // 3. Something went wrong while trying to reach your database\n  //     callback(new Error(\"my error message\"));\n\n  const msg = 'Please implement the Create script for this database connection ' +\n    'at https://manage.auth0.com/#/connections/database';\n  return callback(new Error(msg));\n}\n",
      "delete": "function remove(id, callback) {\n  // This script remove a user from your existing database.\n  // It is executed whenever a user is deleted from the API or Auth0 dashboard.\n  //\n  // There are two ways that this script can finish:\n  // 1. The user was removed successfully:\n  //     callback(null);\n  // 2. Something went wrong while trying to reach your database:\n  //     callback(new Error(\"my error message\"));\n\n  const msg = 'Please implement the Delete script for this database ' +\n    'connection at https://manage.auth0.com/#/connections/database';\n  return callback(new Error(msg));\n}\n",
      "verify": "function verify(email, callback) {\n  // This script should mark the current user's email address as verified in\n  // your database.\n  // It is executed whenever a user clicks the verification link sent by email.\n  // These emails can be customized at https://manage.auth0.com/#/emails.\n  // It is safe to assume that the user's email already exists in your database,\n  // because verification emails, if enabled, are sent immediately after a\n  // successful signup.\n  //\n  // There are two ways that this script can finish:\n  // 1. The user's email was verified successfully\n  //     callback(null, true);\n  // 2. Something went wrong while trying to reach your database:\n  //     callback(new Error(\"my error message\"));\n  //\n  // If an error is returned, it will be passed to the query string of the page\n  // where the user is being redirected to after clicking the verification link.\n  // For example, returning `callback(new Error(\"error\"))` and redirecting to\n  // https://example.com would redirect to the following URL:\n  //     https://example.com?email=alice%40example.com&message=error&success=false\n\n  const msg = 'Please implement the Verify script for this database connection ' +\n    'at https://manage.auth0.com/#/connections/database';\n  return callback(new Error(msg));\n}\n",
      "get_user": "function getUser(identifierValue, callback) {\n  // This script should retrieve a user profile from your existing database,\n  // without authenticating the user.\n  // It is used to check if a user exists before executing flows that do not\n  // require authentication (signup and password reset).\n  //\n  // There are three ways this script can finish:\n  // 1. A user was successfully found. The profile should be in the following\n  // format: https://auth0.com/docs/users/normalized/auth0/normalized-user-profile-schema.\n  //     callback(null, profile);\n  // 2. A user was not found\n  //     callback(null);\n  // 3. Something went wrong while trying to reach your database:\n  //     callback(new Error(\"my error message\"));\n\n  const msg = 'Please implement the Get User script for this database connection ' +\n    'at https://manage.auth0.com/#/connections/database';\n  return callback(new Error(msg));\n}\n",
      "change_password": "function changePassword(identifierValue, newPassword, callback) {\n  // This script should change the password stored for the current user in your\n  // database. It is executed when the user clicks on the confirmation link\n  // after a reset password request.\n  // The content and behavior of password confirmation emails can be customized\n  // here: https://manage.auth0.com/#/emails\n  // The `newPassword` parameter of this function is in plain text. It must be\n  // hashed/salted to match whatever is stored in your database.\n  //\n  // There are three ways that this script can finish:\n  // 1. The user's password was updated successfully:\n  //     callback(null, true);\n  // 2. The user's password was not updated:\n  //     callback(null, false);\n  // 3. Something went wrong while trying to reach your database:\n  //     callback(new Error(\"my error message\"));\n  //\n  // If an error is returned, it will be passed to the query string of the page\n  // where the user is being redirected to after clicking the confirmation link.\n  // For example, returning `callback(new Error(\"error\"))` and redirecting to\n  // https://example.com would redirect to the following URL:\n  //     https://example.com?email=alice%40example.com&message=error&success=false\n\n  const msg = 'Please implement the Change Password script for this database ' +\n    'connection at https://manage.auth0.com/#/connections/database';\n  return callback(new Error(msg));\n}\n"
    },
    "passwordPolicy": "fair",
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
  "enabled_clients": [
  ],
  "realms": [
    "Username-Password-Authentication"
  ]
}
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkEmailAttributeVerification(options) {
  const { databases } = options || [];
  return executeCheck("checkEmailAttributeVerification", (callback) => {
    const report = [];
    if (_.isEmpty(databases)) {
      report.push({
        field: "no_database_connections_found",
        status: CONSTANTS.FAIL,
      });
      return callback(report);
    }
    databases.forEach((connection) => {
      if (_.isEmpty(connection.options.attributes)) {
        //defaults to email
        report.push({
          name: connection.name,
          status: CONSTANTS.FAIL,
          field: "flexible_identifiers_disabled",
        });
      } else if (
        connection.options.attributes.email?.verification_method &&
        connection.options.attributes.email?.verification_method !== 'otp'
      ) {
        report.push({
          name: connection.name,
          status: CONSTANTS.FAIL,
          field: "verification_by_link_method",
        });
      }
    });
    return callback(report);
  });
}

module.exports = checkEmailAttributeVerification;

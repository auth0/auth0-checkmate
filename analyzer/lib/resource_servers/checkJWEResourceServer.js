/*
{
  resourceServers: [
    {
      "id": "rs_abc123",
      "name": "Secure Banking API",
      "identifier": "https://secure.bank.ciam.rocks",
      "is_system": false,
      "token_encryption": {
        "format": "compact-nested-jwe",
        "encryption_key": {
          "name": "ApiPubKey",
          "alg": "RSA-OAEP-256",
          "thumbprint_sha256": "0TAjxEoZw-DEsXzzaSXHDof6_IJfxpK8JXTMvewQmlU"
        }
      }
    }
  ]
}

token_encryption.format valid values:
  "compact-nested-jwe"  => JWE Compact Serialization with nested signing (sign-then-encrypt)

token_encryption.encryption_key must be configured with a valid public key.

JWE for Resource Servers is only available to tenants with the Highly Regulated
Identity (HRI) add-on. When the field is absent the Management API v2 does not
expose it, so we emit an advisory finding rather than asserting a definitive
misconfiguration.
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

const VALID_JWE_FORMATS = ["compact-nested-jwe"];

function validateJWEForResourceServer(rs) {
    const report = [];

    const name = rs.name || rs.identifier;
    const displayName = rs.identifier ? `${name} (${rs.identifier})` : name;
    const tokenEncryption = rs.token_encryption;

    // The Auth0 Management API v2 does not expose JWE token encryption
    // configuration in the resource server object for tenants that do not have
    // the HRI add-on, or where the feature has not been configured. When the
    // field is absent we emit an advisory finding rather than asserting a
    // definitive misconfiguration.
    if (tokenEncryption === undefined) {
        report.push({
            name: displayName,
            identifier: rs.identifier,
            field: "token_encryption",
            status: CONSTANTS.FAIL,
            value: "not_verifiable",
        });
        return report;
    }

    const format = tokenEncryption.format;
    if (!VALID_JWE_FORMATS.includes(format)) {
        report.push({
            name: displayName,
            identifier: rs.identifier,
            field: "token_encryption.format",
            status: CONSTANTS.FAIL,
            value: format ?? "not_set",
        });
        return report;
    }

    const encryptionKey = tokenEncryption.encryption_key;
    if (!encryptionKey || _.isEmpty(encryptionKey)) {
        report.push({
            name: displayName,
            identifier: rs.identifier,
            field: "token_encryption.encryption_key",
            status: CONSTANTS.FAIL,
            value: "not_configured",
        });
    }

    return report;
}

function checkJWEResourceServer(options) {
    return executeCheck("checkJWEResourceServer", (callback) => {
        const { resourceServers } = options || {};
        const reports = [];
        if (_.isEmpty(resourceServers)) {
            return callback(reports);
        }
        resourceServers.forEach((rs) => {
            if (rs.is_system) {
                return;
            }
            const report = validateJWEForResourceServer(rs);
            const name = rs.name || rs.identifier;
            const displayName = rs.identifier ? `${name} (${rs.identifier})` : name;
            reports.push({ name: displayName, report: report });
        });
        return callback(reports);
    });
}

module.exports = checkJWEResourceServer;

/*
Check if canonical domain is blocked when custom domain is configured.

When a custom domain exists and is ready, it's a best practice to block
access to the canonical domain to prevent users from
bypassing the custom domain.

ACL list structure:
[
  {
    "description": "Block canonical domain to enforce custom domain usage",
    "active": true,
    "priority": 1,
    "rule": {
      "match": {
        "hostnames": [
          "xxx.xxx.yyy.com"
        ]
      },
      "scope": "authentication",
      "action": {
        "block": true
      }
    },
    "created_at": "2026-05-05T05:51:44.045Z",
    "updated_at": "2026-05-05T05:51:44.045Z",
    "id": "xxxxxx"
  }
]

Custom domain structure:
[
  {
    "custom_domain_id": "something",
    "domain": "bbbb.bbbb.io",
    "primary": true,
    "is_default": false,
    "status": "ready",
    "type": "auth0_managed_certs",
    "verification": {
      "methods": [
        {
          "name": "CNAME",
          "record": "something",
          "domain": "bbbb.bbbb.io"
        }
      ],
      "last_verified_at": "2026-04-18T03:17:46Z",
      "status": "verified"
    },
    "tls_policy": "recommended",
    "certificate": {
      "certificate_authority": "letsencrypt",
      "renews_before": "2026-07-17T02:19:38Z",
      "status": "provisioned"
    },
    "created_at": "2024-10-18T04:19:50.000Z"
  }
]
*/

const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkBlockCanonicalDomain(options) {
  const { customDomains, networkAcl, canonicalDomain } = options;

  return executeCheck("checkBlockCanonicalDomain", (callback) => {
    const report = [];

    const hasInsufficientScope = _.some(networkAcl, {
      errorCode: "insufficient_scope",
    });
    if (hasInsufficientScope) {
      return callback(report);
    }

    // Only check if custom domain exists and is ready
    const hasReadyCustomDomain = _.some(customDomains, { status: "ready" });
    if (!hasReadyCustomDomain) {
      return callback(report);
    }

    const hasBlockingRule = _.some(networkAcl, (acl) => {
      if (!acl.active || !acl.rule) {
        return false;
      }

      const { match, scope, action } = acl.rule;

      const blocksAuth = scope === "authentication";

      const isBlocking = action && action.block === true;

      const matchesCanonical =
        match &&
        match.hostnames &&
        _.some(match.hostnames, (hostname) => {
          return hostname === canonicalDomain ||
                 hostname === `*.auth0.com` ||
                 hostname === `*.auth0app.com`;
        });

      return blocksAuth && isBlocking && matchesCanonical;
    });

    if (!hasBlockingRule) {
      const customDomainList = customDomains
        .filter(d => d.status === "ready")
        .map(d => d.domain)
        .join(", ");

      report.push({
        field: "canonical_domain_not_blocked",
        status: CONSTANTS.WARN,
        value: canonicalDomain,
        customDomains: customDomainList,
      });
    }

    return callback(report);
  });
}

module.exports = checkBlockCanonicalDomain;
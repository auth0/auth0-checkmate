/*
{
   "enabled_locales":[
      "en"
   ],
   "error_page":{
      "html":"<html>",
      "show_log_link":false,
      "url":""
   },
   "flags":{
      "allow_changing_enable_sso":false,
      "allow_legacy_delegation_grant_types":true,
      "allow_legacy_ro_grant_types":true,
      "allow_other_legacy_grant_types":true,
      "disable_impersonation":true,
      "enable_sso":true,
      "universal_login":true,
      "revoke_refresh_token_grant":false,
      "disable_clickjack_protection_headers":false
   },
   "sandbox_version":"22",
   "oidc_logout":{
      "rp_logout_end_session_endpoint_discovery":true
   },
   "sandbox_versions_available":[
      "22",
      "18",
      "16"
      ]
  }
 */

const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");
const logger = require("../logger");

/**
 * Patterns that indicate potential XSS vulnerabilities in LiquidJS templates
 */
const XSS_PATTERNS = {
  // Unescaped variable output - {{ variable }} without proper escaping
  UNESCAPED_OUTPUT: /\{\{\s*([^}|]+?)(?:\s*\|\s*(?!escape|escape_once|h|html_escape)([^}]*))?\s*\}\}/g,

  // Raw/unescaped filters that bypass HTML escaping
  RAW_FILTERS: /\{\{\s*[^}]*\|\s*(raw|unescaped|safe)\s*\}\}/g,

  // Direct HTML construction with variables
  HTML_CONSTRUCTION: /<[^>]*\{\{[^}]*\}\}[^>]*>/g,

  // JavaScript context insertions (dangerous)
  SCRIPT_CONTEXT: /<script[^>]*>[\s\S]*?\{\{[^}]*\}\}[\s\S]*?<\/script>/gi,

  // Event handler attributes with Liquid variables
  EVENT_HANDLERS: /on\w+\s*=\s*["'][^"']*\{\{[^}]*\}\}[^"']*["']/gi,

  // URL/href context without proper encoding
  URL_CONTEXT: /href\s*=\s*["'][^"']*\{\{[^}]*\}\}[^"']*["']/gi,

  // Style attribute context
  STYLE_CONTEXT: /style\s*=\s*["'][^"']*\{\{[^}]*\}\}[^"']*["']/gi,

  // Potentially dangerous user-controlled variables
  USER_VARIABLES: /\{\{\s*(user\.|client\.|application\.)/g,
};

/**
 * Safe filters that provide XSS protection
 */
const SAFE_FILTERS = [
  'escape',
  'escape_once',
  'h',
  'html_escape',
  'url_encode',
  'uri_escape',
  'cgi_escape'
];

async function checkErrorPageTemplate(options) {
  const { errorPageTemplate } = options || {};
  return executeCheck("checkErrorPageTemplate", (callback) => {
    const report = [];
    logger.log("info", `Checking error page templates... ${errorPageTemplate}`);

    if (_.isEmpty(errorPageTemplate)) {
      report.push({
        field: "liquidjs_no_templates_to_analyze",
        status: CONSTANTS.SUCCESS,
        value: "No custom error page templates found to analyze for XSS"
      });
      return callback(report);
    }

    // Check for potential matches first
    const potentialMatches = errorPageTemplate.match(XSS_PATTERNS.UNESCAPED_OUTPUT);
    logger.log("info", `Checking error page templates... ${potentialMatches}`);

    // Check for raw filters first (before checking unescaped)
    const raw = errorPageTemplate.match(XSS_PATTERNS.RAW_FILTERS);
    if (raw) {
      logger.log("info", `logging error page template raw: ${raw}`);
      report.push({
        field: "liquidjs_raw_filter_usage",
        status: CONSTANTS.FAIL,
        value: JSON.stringify(raw),
      });
    } else {
      report.push({
        field: "liquidjs_raw_filter_usage",
        status: CONSTANTS.SUCCESS,
        value: JSON.stringify(raw) || "null",
      });
    }

    // Now check for unescaped output, filtering out properly escaped variables
    const unescaped = errorPageTemplate.match(XSS_PATTERNS.UNESCAPED_OUTPUT);
    if (unescaped) {
      // Filter out variables that actually have safe filters
      const actuallyUnescaped = unescaped.filter(match => {
        // Check if this match contains any safe filter
        return !SAFE_FILTERS.some(filter =>
          match.includes(`| ${filter}`) || match.includes(`|${filter}`)
        );
      });

      if (actuallyUnescaped.length > 0) {
        report.push({
          field: "liquidjs_unescaped_output",
          status: CONSTANTS.FAIL,
          value: JSON.stringify(actuallyUnescaped),
        });
      } else {
        report.push({
          field: "liquidjs_unescaped_output",
          status: CONSTANTS.SUCCESS,
          value: "All variables properly escaped",
        });
      }
    } else {
      report.push({
        field: "liquidjs_unescaped_output",
        status: CONSTANTS.SUCCESS,
        value: "No Liquid variables found",
      });
    }

    return callback(report);
  });
}

module.exports = checkErrorPageTemplate;

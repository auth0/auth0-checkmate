const fs = require("fs");
const i18n = require("i18n");
const path = require("path");
const _ = require("lodash");
const Handlebars = require("handlebars");
const listOfAnalyser = require("./lib/listOfAnalyser");
const {
  getAccessToken,
  getCustomDomains,
  getApplications,
  getConnections,
  getAttackProtection,
  getEmailProvider,
  getLogStreams,
  getEmailTemplates,
  getErrorPageTemplate,
  getTenantSettings,
  getGuardianFactors,
  getGuardianPolicies,
  getRules,
  getHooks,
  getActions,
  getLogs,
  getNetworkACL,
  getEventStreams,
  getResourceServers,
} = require("./tools/auth0");

const logger = require("./lib/logger");
const { getSummaryReport } = require("./tools/summary");
const { convertToTitleCase, tranformReport, getToday } = require("./tools/utils");
const { version } = require("../package.json");

i18n.configure({
  defaultLocale: "en",
  objectNotation: true,
  directory: path.join(__dirname, "../locales")
});

Handlebars.registerHelper("chooseFont", function (locale) {
  if (locale === "ja") return "Noto Sans JP, sans-serif";
  if (locale === "ko") return "Noto Sans KR, sans-serif";
  return "DM Sans, sans-serif";
});
Handlebars.registerHelper("replace", function (str, search, replace) {
  return str.replace(search, replace);
});
Handlebars.registerHelper("and", (a, b) => a && b);
Handlebars.registerHelper("inc", (a) => parseInt(a) + 1);

const templateData = fs.readFileSync(
  path.join(__dirname, "../views/pdf_cli_report.handlebars"),
  "utf8"
);

/**
 * Trim, drop empties and de-duplicate a list of requested validator names.
 */
function normalizeValidatorSelection(selection) {
  return _.uniq(
    _.compact((selection || []).map((name) => String(name).trim())),
  );
}

/**
 * Find the closest known validator name for a mistyped one, so the error can
 * point at the intended validator instead of just rejecting the input.
 */
function suggestValidatorName(name, knownNames) {
  const requested = name.toLowerCase();
  return (
    knownNames.find((known) => known.toLowerCase() === requested) ||
    knownNames.find((known) => {
      const candidate = known.toLowerCase();
      return (
        candidate.startsWith(requested) || requested.startsWith(candidate)
      );
    }) ||
    null
  );
}

/**
 * Resolve requested validator names into the checks to run, in the order they
 * were requested. An empty selection runs every validator.
 * Throws when a name does not match a known validator, since silently running
 * everything (or nothing) would produce a misleading report.
 */
function resolveSelectedValidators(selection) {
  const { checks } = listOfAnalyser;
  const requested = normalizeValidatorSelection(selection);
  if (_.isEmpty(requested)) {
    return checks;
  }
  const checksByName = new Map(checks.map((check) => [check.name, check]));
  const unknown = requested.filter((name) => !checksByName.has(name));
  if (!_.isEmpty(unknown)) {
    const knownNames = [...checksByName.keys()];
    const details = unknown.map((name) => {
      const suggestion = suggestValidatorName(name, knownNames);
      return suggestion ? `"${name}" (did you mean "${suggestion}"?)` : `"${name}"`;
    });
    throw new Error(
      `Unknown validator name(s): ${details.join(", ")}. ` +
        `Validator names are case-sensitive. Run with RUN_VALIDATORS=list to print all ${knownNames.length} available names.`,
    );
  }
  return requested.map((name) => checksByName.get(name));
}

/**
 * Every available validator name, for discovery and error messages.
 */
function getValidatorNames() {
  return listOfAnalyser.checks.map((check) => check.name);
}

/**
 * Parse a comma-separated validator list (e.g. the RUN_VALIDATORS environment
 * variable) into a validated selection. Throws on unknown names so callers can
 * fail fast rather than produce a report that silently checked nothing.
 */
function parseValidatorSelection(value) {
  const selection = normalizeValidatorSelection((value || "").split(","));
  if (!_.isEmpty(selection)) {
    resolveSelectedValidators(selection);
  }
  return selection;
}

async function runProductionChecks(tenant, checksToRun) {
  try {
    logger.log("info", "Checking your configuration...");
    const checksPromises = checksToRun.map((check) => {
      return new Promise((resolve) => {
        logger.log(
          "info",
          `Running validator ${convertToTitleCase(check.name)}`,
        );
        check(tenant)
          .then((checkResult) => {
            resolve({ name: check.name, details: checkResult.details });
          })
          .catch((e) => {
            resolve({ name: check.name, error: e });
          });
      });
    });
    return Promise.all(checksPromises);
  } catch (e) {
    logger.log("info", e);
  }
}
async function generateReport(locale, tenantConfig, config) {
  i18n.setLocale(locale);
  // Resolved before the try block so an invalid selection surfaces to the
  // caller instead of being swallowed into an empty report.
  const checksToRun = resolveSelectedValidators(config.selectedValidators);
  const isFilteredRun = checksToRun.length !== listOfAnalyser.checks.length;
  try {
    if (_.isEmpty(tenantConfig)) {
      if (!config.auth0MgmtToken) {
        config.auth0MgmtToken = await getAccessToken(
          config.auth0Domain,
          config.auth0ClientId,
          config.auth0ClientSecret,
          config.auth0CanonicalDomain,
        );
      }
      tenantConfig.customDomains = await getCustomDomains(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      if (config.skipApplications) {
        logger.log(
          "info",
          `Skipping Applications retrieval (AUTH0CHECKMATE_SKIP_APPLICATIONS enabled)`,
        );
        tenantConfig.clients = [];
      } else {
        tenantConfig.clients = await getApplications(
          config.auth0Domain,
          config.auth0MgmtToken,
        );
        if (tenantConfig.clients.length > 2000) {
          logger.log(
            "info",
            `Skipping client validations: tenant has ${tenantConfig.clients.length} applications (limit: 2000)`,
          );
          tenantConfig.clients = [];
        }
      }
      tenantConfig.databases = await getConnections(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.attackProtection = await getAttackProtection(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.emailProvider = await getEmailProvider(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.logStreams = await getLogStreams(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.emailTemplates = await getEmailTemplates(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.errorPageTemplate = await getErrorPageTemplate(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.tenant = await getTenantSettings(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.guardianFactors = await getGuardianFactors(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.guardianPolicies = await getGuardianPolicies(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.rules = await getRules(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.hooks = await getHooks(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.actions = await getActions(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      const { log_query, logs } = await getLogs(
        config.auth0Domain,
        config.auth0MgmtToken,
        config.auth0CanonicalDomain,
      );
      tenantConfig.logs = logs;
      tenantConfig.log_query = log_query;

      tenantConfig.networkAcl = await getNetworkACL(
        config.auth0Domain,
        config.auth0MgmtToken
      );

      tenantConfig.canonicalDomain = config.auth0CanonicalDomain || config.auth0Domain;

      tenantConfig.eventStreams = await getEventStreams(
        config.auth0Domain,
        config.auth0MgmtToken
      );

      tenantConfig.resourceServers = await getResourceServers(
        config.auth0Domain,
        config.auth0MgmtToken
      );
    }
    
    const statusOrder = ["green", "amber", "red"];
    let fullReport = (await runProductionChecks(tenantConfig, checksToRun)) || [];
    fullReport.forEach((report) => {
      let grouped = [],
        res = [],
        sortedData = [];
      report.title = i18n.__(`${report.name}.title`);
      report.description = i18n.__(`${report.name}.description`);
      report.docsPath = i18n.__(`${report.name}.docsPath`);
      report.severity = i18n.__(`${report.name}.severity`);
      report.severity_message = i18n.__(`${report.name}.severity_message`);
      report.status = i18n.getCatalog("en")[`${report.name}`].status;
      report.advisory = i18n.__(`${report.name}.advisory`);
      let transformedDetails = [];
      switch (report.name) {
        case "checkCustomDomain":
          report.details.forEach((cd) => {
            cd.message = i18n.__(`checkCustomDomain.${cd.field}`, cd.value);
          });
          break;
        case "checkEmailProvider":
          report.details.forEach((cd) => {
            cd.message = i18n.__(`checkEmailProvider.${cd.field}`, cd.value);
          });
          break;
        case "checkEmailTemplates":
          report.details.forEach((cd) => {
            cd.message = i18n.__(`checkEmailTemplates.${cd.field}`, cd.value);
          });
          break;
        case "checkErrorPageTemplate":
          report.details.forEach((cd) => {
            cd.message = i18n.__(`checkErrorPageTemplate.${cd.field}`, cd.value);
          });
          break;
        case "checkLogStream":
        case "checkEventStreams":
          report.details.forEach((cd) => {
            cd.message = i18n.__(
              `${report.name}.${cd.field}`,
              cd.name,
              cd.type,
              cd.stream_status,
            );
          });
          break;
        case "checkTenantSettings":
          report.details.forEach((cd) => {
            cd.message = i18n.__(`checkTenantSettings.${cd.field}`, cd.value);
          });
          break;
        case "checkPasswordPolicy":
        case "checkPasswordHistory":
        case "checkPasswordNoPersonalInfo":
        case "checkPromotedDBConnection":
        case "checkPasswordComplexity":
          report.details.forEach((cd) => {
            cd.message = i18n.__(
              `${report.name}.${cd.field}`,
              cd.name,
              cd.value,
            );
          });
          break;
        case "checkEmailAttributeVerification":
        case "checkAuthenticationMethods":
          report.pre_requisites = i18n.__(`${report.name}.pre_requisites`);
          report.details.forEach((cd) => {
            cd.message = i18n.__(
              `${report.name}.${cd.field}`,
              cd.name,
              cd.value,
            );
          });
          break;
        case "checkJWTSignAlg":
          report.advisory = i18n.__(`${report.name}.advisory`);
          grouped = _.groupBy(report.details, "name");
          res = tranformReport(grouped);
          // Apply i18n translation to all reports
          res.forEach((client) => {
            client.values.forEach((detail) => {
              detail.report.forEach((c) => {
                c.name = client.name;
                c.message = i18n.__(
                  `${report.name}.${c.field}`,
                  c.client_id,
                  c.value || "RS256",
                );
              });
            });
          });
          break;
        case "checkGrantTypes":
          report.advisory = i18n.__(`${report.name}.advisory`);
          grouped = _.groupBy(report.details, "name");
          res = tranformReport(grouped);
          // Apply i18n translation to all reports
          res.forEach((client) => {
            client.values.forEach((detail) => {
              detail.report.forEach((c) => {
                c.name = client.name;
                c.message = i18n.__(
                  `${report.name}.${c.field}`,
                  c.value,
                  c.name,
                  c.app_type || "unknown",
                );
              });
            });
          });
          break;
        case "checkAllowedLogoutUrl":
        case "checkApplicationLoginUri":
        case "checkAllowedCallbacks":
        case "checkWebOrigins":
          grouped = _.groupBy(report.details, "name");

          res = tranformReport(grouped);
          // Apply i18n translation to all reports
          res.forEach((client) => {
            client.values.forEach((detail) => {
              detail.report.forEach((c) => {
                c.name = client.name;
                c.message = i18n.__(`${report.name}.${c.field}`, c.value);
              });
            });
          });
          break;
        case "checkCrossOriginAuthentication":
          report.advisory = i18n.__(`${report.name}.advisory`);
          grouped = _.groupBy(report.details, "name");
          res = tranformReport(grouped);
          // Apply i18n translation to all reports
          res.forEach((client) => {
            client.values.forEach((detail) => {
              detail.report.forEach((c) => {
                c.name = client.name;
                c.message = i18n.__(
                  `${report.name}.${c.field}`,
                  c.name,
                  c.app_type,
                );
              });
            });
          });
          break;
        case "checkRefreshToken":
          report.advisory = i18n.__(`${report.name}.advisory`);
          grouped = _.groupBy(report.details, "name");
          res = _.map(grouped, (values, name) => ({
            name,
            values: values,
          }));
          res.forEach((client) => {
            sortedData = _.sortBy(client.values[0].report, (item) =>
              statusOrder.indexOf(item.status),
            );
            sortedData.forEach((c) => {
              c.message = i18n.__(
                `checkRefreshToken.${c.field}`,
                c.name,
                c.value
              );
            });
          });
          break;
        case "checkPasswordResetMFA":
        case "checkPreRegistrationUserEnumeration":
        case "checkActionsHardCodedValues":
        case "checkDASHardCodedValues":
          report.disclaimer = i18n.__(`${report.name}.disclaimer`);

          grouped = _.groupBy(report.details, "name");

          _.forEach(grouped, (detailsArray) => {
            detailsArray.forEach((detailItem) => {
              const reportItems = detailItem.report;

              // Group messages by scriptName
              const groupedByScript = _.groupBy(reportItems, "scriptName");

              // Build HTML per script
              const htmlSections = Object.entries(groupedByScript).map(([scriptName, items]) => {
                const listItems = items.map((c) => {
                  const message = i18n.__(
                    `${report.name}.${c.field}`,
                    c.variableName,
                    c.line,
                    c.column
                  );
                  return `<li>${message}</li>`;
                }).join("\n");
                const dasTitle = i18n.__(`${report.name}.action_script_title`,
                  scriptName);
                return `<p>${dasTitle}<p>\n<ul>\n${listItems}\n</ul>`;
              });

              const fullHtml = `<div>\n${htmlSections.join("\n")}\n</div>`;

              // Push transformed object to new structure
              transformedDetails.push({
                status: "red",
                name: detailItem.name, // e.g., "login", "create"
                field: "hard_coded_value_detected",
                message: fullHtml
              });
            });
          });

          // Replace original report.details with the new structure
          report.details = transformedDetails;
          break;
        case "checkAppTokenSenderConstraining":
          report.disclaimer = i18n.__(`${report.name}.disclaimer`);
          report.advisory = i18n.__(`${report.name}.advisory`);
          grouped = _.groupBy(report.details, "name");
          res = tranformReport(grouped);
          res.forEach((item) => {
            item.values.forEach((detail) => {
              detail.report.forEach((c) => {
                c.message = i18n.__(`${report.name}.${c.field}`, c.value);
              });
            });
          });
          break;
        case "checkDependencies":
          report.details.forEach((cd) => {
            cd.message = i18n.__(`${report.name}.${cd.field}`, cd.value);
            cd.vulnFindings = cd.vulnFindings || [];
          });
          break;
        case "checkNetworkACL":
          report.disclaimer = i18n.__(`${report.name}.disclaimer`);
          report.details.forEach((cd) => {
            cd.message = i18n.__(`${report.name}.${cd.field}`, cd.value);
          });
          break;
        case "checkBlockCanonicalDomain":
          report.disclaimer = i18n.__(`${report.name}.disclaimer`);
          report.details.forEach((cd) => {
            cd.message = i18n.__(`${report.name}.${cd.field}`, cd.customDomains, cd.value);
          });
          break;
        case "checkManagementAPIACL":
          report.disclaimer = i18n.__(`${report.name}.disclaimer`);
          report.details.forEach((cd) => {
            cd.message = i18n.__(`${report.name}.${cd.field}`);
          });
          break;
        case "checkManagementAPIUserAccess":
          report.advisory = i18n.__(`${report.name}.advisory`);
          report.details.forEach((cd) => {
            cd.message = i18n.__(`${report.name}.${cd.field}`);
          });
          break;
        case "checkAPIAuthorizationPolicy":
          report.advisory = i18n.__(`${report.name}.advisory`);
          report.details.forEach((detail) => {
            detail.report.forEach((c) => {
              c.message = i18n.__(`${report.name}.${c.field}`, c.api_name);
            });
          });
          break;
        case "checkAPISigningAlgorithm":
        case "checkAPITokenLifetime":
          report.advisory = i18n.__(`${report.name}.advisory`);
          grouped = _.groupBy(report.details, "name");
          res = tranformReport(grouped);
          res.forEach((api) => {
            api.values.forEach((detail) => {
              detail.report.forEach((c) => {
                c.name = api.name;
                c.message = i18n.__(
                  `${report.name}.${c.field}`,
                  c.api_name,
                  c.value
                );
              });
            });
          });
          break;
        case "checkJWEResourceServer":
          report.disclaimer = i18n.__(`${report.name}.disclaimer`);
          grouped = _.groupBy(report.details, "name");
          res = tranformReport(grouped);
          res.forEach((item) => {
            item.values.forEach((detail) => {
              detail.report.forEach((c) => {
                c.message = i18n.__(`${report.name}.${c.field}`, c.value);
              });
            });
          });
          break;
        case "checkTokenConstrainingResourceServer":
          report.disclaimer = i18n.__(`${report.name}.disclaimer`);
          report.advisory = i18n.__(`${report.name}.advisory`);
          grouped = _.groupBy(report.details, "name");
          res = tranformReport(grouped);
          res.forEach((item) => {
            item.values.forEach((detail) => {
              detail.report.forEach((c) => {
                c.message = i18n.__(`${report.name}.${c.field}`, c.value);
              });
            });
          });
          break;
        default:
          report.details.forEach((cd) => {
            cd.message = i18n.__(`${report.name}.${cd.field}`, cd.value);
          });
          break;
      }
    });
    // On a filtered run the documented scope must list only the validators that
    // actually ran, otherwise the report overstates what was reviewed.
    const list_of_validators = isFilteredRun
      ? checksToRun.map((check) => ({
          title: i18n.__(`${check.name}.title`),
          items: [],
        }))
      : i18n.__("list_of_validators");
    let all_validators = [];
    list_of_validators.forEach((validator) => {
      all_validators =
        validator.items.length > 0
          ? all_validators.concat(validator.items)
          : all_validators.concat([validator.title]);
    });
    const total_validators = all_validators.length;
    const summary = await getSummaryReport(fullReport);
    const report = {};
    report.preamble = i18n.getCatalog(locale).preamble;
    report.report_title = i18n.__("report_title");
    (report.summary = summary), (report.full_report = fullReport);
    report.tenantConfig = tenantConfig;
    report.list_of_validators = list_of_validators;
    report.validator_summary = i18n.__(
      "validator_summary",
      total_validators,
      config.auth0Domain,
    );
    return report;
  } catch (error) {
    console.log(error);
    logger.log("error", `Error generating report: ${error}`);
    return {};
  }
}

async function generateHtml(report, auth0Domain, locale) {
  locale = locale || "en";
  const today = await getToday(locale);
  const data = { report, auth0Domain, today, locale, version, config: {} };
  const template = Handlebars.compile(templateData);
  return template({
    locale: data.locale,
    data,
    preamble: data.report.preamble,
  });
}


module.exports = {
  generateReport,
  generateHtml,
  resolveSelectedValidators,
  parseValidatorSelection,
  getValidatorNames,
};

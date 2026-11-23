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
  getPrompts,
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
const CONSTANTS = require("./lib/constants");
const { getSummaryReport } = require("./tools/summary");
const { convertToTitleCase, tranformReport, getToday } = require("./tools/utils");
const { version } = require("../package.json");

// Shared i18n / Handlebars setup (bin/index.js relies on this module for both).
// updateFiles is off so a missing key never rewrites locales/*.json at runtime.
i18n.configure({
  defaultLocale: "en",
  objectNotation: true,
  directory: path.join(__dirname, "../locales"),
  updateFiles: false,
});

Handlebars.registerHelper("chooseFont", () => "DM Sans, sans-serif");
Handlebars.registerHelper("replace", function (str, search, replace) {
  return str.replace(search, replace);
});
Handlebars.registerHelper("and", (a, b) => a && b);
Handlebars.registerHelper("inc", (a) => parseInt(a) + 1);

const templateData = fs.readFileSync(
  path.join(__dirname, "../views/pdf_cli_report.handlebars"),
  "utf8",
);

/**
 * How each check's details are turned into report messages.
 *
 * shape:
 *  - flat    (default) details are findings; message = i18n(name.field, ...args(detail))
 *  - grouped details are { name, report: [...] } per client; only findings with an
 *            is_first_party flag are rendered, under "(First-Party|Third-Party Application)"
 *            headings (see tranformReport). setName copies that heading onto each finding.
 *  - nested  details are { name, report: [...] }; every finding in report gets a message
 *  - script  details are { name, report: [...] } of per-script findings, rendered
 *            into one HTML list per detail
 * args receives the finding and returns the i18n format arguments.
 * Disclaimer, advisory and pre_requisites are attached for every check that
 * has them in the locale catalog.
 */
const valueArg = (c) => [c.value];
const nameValueArgs = (c) => [c.name, c.value];
const streamArgs = (c) => [c.name, c.type, c.stream_status];
const noArgs = () => [];

const CHECK_CONFIG = {
  // flat, with non-default message arguments
  checkLogStream: { args: streamArgs },
  checkEventStreams: { args: streamArgs },
  checkPasswordPolicy: { args: nameValueArgs },
  checkPasswordHistory: { args: nameValueArgs },
  checkPasswordNoPersonalInfo: { args: nameValueArgs },
  checkPromotedDBConnection: { args: nameValueArgs },
  checkPasswordComplexity: { args: nameValueArgs },
  checkEmailAttributeVerification: { args: nameValueArgs },
  checkAuthenticationMethods: { args: nameValueArgs },
  checkBlockCanonicalDomain: { args: (c) => [c.customDomains, c.value] },
  checkManagementAPIACL: { args: noArgs },
  checkManagementAPIUserAccess: { args: noArgs },
  checkDependencies: {
    prepare: (c) => {
      c.vulnFindings = c.vulnFindings || [];
    },
  },

  // grouped by client (first-party / third-party)
  checkJWTSignAlg: {
    shape: "grouped",
    setName: true,
    args: (c) => [c.client_id, c.value || "RS256"],
  },
  checkGrantTypes: {
    shape: "grouped",
    setName: true,
    args: (c) => [c.value, c.name, c.app_type || "unknown"],
  },
  checkAllowedLogoutUrl: { shape: "grouped", setName: true },
  checkApplicationLoginUri: { shape: "grouped", setName: true },
  checkAllowedCallbacks: { shape: "grouped", setName: true },
  checkWebOrigins: { shape: "grouped", setName: true },
  checkCrossOriginAuthentication: {
    shape: "grouped",
    setName: true,
    args: (c) => [c.name, c.app_type],
  },
  checkAppTokenSenderConstraining: { shape: "grouped" },

  // nested findings
  checkPAR: { shape: "nested" },
  checkJAR: { shape: "nested" },
  checkPKCEEnforcement: { shape: "nested" },
  checkPrivateKeyJWT: { shape: "nested" },
  checkBackchannelLogout: { shape: "nested" },
  checkRefreshToken: { shape: "nested", args: nameValueArgs },
  checkAPIAuthorizationPolicy: { shape: "nested", args: (c) => [c.api_name] },
  checkAPISigningAlgorithm: {
    shape: "nested",
    args: (c) => [c.api_name, c.value],
  },
  checkAPITokenLifetime: {
    shape: "nested",
    args: (c) => [c.api_name, c.value],
  },
  checkJWEResourceServer: { shape: "nested" },
  checkTokenConstrainingResourceServer: { shape: "nested" },

  // per-script findings rendered as HTML
  checkPasswordResetMFA: { shape: "script" },
  checkPreRegistrationUserEnumeration: { shape: "script" },
  checkActionsHardCodedValues: { shape: "script" },
  checkDASHardCodedValues: { shape: "script" },
};

/**
 * Findings whose field contains a dot (e.g. "signed_request_object.required")
 * are flat keys in the catalog, which i18n's dot notation cannot reach, so
 * they are read from the catalog directly and %s placeholders filled in order.
 */
function messageFor(name, finding, args) {
  const values = args(finding);
  const template = finding.field.includes(".")
    ? i18n.getCatalog(i18n.getLocale())[name]?.[finding.field]
    : undefined;
  if (typeof template === "string") {
    let next = 0;
    return template.replace(/%s/g, () => String(values[next++]));
  }
  return i18n.__(`${name}.${finding.field}`, ...values);
}

const SHAPE_HANDLERS = {
  flat(report, { args = valueArg, prepare }) {
    report.details.forEach((detail) => {
      detail.message = messageFor(report.name, detail, args);
      if (prepare) prepare(detail);
    });
  },

  grouped(report, { args = valueArg, setName }) {
    const grouped = _.groupBy(report.details, "name");
    tranformReport(grouped).forEach((client) => {
      client.values.forEach((detail) => {
        detail.report.forEach((c) => {
          if (setName) c.name = client.name;
          c.message = messageFor(report.name, c, args);
        });
      });
    });
  },

  nested(report, { args = valueArg }) {
    report.details.forEach((detail) => {
      (detail.report || []).forEach((c) => {
        c.message = messageFor(report.name, c, args);
      });
    });
  },

  script(report) {
    const transformedDetails = [];
    _.forEach(_.groupBy(report.details, "name"), (detailsArray) => {
      detailsArray.forEach((detailItem) => {
        const groupedByScript = _.groupBy(detailItem.report, "scriptName");
        const htmlSections = Object.entries(groupedByScript).map(
          ([scriptName, items]) => {
            const listItems = items
              .map((c) => {
                const message = i18n.__(
                  `${report.name}.${c.field}`,
                  c.variableName,
                  c.line,
                  c.column,
                );
                return `<li>${message}</li>`;
              })
              .join("\n");
            const title = i18n.__(`${report.name}.action_script_title`, scriptName);
            return `<p>${title}<p>\n<ul>\n${listItems}\n</ul>`;
          },
        );
        transformedDetails.push({
          status: "red",
          name: detailItem.name, // e.g., "login", "create"
          field: "hard_coded_value_detected",
          message: `<div>\n${htmlSections.join("\n")}\n</div>`,
        });
      });
    });
    report.details = transformedDetails;
  },
};

/** Fill in the catalog text (title, severity, ...) and the per-finding messages. */
function localizeReport(report, locale) {
  const catalog = i18n.getCatalog(locale)[report.name] || {};
  report.title = i18n.__(`${report.name}.title`);
  report.description = i18n.__(`${report.name}.description`);
  report.docsPath = i18n.__(`${report.name}.docsPath`);
  report.severity = i18n.__(`${report.name}.severity`);
  report.severity_message = i18n.__(`${report.name}.severity_message`);
  report.status = i18n.getCatalog("en")[report.name].status;
  report.advisory = i18n.__(`${report.name}.advisory`);
  ["disclaimer", "pre_requisites"].forEach((key) => {
    if (_.has(catalog, key)) report[key] = i18n.__(`${report.name}.${key}`);
  });
  const config = CHECK_CONFIG[report.name] || {};
  SHAPE_HANDLERS[config.shape || "flat"](report, config);
}

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

/*Resolve requested validator names into the checks to run, in the order they were requested. An empty selection runs every validator. */

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

function getValidatorNames() {
  return listOfAnalyser.checks.map((check) => check.name);
}

/* Parse a comma-separated validator list */
function parseValidatorSelection(value) {
  const selection = normalizeValidatorSelection((value || "").split(","));
  if (!_.isEmpty(selection)) {
    resolveSelectedValidators(selection);
  }
  return selection;
}

function runProductionChecks(tenant, checksToRun) {
  logger.log("info", "Checking your configuration...");
  return Promise.all(
    checksToRun.map(async (check) => {
      logger.log("info", `Running validator ${convertToTitleCase(check.name)}`);
      try {
        const checkResult = await check(tenant);
        return { name: check.name, details: checkResult.details };
      } catch (e) {
        // Keep the rest of the report: a check that throws reports no findings.
        logger.log("error", `Validator ${check.name} failed: ${e.message}`);
        return { name: check.name, details: [], error: e };
      }
    }),
  );
}

async function generateReport(locale, tenantConfig, config) {
  i18n.setLocale(locale);
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
        if (tenantConfig.clients.length > CONSTANTS.MAX_APPLICATIONS) {
          logger.log(
            "info",
            `Skipping client validations: tenant has more than ${CONSTANTS.MAX_APPLICATIONS} applications`,
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
      tenantConfig.prompts = await getPrompts(
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

    const fullReport = await runProductionChecks(tenantConfig, checksToRun);
    fullReport.forEach((report) => localizeReport(report, locale));
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
    report.summary = summary;
    report.full_report = fullReport;
    report.tenantConfig = tenantConfig;
    report.list_of_validators = list_of_validators;
    report.validator_summary = i18n.__(
      "validator_summary",
      total_validators,
      config.auth0Domain,
    );
    return report;
  } catch (error) {
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

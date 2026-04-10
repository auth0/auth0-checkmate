const fs = require("fs");
const i18n = require("i18n");
const path = require("path");
const _ = require("lodash");
const Handlebars = require("handlebars");
const puppeteer = require("puppeteer");
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

async function runProductionChecks(tenant, validators) {
  try {
    logger.log("info", "Checking your configuration...");
    const validatorsToRun = new Set(validators);
    const checksPromises = listOfAnalyser.checks.map((check) => {
      return new Promise((resolve) => {
        if (!_.isEmpty(validatorsToRun) && !validatorsToRun.has(check.name)) {
          //console.log(`Skipping ${check.name} `);
          resolve({ name: check.name, details: [] });
        }
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
  try {
    if (_.isEmpty(tenantConfig)) {
      if (!config.auth0MgmtToken) {
        config.auth0MgmtToken = await getAccessToken(
          config.auth0Domain,
          config.auth0ClientId,
          config.auth0ClientSecret,
          config.auth0MgmtToken,
        );
      }
      tenantConfig.customDomains = await getCustomDomains(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
      tenantConfig.clients = await getApplications(
        config.auth0Domain,
        config.auth0MgmtToken,
      );
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
      );
      tenantConfig.logs = logs;
      tenantConfig.log_query = log_query;

      tenantConfig.networkAcl = await getNetworkACL(
        config.auth0Domain,
        config.auth0MgmtToken
      );

      tenantConfig.eventStreams = await getEventStreams(
        config.auth0Domain,
        config.auth0MgmtToken
      );

    }
    const statusOrder = ["green", "amber", "red"];
    let fullReport =
      (await runProductionChecks(tenantConfig, config.selectedValidators)) ||
      [];
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
        case "checkDPoP":
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
        default:
          report.details.forEach((cd) => {
            cd.message = i18n.__(`${report.name}.${cd.field}`, cd.value);
          });
          break;
      }
    });
    const list_of_validators = i18n.__("list_of_validators");
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

async function generatePdfBuffer(report, auth0Domain, locale) {
  locale = locale || "en";
  const today = await getToday(locale);

  const data = { report, auth0Domain, today, locale, version, config: {} };

  const browser = await puppeteer.launch({
    headless: true, // Run in headless mode
    args: [
      "--no-sandbox", // Disable the sandbox
      "--disable-setuid-sandbox", // Disable setuid sandbox
    ],
  });

  try {
    const template = Handlebars.compile(templateData);
    const htmlContent = template({
      locale: data.locale,
      data,
      preamble: data.report.preamble,
    });
    const page = await browser.newPage();

    // Disable JS execution in the Puppeteer page. Disabling
    // JS eliminates the browser-side execution surface during PDF rendering.
    await page.setJavaScriptEnabled(false);

    // Allowlist only the CDN hostnames the template legitimately loads from
    // (Bootstrap, Google Fonts). All other outbound requests — including RFC 1918
    // addresses and cloud metadata endpoints — are aborted to prevent SSRF via
    // passive resource loading (e.g. <img src="http://169.254.169.254/...">) in
    // case tenant-controlled data ever reaches an unescaped template field.
    await page.setRequestInterception(true);
    page.on("request", (req) => {
      const url = new URL(req.url());
      const allowed = [
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "cdn.jsdelivr.net",
      ];
      if (req.resourceType() === "document" || allowed.includes(url.hostname)) {
        req.continue();
      } else {
        req.abort();
      }
    });

    await page.setContent(htmlContent, { waitUntil: "networkidle2" });

    const pdfResult = await page.pdf({
      format: "A4",
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: `<div></div>`,
      footerTemplate: `
        <div style="font-size:10px; width:100%; padding:10px 0; display:flex; align-items:center; justify-content:space-between; border-top:1px solid #ddd;">
          <span style="flex:1; text-align:center;">Confidential. For internal evaluation purposes only.</span>
          <span style="flex:1; text-align:right; padding-right:20px;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
        </div>`,
      margin: {
        top: "20px",
        bottom: "60px",
      },
    });
    // Puppeteer v20+ returns Uint8Array, not Buffer. Express's res.send() calls
    // Buffer.isBuffer() and JSON-serialises anything that fails the check,
    // producing {"0":37,"1":80,...} instead of raw binary. Convert explicitly.

    return Buffer.from(pdfResult);
  } catch (error) {
    logger.log("error", `Error generating PDF: ${error}`);
    throw error;
  } finally {
    await browser.close();
  }
}

module.exports = {
  generateReport,
  generatePdfBuffer,
};

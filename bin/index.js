#!/usr/bin/env node

const fs = require("node:fs");
const jwt = require('jsonwebtoken');
const path = require("path");
const logger = require("../analyzer/lib/logger");
const { generateReport } = require("../analyzer/report");
const chalk = require("chalk");
const figlet = require("figlet");
const inquirer = require("inquirer").default;
const puppeteer = require("puppeteer");
const { getToday, getFormattedDateTime } = require("../analyzer/tools/utils");
const Handlebars = require("handlebars");
const i18n = require("i18n");
const os = require("os");
const userHomeDir = os.homedir();
const Table = require("cli-table3");
const {
  getAccessToken,
} = require("../analyzer/tools/auth0");
const CONSTANTS = require('../analyzer/lib/constants');
/**
 * print current version of the package
 * Access the version from package.json
 */
const { version } = require("../package.json");

/**
 * configure shared state
 */
i18n.configure({
  defaultLocale: "en",
  objectNotation: true,
  directory: path.join(__dirname, "../locales"),
});

Handlebars.registerHelper("chooseFont", function (locale) {
  if (locale === "ja") {
    return "Noto Sans JP, sans-serif";
  } else if (locale === "ko") {
    return "Noto Sans KR, sans-serif"; // For Simplified Chinese
  } else {
    return "DM Sans, sans-serif"; // Default font
  }
});
Handlebars.registerHelper("replace", function (str, search, replace) {
  return str.replace(search, replace);
});
Handlebars.registerHelper("and", (a, b) => a && b); // Logical AND
Handlebars.registerHelper("inc", (a) => parseInt(a) + 1);

console.log(
  chalk.yellow(
    figlet.textSync("CheckMate\nfor Auth0", {
      horizontalLayout: "full",
      width: 80,
    }),
  ),
);
console.log(chalk.yellow(`Current Version: ${version}\n`));
// Load static assets required for report generation.
const templateData = fs.readFileSync(
  path.join(__dirname, "../views/pdf_cli_report.handlebars"),
  "utf8",
);

/**
 * 
 * @param {*} accessToken 
 * @returns 
 */
function decodeTokenScopes(accessToken) {
  try {
    const decoded = jwt.decode(accessToken);
    if (!decoded) {
      console.error("❌ Failed to decode token.");
      return null;
    }

    const scopeString = decoded.scope || "";
    return scopeString.split(" ").map(scope => scope.trim()).filter(Boolean);
  } catch (err) {
    console.error("❌ Error decoding token:", err.message);
    return null;
  }
}

function filterByKey(array, keyArray, key) {
  return array.filter(item => {
    const words = item[key].split(' ');
    return words.some(word => keyArray.includes(word));
  });
}

/**
 * 
 * @param {*} accessToken 
 * @param {*} requiredScopes 
 * @returns 
 */
function checkScopes(accessToken, requiredScopes) {
  const tokenScopes = decodeTokenScopes(accessToken);
  if (!tokenScopes) {
    console.error("❌ No scopes found in token.");
    return;
  }

  const missingScopes = requiredScopes.filter(scope => !tokenScopes.includes(scope));
  const listOfValidators = i18n.__("list_of_validators");
  const filteredValidators = filterByKey(listOfValidators, missingScopes, 'required_scope');
  if (missingScopes.length > 0) {
    console.log("❌ The following validators will be skipped as it is missing required scopes:");
    filteredValidators.forEach(v => {
      v.title = v.title.concat(` - ${v.required_scope}`);
      delete v.required_scope;
      printJsonAsBullets(v);
    });
  } else {
    console.log("✅ All required scopes are present.");
  }
}

/**
 * 
 * @param {*} locale 
 * @param {*} tenant 
 * @param {*} config 
 */

// Placeholder function to simulate processing Auth0 configuration
async function processAuth0Config(locale, tenant, config) {
  logger.log("info", "Processing Auth0 configuration:");
  const report = await generateReport(locale, tenant, config);
  const today = await getToday(locale);
  const { auth0Domain, filePath } = config;
  const data = { report, auth0Domain, today, locale, version };
  await printReportToCli(filePath, data);
}

async function printReportToCli(filePath, data) {
  if (data.report && data.report.summary) {
    console.log(
      chalk.yellow(
        `\nHigh level summary of ${data.report.summary.length} findings\n`,
      ),
    );
    // Create a table instance
    const table = new Table({
      head: ["Index", "Priority", "Recommendation"],
      colWidths: [10, 15, 150],
    });

    // Add rows to the table
    data.report.summary.forEach((report, index) => {
      table.push([
        ++index,
        report.severity,
        `${report.title} - ${report.severity_message.replace("%s", report.detailsLength)}`,
      ]);
    });

    // Print the table
    console.log(table.toString());
    await generatePdf(filePath, data);
  } else {
    console.log(chalk.red(`failed to generate report`));
  }
}

async function generatePdf(filePath, data) {
  try {
    console.log(chalk.yellow(`\nGenerating a PDF report\n`));
    const fileFullPath = `${filePath}/${data.auth0Domain}_${data.locale}_${getFormattedDateTime()}_report.pdf`;
    const fileFullPathJSON = `${filePath}/${data.auth0Domain}_${data.locale}_${getFormattedDateTime()}_report.json`;
    if (!fs.existsSync(filePath)) {
      console.log("The directory does not exist, creating it...");
      await fs.mkdirSync(filePath, { recursive: true });
    }
    // save JSON report
    fs.writeFileSync(fileFullPathJSON, JSON.stringify(data.report.summary, null, 2));
    const browser = await puppeteer.launch({
      headless: true, // Run in headless mode
      args: [
        "--no-sandbox", // Disable the sandbox
        "--disable-setuid-sandbox", // Disable setuid sandbox
      ],
    });
    const template = Handlebars.compile(templateData);
    const htmlContent = template({
      locale: data.locale,
      data,
      preamble: data.report.preamble,
    });
    const page = await browser.newPage();
    // Load the compiled HTML content into Puppeteer

    await page.setContent(`${htmlContent}`, { waitUntil: "networkidle2" });

    // Generate PDF
    await page.pdf({
      path: fileFullPath,
      format: "A4",
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: `<div></div>`,
      footerTemplate: `
                      <div style="font-size:10px; width:100%; padding:10px 0; display:flex; align-items:center; justify-content:space-between; border-top:1px solid #ddd;">
                        <span style="flex:1; text-align:center;">Confidential. For internal evaluation purposes only.</span>
                        <span style="flex:1; text-align:right; padding-right:20px;"">Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
                      </div>`,
      margin: {
        top: "20px", // Space for header
        bottom: "60px", // Space for footer
      },
    });
    await browser.close();
    console.log(
      chalk.yellow(`\nA full PDF report has been saved at ${fileFullPath}\n`),
    );
    console.log(
      chalk.yellow(`\nJSON report has been saved at ${fileFullPathJSON}\n`),
    );
  } catch (e) {
    logger.log("error", `Failed to generate pdf ${e}`);
  }
}

function printJsonAsBullets(json, indent = 0) {
  const indentStr = '  '.repeat(indent);

  for (const key in json) {
    if (key != 'required_scope') {
      const value = json[key];

      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        printJsonAsBullets(value, indent + 1);
      } else if (Array.isArray(value)) {
        //console.log(`${indentStr}• ${key}:`);
        value.forEach(item => {
          if (typeof item === 'object') {
            printJsonAsBullets(item, indent + 1);
          } else {
            console.log(`${indentStr}  - ${item}`);
          }
        });
      } else {
        console.log(`${indentStr}• ${value}`);
      }
    }
  }
}

async function main() {
  const selectedValidators = process.env.RUN_VALIDATORS;
  if (selectedValidators && !/^(\w+)(,\w+)*$/.test(selectedValidators)) {
    throw new Error(
      `RUN_VALIDATORS must be a comma-separated list of available validator names`
    );
  }
  const answers = {};

  // Prompt 1: Show validators
  const { showValidators } = await inquirer.prompt({
    type: "confirm",
    name: "showValidators",
    message: "Show me the list of validators:",
    default: false,
  });
  answers.showValidators = showValidators;

  if (showValidators) {
    console.log("Currently supports for the following tenant configurations:");
    printJsonAsBullets(i18n.__("list_of_validators"));
  }

  // Prompt 2: Auth method
  const { authMethod } = await inquirer.prompt({
    type: "list",
    name: "authMethod",
    message: "How would you like to provide credentials?",
    choices: [
      { name: "Auth0 Client ID & Secret", value: "clientSecret" },
      { name: "Auth0 Management API Token", value: "auth0MgmtToken" },
    ],
  });
  answers.authMethod = authMethod;

  // Prompt 3: Auth0 Domain
  const { auth0Domain } = await inquirer.prompt({
    type: "input",
    name: "auth0Domain",
    message: "Enter your Auth0 domain:",
    validate: (input) => (input ? true : "Auth0 domain is required."),
  });
  answers.auth0Domain = auth0Domain;

  // Prompt 4: Auth0 Client ID (if needed)
  if (authMethod === "clientSecret") {
    const { auth0ClientId } = await inquirer.prompt({
      type: "input",
      name: "auth0ClientId",
      message: "Enter your Auth0 Client ID:",
      validate: (input) => (input ? true : "Auth0 Client ID is required."),
    });
    answers.auth0ClientId = auth0ClientId;
  }

  // Prompt 5: Auth0 Client Secret (if needed)
  if (authMethod === "clientSecret") {
    const { auth0ClientSecret } = await inquirer.prompt({
      type: "password",
      name: "auth0ClientSecret",
      message: "Enter your Auth0 Client Secret:",
      validate: (input) => (input ? true : "Auth0 Client Secret is required."),
    });
    answers.auth0ClientSecret = auth0ClientSecret;
    try {
      const accessToken = await getAccessToken(answers.auth0Domain, answers.auth0ClientId, answers.auth0ClientSecret);
      checkScopes(accessToken, CONSTANTS.REQUIRED_SCOPES.split(' '));
      answers.auth0MgmtToken = accessToken;
    } catch (e) {
      console.error(e.message);
      process.exit(0);
    }
  }

  // Prompt 6: Auth0 Management Token (if needed)
  if (authMethod === "auth0MgmtToken") {
    const { auth0MgmtToken } = await inquirer.prompt({
      type: "input",
      name: "auth0MgmtToken",
      message: "Enter your Auth0 Management API Token:",
      validate: (input) =>
        input ? true : "Auth0 Management API token is required.",
    });
    checkScopes(auth0MgmtToken, CONSTANTS.REQUIRED_SCOPES.split(' '));
    answers.auth0MgmtToken = auth0MgmtToken;
  }

  // Prompt 7: Locale (if more than one)
  const locales = i18n.getLocales();
  if (locales.length > 1) {
    const { locale } = await inquirer.prompt({
      type: "list",
      name: "locale",
      message: "Select a locale:",
      choices: locales,
      default: "en",
    });
    answers.locale = locale;
  } else {
    answers.locale = "en";
  }

  // Prompt 8: File path
  const { filePath } = await inquirer.prompt({
    type: "input",
    name: "filePath",
    message:
      "Enter the full path where you want to save the file (e.g., /path/to/file.pdf):",
    default: "./reports",
    validate: (input) => {
      if (input.trim() === "") {
        return "Please enter a valid file path.";
      }
      return true;
    },
  });
  answers.filePath = filePath;
  // Construct config
  const config = {
    auth0Domain: answers.auth0Domain,
    auth0ClientId: answers.auth0ClientId || null,
    auth0ClientSecret: answers.auth0ClientSecret || null,
    auth0MgmtToken: answers.auth0MgmtToken || null,
    filePath: path.isAbsolute(answers.filePath) ? answers.filePath : path.resolve(answers.filePath),
    selectedValidators: selectedValidators ? selectedValidators.split(',') : []
  };

  const tenant = {};

  processAuth0Config(answers.locale, tenant, config);
}
// Execute the script
main().catch((err) => {
  logger.log("error", `Error: ${err.message}`);
  process.exit(1);
});

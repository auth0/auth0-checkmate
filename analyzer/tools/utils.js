const moment = require("moment");
const _ = require('lodash');
function getFormattedDateTime() {
    return moment().format("YYYY-MM-DD_HH:mm:ss").replace(/:/g, "_");
}

async function getToday(locale) {
    const date = new Date();
    const formattedDate = date.toLocaleDateString(locale, {
        month: "long", // Full month name (e.g., 'January')
        day: "numeric", // Day of the month (e.g., '20')
        year: "numeric", // Full year (e.g., '2025')
    });
    return formattedDate;
}

function convertToTitleCase(str) {
    // Insert space before each uppercase letter and capitalize the first letter
    return str
        .replace(/([a-z])([A-Z])/g, '$1 $2')  // Add space between lowercase and uppercase letters
        .replace(/^./, (match) => match.toUpperCase()); // Capitalize the first letter
}

function tranformReport(grouped) {
    const report = _.flatMap(grouped, (values, name) => {
        const firstPartyValues = [];
        const thirdPartyValues = [];
        values.forEach((detail) => {
            const firstReports = detail.report.filter(r => r.is_first_party === true);
            const thirdReports = detail.report.filter(r => r.is_first_party === false);

            if (firstReports.length) {
                firstPartyValues.push({
                    ...detail,
                    report: firstReports
                });
            }

            if (thirdReports.length) {
                thirdPartyValues.push({
                    ...detail,
                    report: thirdReports
                });
            }
        });

        const result = [];

        if (firstPartyValues.length) {
            result.push({
                name: `${name} (First-Party Application)`,
                values: firstPartyValues
            });
        }

        if (thirdPartyValues.length) {
            result.push({
                name: `${name} (Third-Party Application)`,
                values: thirdPartyValues
            });
        }

        return result;
    });
    return report;
}
module.exports = {
    getFormattedDateTime,
    getToday,
    convertToTitleCase,
    tranformReport
};

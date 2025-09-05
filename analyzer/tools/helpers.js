const axios = require("axios");
const semver = require("semver");
const logger = require("../lib/logger");
async function checkVulnerableVersion(currentVersion, advisoryData) {
  const vulnerabilitiesAdvisory = [];
  advisoryData.forEach((advisory) => {
    advisory.vulnerabilities.forEach((vulnerability) => {
      const vulnerableVersionRange = vulnerability.vulnerable_version_range;
      const isVulnerable = semver.satisfies(
        currentVersion,
        vulnerableVersionRange,
      );

      if (isVulnerable) {
        vulnerabilitiesAdvisory.push({
          description: `Vulnerable to ${advisory.cve_id} (range: ${vulnerableVersionRange})`,
          advisory_url: advisory.html_url,
          advisory_summary: advisory.summary,
          severity: advisory.severity,
        });
      }
    });
  });
  return vulnerabilitiesAdvisory;
}

async function checkGitHubAdvisories(packageName, version) {
  try {
    const headers = {
      Accept: "application/vnd.github.v3+json",
    };
    const url = `https://api.github.com/advisories?affects=${packageName}@${version}`;
    const response = await axios.get(url, { headers });
    const vulnFindings = await checkVulnerableVersion(version, response.data);
    return vulnFindings;
  } catch (error) {
    logger.log(
      "error",
      `Failed to get github advisory skipping - ${error.message}`,
    );
    return [];
  }
}

async function getActionDependencies(actionsList) {
  var vulnDependencyList = [];
  for (let i = 0; i < actionsList.length; i++) {
    for (const dependency of actionsList[i].dependencies) {
      var vulnFindings = await checkGitHubAdvisories(
        dependency.name,
        dependency.version,
      );
      if (vulnFindings.length > 0) {
        vulnDependencyList.push({
          name: dependency.name,
          actionName: actionsList[i].name,
          version: dependency.version,
          vulnFindings: vulnFindings,
          trigger: actionsList[i].supported_triggers[0].id,
        });
      }
    }
  }
  return vulnDependencyList;
}

module.exports = {
  checkVulnerableVersion,
  checkGitHubAdvisories,
  getActionDependencies,
};

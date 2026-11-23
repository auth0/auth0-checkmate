const fs = require("fs");
const path = require("path");
const logger = require("./logger");

// Every file in each sub-directory of this folder is a check module.
// Directories and files are sorted so the check order is deterministic.
const requiredModules = [];

const directories = fs
  .readdirSync(__dirname, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();

directories.forEach((directory) => {
  const directoryPath = path.join(__dirname, directory);
  const files = fs
    .readdirSync(directoryPath, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.includes("."))
    .map((entry) => entry.name)
    .sort();
  files.forEach((file) => {
    const filePath = path.join(directoryPath, file);
    try {
      requiredModules.push(require(filePath));
    } catch (error) {
      logger.log("error", `Error requiring file: ${filePath} ${error}`);
    }
  });
});

module.exports.checks = requiredModules;

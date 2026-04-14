const glob = require("glob");
const path = require("path");
// Array to hold the required modules
let requiredModules = [];

// Match only directories in the current directory
// Fix Windows backslash issue by converting to forward slashes (glob only recognizes forward slashes)
const basePath = __dirname.replace(/\\/g, '/');
const directories = glob.sync(basePath + "/*/");
directories.forEach((directory) => {
  // Match all files in each directory
  const pathName = directory.replace(/\\/g, '/') + "*.*"; // Fix Windows backslash issue
  const files = glob.sync(pathName); // Synchronously match files in the directory
  files.forEach((file) => {
    const filePath = path.resolve(file);
    try {
      const module = require(filePath); // Dynamically require the file
      requiredModules.push(module); // Add the required module to the array
    } catch (error) {
      console.error(`Error requiring file: ${filePath}`, error);
    }
  });
});

// Export the required modules
module.exports.checks = requiredModules;

const glob = require("glob");
const path = require("path");
// Array to hold the required modules
let requiredModules = [];

// Match only directories in the current directory
// Fix Windows backslash issue: glob only recognizes forward slashes as path separators
const directories = glob.sync(path.join(__dirname, "/*/").replace(/\\/g, '/'));
directories.forEach((directory) => {
  // Match all files in each directory
  const pathName = path.join(directory, "*.*").replace(/\\/g, '/'); // Fix Windows backslash issue
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

const { expect } = require("chai");
const { generateReport } = require("../analyzer/report");
const CONSTANTS = require("../analyzer/lib/constants");
const tenantConfig = require("./fixtures/tenantConfig.json");
const golden = require("./fixtures/report.golden.json");

const STATUSES = { FAIL: "red", SUCCESS: "green", INFO: "blue", WARN: "yellow" };

// Check discovery order is filesystem dependent, so compare in a stable order.
// The tenantConfig echo is dropped: it is the fixture itself.
function normalize(report) {
  const copy = JSON.parse(JSON.stringify(report));
  delete copy.tenantConfig;
  delete copy.timestamp;
  const byName = (a, b) => a.name.localeCompare(b.name);
  copy.full_report.sort(byName);
  copy.summary.sort(byName);
  return copy;
}

describe("generateReport golden fixture", function () {
  this.timeout(20000);
  let originalStatuses;

  // Other test files overwrite the shared status constants at load time
  before(function () {
    originalStatuses = Object.fromEntries(
      Object.keys(STATUSES).map((key) => [key, CONSTANTS[key]]),
    );
    Object.assign(CONSTANTS, STATUSES);
  });

  after(function () {
    Object.assign(CONSTANTS, originalStatuses);
  });

  it("produces the same report as the recorded golden file", async function () {
    const report = await generateReport(
      "en",
      JSON.parse(JSON.stringify(tenantConfig)),
      { selectedValidators: [], auth0Domain: "example.auth0.com" },
    );
    expect(normalize(report)).to.deep.equal(golden);
  });
});

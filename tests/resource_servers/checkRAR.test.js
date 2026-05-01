const chai = require("chai");
const expect = chai.expect;

const checkRAR = require("../../analyzer/lib/resource_servers/checkRAR");
const CONSTANTS = require("../../analyzer/lib/constants");

const CIBA_GRANT = "urn:openid:params:grant-type:ciba";

function makeParClient(overrides) {
  return Object.assign(
    {
      client_id: "par_client",
      grant_types: ["authorization_code"],
      require_pushed_authorization_requests: true,
      global: false,
    },
    overrides
  );
}

function makeCibaClient(overrides) {
  return Object.assign(
    {
      client_id: "ciba_client",
      grant_types: [CIBA_GRANT],
      require_pushed_authorization_requests: false,
      global: false,
    },
    overrides
  );
}

function makeRS(overrides) {
  return Object.assign(
    {
      id: "rs1",
      name: "My API",
      identifier: "https://api.example.com",
      is_system: false,
    },
    overrides
  );
}

describe("checkRAR", function () {
  it("PAR+AuthCode client with grant to RS lacking authorization_details → INFO finding", async function () {
    const options = {
      clients: [makeParClient()],
      resourceServers: [makeRS()],
      clientGrants: [{ client_id: "par_client", audience: "https://api.example.com" }],
    };

    const result = await checkRAR(options);
    expect(result.details).to.have.lengthOf(1);
    const report = result.details[0].report;
    expect(report).to.have.lengthOf(1);
    expect(report[0].field).to.equal("authorization_details");
    expect(report[0].status).to.equal(CONSTANTS.FAIL);
    expect(report[0].value).to.equal("not_configured");
  });

  it("CIBA client with grant to RS lacking authorization_details → INFO finding", async function () {
    const options = {
      clients: [makeCibaClient()],
      resourceServers: [makeRS()],
      clientGrants: [{ client_id: "ciba_client", audience: "https://api.example.com" }],
    };

    const result = await checkRAR(options);
    expect(result.details).to.have.lengthOf(1);
    const report = result.details[0].report;
    expect(report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("PAR+AuthCode client with grant to RS that HAS authorization_details → no finding in report", async function () {
    const options = {
      clients: [makeParClient()],
      resourceServers: [
        makeRS({ authorization_details: [{ type: "payment_initiation" }] }),
      ],
      clientGrants: [{ client_id: "par_client", audience: "https://api.example.com" }],
    };

    const result = await checkRAR(options);
    expect(result.details).to.have.lengthOf(1);
    const report = result.details[0].report;
    expect(report).to.have.lengthOf(0);
  });

  it("no PAR or CIBA clients → callback with empty array", async function () {
    const options = {
      clients: [
        {
          client_id: "regular_client",
          grant_types: ["authorization_code"],
          require_pushed_authorization_requests: false,
          global: false,
        },
      ],
      resourceServers: [makeRS()],
      clientGrants: [{ client_id: "regular_client", audience: "https://api.example.com" }],
    };

    const result = await checkRAR(options);
    expect(result.details).to.deep.equal([]);
  });

  it("PAR client without authorization_code grant → not RAR-capable, no findings", async function () {
    const options = {
      clients: [
        makeParClient({ grant_types: ["client_credentials"] }),
      ],
      resourceServers: [makeRS()],
      clientGrants: [{ client_id: "par_client", audience: "https://api.example.com" }],
    };

    const result = await checkRAR(options);
    expect(result.details).to.deep.equal([]);
  });

  it("system RS → always skipped even if used by PAR client", async function () {
    const options = {
      clients: [makeParClient()],
      resourceServers: [
        makeRS({ is_system: true, identifier: "https://tenant.auth0.com/api/v2/" }),
      ],
      clientGrants: [
        { client_id: "par_client", audience: "https://tenant.auth0.com/api/v2/" },
      ],
    };

    const result = await checkRAR(options);
    expect(result.details).to.deep.equal([]);
  });

  it("RS not linked to any PAR/CIBA client via grants → skipped", async function () {
    const options = {
      clients: [makeParClient()],
      resourceServers: [makeRS({ identifier: "https://other.api.com" })],
      clientGrants: [
        { client_id: "par_client", audience: "https://unrelated.api.com" },
      ],
    };

    const result = await checkRAR(options);
    expect(result.details).to.deep.equal([]);
  });

  it("empty authorization_details array treated same as absent → INFO finding", async function () {
    const options = {
      clients: [makeParClient()],
      resourceServers: [makeRS({ authorization_details: [] })],
      clientGrants: [{ client_id: "par_client", audience: "https://api.example.com" }],
    };

    const result = await checkRAR(options);
    expect(result.details).to.have.lengthOf(1);
    const report = result.details[0].report;
    expect(report[0].status).to.equal(CONSTANTS.FAIL);
  });

  it("mixed batch: only RSes without RAR that are linked to PAR/CIBA clients are flagged", async function () {
    const options = {
      clients: [
        makeParClient({ client_id: "par1" }),
        makeCibaClient({ client_id: "ciba1" }),
        {
          client_id: "plain",
          grant_types: ["authorization_code"],
          require_pushed_authorization_requests: false,
          global: false,
        },
      ],
      resourceServers: [
        makeRS({ id: "rs1", name: "Banking API", identifier: "https://bank.api.com" }),
        makeRS({
          id: "rs2",
          name: "Secure API",
          identifier: "https://secure.api.com",
          authorization_details: [{ type: "account_information" }],
        }),
        makeRS({ id: "rs3", name: "Plain API", identifier: "https://plain.api.com" }),
        makeRS({
          id: "rs4",
          name: "Auth0 Management API",
          identifier: "https://tenant.auth0.com/api/v2/",
          is_system: true,
        }),
      ],
      clientGrants: [
        { client_id: "par1", audience: "https://bank.api.com" },
        { client_id: "ciba1", audience: "https://secure.api.com" },
        { client_id: "plain", audience: "https://plain.api.com" },
        { client_id: "par1", audience: "https://tenant.auth0.com/api/v2/" },
      ],
    };

    const result = await checkRAR(options);

    // Banking API: no RAR, linked to par1 → flagged
    const bankingEntry = result.details.find((d) => d.name.includes("Banking API"));
    expect(bankingEntry, "Banking API should be in details").to.exist;
    expect(bankingEntry.report[0].status).to.equal(CONSTANTS.FAIL);

    // Secure API: has RAR, linked to ciba1 → in details but empty report
    const secureEntry = result.details.find((d) => d.name.includes("Secure API"));
    expect(secureEntry, "Secure API should be in details").to.exist;
    expect(secureEntry.report).to.have.lengthOf(0);

    // Plain API: linked to plain (non-RAR client) → not in details at all
    const plainEntry = result.details.find((d) => d.name.includes("Plain API"));
    expect(plainEntry, "Plain API should not appear").to.not.exist;

    // System RS: always skipped
    const systemEntry = result.details.find((d) => d.name.includes("Management API"));
    expect(systemEntry, "System RS should not appear").to.not.exist;
  });
});

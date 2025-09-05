const chai = require("chai");
const expect = chai.expect;

const checkLogStream = require("../../analyzer/lib/log_streams/checkLogStream");
const CONSTANTS = require("../../analyzer/lib/constants");

// Mock the CONSTANTS values
CONSTANTS.SUCCESS = "success";
CONSTANTS.FAIL = "fail";

describe("checkLogStream", function () {
  it("should return fail when logStreams is empty", function () {
    const options = { logStreams: [] };

    checkLogStream(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "log_stream_not_configured",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it("should return success when a log stream is active", function () {
    const options = {
      logStreams: [
        {
          id: "lst_0001",
          name: "Auth0 Logstream",
          type: "http",
          status: "active",
          filters: [],
          isPriority: false,
        },
      ],
    };

    checkLogStream(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "log_stream_active",
          name: "Auth0 Logstream",
          type: "http",
          stream_status: "active",
          status: CONSTANTS.SUCCESS,
        },
      ]);
    });
  });

  it("should return fail when a log stream is inactive", function () {
    const options = {
      logStreams: [
        {
          id: "lst_0001",
          name: "Auth0 Logstream",
          type: "http",
          status: "inactive",
          filters: [],
          isPriority: false,
        },
      ],
    };

    checkLogStream(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "log_stream_inactive",
          name: "Auth0 Logstream",
          type: "http",
          stream_status: "inactive",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });

  it('should return an empty report if errorCode "insufficient_scope" is present', function () {
    const options = {
      logStreams: [
        {
          id: "lst_0001",
          name: "Auth0 Logstream",
          type: "http",
          status: "active",
          errorCode: "insufficient_scope",
          filters: [],
          isPriority: false,
        },
      ],
    };

    checkLogStream(options, (report) => {
      expect(report).to.deep.equal([]); // The report should be empty for insufficient scope
    });
  });

  it("should handle multiple log streams with mixed statuses", function () {
    const options = {
      logStreams: [
        {
          id: "lst_0001",
          name: "Auth0 Logstream",
          type: "http",
          status: "active",
          filters: [],
          isPriority: false,
        },
        {
          id: "lst_0000000000014672",
          name: "Another Logstream",
          type: "http",
          status: "inactive",
          filters: [],
          isPriority: true,
        },
      ],
    };

    checkLogStream(options, (report) => {
      expect(report).to.deep.equal([
        {
          field: "log_stream_active",
          name: "Auth0 Logstream",
          type: "http",
          stream_status: "active",
          status: CONSTANTS.SUCCESS,
        },
        {
          field: "log_stream_inactive",
          name: "Another Logstream",
          type: "http",
          stream_status: "inactive",
          status: CONSTANTS.FAIL,
        },
      ]);
    });
  });
});

/*
[
  {
    "id": "lst_0000000000014671",
    "name": "Okta Logstream",
    "type": "http",
    "status": "active",
    "filters": [
      
    ],
    "isPriority": false
  }
]
*/

const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkLogStream(options) {
  const { logStreams } = options;
  return executeCheck("checkLogStream", (callback) => {
    const report = [];
    const hasInsufficientScope = _.some(logStreams, {
      errorCode: "insufficient_scope",
    });
    if (hasInsufficientScope) {
      return callback(report);
    }
    if (_.isEmpty(logStreams)) {
      report.push({
        field: "log_stream_not_configured",
        status: CONSTANTS.FAIL,
      });
    } else {
      logStreams.forEach((stream) => {
        if (stream.status === "active") {
          report.push({
            field: "log_stream_active",
            name: stream.name,
            type: stream.type,
            stream_status: stream.status,
            status: CONSTANTS.SUCCESS,
          });
        } else {
          report.push({
            field: "log_stream_inactive",
            name: stream.name,
            type: stream.type,
            stream_status: stream.status,
            status: CONSTANTS.FAIL,
          });
        }
      });
    }
    return callback(report);
  });
}

module.exports = checkLogStream;

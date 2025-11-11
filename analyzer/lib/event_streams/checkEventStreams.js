/*

  "eventStreams": [
    {
      "id": "est_jtCx6JaM4zvimx9N7enZ7p",
      "status": "enabled|disabled",
      "name": "Test Event Streams",
      "subscriptions": [
        {
          "event_type": "user.created"
        },
        {
          "event_type": "user.updated"
        },
        {
          "event_type": "user.deleted"
        }
      ],
      "created_at": "2025-05-30T04:08:17.775Z",
      "updated_at": "2025-05-30T04:08:56.303Z",
      "destination": {
        "type": "webhook",
        "configuration": {
          "webhook_endpoint": "https://localhost/webhook",
          "webhook_authorization": {
            "method": "bearer"
          }
        }
      }
    }
  ]
}
*/

const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkEventStreams(options) {
  const { eventStreams } = options;
  return executeCheck("checkEventStreams", (callback) => {
    const report = [];
    const hasInsufficientScope = _.some(eventStreams, {
      errorCode: "insufficient_scope",
    });
    if (hasInsufficientScope) {
      return callback(report);
    }
    if (_.isEmpty(eventStreams)) {
      report.push({
        field: "event_stream_not_configured",
        status: CONSTANTS.FAIL,
      });
    } else {
        eventStreams.forEach((stream) => {
          stream = stream || {};
          if (stream.status !== "enabled") {
            report.push({
              field: "event_stream_disabled",
              name: stream.name || "unknown",
              type: stream.destination?.type || "unknown",
              stream_status: stream.status || "unknown",
              status: CONSTANTS.FAIL,
            });
          }
        });
    }
    return callback(report);
  });
}

module.exports = checkEventStreams;

const chai = require("chai");
const expect = chai.expect;

const checkEventStreams = require("../../analyzer/lib/event_streams/checkEventStreams");
const CONSTANTS = require("../../analyzer/lib/constants");


describe("checkEventStreams", function () {
    it("should return fail when eventStreams is empty", function () {
        const options = { eventStreams: [] };

        checkEventStreams(options, (report) => {
            expect(report).to.deep.equal([
                {
                    field: "event_stream_not_configured",
                    status: CONSTANTS.FAIL,
                },
            ]);
        });
    });

    it("should return empty when a event stream is enabled", function () {
        const options = {
            eventStreams: [
                {
                    id: "lst_0001",
                    name: "Auth0 Eventstream",
                    destination: {
                        type: "webhook",
                    },
                    status: "enabled"
                },
            ],
        };

        checkEventStreams(options, (report) => {
            expect(report).to.deep.equal([]);
        });
    });

    it("should return fail when a event stream is disabled", function () {
        const options = {
            eventStreams: [
                {
                    id: "lst_0001",
                    name: "Auth0 Eventstream",
                    destination: {
                        type: "webhook",
                    },
                    status: "disabled"
                },
            ],
        };

        checkEventStreams(options, (report) => {
            expect(report).to.deep.equal([
                {
                    field: "event_stream_disabled",
                    name: "Auth0 Eventstream",
                    type: "http",
                    stream_status: "disabled",
                    status: CONSTANTS.FAIL,
                },
            ]);
        });
    });

    it('should return an empty report if errorCode "insufficient_scope" is present', function () {
        const options = {
            eventStreams: [
                {
                    id: "lst_0001",
                    name: "Auth0 Eventstream",
                    errorCode: "insufficient_scope"
                },
            ],
        };

        checkEventStreams(options, (report) => {
            expect(report).to.deep.equal([]); // The report should be empty for insufficient scope
        });
    });

    it("should handle multiple log streams with mixed statuses", function () {
        const options = {
            eventStreams: [
                {
                    id: "lst_0001",
                    name: "Auth0 Eventstream",
                    destination: {
                        type: "webhook",
                    },
                    status: "enabled"
                },
                {
                    id: "lst_0000000000014672",
                    name: "Another Eventstream",
                    destination: {
                        type: "aws",
                    },
                    status: "disabled"
                },
            ],
        };

        checkEventStreams(options, (report) => {
            expect(report).to.deep.equal([
                {
                    field: "event_stream_disabled",
                    name: "Another Eventstream",
                    type: "aws",
                    stream_status: "disabled",
                    status: CONSTANTS.FAIL,
                },
            ]);
        });
    });
});

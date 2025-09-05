const chai = require("chai");
const expect = chai.expect;

const checkErrorPageTemplate = require("../../analyzer/lib/error_page_template/checkErrorPageTemplate");
const CONSTANTS = require("../../analyzer/lib/constants");

describe("checkErrorPageTemplate", function () {
  it("should return success when no error page template is provided", function (done) {
    const options = {};

    checkErrorPageTemplate(options).then((result) => {
      expect(result.details).to.deep.include({
        field: "liquidjs_no_templates_to_analyze",
        status: CONSTANTS.SUCCESS,
        value: "No custom error page templates found to analyze for XSS"
      });
      done();
    }).catch(done);
  });

  it("should return success when error page template is empty", function (done) {
    const options = {
      errorPageTemplate: ""
    };

    checkErrorPageTemplate(options).then((result) => {
      expect(result.details).to.deep.include({
        field: "liquidjs_no_templates_to_analyze",
        status: CONSTANTS.SUCCESS,
        value: "No custom error page templates found to analyze for XSS"
      });
      done();
    }).catch(done);
  });

  it("should detect unescaped variable output", function (done) {
    const options = {
      errorPageTemplate: `
        <html>
          <body>
            <h1>Error</h1>
            <p>Hello {{ user.name }}</p>
            <p>Error details: {{ error.description }}</p>
          </body>
        </html>
      `
    };

    checkErrorPageTemplate(options).then((result) => {
      const unescapedIssue = result.details.find(d => d.field === "liquidjs_unescaped_output");
      expect(unescapedIssue).to.exist;
      expect(unescapedIssue.status).to.equal(CONSTANTS.FAIL);
      expect(unescapedIssue.value).to.be.a("string");
      done();
    }).catch(done);
  });

  it("should not flag properly escaped variables as issues", function (done) {
    const options = {
      errorPageTemplate: `
        <html>
          <body>
            <h1>Error</h1>
            <p>Hello {{ user.name | escape }}</p>
            <p>Error: {{ error.description | h }}</p>
          </body>
        </html>
      `
    };

    checkErrorPageTemplate(options).then((result) => {
      // Should not detect unescaped output since variables are properly escaped
      const unescapedIssue = result.details.find(d => 
        d.field === "liquidjs_unescaped_output" && d.status === CONSTANTS.FAIL
      );
      expect(unescapedIssue).to.not.exist;
      
      // Should have a success entry for unescaped output
      const successIssue = result.details.find(d => 
        d.field === "liquidjs_unescaped_output" && d.status === CONSTANTS.SUCCESS
      );
      expect(successIssue).to.exist;
      done();
    }).catch(done);
  });

  it("should detect raw filter usage", function (done) {
    const options = {
      errorPageTemplate: `
        <html>
          <body>
            <h1>Error</h1>
            <div>{{ error.html_content | raw }}</div>
          </body>
        </html>
      `
    };

    checkErrorPageTemplate(options).then((result) => {
      const rawFilterIssue = result.details.find(d => d.field === "liquidjs_raw_filter_usage");
      expect(rawFilterIssue).to.exist;
      expect(rawFilterIssue.status).to.equal(CONSTANTS.FAIL);
      expect(rawFilterIssue.value).to.be.a("string");
      done();
    }).catch(done);
  });

  it("should detect unsafe filter usage", function (done) {
    const options = {
      errorPageTemplate: `
        <html>
          <body>
            <p>{{ user.bio | safe }}</p>
            <p>{{ content | unescaped }}</p>
          </body>
        </html>
      `
    };

    checkErrorPageTemplate(options).then((result) => {
      const rawFilterIssue = result.details.find(d => d.field === "liquidjs_raw_filter_usage");
      expect(rawFilterIssue).to.exist;
      expect(rawFilterIssue.status).to.equal(CONSTANTS.FAIL);
      done();
    }).catch(done);
  });

  it("should handle templates with no liquid variables", function (done) {
    const options = {
      errorPageTemplate: `
        <html>
          <body>
            <h1>Error Page</h1>
            <p>Something went wrong. Please try again later.</p>
          </body>
        </html>
      `
    };

    checkErrorPageTemplate(options).then((result) => {
      // Should not find any unescaped output issues
      const unescapedIssue = result.details.find(d => 
        d.field === "liquidjs_unescaped_output" && d.status === CONSTANTS.FAIL
      );
      expect(unescapedIssue).to.not.exist;

      // Should not find any raw filter issues
      const rawIssue = result.details.find(d => 
        d.field === "liquidjs_raw_filter_usage" && d.status === CONSTANTS.FAIL
      );
      expect(rawIssue).to.not.exist;

      // Should have success entries
      const successUnescaped = result.details.find(d => 
        d.field === "liquidjs_unescaped_output" && d.status === CONSTANTS.SUCCESS
      );
      expect(successUnescaped).to.exist;

      const successRaw = result.details.find(d => 
        d.field === "liquidjs_raw_filter_usage" && d.status === CONSTANTS.SUCCESS
      );
      expect(successRaw).to.exist;
      done();
    }).catch(done);
  });

  it("should handle complex templates with mixed safe and unsafe patterns", function (done) {
    const options = {
      errorPageTemplate: `
        <html>
          <head>
            <title>Error - {{ error.code | escape }}</title>
          </head>
          <body>
            <h1>{{ error.title }}</h1>
            <p>Hello {{ user.name | escape }}, an error occurred.</p>
            <div>{{ error.html_details | raw }}</div>
            <p>Error ID: {{ error.id }}</p>
          </body>
        </html>
      `
    };

    checkErrorPageTemplate(options).then((result) => {
      // Should detect unescaped variables (error.title and error.id)
      const unescapedIssue = result.details.find(d => 
        d.field === "liquidjs_unescaped_output" && d.status === CONSTANTS.FAIL
      );
      expect(unescapedIssue).to.exist;

      // Should detect raw filter usage
      const rawIssue = result.details.find(d => 
        d.field === "liquidjs_raw_filter_usage" && d.status === CONSTANTS.FAIL
      );
      expect(rawIssue).to.exist;
      done();
    }).catch(done);
  });

  it("should handle templates with various safe filters", function (done) {
    const options = {
      errorPageTemplate: `
        <html>
          <body>
            <p>{{ user.name | escape }}</p>
            <p>{{ user.email | h }}</p>
            <p>{{ user.bio | html_escape }}</p>
            <p>{{ user.url | url_encode }}</p>
            <p>{{ user.data | escape_once }}</p>
          </body>
        </html>
      `
    };

    checkErrorPageTemplate(options).then((result) => {
      // Should not detect unescaped output issues since all variables use safe filters
      const unescapedIssue = result.details.find(d => 
        d.field === "liquidjs_unescaped_output" && d.status === CONSTANTS.FAIL
      );
      expect(unescapedIssue).to.not.exist;

      // Should have a success entry for unescaped output
      const successIssue = result.details.find(d => 
        d.field === "liquidjs_unescaped_output" && d.status === CONSTANTS.SUCCESS
      );
      expect(successIssue).to.exist;
      done();
    }).catch(done);
  });

  it("should detect variables with unsafe filter combinations", function (done) {
    const options = {
      errorPageTemplate: `
        <html>
          <body>
            <p>{{ user.name | downcase }}</p>
            <p>{{ user.bio | truncate: 100 }}</p>
            <p>{{ user.title | upcase | strip }}</p>
          </body>
        </html>
      `
    };

    checkErrorPageTemplate(options).then((result) => {
      // Should detect unescaped output since these filters don't provide XSS protection
      const unescapedIssue = result.details.find(d => 
        d.field === "liquidjs_unescaped_output" && d.status === CONSTANTS.FAIL
      );
      expect(unescapedIssue).to.exist;
      expect(unescapedIssue.status).to.equal(CONSTANTS.FAIL);
      done();
    }).catch(done);
  });

  it("should handle edge cases with whitespace and formatting", function (done) {
    const options = {
      errorPageTemplate: `
        <html>
          <body>
            <p>{{user.name}}</p>
            <p>{{ user.email }}</p>
            <p>{{  user.bio  }}</p>
            <p>{{ user.data|escape }}</p>
            <p>{{ user.info | escape }}</p>
          </body>
        </html>
      `
    };

    checkErrorPageTemplate(options).then((result) => {
      // Should detect unescaped variables regardless of whitespace
      const unescapedIssue = result.details.find(d => 
        d.field === "liquidjs_unescaped_output" && d.status === CONSTANTS.FAIL
      );
      expect(unescapedIssue).to.exist;
      done();
    }).catch(done);
  });

  it("should handle malformed liquid syntax gracefully", function (done) {
    const options = {
      errorPageTemplate: `
        <html>
          <body>
            <p>{{ user.name</p>
            <p>user.email }}</p>
            <p>{{ user.bio | }}</p>
            <p>{{ | escape }}</p>
          </body>
        </html>
      `
    };

    checkErrorPageTemplate(options).then((result) => {
      // Should not crash and should handle malformed syntax gracefully
      expect(result).to.exist;
      expect(result.details).to.be.an("array");
      done();
    }).catch(done);
  });

  it("should return proper structure with checkName and timestamp", function (done) {
    const options = {
      errorPageTemplate: "<p>{{ user.name }}</p>"
    };

    checkErrorPageTemplate(options).then((result) => {
      expect(result).to.have.property("checkName", "checkErrorPageTemplate");
      expect(result).to.have.property("timestamp");
      expect(result).to.have.property("details");
      expect(result.details).to.be.an("array");
      done();
    }).catch(done);
  });
});

/*
[
  {
    name: 'Verification Email (Link)',
    template: {
      template: 'verify_email',
      syntax: 'liquid',
      body: ''
      from: '',
      subject: '',
      urlLifetimeInSeconds: 432000,
      enabled: true
    }
  },
  { name: 'Verification Email (Code)', template: null },
  { name: 'Welcome Email', template: null },
  { name: 'Enroll in Multifactor Authentication', template: null },
  { name: 'Change Password (Link)', template: null },
  { name: 'Change Password (Code)', template: null },
  { name: 'Blocked Account Email', template: null },
  { name: 'Password Breach Alert', template: null },
  { name: 'Verification Code for Email MFA', template: null },
  { name: 'User Invitation', template: null }
]
*/
const _ = require("lodash");
const executeCheck = require("../executeCheck");
const CONSTANTS = require("../constants");

function checkEmailTemplates(options) {
  const { emailTemplates } = options || [];
  return executeCheck("checkEmailTemplates", (callback) => {
    const report = [];
    if (_.isEmpty(emailTemplates)) {
      report.push({
        field: "email_templates_not_configured",
        status: CONSTANTS.FAIL,
      });
      return callback(report);
    }
    emailTemplates.forEach((t) => {
      if (_.isEmpty(t.template)) {
        report.push({
          field: "email_template_not_configured",
          status: CONSTANTS.FAIL,
          attr: t.name,
          value: t.name,
        });
        return;
      }
      if (t.template.enabled) {
        report.push({
          field: "email_template_enabled",
          status: CONSTANTS.SUCCESS,
          attr: t.template.template,
          value: t.template.template,
        });
      } else {
        report.push({
          field: "email_template_not_enabled",
          status: CONSTANTS.FAIL,
          attr: t.name,
          value: t.name,
        });
      }
    });
    return callback(report);
  });
}

module.exports = checkEmailTemplates;

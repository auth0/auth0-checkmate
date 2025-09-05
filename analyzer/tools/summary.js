const _ = require("lodash");
module.exports.getSummaryReport = async (data) => {
  const filteredData = _.map(data, (item) => {
    const filteredDetails = _.flatMap(item.details, (detail) => {
      if (_.isArray(detail.report)) {
        // Process if the detail has a 'report' array
        return _.filter(detail.report, (report) =>
          ["red", "yellow"].includes(report.status),
        ).map((report) =>
          _.pick(report, [
            "name",
            "status",
            "field",
            "value",
            "message",
            "vulnFindings",
            "pre_requisites",
          ]),
        );
      }
      // Process other fields if no 'report' array exists
      return _.filter([detail], (detailItem) =>
        ["red", "yellow"].includes(detailItem.status),
      ).map((detailItem) =>
        _.pick(detailItem, [
          "name",
          "title",
          "description",
          "docsPath",
          "field",
          "value",
          "status",
          "message",
          "vulnFindings",
          "pre_requisites",
        ]),
      );
    });
    // Only return items with 'red' or 'yellow' status after filtering
    const detailsLength = _.uniqBy(filteredDetails, "name").length;
    return {
      name: item.name,
      title: item.title,
      description: item.description,
      status: item.status,
      disclaimer: item.disclaimer || null,
      advisory: item.advisory || null,
      pre_requisites: item.pre_requisites || null,
      vulnFindings: item.vulnFindings || null,
      severity: item.severity,
      severity_message: item.severity_message,
      docsPath: item.docsPath,
      details: filteredDetails,
      detailsLength: detailsLength > 0 ? detailsLength : filteredDetails.length,
    };
  }).filter((item) => item.details.length > 0); // Ensure that at least one detail exists

  const transformedFindings = filteredData.map((finding) => ({
    name: finding.name,
    title: finding.title, // Set title from name
    description: finding.description, // Set description
    status: finding.status, // Set status
    disclaimer: finding.disclaimer || null,
    advisory: finding.advisory || null,
    vulnFindings: finding.vulnFindings || [],
    pre_requisites: finding.pre_requisites || null,
    severity: finding.severity,
    severity_message: finding.severity_message.replace(
      "%s",
      finding.details.length,
    ),
    docsPath: finding.docsPath,
    details: finding.details,
    detailsLength: finding.detailsLength, // Get the length of the details array
  }));
  const severityOrder = ["red", "yellow", "green", "blue", "violet"];

  // Sort the array using the custom order
  const sortedFindings = _.sortBy(transformedFindings, (item) =>
    severityOrder.indexOf(item.status),
  );
  //console.log(JSON.stringify(sortedFindings, null, 2))
  return sortedFindings;
};

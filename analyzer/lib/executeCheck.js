module.exports = function (name, checkFx) {
  const result = {
    checkName: name,
    result: null,
    details: [],
    timestamp: Date.now(),
  };
  return checkFx(function callback(details) {
    result.details = details;
    return Promise.resolve(result);
  });
};

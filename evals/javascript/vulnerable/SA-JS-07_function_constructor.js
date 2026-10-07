// SA-JS-07: Function constructor with user input
const userCode = getQueryParam('transform');
const fn = new Function('data', userCode);
const result = fn(inputData);

// SA-JS-07: Safe alternative using a predefined transform map
const transforms = {
  uppercase: (data) => data.toUpperCase(),
  lowercase: (data) => data.toLowerCase(),
  trim: (data) => data.trim(),
};
const transformName = getQueryParam('transform');
if (transforms[transformName]) {
  const result = transforms[transformName](inputData);
}

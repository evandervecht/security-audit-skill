// SA-JS-06: Prototype pollution via __proto__
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
const payload = JSON.parse('{"__proto__": {"isAdmin": true}}');
deepMerge({}, payload);

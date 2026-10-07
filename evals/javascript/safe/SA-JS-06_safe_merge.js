// SA-JS-06: Safe deep merge that filters dangerous keys
function safeDeepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === 'constructor' || key === 'prototype') {
      continue; // Skip dangerous prototype keys
    }
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = Object.create(null);
      safeDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

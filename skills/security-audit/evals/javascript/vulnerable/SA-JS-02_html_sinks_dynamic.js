// SA-JS-02: dynamic, user-controlled HTML written to DOM sinks
const name = new URLSearchParams(location.search).get('name');
el.innerHTML = `Hello, ${name}`;
target.insertAdjacentHTML('beforeend', userInput);
node.outerHTML = buildMarkup(data);

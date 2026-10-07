// SA-JS-02: Safe alternative using textContent (no HTML parsing)
const name = new URLSearchParams(location.search).get('name');
document.getElementById('greeting').textContent = 'Hello, ' + name;

// SA-JS-02: innerHTML with user-controlled input
const name = new URLSearchParams(location.search).get('name');
document.getElementById('greeting').innerHTML = 'Hello, ' + name;

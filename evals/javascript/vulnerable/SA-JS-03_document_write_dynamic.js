// SA-JS-03: DOM XSS via document.write / writeln with dynamic content
const q = new URLSearchParams(location.search).get('q');
document.write('<p>' + q + '</p>');
document.writeln(`Results for ${q}`);

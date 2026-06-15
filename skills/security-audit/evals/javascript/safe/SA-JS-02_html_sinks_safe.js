// SA-JS-02: safe HTML sinks - static literals, DOMPurify, textContent
el.innerHTML = '<b>Welcome to the site</b>';
panel.innerHTML = "<div class='card'></div>";
clean.innerHTML = DOMPurify.sanitize(userInput);
wrap.outerHTML = DOMPurify.sanitize(markup);
greeting.textContent = 'Hello, ' + name;
box.insertAdjacentHTML('beforeend', DOMPurify.sanitize(frag));

# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) / Day 6 - Cross-site Scripting in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## Disabling auto-escaping in template engines is security-sensitive

To reduce the risk of cross-site scripting attacks, templating systems, such as Twig, Django, Smarty, Groovy's template engine, allow configuration of automatic variable escaping before rendering templates. When escape occurs, characters that make sense to the browser (eg: <a>) will be transformed/replaced with escaped/sanitized values (eg: & lt;a& gt; ).

Auto-escaping is not a magic feature to annihilate all cross-site scripting attacks, it depends on the [strategy applied](https://twig.symfony.com/doc/3.x/filters/escape.html) and the context, for example a "html auto-escaping" strategy (which only transforms html characters into [html entities](https://developer.mozilla.org/en-US/docs/Glossary/Entity)) will not be relevant when variables are used in a [html attribute](https://en.wikipedia.org/wiki/HTML_attribute) because ':' character is not escaped and thus an attack as below is possible:

```
<a href="{{ myLink }}">link</a> // myLink = javascript:alert(document.cookie)
<a href="javascript:alert(document.cookie)">link</a> // JS injection (XSS attack)
```

**Ask Yourself Whether**

* Templates are used to render web content and
  * dynamic variables in templates come from untrusted locations or are user-controlled inputs
  * there is no local mechanism in place to sanitize or validate the inputs.
There is a risk if you answered yes to any of those questions.

**Recommended Secure Coding Practices**

Enable auto-escaping by default and continue to review the use of inputs in order to be sure that the chosen auto-escaping strategy is the right one.

**Sensitive Code Example**

[mustache.js](https://www.npmjs.com/package/mustache) template engine:
```
let Mustache = require("mustache");

Mustache.escape = function(text) {return text;}; // Sensitive

let rendered = Mustache.render(template, { name: inputName });
```

[handlebars.js](https://www.npmjs.com/package/handlebars) template engine:
```
const Handlebars = require('handlebars');

let source = "<p>attack {{name}}</p>";

let template = Handlebars.compile(source, { noEscape: true }); // Sensitive
```

[markdown-it](https://www.npmjs.com/package/markdown-it) markup language parser:
```
const markdownIt = require('markdown-it');
let md = markdownIt({
  html: true // Sensitive
});

let result = md.render('# <b>attack</b>');
```

[marked](https://www.npmjs.com/package/marked) markup language parser:
```
const marked = require('marked');

marked.setOptions({
  renderer: new marked.Renderer(),
  sanitize: false // Sensitive
});

console.log(marked("# test <b>attack/b>"));
```

[kramed](https://www.npmjs.com/package/kramed) markup language parser:
```
let kramed = require('kramed');

var options = {
  renderer: new kramed.Renderer({
    sanitize: false // Sensitive
  })
};
```

**Compliant Solution**

[mustache.js](https://www.npmjs.com/package/mustache) template engine:
```
let Mustache = require("mustache");

let rendered = Mustache.render(template, { name: inputName }); // Compliant autoescaping is on by default
```

[handlebars.js](https://www.npmjs.com/package/handlebars) template engine:
```
const Handlebars = require('handlebars');

let source = "<p>attack {{name}}</p>";
let data = { "name": "<b>Alan</b>" };

let template = Handlebars.compile(source); // Compliant by default noEscape is set to false
```

[markdown-it](https://www.npmjs.com/package/markdown-it) markup language parser:
```
let md = require('markdown-it')(); // Compliant by default html is set to false

let result = md.render('# <b>attack</b>');
```
[marked](https://www.npmjs.com/package/marked) markup language parser:

```
const marked = require('marked');

marked.setOptions({
  renderer: new marked.Renderer()
}); // Compliant by default sanitize is set to true

console.log(marked("# test <b>attack/b>"));
```
  
[kramed](https://www.npmjs.com/package/kramed) markup language parser:
  
```
let kramed = require('kramed');

let options = {
  renderer: new kramed.Renderer({
    sanitize: true // Compliant
  })
};

console.log(kramed('Attack [xss?](javascript:alert("xss")).', options));
```

**See**

* [OWASP Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md) - XSS Prevention Cheat Sheet
* [OWASP Top 10 2017 Category A7](https://www.owasp.org/index.php/Top_10-2017_A7-Cross-Site_Scripting_(XSS)) - Cross-Site Scripting (XSS)
* [MITRE, CWE-79](https://cwe.mitre.org/data/definitions/79.html) - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
* [MITRE, CWE-80](https://cwe.mitre.org/data/definitions/80.html) - Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
* [MITRE, CWE-83](https://cwe.mitre.org/data/definitions/83.html) - Improper Neutralization of Script in Attributes in a Web Page
* [MITRE, CWE-84](https://cwe.mitre.org/data/definitions/84.html) - Improper Neutralization of Encoded URI Schemes in a Web Page

**แหล่งที่มา**

[<img src="/images/SonarSourceRules.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-5247)

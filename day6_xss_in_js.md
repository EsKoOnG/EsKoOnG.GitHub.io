# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) / Day 6 - Cross-site Scripting in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## Disabling auto-escaping in template engines is security-sensitive

เพื่อลดความเสี่ยงจากการโจมตีด้วยเทคนิค cross-site scripting ในพวกระบบที่ใช่ Template เช่น Twig Django Smarty Groovy จะเปิดการใช้งาน variable escapin ก่อนที่ทำการ render template ขึ้นมา เมื่อฟังก์ชั่น escape ทำงาน ผลที่เกิดขึ้นคืออักขระที่ประมวลผลด้วย browser เช่น <a> จะถูกแปลงค่า หรือ แทนที่ ด้วยค่า escaped/sanitized เช่น & lt;a& gt;

Auto-escaping ไม่ใช่คุณสมบัติพิเศษที่จะสามารถทำลาย cross-site scripting ได้ทั้งหมด มันขึ้นอยู่กับวิธีการที่ใช้ [(strategy applied)](https://twig.symfony.com/doc/3.x/filters/escape.html) และบริบทของมัน, ตัวอย่างวิธีการ เช่น "html auto-escaping" (ที่จะเปลี่ยนตัวอักขระของ html ให้เป็น [html entities](https://developer.mozilla.org/en-US/docs/Glossary/Entity)) ที่จะไม่เป็นผลเมื่อตัวแปรถูกใช้ใน [html attribute](https://en.wikipedia.org/wiki/HTML_attribute) เพราะตัวอักขระ ':' จะไม่ถูก escaped ดังนั้นการโจมตีดังต่อไปนี้อาจจะเกิดขึ้นได้

```
<a href="{{ myLink }}">link</a> // myLink = javascript:alert(document.cookie)
<a href="javascript:alert(document.cookie)">link</a> // JS injection (XSS attack)
```

**ลองถามตัวเองดู**

* Templates ถูกใช้เพื่อสร้างเว็บและแสดงผล
  * ตัวแปรที่ไม่คงที่ใน templates มาจากแหล่งที่ไม่น่าเชื่อถือหรือผู้ใช้งานเป็นผู้กำหนดค่า inputs
  * ระบบที่ไม่มีกลไกในการที่จะ sanitize หรือ validate ข้อมูลที่ input เข้ามา
  
มันเป็นความเสี่ยงหากคุณตอบใช่จากคำถามเหล่านี้

**คำแนะนำในการเขียน Code ให้ปลอดภัย**

เปิดใช้งาน auto-escaping โดยค่าเริ่มต้นและหมั่นตรวจสอบการใช้งาน input อยู่เสมอเพื่อให้แน่ใจว่าการเลือกใช้ auto-escaping แต่ละฟังก์ชั่นที่เหมาะสม

**ตัวอย่างที่ไม่ปลอดภัย**

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

**แนวทางแก้ไขที่ถูกต้อง**

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

**เพิ่มเติม**

* [OWASP Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md) - XSS Prevention Cheat Sheet
* [OWASP Top 10 2017 Category A7](https://www.owasp.org/index.php/Top_10-2017_A7-Cross-Site_Scripting_(XSS)) - Cross-Site Scripting (XSS)
* [MITRE, CWE-79](https://cwe.mitre.org/data/definitions/79.html) - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
* [MITRE, CWE-80](https://cwe.mitre.org/data/definitions/80.html) - Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
* [MITRE, CWE-83](https://cwe.mitre.org/data/definitions/83.html) - Improper Neutralization of Script in Attributes in a Web Page
* [MITRE, CWE-84](https://cwe.mitre.org/data/definitions/84.html) - Improper Neutralization of Encoded URI Schemes in a Web Page

**แหล่งที่มา**

[<img src="/images/SonarSourceRules.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-5247)

# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) / Day 7 - Security Misconfiguration in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## Disabling CSRF protections is security-sensitive

Cross-site request forgery (CSRF) vulnerabilities occur when attackers can trick a user to perform sensitive authenticated operations on a web application without his consent.

Imagine a web application where an authenticated user can do actions like changing his email address and which has no CSRF protection. A malicious website could forge a web page form to send the HTTP request that change the user email. When the user visits the malicious web page, the form is automatically submitted in his name and his account email is changed to an arbitrary email.

Such an attack is only possible if the web browser automatically sends authentication information to the trusted domain (e.g cookie based authentication)

**Ask Yourself Whether**

* The web application uses cookies to authenticate users.
* There exist sensitive operations in the web application that can be performed when the user is authenticated.
* The state / resources of the web application can be modified by doing HTTP POST or HTTP DELETE requests for example.

There is a risk if you answered yes to any of those questions.

**Recommended Secure Coding Practices**

* Protection against CSRF attacks is strongly recommended:
  * to be activated by default for all [unsafe HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Safe_methods) methods.
  * implemented, for example, with an unguessable CSRF token
* Of course all sensitive operations should not be performed with [safe HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Safe_methods) methods like GET which are designed to be used only for information retrieval.

**Sensitive Code Example**

[Express.js CSURF middleware](https://www.npmjs.com/package/csurf) protection is not found on an unsafe HTTP method like POST method:

```
let csrf = require('csurf');
let express = require('express');

let csrfProtection = csrf({ cookie: true });

let app = express();

// Sensitive: this operation doesn't look like protected by CSURF middleware (csrfProtection is not used)
app.post('/money_transfer', parseForm, function (req, res) {
  res.send('Money transferred');
});
```

Protection provided by [Express.js CSURF middleware](https://www.npmjs.com/package/csurf) is globally disabled on unsafe methods:

```
let csrf = require('csurf');
let express = require('express');

app.use(csrf({ cookie: true, ignoreMethods: ["POST", "GET"] })); // Sensitive as POST is unsafe method
```

**Compliant Solution**

[Express.js CSURF middleware](https://www.npmjs.com/package/csurf) protection is used on unsafe methods:

```
let csrf = require('csurf');
let express = require('express');

let csrfProtection = csrf({ cookie:  true });

let app = express();

app.post('/money_transfer', parseForm, csrfProtection, function (req, res) { // Compliant
  res.send('Money transferred')
});
```

Protection provided by [Express.js CSURF middleware](https://www.npmjs.com/package/csurf) is enabled on unsafe methods:

```
let csrf = require('csurf');
let express = require('express');

app.use(csrf({ cookie: true, ignoreMethods: ["GET"] })); // Compliant
```

**See**

* [MITRE, CWE-352](https://cwe.mitre.org/data/definitions/352.html) - Cross-Site Request Forgery (CSRF)
* [OWASP Top 10 2017 Category A6](https://www.owasp.org/index.php/Top_10-2017_A6-Security_Misconfiguration) - Security Misconfiguration
* [OWASP: Cross-Site Request Forgery](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29)
* [SANS Top 25](https://www.sans.org/top25-software-errors/#cat1) - Insecure Interaction Between Components

**แหล่งที่มา**

[<img src="/images/SonarSourceRules.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-4502)

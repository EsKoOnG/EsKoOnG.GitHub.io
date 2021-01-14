# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) / Day 7 - Security Misconfiguration in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## Disabling CSRF protections is security-sensitive

ช่องโหว่ Cross-site request forgery (CSRF) จะเกิดขึ้นเมื่อผู้โจมตีสามารถหลอกผู้ใช้งานให้ทำการยืนยันตัวตนบนเว็บแอปพลิเคชั่นโดยเขาไม่ได้ยินยอม.

ลองนึกภาพว่าเว็บแอปพลิเคชั่นที่เมื่อมีการยืนยันตัวตนแล้ว ผู้ใช้งานสามารถทำกิจกรรมบางอย่างได้ เช่น เปลี่ยนแปลงอีเมล์ และเมื่อไม่มีการป้องกัน CSRF เว็บที่ไม่ประสงค์ดีอาจจะปลอมแปลงเว็บฟอร์มเพื่อร้องขอให้ผู้ใช้งานเปลี่ยนแปลงอีเมล์ของพวกเขา และเมื่อผู้ใช้งานเข้าใช้งานเว็บไซต์ที่ปลอมแปลงขึ้นมา ตัวฟอร์มจะเก็บข้อมูลชื่อและอีเมล์โดยอัตโนมัติและจะโดนเปลี่ยนไปโดยพลการ

อย่างการโจมตีอย่างเดียวที่เกิดขึ้นได้ถ้าเว็บเบราเซอร์ส่งข้อมูลยืนยันตัวตนโดยอัตโนมัติไปยังโดนเมนที่น่าเชื่อถือ เช่น cookie based authentication

**ลองถามตัวเองดู**

* เว็บแอปพลิเคชั่นใช้คุกกี้ในการยืนยันตัวตนผู้ใช้งาน
* มีขั้นตอนที่ละเอียดอ่อนในเว็บแอปพลิเคชั่นที่เกิดขึ้นเมื่อผู้ใช้งานดำเนินการยืนยันตัวตน
* สถานะหรือทรัพยากรของเว็บแอปพลิเคชั่นสามารถแก้ไขได้ด้วยเช่น คำขอ HTTP POST หรือ HTTP DELETE เป็นต้น

มันเป็นความเสี่ยงหากคุณตอบว่า "ใช่" จากคำถามข้างต้น

**คำแนะนำในการเขียน Code ให้ปลอดภัย**

* การป้องกันการโจมตี CSRF ที่แนะนำเป็นอย่างยิ่ง:
  * เปิดใช้งานการป้องกันเป็นค่าเริ่มต้นพวก Method ที่ไม่ปลอดภัย [unsafe HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Safe_methods)
  * มีการใช้งานการป้องกัน เช่น การใช้งาน CSRF token ที่ไม่สามารถคาดเดาได้
* แน่นอนว่ากระบวนการที่ละเอียดอ่อนไม่ควรใช้ method โดย [safe HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Safe_methods) เช่น GET ถูกออกแบบมาเพื่อรับข้อมูลเท่านั้น

**ตัวอย่างที่ไม่ปลอดภัย**

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

**แนวทางแก้ไขที่ถูกต้อง**

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

**เพิ่มเติม**

* [MITRE, CWE-352](https://cwe.mitre.org/data/definitions/352.html) - Cross-Site Request Forgery (CSRF)
* [OWASP Top 10 2017 Category A6](https://www.owasp.org/index.php/Top_10-2017_A6-Security_Misconfiguration) - Security Misconfiguration
* [OWASP: Cross-Site Request Forgery](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29)
* [SANS Top 25](https://www.sans.org/top25-software-errors/#cat1) - Insecure Interaction Between Components

**แหล่งที่มา**

[<img src="/images/SonarSourceRules.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-4502)

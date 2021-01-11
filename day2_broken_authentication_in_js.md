# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) / Day 2 - Broken Authentication in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## Hard-coded credentials are security-sensitive.

เพราะมันง่ายมากที่จะถูกแกะค่าใน Source Code จาก Application หรือ Binary และ Credentials ไม่ควรใส่ไว้ใน Code ตรง ๆ โดยเฉพาะอย่างยิ่งสำหรับแอปพลิเคชั่นที่ถูกแจกจ่ายหรือแบบ Opensource

ในอดีตมันมีช่องโหว่ที่ผ่านมาดังนี้:

* [CVE-2019-13466](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13466)
* [CVE-2018-15389](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15389)

Credential ควรถูกจัดเก็บไว้ในไฟล์การตั้งค่า ฐานข้อมูล หรือการจัดการบริการสำหรับความลับโดยเฉพาะ

**ลองถามตัวเองดู**

* มี Credentials ที่อนุญาตให้เข้าถึงส่วนประกอบที่สำคัญ เช่น ฐานข้อมูล พื้นที่จัดเก็บไฟล์ และ API หรือ บริการต่าง ๆ อยู่ใน Source Code
* มี Credentials ที่ถูกใช้ในระบบที่กำลังให้บริการจริง อยู่ใน Source Code
* แอปพลิเคชั่นถูกแจกจ่ายออกไปไม่ได้อัพเดท Credentials 

นั่นคือความเสี่ยงหากคุณตอบใช่ในคำถามใดคำถามนึง

**คำแนะนำในการเขียน Code ให้ปลอดภัย**

* จัดเก็บ credentials ในไฟล์การตั้งค่าไม่ใส่รวมกับที่จัดเก็บ Source Code
* จัดเก็บ credentials ในฐานข้อมูล
* ใช้งานระบบบริหารจัดการความลับของผู้ให้บริการคลาวด์ของคุณ
* ถ้ารหัสผ่านถูกเปิดเผยผ่าน Source Code ที่ถูกแจกจ่ายออกไป ให้เปลี่ยนทันที

**ตัวอย่างที่ไม่ปลอดภัย**
```
var mysql = require('mysql');

var connection = mysql.createConnection(
{
  host:'localhost',
  user: "admin",
  database: "project",
  password: "mypassword", // sensitive
  multipleStatements: true
});

connection.connect();
```

**แนวทางแก้ไขที่ถูกต้อง**

```
var mysql = require('mysql');

var connection = mysql.createConnection({
  host: process.env.MYSQL_URL,
  user: process.env.MYSQL_USERNAME,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE
});
connection.connect();
```

**เพิ่มเติม**
* [OWASP Top 10 2017 Category A2](https://www.owasp.org/index.php/Top_10-2017_A2-Broken_Authentication) - Broken Authentication
* [MITRE, CWE-798](http://cwe.mitre.org/data/definitions/798) - Use of Hard-coded Credentials
* [MITRE, CWE-259](http://cwe.mitre.org/data/definitions/259) - Use of Hard-coded Password
* [CERT, MSC03-J.](https://wiki.sei.cmu.edu/confluence/x/OjdGBQ) - Never hard code sensitive information
* [SANS Top 25](https://www.sans.org/top25-software-errors/#cat3) - Porous Defenses
* Derived from FindSecBugs rule [Hard Coded Password](http://h3xstream.github.io/find-sec-bugs/bugs.htm#HARD_CODE_PASSWORD)

**แหล่งที่มา**

[<img src="/images/sonarqube.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-2068)

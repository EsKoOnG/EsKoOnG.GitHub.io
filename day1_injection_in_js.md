
# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) 
# Day 1 - Injection in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## Formatting SQL queries is security-sensitive

การจัดรูปแบบข้อความในการใช้งานคำสั่ง SQL queries มีผลกระทบด้านความปลอดภัยและมันเคยก่อให้เกิดช่องโหว่ในอดีตดังต่อไปนี้

* [CVE-2018-9019](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9019)

* [CVE-2018-7318](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7318)

* [CVE-2017-5611](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5611)

SQL queries บ่อยครั้งที่ถูกใช้โดยการเขียนคำสั่ง SQL string ลงไปใน Code ตรงๆ พร้อมกับตัวแปรที่รอรับคำร้องขอจากผู้ใช้งานซึ่งการใช้งานในลักษณะนี้เป็นวิธีการที่ไม่ดีและส่งผลให้ผู้ไม่หวังดีสามารถโจมตีด้วยเทคนิค SQL Injection ได้ และวิธีที่ปลอดภัยในการสืบค้นข้อมูล SQL ให้ใช้การผูกเป็นคำสั่งทดแทนการรับค่าโดยตรง

**ลองถามตัวเองดู**

* คำสั่ง SQL query ถูกสร้างโดยการใช้การจัดรูปแบบของ string เช่น การใช้ตัวแปรมาต่อภายในคำสั่งโดยตรง
* การรับค่าบางค่ามาจากแหล่งที่ไม่น่าเชื่อถือได้และไม่มีการตรวจสอบหรือทำให้ถูกต้องก่อนการประมวลผล

มันเป็นความเสี่ยงหากคุณตอบว่า "ใช่" จาก 2 คำถามข้างต้น

**คำแนะนำในการเขียน Code ให้ปลอดภัย**

* หลีกเลี่ยงการสร้างคำสั่งแบบกำหนดเองโดยใช้เทคนิคการจัดรูปแบบ ถ้าคุณจำเป็นต้องทำ ก็ไม่ควรรับค่าจากผู้ใช้งานไปเป็นส่วนนึงของการทำขั้นตอนนี้
* กำหนดคำสั่ง queries ให้เป็นค่า parameter ที่ถูกกำหนดขอบเขตอย่างชัดเจน เฉพาะที่ต้องการใช้งาน หรือถูกกำหนดเป็นขั้นตอนไว้แล้วเมื่อทำได้
* คุณอาจจะใช้ Object–relational mapping (ORM) frameworks เช่น Hibernate ซึ่งหากสามารถใช้มันได้อย่างถูกต้องก็จะสามารถช่วยลดความเสี่ยงในส่วนนี้ได้
* หลีกเลี่ยงการประมวลผลสืบค้นข้อมูล SQL ที่ประกอบไปด้วยขั้นตอนการเก็บค่าหรือฟังก์ชั่นที่ใช้ช่องทาง input ที่ไม่ปลอดภัย 
* คัดกรองและตรวจสอบข้อมูลทุกช่องทางที่ input ไม่ปลอดภัย

คุณสามารถลดผลกระทบของการโจมตีได้โดยการกำหนดให้บัญชีผู้ใช้ฐานข้อมูลด้วยสิทธิ์ที่ต่ำที่สุด

**ตัวอย่างที่ไม่ปลอดภัย**
```
// === MySQL ===
const mysql = require('mysql');
const mycon = mysql.createConnection({ host: host, user: user, password: pass, database: db });
mycon.connect(function(err) {
  mycon.query('SELECT * FROM users WHERE id = ' + userinput, (err, res) => {}); // Sensitive
});

// === PostgreSQL ===
const pg = require('pg');
const pgcon = new pg.Client({ host: host, user: user, password: pass, database: db });
pgcon.connect();
pgcon.query('SELECT * FROM users WHERE id = ' + userinput, (err, res) => {}); // Sensitive
```

**แนวทางแก้ไขที่ถูกต้อง**
```
// === MySQL ===
const mysql = require('mysql');
const mycon = mysql.createConnection({ host: host, user: user, password: pass, database: db });
mycon.connect(function(err) {
  mycon.query('SELECT name FROM users WHERE id = ?', [userinput], (err, res) => {});
});

// === PostgreSQL ===
const pg = require('pg');
const pgcon = new pg.Client({ host: host, user: user, password: pass, database: db });
pgcon.connect();
pgcon.query('SELECT name FROM users WHERE id = $1', [userinput], (err, res) => {});
```

**เพิ่มเติม**
* [OWASP Top 10 2017 Category A1](https://www.owasp.org/index.php/Top_10-2017_A1-Injection) - Injection
* [MITRE, CWE-89](http://cwe.mitre.org/data/definitions/89) - Improper Neutralization of Special Elements used in an SQL Command
* [MITRE, CWE-564](http://cwe.mitre.org/data/definitions/564.html) - SQL Injection: Hibernate
* [MITRE, CWE-20](http://cwe.mitre.org/data/definitions/20.html) - Improper Input Validation
* [MITRE, CWE-943](http://cwe.mitre.org/data/definitions/943.html) - Improper Neutralization of Special Elements in Data Query Logic
* [CERT, IDS00-J.](https://wiki.sei.cmu.edu/confluence/x/ITdGBQ) - Prevent SQL injection
* [SANS Top 25](https://www.sans.org/top25-software-errors/#cat1) - Insecure Interaction Between Components
* Derived from FindSecBugs rules [Potential SQL/JPQL Injection (JPA)](http://h3xstream.github.io/find-sec-bugs/bugs.htm#SQL_INJECTION_JPA), [Potential SQL/JDOQL Injection (JDO)](http://h3xstream.github.io/find-sec-bugs/bugs.htm#SQL_INJECTION_JDO), [Potential SQL/HQL Injection (Hibernate)](http://h3xstream.github.io/find-sec-bugs/bugs.htm#SQL_INJECTION_HIBERNATE)

**แหล่งที่มา**

[<img src="/images/sonarqube.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-2077)

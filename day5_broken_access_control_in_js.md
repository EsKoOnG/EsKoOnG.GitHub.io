# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) / Day 5 - Broken Access Control in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## Using publicly writable directories is security-sensitive

ระบบปฏิบัติการโดยทั่วไปแล้วจะมีพื้นที่ส่วนกลางที่ไม่ว่าผู้ใช้ไหนก็สามารถมีสิทธิ์เข้าถึงและเขียนไฟล์ได้ ซึ่งโฟลเดอร์เหล่านั้นส่วนใหญ่จะเป็นพื้นที่ใช้งานชั่วคราวเช่น /tmp ใน Linux based โดยแอปพลิเคชั่นจะที่มีการจัดการไฟล์ในโฟลเดอร์เหล่านี้อาจนำไปสู่ race conditions บนชื่อไฟล์ เช่น ผู้ไม่ประสงค์ดีพยายามที่จะเดาชื่อไฟล์ที่จะถูกสร้างโดยแอปพลิเคชั่น และสร้างมันก่อนที่แอปพลิเคชั่นจะสร้าง หากทำสำเร็จผลลัพธ์ที่ได้คือ ไฟล์ที่ถูกสร้างก็จะสามารถ เข้าถึงได้ แก้ไขได้ ทำให้เสียหายหรือลบได้ ความเสี่ยงก็จะสูงขึ้นไปอีกหากแอปพลิเคชั่นนั้นใช้งานด้วยสิทธิ์สูงของระบบ

ในอดีตที่ผ่านมาเคยเกิดช่องโหว่ที่เกี่ยวของดังนี้

* [CVE-2012-2451](https://nvd.nist.gov/vuln/detail/CVE-2012-2451)
* [CVE-2015-1838](https://nvd.nist.gov/vuln/detail/CVE-2015-1838)

**ลองถามตัวเองดูr**

* ไฟล์ที่อ่านหรือถูกเขียนลงบนโฟล์เดอร์ที่เข้าถึงโดยสาธารณะ
* แอปพลิเคชั่นสร้างไฟล์ที่สามารถคาดเดาชื่อไฟล์ลงบนโฟล์เดอร์ที่เข้าถึงโดยสาธารณะ

มันเป็นความเสี่ยงหากคุณตอบใช่จากคำถามเหล่านี้

**คำแนะนำในการเขียน Code ให้ปลอดภัย**

* ใช้งานโฟลเดอร์ย่อยเฉพาะด้วยการควบคุมสิทธิ์ที่แน่นหนา
* ใช้การออกแบบ API ที่ปลอดภัยที่จะสร้างไฟล์ใช้งานชั่วคราว ดังนี้
  * สร้างไฟล์ที่ไม่สามารถคาดเดาชื่อไฟล์ได้
  * ไฟล์ที่อ่านและเขียนได้เฉพาะชื่อผู้ใช้งานที่สร้างไฟล์นั้น ๆ
  * คำอธิบายหรือเนื้อหาของไฟล์จะไม่ถูกสืบทอดไปยัง child processes
  * ไฟล์จะถูกทำลายโดยทันทีเมื่อถูกปิดการใช้งาน

**ตัวอย่างที่ไม่ปลอดภัย**
```
const fs = require('fs');

let tmp_file = "/tmp/temporary_file"; // Sensitive
fs.readFile(tmp_file, 'utf8', function (err, data) {
  // ...
});
```
```
const fs = require('fs');

let tmp_dir = process.env.TMPDIR; // Sensitive
fs.readFile(tmp_dir + "/temporary_file", 'utf8', function (err, data) {
  // ...
});
```

**แนวทางแก้ไขที่ถูกต้อง**

```
const tmp = require('tmp');

const tmpobj = tmp.fileSync(); // Compliant
```

**See**
* [OWASP Top 10 2017 Category A5](https://www.owasp.org/index.php/Top_10-2017_A5-Broken_Access_Control) - Broken Access Control
* [OWASP Top 10 2017 Category A3](https://www.owasp.org/index.php/Top_10-2017_A3-Sensitive_Data_Exposure) - Sensitive Data Exposure
* [MITRE, CWE-377](http://cwe.mitre.org/data/definitions/377) - Insecure Temporary File
* [MITRE, CWE-379](http://cwe.mitre.org/data/definitions/379) - Creation of Temporary File in Directory with Incorrect Permissions
* [OWASP, Insecure Temporary File](https://www.owasp.org/index.php/Insecure_Temporary_File)

**แหล่งที่มา**

[<img src="/images/SonarSourceRules.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-5443)

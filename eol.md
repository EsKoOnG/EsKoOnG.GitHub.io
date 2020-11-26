# Warning: line endings have changed from ‘LF’ to ‘CRLF’.
คำเตือน : การสิ้นสุดบรรทัดถูกเปลี่ยน จาก LF เป็น CRLF

---

![Warning](https://user-images.githubusercontent.com/4097841/46043452-13ae4800-c0e6-11e8-8d68-b83b86e3e58a.png)
<p>บางครั้งการสร้างโปรแกรม หรือ การพัฒนาระบบขึ้นมาซักระบบ ก็ต้องอาศัยความร่วมมือจากนักพัฒนาหลายคน ๆ และแน่นอนว่า นักพัฒนา (Developer) แต่ละคนก็จะมีความถนัดที่แตกต่างกันไป รวมถึงเครื่องมือที่ใช้ก็ยังแตกต่างกันออกไปอีกด้วย จึงเป็นสาเหตุให้ต้องมีการตกลงร่วมกันก่อนว่า จะต้องมีแนวทางพัฒนาร่วมกันอย่างไร หรือมีเครื่องมืออะไรมาเป็นตัวช่วย เพื่อที่จะบรรลุเป้าหมายได้โดยไม่ติดขัด</p>
<p>ซึ่งหนึ่งใน Platform ที่ได้รับความนิยมเป็นอันดับต้น ๆ ของโลกก็คือ GitHub ที่จะเข้ามาช่วยในการจัดเก็บ Source Code, ทำ Version Control, หรือแม้แต่ Project Management และการควบคุมด้าน Security เป็นต้น บางครั้งก็จะมีนักพัฒนามือใหม่ที่เพิ่งใช้งาน GitHub และเจอคำเตือน </p>

> **Warning : line endings have changed from 'LF' to 'CRLF'**

<p>และอาจเกิดข้อสงสัยว่ามันคืออะไร แล้วมันทำหน้าที่อะไร จะได้เรียนรู้กันในบทความนี้</p>

## What's Newline
![NewLine](https://upload.wikimedia.org/wikipedia/commons/b/b3/Illustration_of_a_newline.png)
<p>Newline หรือบ่อยครั้งอาจถูกเรียกว่า Line Ending, End of Line (EOL), Line Feed หรือ Line Break ทั้งหมดคือ Control Charactor หรือลำดับตัวอักษรที่ถูกระบุไว้ใน ASCII หรือ EBCDIC เป็นต้น ที่จะใช้ระบุเป็นสัญลักษณ์ แทนการสิ้นสุดบรรทัด เพื่อที่จะเริ่มต้นบรรทัดใหม่ โดย Editor Application ส่วนใหญ่จะตั้งค่าการขึ้นบรทัดใหม่ไว้กับปุ่ม ↵ Enter </p>

## Representation
<p>แนวคิดของ New Line ที่กล่าวถึงจะหยิบยกจากระบบปฏิบัติการที่พบเจอได้บ่อย ๆ อย่าง Unix(Linux,MacOS,FreeBSD, ect.) และ Microsoft Windows ซึ่งทั้ง 2 ระบบนี้ก็มีการใช้งานตัว Newline หรือ EOL ที่ต่างกันโดยฝั่ง Unix จะใช้ชื่อ Line Feed (LF) และฝั่ง Microsoft Windows จะใช้ Carriage Return (CR) ร่วมกับ LF เป็น 'CRLF' แล้วสองคำนี้ต่างกันอย่างไร</p>

|Operating system|Charactor Enconding|Abbreviation|Hex Value|Dec Value|Escape Sequence|
|:-:|:-:|:-:|:-:|:-:|:-:|
|Unix(Linux,MacOS,FreeBSD, ect.)|ASCII|LF|0A|10|\n|
|Microsoft Windows|ASCII|CR LF|0D 0A|13 10|\r\n|

<p>จากตารางจะเห็นว่า CRLF จะมี Control Charactor ที่มากกว่า แล้วจะเกิดอะไรขึ้นเมื่อนักพัฒนาที่ใช้ Unix กับ นักพัฒนาที่ใช้ Windows ต้องมาพัฒนาระบบร่วมกัน</p>

## Issues with Difference newline formats
![EOL](https://upload.wikimedia.org/wikipedia/commons/2/27/Newline_hex_0A.png)
<p>ปัญหาที่จะพบได้บ่อยครั้งคือ Code จากนักพัฒนา ทั้ง 2 ฝั่งแสดงผลผิดปกติหรือทำงานร่วมกันไม่ได้ เนื่องจาก Editor Application แต่ละฝั่งใช้ EOL ที่แตกต่างกันนั่นเอง ซึ่งอาจจะพบเจอในลักษณะที่ว่า นักพัฒนาฝั่ง Windows เปิดไฟล์ที่ได้รับจากนักพัฒนาฝั่ง Unix แล้วพบว่า code นั้นแสดงผลอยู่ในบรรทัดเดียวกันทั้งหมด ก็เพราะว่า Editor Application ของฝั่ง Unix ใช้ EOL เป็น LF หรือ \n จึงทำให้ Editor Application ฝั่ง Windows แสดงผลผิดเพี้ยนไป เนื่องจากว่าตัวมันเองพยายามมองหา CRLF หรือ \r\n แต่เมื่อมันอ่านแล้วไม่พบ \r มาด้วยมันจึงไม่แสดงผลของ EOL อย่างที่ควรเป็น </p> แล้วเราจะแก้ไขปัญหานี้ได้อย่างไร

## Conversion between newline formats
ท้ายที่สุดก็มาถึงสาเหตุที่เราอาจจะพบเห็นข้อความ

> **Warning : line endings have changed from 'LF' to 'CRLF'**

นั่นก็เพราะว่า GitHub Platform ถูกพัฒนามาด้วยระบบปฏิบัติการที่เป็น Unix และใช้ EOL เป็น LF เพียงเท่านั้น จึงเป็นที่มาว่าทำไม Software ของ GitHub จึงมีคำเตือนเกี่ยว EOL ที่ถูกเปลี่ยนแปลงแก้ไข นั่นก็เพื่อการแสดงผลที่ถูกต้องบน WebSite หรือการใช้งานอื่น ๆ ให้มันเป็นมาตรฐานเดียวกัน และถูกเปลี่ยนแปลงแก้ไขกลับเมื่อถูก Pull กลับมาที่ Local ฝั่ง Windows นั่นเอง โดยสามารถตั้งค่าเพิ่มเติมเพื่อความสะดวกสบายได้ในหัวข้อถัดไป

## The concept of autocrlf is to handle line endings conversions transparently. And it does!
![AutoCRLF](/images/autocrlf.png)
<p>ข่าวร้าย : การตั้งค่านี้ต้องทำด้วยวิธี Manual เท่านั้น</p>
<p>ข่าวดี : การตั้งค่านี้ทำเพียงครั้งเดียวตอนติดตั้ง Git Software (หรืออาจจะเป็น by projects).</p>

### autocrlf ทำงานและใช้งานอย่างไร:

fuction นี้สามารถใช้งานผ่าน Command Line หรือ CLI ได้ดังนี้

>>>

1) **git config core.autocrlf true**  :   x -> LF -> CRLF
2) **git config core.autocrlf input** :   x -> LF -> LF
3) **git config core.autocrlf false** :   x -> x -> x

>>>

x คือ EOL ที่ใช้งานอยู่ในปัจจุบัน ไม่ว่าจะเป็น LF หรือ CRLF และขั้นตอนถัดมาจะแสดงถึงตอนที่ Push ขึ้น Repository ว่าจะ Convert เป็น LF หรือไม่ และขั้นตอนถัดมาคือการ Pull ลงมาจะให้ Convert กลับเป็น CRLF หรือไม่ แต่หากตั้งค่าเป็น False จะไม่มีการเปลี่ยนแก้ไข EOL ใด ๆ ทั้ง Push และ Pull

---

Reference : 
- https://en.wikipedia.org/wiki/Newline
- https://stackoverflow.com/questions/1967370/git-replacing-lf-with-crlf

Written By
[Mr.Piyawit Khumkrong [Es]](http://eskoong.github.io/)

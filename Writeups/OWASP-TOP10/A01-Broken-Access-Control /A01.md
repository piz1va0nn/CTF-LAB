## A01:2021 - Broken Access Control

### Root Cause Analysis

ช่องโหว่นี้เกิดจากการควบคุมการเข้าถึงที่ไม่เหมาะสม หรือขาดการตรวจสอบสิทธิ์การเข้าถึงทรัพยากรต่างๆ

**Definition:**
- **Definition:** Brief explanation in your own words.
- **Impact:** What can an attacker achieve?
- **Example:** Real-world example if available.

**สาเหตุหลัก:**
- ขาดการตรวจสอบ Authorization ฝั่ง Server
- การพึ่งพา Client-side Controls
- การ Hard-code URL หรือ Path ที่สามารถเข้าถึงได้โดยตรง
- การกำหนดสิทธิ์แบบ Default Allow
- ไม่มีการ Validate Object References



---


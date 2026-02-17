# Web Security

Web security vulnerabilities can be grouped into three broad areas: **server-side**, **client-side**, and **advanced/modern attack surfaces**. Each category targets different parts of the stack (backend logic and infrastructure, browser-side behavior, or complex protocol/framework design flaws).

## 1) Server-side (backend)

These issues live in the application server, backend services, databases, and internal network integrations. They often lead to data access, account takeover, remote code execution, or internal network compromise.

- [SQL Injection](https://github.com/vsang181/Web-Security/tree/main#:~:text=8%20Commits-,SQL%20injection,-Create%20SQL%20injection) 
- [Authentication issues](https://github.com/vsang181/Web-Security/tree/main/Authentication%20issues) 
- [Path Traversal](https://github.com/vsang181/Web-Security/tree/main/Path%20Traversal)
- [Command Injection](https://github.com/vsang181/Web-Security/tree/main/Command%20Injection)
- [Business Logic Vulnerabilities](https://github.com/vsang181/Web-Security/tree/main/Business%20Logic%20Vulnerabilities)
- Information Disclosure
- Access Control issues 
- File Upload Vulnerabilities
- Race Conditions 
- Server-Side Request Forgery (SSRF)
- XXE Injection
- NoSQL Injection
- API Testing 
- Web Cache Deception

## 2) Client-side (browser)

These issues execute in or abuse the user’s browser context. They commonly lead to session theft, account compromise, unauthorized actions, or data exposure via the victim’s browser.

- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Cross-Origin Resource Sharing (CORS) 
- Clickjacking
- DOM-based vulnerabilities 
- WebSockets 

## 3) Advanced (modern + complex)

These are higher-complexity vulnerabilities involving modern architectures, middleware, authentication standards, serialization, caches, and protocol quirks.

- Insecure Deserialization
- Web LLM Attacks 
- GraphQL API vulnerabilities 
- Server-Side Template Injection 
- Web Cache Poisoning
- HTTP Host Header attacks
- HTTP Request Smuggling
- OAuth authentication issues 
- JWT attacks 
- Prototype Pollution

> Essential Skills

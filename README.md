# Passive Recon Burp Extension

Passive Recon is a **Burp Suite extension** that performs **all-in-one passive reconnaissance** while you browse or test a target.  
It automatically detects and collects **endpoints**, **subdomains**, **GraphQL queries (including meta-GraphQL)**, and **URLs** from every request/response.

![p (1)](https://github.com/user-attachments/assets/a8b00ecb-a3c3-4ec9-8a21-381308c00793)

---

## ✨ Features
- **GraphQL Detection**
  - Parses GraphQL requests and responses
  - Supports normal queries, mutations, fragments
  - Detects **meta-GraphQL** style requests often missed by other tools

- **Subdomain Collection**
  - Extracts subdomains passively from traffic
  - Displays unique findings in a dedicated tab

- **Endpoint & URL Extraction**
  - Collects parameters, API endpoints, and in-scope URLs
  - Deduplicated and shown in clean lists
  - Helps build a quick map of the attack surface

- **Burp UI Integration**
  - Four tabs inside Burp: **GraphQL**, **Subdomains**, **Endpoints**, **URLs**
  - Easy copy/paste for recon workflows

---

## 🔗 Works Great with Wayback Recon
Use together with [Wayback Recon](https://github.com/aditisingh2707/Wayback-Recon) for maximum coverage:
1. Run **Wayback Recon** to fetch archived URLs from Wayback Machine
2. Send those URLs to Burp’s sitemap
3. **Passive Recon** will automatically scan them for:
   - Subdomains
   - Endpoints
   - GraphQL queries (including meta-GraphQL)
   - URLs  

---

## ⚠️ Notes
- Some large responses may slow down parsing  
- May produce **false positives or noisy results**, depending on the target and response contents

---

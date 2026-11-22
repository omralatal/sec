# 🛡️ SecureShop — Hardened E-Commerce Platform & Comparative Security Lab

**Course:** CET431 – Software Security (Fall 2026)  
**Institution:** Elsewedy University of Technology – Polytechnic of Egypt  
**Team Structure:** 6 Members (3 Blue Team Engineers & 3 Red Team Penetration Testers)

---

## 1. Project Overview

**SecureShop** is a full-stack e-commerce web application built to demonstrate practical defense-in-depth engineering against web application vulnerabilities covered in **CET431 Software Security**. To provide reproducible comparative verification, the repository includes:

1. **Hardened Application (`app.py` + `index.html` on Port `5000`):** The production-hardened application implementing all 12 functional e-commerce requirements protected by multi-layered security controls.
2. **Baseline Naive Application (`naive_app.py` on Port `5001`):** An intentionally unhardened reference build used to demonstrate successful vulnerability exploitation.
3. **Automated Security Verification Harness (`dashboard.py` on Port `5050`):** A live comparative test runner executing 7 attack vectors simultaneously against both `:5000` and `:5001`.

---

## 2. Setup & Installation Steps

### Prerequisites
* Python **3.9+**
* `pip` package manager
* Any TOTP Authenticator app (or Python `pyotp`) for MFA login verification

### Installation & Running Locally
```bash

git clone [https://github.com/](https://github.com/)<omarelattal44>/SecureShop-CET431.git
cd SecureShop-CET431


python3 -m venv venv
source venv/bin/activate        


pip install flask argon2-cffi pyotp requests


python3 app.py

python3 naive_app.py
python3 dashboard.py
```

### Access URLs
* **Hardened SecureShop:** `http://127.0.0.1:5000`
* **Naive Baseline App:** `http://127.0.0.1:5001`
* **Comparative Security Dashboard:** `http://127.0.0.1:5050`

---

## 3. Test Accounts & Coupons

Both applications initialize with pre-seeded test accounts for functional and security testing:

| Role | Username | Password | TOTP Secret (Base32) | Initial Store Credit |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `AdminSecret2026!` | `JBSWY3DPEHPK3PXP` | `$5,000.00` |
| **Standard Customer** | `omar` | `UserSecret2026!` | `JBSWY3DPEHPK3PXP` | `$999.00` |

* **Generating a Live 6-Digit OTP for Login:**
  ```bash
  python3 -c "import pyotp; print(pyotp.TOTP('JBSWY3DPEHPK3PXP').now())"
  ```
* **Active Promotional Coupons:** `WELCOME20` (20% off) and `NEWSLETTER10` (10% off via newsletter signup).

---

## 4. One-Page Architecture Overview

SecureShop follows a decoupled **Client–Server REST Architecture** where a single-page frontend (`index.html`) communicates via JSON APIs with a Python Flask backend (`app.py`) backed by SQLite (`secureshop.db`). Every incoming request traverses **five defense-in-depth layers**:

```text
[Browser SPA: index.html]
   │  (JSON over HTTP + HttpOnly/SameSite=Lax Session Cookie + X-CSRF-Token Header)
   ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: Perimeter & Header Middleware (@before_request / @after_request)    │
│ • Constant-time CSRF validation (secrets.compare_digest) on mutating routes  │
│ • Security headers: CSP, X-Frame-Options: DENY, nosniff, Referrer-Policy     │
├──────────────────────────────────────────────────────────────────────────────┤
│ LAYER 2: Identity, Cryptography & Session Hardening                          │
│ • Argon2id password hashing + server-side pepper + breached-password check   │
│ • Mandatory RFC 6238 TOTP MFA with per-user step tracking (anti-replay)      │
│ • Session ID rotation (session.clear()) on login to prevent session fixation │
├──────────────────────────────────────────────────────────────────────────────┤
│ LAYER 3: Role-Based & Object-Level Access Control (RBAC & IDOR Defense)      │
│ • @login_required binds /orders and /account strictly to session['user_id']  │
│ • @admin_required re-verifies role='admin' from SQLite on every admin call   │
├──────────────────────────────────────────────────────────────────────────────┤
│ LAYER 4: Input Validation, Business Logic & Atomic Transactions              │
│ • Parameterized SQL queries (?) across all database reads and writes         │
│ • Server-side price/coupon calculation; rejects client price/total tampering │
│ • Atomic SQLite BEGIN IMMEDIATE transactions prevent checkout race conditions│
├──────────────────────────────────────────────────────────────────────────────┤
│ LAYER 5: Forensic Audit Logging & Safe Error Handling                        │
│ • audit_logs table tracks INFO/WARN/ALERT security events with client IPs    │
│ • Global 404/405/500 JSON handlers suppress stack traces and debug info      │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Repository Structure

```text
SecureShop-CET431/
├── app.py                                      # Hardened Flask backend (:5000)
├── naive_app.py                                # Unhardened baseline backend (:5001)
├── dashboard.py                                # Automated 7-vector comparison harness (:5050)
├── index.html                                  # Frontend SPA (HTML5 + TailwindCSS + JS)
├── README.md                                   # Project setup, credentials & architecture
└── docs/
    ├── SecureShop_Security_Design_Report.pdf   # Threat model, STRIDE & coverage matrix
    ├── Red taam.pdf          # Burp Suite 
    └── SecureShop_Attack_Evidence_Report.pdf   # Comparative HTTP request/response logs
```
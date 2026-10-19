# Real-World Repository Validation Report

Scanned 32 repositories across Python, JavaScript, and TypeScript.

## 1. Held-Out Evaluation Metrics

- **Held-Out Repositories**: 17 (2 vulnerable, 15 maintained)
- **ROC AUC**: **1.000** (Bootstrap 95% CI: [1.000, 1.000])

## 2. Maintained Repositories Score Distribution

- Count: 26
- Min: 0.0 | 25%: 0.0 | Median: 1.0 | Mean: 2.9 | 75%: 4.0 | Max: 11.0

## 3. Detailed Results Table

| Repository | Language | Type | Set | LOC | Score | Tier | Floor | Findings | Top Rules |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `appsecco/dvna` | javascript | vulnerable | tuning | 762 | **41** | `moderate` | True | 5 | ENT-AUTHZ-002, ENT-INPUT-JS-001 |
| `we45/Vulnerable-Flask-App` | python | vulnerable | tuning | 565 | **30** | `low` | False | 28 | ENT-ARCH-005, ENT-ERR-002, ENT-ERR-001, ENT-ERR-JS-001 |
| `OWASP/NodeGoat` | javascript | vulnerable | tuning | 1,968 | **41** | `moderate` | True | 20 | ENT-AUTH-001, ENT-INPUT-JS-001, ENT-LOG-JS-002, ENT-DUP-005, ENT-DUP-004 |
| `payatu/Tiredful-API` | python | vulnerable | tuning | 6,111 | **41** | `moderate` | True | 15 | ENT-LOG-002, ENT-DUP-004, ENT-DUP-005, ENT-ERR-JS-002, ENT-DUP-002 |
| `pallets/flask` | python | maintained | tuning | 9,507 | **4** | `very_low` | False | 39 | ENT-DUP-004, ENT-DUP-005, ENT-ARCH-006 |
| `encode/starlette` | python | maintained | tuning | 7,079 | **7** | `very_low` | False | 55 | ENT-DUP-004, ENT-DUP-005, ENT-ERR-004, ENT-ERR-002, ENT-ERR-003 |
| `encode/httpx` | python | maintained | tuning | 8,827 | **4** | `very_low` | False | 63 | ENT-DUP-005, ENT-ARCH-006, ENT-ERR-004, ENT-ERR-002 |
| `pallets/click` | python | maintained | tuning | 12,930 | **6** | `very_low` | False | 81 | ENT-DUP-005, ENT-ERR-002, ENT-ERR-003 |
| `marshmallow-code/marshmallow` | python | maintained | tuning | 5,201 | **5** | `very_low` | False | 24 | ENT-ERR-004, ENT-ERR-003 |
| `tiangolo/sqlmodel` | python | maintained | tuning | 3,444 | **1** | `very_low` | False | 2 | ENT-ARCH-001 |
| `encode/databases` | python | maintained | tuning | 2,375 | **4** | `very_low` | False | 22 | ENT-DUP-005, ENT-DUP-004 |
| `expressjs/express` | javascript | maintained | tuning | 2,776 | **0** | `very_low` | False | 3 | ENT-ERR-JS-002, ENT-DUP-001 |
| `pillarjs/router` | javascript | maintained | tuning | 1,715 | **0** | `very_low` | False | 2 | ENT-ERR-JS-002, ENT-DUP-001 |
| `expressjs/cors` | javascript | maintained | tuning | 238 | **0** | `very_low` | False | 0 | None |
| `motdotla/dotenv` | javascript | maintained | tuning | 1,157 | **1** | `very_low` | False | 2 | ENT-ERR-JS-001, ENT-DUP-001 |
| `juice-shop/juice-shop` | typescript | vulnerable | held_out | 70,238 | **41** | `moderate` | True | 193 | ENT-AUTH-001 |
| `JasonHinds13/hackable` | python | vulnerable | held_out | 171 | **41** | `moderate` | True | 5 | ENT-INPUT-003, ENT-AUTH-001, ENT-INPUT-001 |
| `psf/requests` | python | maintained | held_out | 6,403 | **7** | `very_low` | False | 43 | ENT-DUP-005, ENT-ERR-004, ENT-ERR-003 |
| `fastapi/full-stack-fastapi-template` | python | maintained | held_out | 11,795 | **2** | `very_low` | False | 31 | ENT-AUTHZ-002, ENT-INPUT-001, ENT-DUP-005, ENT-DUP-004, ENT-ERR-JS-001 |
| `miguelgrinberg/microblog` | python | maintained | held_out | 1,843 | **11** | `very_low` | False | 23 | ENT-INPUT-001, ENT-ERR-004, ENT-ERR-002 |
| `pallets/werkzeug` | python | maintained | held_out | 24,254 | **4** | `very_low` | False | 127 | ENT-DUP-005, ENT-DUP-004 |
| `pallets/jinja` | python | maintained | held_out | 14,424 | **6** | `very_low` | False | 93 | ENT-DUP-005, ENT-ARCH-006, ENT-ERR-003, ENT-ERR-002, ENT-ERR-004 |
| `bottlepy/bottle` | python | maintained | held_out | 4,566 | **7** | `very_low` | False | 33 | ENT-ARCH-006, ENT-ERR-004, ENT-ERR-003, ENT-ERR-002 |
| `gothinkster/node-express-realworld-example-app` | javascript | maintained | held_out | 1,673 | **1** | `very_low` | False | 3 | ENT-DUP-005, ENT-ARCH-001, ENT-DUP-001 |
| `fastify/fastify` | javascript | maintained | held_out | 12,798 | **1** | `very_low` | False | 39 | ENT-DUP-005, ENT-DUP-004 |
| `koajs/koa` | javascript | maintained | held_out | 2,144 | **0** | `very_low` | False | 3 | ENT-DUP-004, ENT-ERR-JS-002 |
| `expressjs/session` | javascript | maintained | held_out | 1,481 | **1** | `very_low` | False | 4 | ENT-DUP-005, ENT-ERR-JS-002, ENT-DUP-002 |
| `auth0/node-jsonwebtoken` | javascript | maintained | held_out | 687 | **3** | `very_low` | False | 2 | ENT-ERR-JS-001, ENT-DUP-004 |
| `lukeed/polka` | javascript | maintained | held_out | 166 | **0** | `very_low` | False | 0 | None |
| `colinhacks/zod` | typescript | maintained | held_out | 40,548 | **1** | `very_low` | False | 76 | ENT-DUP-005, ENT-DUP-004 |
| `jaredhanson/passport` | javascript | maintained | held_out | 1,352 | **0** | `very_low` | False | 0 | None |
| `nestjs/typescript-starter` | typescript | maintained | held_out | 76 | **0** | `very_low` | False | 0 | None |


# 🎯 Deep Findings Triage Report

**Generated:** 2026-07-08 12:45
**Total findings:** 1209
**Exposed ports:** 67

## Summary
| Tier | Count | Action |
|---|---|---|
| 🔴 Tier 1 (Report Now) | 62 | Submit to HackerOne immediately |
| 🟡 Tier 2 (Verify First) | 258 | Manually verify, then report |
| ⚪ Tier 3 (Low Priority) | 656 | Investigate if time permits |
| ❌ Rejected | 233 | Skip — HackerOne will reject |

---
## 🔴 Exposed Database Ports (Tier 1)
> [!CAUTION]
> These are the highest-impact findings. Exposed database ports have the
> highest acceptance rate on HackerOne.

| IP | Port | Service | Domains |
|---|---|---|---|
| `35.71.185.205` | 5432 | PostgreSQL | rb-rivals-prod-p16.hmxservices.com, rb-rivals-prod.hmxservices.com |
| `89.161.254.244` | 5432 | PostgreSQL | kariera.itesco.cz |
| `35.214.204.16` | 5432 | PostgreSQL | blog.sketchfab.com |
| `37.16.15.184` | 2375 | Docker API (Unauthenticated) |  |
| `37.16.15.184` | 6379 | Redis |  |
| `37.16.15.184` | 27017 | MongoDB |  |
| `37.16.15.184` | 11211 | Memcached |  |
| `37.16.15.184` | 5432 | PostgreSQL |  |
| `37.16.15.184` | 3306 | MySQL |  |
| `37.16.15.184` | 9090 | Prometheus |  |
| `37.16.15.184` | 8500 | Consul |  |
| `37.16.15.184` | 9200 | Elasticsearch |  |
| `37.16.15.184` | 5601 | Kibana |  |
| `37.16.15.184` | 8888 | Jupyter Notebook |  |
| `45.60.73.192` | 2375 | Docker API (Unauthenticated) |  |
| `45.60.73.192` | 6379 | Redis |  |
| `45.60.73.192` | 3306 | MySQL |  |
| `45.60.73.192` | 9090 | Prometheus |  |
| `45.60.73.192` | 8500 | Consul |  |
| `45.60.73.192` | 5601 | Kibana |  |
| `45.60.73.192` | 9200 | Elasticsearch |  |
| `45.60.73.192` | 8888 | Jupyter Notebook |  |
| `45.223.57.41` | 2375 | Docker API (Unauthenticated) |  |
| `45.223.57.41` | 6379 | Redis |  |
| `45.223.57.41` | 3306 | MySQL |  |
| `45.223.57.41` | 8500 | Consul |  |
| `45.223.57.41` | 5601 | Kibana |  |
| `45.223.57.41` | 8888 | Jupyter Notebook |  |
| `45.223.57.41` | 9200 | Elasticsearch |  |
| `45.223.57.41` | 9090 | Prometheus |  |
| `107.154.133.13` | 2375 | Docker API (Unauthenticated) |  |
| `107.154.133.13` | 3306 | MySQL |  |
| `107.154.133.13` | 6379 | Redis |  |
| `107.154.133.13` | 5601 | Kibana |  |
| `107.154.133.13` | 8500 | Consul |  |
| `107.154.133.13` | 9090 | Prometheus |  |
| `107.154.133.13` | 8888 | Jupyter Notebook |  |
| `107.154.133.13` | 9200 | Elasticsearch |  |
| `45.60.121.26` | 2375 | Docker API (Unauthenticated) |  |
| `45.60.121.26` | 6379 | Redis |  |
| `45.60.121.26` | 3306 | MySQL |  |
| `45.60.121.26` | 9090 | Prometheus |  |
| `45.60.121.26` | 9200 | Elasticsearch |  |
| `45.60.121.26` | 5601 | Kibana |  |
| `45.60.121.26` | 8500 | Consul |  |
| `45.60.121.26` | 8888 | Jupyter Notebook |  |
| `43.175.136.157` | 6379 | Redis |  |
| `43.175.136.157` | 8888 | Jupyter Notebook |  |
| `43.175.136.157` | 9090 | Prometheus |  |
| `157.185.160.139` | 9200 | Elasticsearch |  |
| `157.185.160.139` | 8500 | Consul |  |
| `157.185.160.139` | 9090 | Prometheus |  |
| `157.185.160.139` | 8888 | Jupyter Notebook |  |
| `43.152.136.157` | 6379 | Redis |  |
| `43.152.136.157` | 9090 | Prometheus |  |
| `43.152.136.157` | 8888 | Jupyter Notebook |  |
| `43.174.199.245` | 6379 | Redis |  |
| `43.174.199.245` | 9090 | Prometheus |  |
| `43.174.199.245` | 8888 | Jupyter Notebook |  |
| `43.174.196.245` | 6379 | Redis |  |
| `43.174.196.245` | 8888 | Jupyter Notebook |  |
| `43.174.196.245` | 9090 | Prometheus |  |
| `157.185.160.145` | 9200 | Elasticsearch |  |
| `157.185.160.145` | 9090 | Prometheus |  |
| `157.185.160.145` | 8500 | Consul |  |
| `157.185.160.145` | 8888 | Jupyter Notebook |  |
| `45.60.12.94` | 8443 | Alt-HTTPS | estore.malwarebytes.com |

---
## 🔴 Tier 1 — Report Now
> [!IMPORTANT]
> These findings have proven HackerOne acceptance. Report immediately.

### [Password_Reset_UUID] ge.betsson.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `UUID reset token in path: 40f410cb-8d60-4900-b45e-fc44b4534f78`
- **URL:** `https://ge.betsson.com/ka/reset-password/40f410cb-8d60-4900-b45e-fc44b4534f78`

### [VirusTotal Credential Submission] sportsbook.betsson.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: adrianedir@gmail.com:992296890Adrian`
- **URL:** `https://sportsbook.betsson.com/pe/:adrianedir@gmail.com:992296890Adrian`

### [Password_Reset_UUID] www.betsson.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `UUID reset token in path: b8fbe395-b844-4744-8d19-50e0d4294d0e`
- **URL:** `https://www.betsson.com/en/reset-password/b8fbe395-b844-4744-8d19-50e0d4294d0e`

### [VirusTotal Credential Submission] www.capcut.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: marketing@emvida.com:2546393`
- **URL:** `https://www.capcut.com/editor-graphic/:marketing@emvida.com:2546393`

### [VirusTotal Credential Submission] accounts.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: culacho10@gmail.com:ale250510`
- **URL:** `https://accounts.epicgames.com/:culacho10@gmail.com:ale250510`

### [VirusTotal Credential Submission] accounts.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: israel3028gj@gamail.com:eigj2811`
- **URL:** `https://accounts.epicgames.com/:israel3028gj@gamail.com:eigj2811`

### [VirusTotal Credential Submission] accounts.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: mohalaskruv@gmaol.com:v1234567k`
- **URL:** `https://accounts.epicgames.com/:mohalaskruv@gmaol.com:v1234567k`

### [Password_Reset_Param] accounts.epicgames.com
- **Type:** `Password_Reset_Param`
- **Severity:** CRITICAL
- **Evidence:** `code=48c2df61fa424984b7952b1eec429c8b`
- **URL:** `https://accounts.epicgames.com/resetPassword?code=48c2df61fa424984b7952b1eec429c8b&bt_user_id=ap66BdStYONVNEf5f9wOQFUpjwQksC8D3cTW3Ya4fhguGsMraD/xk+1bsUdst+fCELVYfR5lEk2Hl9K2HzjZ8iHbx45qsre35MWKnrTBDk`

### [Password_Reset_Param] epicgames.com
- **Type:** `Password_Reset_Param`
- **Severity:** CRITICAL
- **Evidence:** `code=903655c63c3a4a59b5f0e704caf56f13`
- **URL:** `https://epicgames.com/id/login/reset-password?code=903655c63c3a4a59b5f0e704caf56f13`

### [VirusTotal Credential Submission] www.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: 29viltz@comcast.net:Toloza2008`
- **URL:** `https://www.epicgames.com/:29viltz@comcast.net:Toloza2008`

### [VirusTotal Credential Submission] www.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: fop20086@gmail.com:Toloza2008`
- **URL:** `https://www.epicgames.com/:fop20086@gmail.com:Toloza2008`

### [VirusTotal Credential Submission] www.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: fpszoro@gmail.com:uaejasoom7919090`
- **URL:** `https://www.epicgames.com/:fpszoro@gmail.com:uaejasoom7919090`

### [VirusTotal Credential Submission] www.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: fry048785@jasaroda.com:Toloza2008`
- **URL:** `https://www.epicgames.com/:fry048785@jasaroda.com:Toloza2008`

### [VirusTotal Credential Submission] www.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: jelenaziramov@gmail.com:kolemole19`
- **URL:** `https://www.epicgames.com/:jelenaziramov@gmail.com:kolemole19`

### [VirusTotal Credential Submission] www.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: laurianoh53@gmail.com:diegolauri54675`
- **URL:** `https://www.epicgames.com/:laurianoh53@gmail.com:diegolauri54675`

### [VirusTotal Credential Submission] www.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: manuelgaliano41@gmail.com:manuel41`
- **URL:** `https://www.epicgames.com/:manuelgaliano41@gmail.com:manuel41`

### [VirusTotal Credential Submission] www.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: miron.yuzhakov@bk.ru:miron2011`
- **URL:** `https://www.epicgames.com/:miron.yuzhakov@bk.ru:miron2011`

### [VirusTotal Credential Submission] www.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: wlcatt@outlook.com:Tolon2008`
- **URL:** `https://www.epicgames.com/:wlcatt@outlook.com:Tolon2008`

### [VirusTotal Credential Submission] www.epicgames.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: xhiruncs@fmaillerbox.com:Toloza2008`
- **URL:** `https://www.epicgames.com/:xhiruncs@fmaillerbox.com:Toloza2008`

### [Password_Reset_UUID] ge.betsson.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `UUID reset token in path: 40f410cb-8d60-4900-b45e-fc44b4534f78`
- **URL:** `https://ge.betsson.com/ka/reset-password/40f410cb-8d60-4900-b45e-fc44b4534f78`

### [VirusTotal Credential Submission] nakup.itesco.cz
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: mirinec1466@gmail.com:Sam102hL`
- **URL:** `https://nakup.itesco.cz/:mirinec1466@gmail.com:Sam102hL`

### [VirusTotal Credential Submission] prihlaseni.itesco.cz
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: spyt@seznam.cz:Martina369`
- **URL:** `https://prihlaseni.itesco.cz/cs-CZ/:spyt@seznam.cz:Martina369`

### [VirusTotal Credential Submission] th.tradingview.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: kungchangc@gmail.com:sansan11`
- **URL:** `https://th.tradingview.com/:kungchangc@gmail.com:sansan11`

### [Password_Reset_UUID] uk.tradingview.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `key=6b2fd43d-02ea-41ba-835e-adb9f4f0d956 (UUID reset token)`
- **URL:** `https://uk.tradingview.com/accounts/activate/?key=6b2fd43d-02ea-41ba-835e-adb9f4f0d956&username=testmoneytest&utm_source=signup&utm_medium=signup&utm_campaign=new_signup`

### [VirusTotal Credential Submission] vn.tradingview.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: secret16029244@gmail.com:Camdoipass9160`
- **URL:** `https://vn.tradingview.com/:secret16029244@gmail.com:Camdoipass9160`

### [Password_Reset_UUID] www.betsson.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `UUID reset token in path: 25afda03-d2a8-4829-997d-a23fb659f213`
- **URL:** `https://www.betsson.com/en/reset-password/25afda03-d2a8-4829-997d-a23fb659f213`

### [VirusTotal Credential Submission] www.capcut.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: marketing@emvida.com:2546393`
- **URL:** `https://www.capcut.com/editor-graphic/:marketing@emvida.com:2546393`

### [Password_Reset_UUID] auth.ripio.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **URL:** `https://auth.ripio.com/api/users/reset-password/be1e2273-7030-4867-a042-b3fb97a76bd8`

### [Password_Reset_UUID] auth.ripio.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **URL:** `https://auth.ripio.com/api/users/reset-password/cd128512-6cf1-4d0a-af4d-d367ea377d12/?redirect_url=https://app.ripio.com`

### [Password_Reset_UUID] auth.ripio.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **URL:** `https://auth.ripio.com/api/users/reset-password/be1e2273-7030-4867-a042-b3fb97a76bd8`

### [Password_Reset_UUID] auth.ripio.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **URL:** `https://auth.ripio.com/api/users/reset-password/cd128512-6cf1-4d0a-af4d-d367ea377d12/?redirect_url=https://app.ripio.com`

### [OAuth Token] api.x.com
- **Type:** `Token_Leak`
- **Severity:** CRITICAL
- **Evidence:** `oauth_token=DqHm5wAAAAABr2JBAAABnsjuoTk`
- **URL:** `https://api.x.com/oauth/authenticate?oauth_token=DqHm5wAAAAABr2JBAAABnsjuoTk`

### [JWT on Auth/Reset Endpoint] api.mercadolibre.com
- **Type:** `JWT_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `JWT in URL: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsIml...`
- **URL:** `https://api.mercadolibre.com/scarif-public/v2/public/consultants/verify-it-contact?Authorization=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcyNzMzNjQwOSwianRpIjoiMzk5Y2JjZTQtYm`

### [Plaintext Credentials] join.booking.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `PATH_CRED: mayhsu2277@hotmail.com:may18000`
- **URL:** `https://join.booking.com/:mayhsu2277@hotmail.com:may18000`

### [Plaintext Credentials] join.booking.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `PATH_CRED: +213659705035:Booking100%`
- **URL:** `https://join.booking.com/hotels/:+213659705035:Booking100%25`

### [JWT on Auth/Reset Endpoint] api.mercadolibre.com
- **Type:** `JWT_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `JWT in URL: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsIml...`
- **URL:** `https://api.mercadolibre.com/scarif-public/v2/public/consultants/verify-it-contact?Authorization=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcyNzMzNjQwOSwianRpIjoiMzk5Y2JjZTQtYm`

### [Plaintext Credentials] registration.mercadolibre.com.pe
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `PATH_CRED: 0992965357:12amor21`
- **URL:** `https://registration.mercadolibre.com.pe/registration/:0992965357:12amor21`

### [Plaintext Credentials] secure.newegg.ca
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `PATH_CRED: El3ctricfire@gmail.com:Guwan3400`
- **URL:** `https://secure.newegg.ca/:El3ctricfire@gmail.com:Guwan3400`

### [Plaintext Credentials] secure.newegg.ca
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `PATH_CRED: El3ctricfire@gmail.com:Guwan3400`
- **URL:** `https://secure.newegg.ca/:El3ctricfire@gmail.com:Guwan3400`

### [Password_Reset_UUID] luckydays.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `UUID reset token in path: d7e38f32-e565-4d5c-a239-6503cf812462`
- **URL:** `https://luckydays.com/reset-password/d7e38f32-e565-4d5c-a239-6503cf812462`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_SIMRwNdaVTFL4UjC2IMI6bzJGO2t42`
- **URL:** `https://api.moonpay.com/v3/accounts/me?apiKey=pk_live_SIMRwNdaVTFL4UjC2IMI6bzJGO2t42`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_9ErzRXE3ynNMGJADbpNQtV7NY8CjzODt`
- **URL:** `https://api.moonpay.com/v3/apple_pay/mid?apiKey=pk_live_9ErzRXE3ynNMGJADbpNQtV7NY8CjzODt&currencyCode=usd`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_zv3wHsP6d1TwIGu7lTcRQNehgac0BCn7`
- **URL:** `https://api.moonpay.com/v3/countries?apiKey=pk_live_zv3wHsP6d1TwIGu7lTcRQNehgac0BCn7`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_Ch5fat39X8NvMZwih2k7hK4sDrKanSPz`
- **URL:** `https://api.moonpay.com/v3/currencies//limits?apiKey=pk_live_Ch5fat39X8NvMZwih2k7hK4sDrKanSPz&baseCurrencyCode=&areFeesIncluded=true`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_hdXyQBAQgn9o6f30zI6CtAtb1VMEolC3`
- **URL:** `https://api.moonpay.com/v3/customers/email_login?apiKey=pk_live_hdXyQBAQgn9o6f30zI6CtAtb1VMEolC3`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_IdYWVj39NNgSrt2t9jBPSgwl9outsydU`
- **URL:** `https://api.moonpay.com/v3/experimentation/show_orion_buy?apiKey=pk_live_IdYWVj39NNgSrt2t9jBPSgwl9outsydU`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_fqMxq4UpqyIEK3q2WnNFVFitIo8ZlTk`
- **URL:** `https://api.moonpay.com/v3/google_pay/merchant_id?apiKey=pk_live_fqMxq4UpqyIEK3q2WnNFVFitIo8ZlTk&currencyCode=USD`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_HLPig9FCVWYUda8RcseeQ8HRAN7q6Y`
- **URL:** `https://api.moonpay.com/v3/ip_address?apiKey=pk_live_HLPig9FCVWYUda8RcseeQ8HRAN7q6Y&ipAddress=178.249.214.136`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_aOK8pD7AkGeG1KuI7JkHvBRk33KxA2in`
- **URL:** `https://api.moonpay.com/v3/nft/availability?apiKey=pk_live_aOK8pD7AkGeG1KuI7JkHvBRk33KxA2in&contractAddress=atomicassets&tokenId=453632&quantity=1`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_peeFrL579k4xnUInNRKrCfB8OeDZT`
- **URL:** `https://api.moonpay.com/v4/accounts/me?apiKey=pk_live_peeFrL579k4xnUInNRKrCfB8OeDZT`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_puB7IiSosfbzQ6fzeMGjCMh5tNoTe5hz`
- **URL:** `https://api.moonpay.com/v4/ip_address?apiKey=pk_live_puB7IiSosfbzQ6fzeMGjCMh5tNoTe5hz`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_57bXVZd9NAzdu0XfZsqoVwwRERUr4eFD`
- **URL:** `https://api.moonpay.com/v4/swap/pairs?apiKey=pk_live_57bXVZd9NAzdu0XfZsqoVwwRERUr4eFD`

### [Stripe Live Key] web3.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_R5Lf25uBfNZyKwccAZpzcxuL3ZdJ3Hc`
- **URL:** `https://web3.moonpay.com/?uxMode=no-ux&target=https://app.moonpay.com&apiKey=pk_live_R5Lf25uBfNZyKwccAZpzcxuL3ZdJ3Hc`

### [Stripe Live Key] auth.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_Gz4JNvlyET7mUKst0BaCupzvcEozQjL`
- **URL:** `https://auth.moonpay.com/?uxMode=prompt&target=https%3A%2F%2Fwallet-connect.moonpay.com&apiKey=pk_live_Gz4JNvlyET7mUKst0BaCupzvcEozQjL&headless=true&ethNetwork=1&noModal=false&legacyMode=false`

### [Stripe Live Key] buy.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_9ErzRXE3ynNMGJADbpNQtV7NY8CjzODt`
- **URL:** `https://buy.moonpay.com/?afsrc=1&partner=Etherscan&utm_content=Online+Tracking+Link_1682092&externalTransactionId=&irgwc=1&group=&utm_medium=affiliate&utm_campaign=19485&mpid=4732724&apiKey=pk_live_9E`

### [Stripe Live Key] buy.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_PrcGnaQchlCHiQknBR8HrkNw6tD3J1Q`
- **URL:** `https://buy.moonpay.com/changelly/?apiKey=pk_live_PrcGnaQchlCHiQknBR8HrkNw6tD3J1Q&defaultCurrencyCode=eth&baseCurrencyCode=ron&currencyCode=eth&baseCurrencyAmount=1000&externalTransactionId=712ba512-f`

### [Stripe Live Key] buy.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_fzb75PNGOvcKVjftUr0YT7qQssYbUFE`
- **URL:** `https://buy.moonpay.com/nft?colorCode=%232081E2&contractAddress=0x2953399124f0cbb46d2cbacd8a89cf0599974963&tokenId=16709622998206283444889905793257369455784749518796167057937201856302570012673&listing`

### [Stripe Live Key] buy.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_4y2NkGS1fM8ycr00TOhqv7P0JKEU1AM0`
- **URL:** `https://buy.moonpay.com/v2/buy?apiKey=pk_live_4y2NkGS1fM8ycr00TOhqv7P0JKEU1AM0&currencyCode=btc&baseCurrencyCode=eur&baseCurrencyAmount=10000&externalTransactionId=5ced4e68-3ec8-4b36-b0fc-5595d0fa8710`

### [Stripe Live Key] buy.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_odAiKKPImvIdrE4CJEpbouwx85M0KZL`
- **URL:** `https://buy.moonpay.com/web3-login?apiKey=pk_live_odAiKKPImvIdrE4CJEpbouwx85M0KZL&target=https%3A%2F%2Fconnect.priceless.com&web3-sdk=true&lng=de&themeId=9388a78e-4ba2-49f8-b283-2e55fa141d35`

### [Stripe Live Key] api.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_R5Lf25uBfNZyKwccAZpzcxuL3ZdJ3Hc`
- **URL:** `https://api.moonpay.com/v4/ip_address?apiKey=pk_live_R5Lf25uBfNZyKwccAZpzcxuL3ZdJ3Hc`

### [Stripe Live Key] sell.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_Tdc0BhIo7uIk8v9MOtWNxVJHr1WCEm`
- **URL:** `https://sell.moonpay.com/?apiKey=pk_live_Tdc0BhIo7uIk8v9MOtWNxVJHr1WCEm&language=pl&colorCode=%232FA761&baseCurrencyCode=doge`

### [Stripe Live Key] web3.moonpay.com
- **Type:** `Token_Leak`
- **Severity:** HIGH
- **Evidence:** `apikey=pk_live_odAiKKPImvIdrE4CJEpbouwx85M0KZL`
- **URL:** `https://web3.moonpay.com/?uxMode=prompt&target=https%3A%2F%2Fconnect.priceless.com&apiKey=pk_live_odAiKKPImvIdrE4CJEpbouwx85M0KZL&headless=true&themeId=9388a78e-4ba2-49f8-b283-2e55fa141d35&lng=de`


---
## 🟡 Tier 2 — Verify First

### API_Spec_Exposed (8 findings)
- `www.capcut.com` — API spec exposed: /openapi.yaml
- `api.metronome.com` — API spec exposed: /openapi.json
- `api.planet.com` — API spec exposed: /swagger.json
- `api.planet.com` — API spec exposed: /swagger.json
- `redocly.github.io` — API spec exposed: /openapi.yaml
- `usefathom.com` — API spec exposed: /openapi.json
- `www.capcut.com` — API spec exposed: /openapi.yaml
- `api.moonpay.com` — API spec exposed: /openapi.json

### Internal_IP_Reference (15 findings)
- `` — Internal IP 192.168.33.10 in URL params/path
- `` — Internal IP 10.1.1.2 in URL params/path
- `` — Internal IP 10.1.1.2 in URL params/path
- `` — Internal IP 10.133.0.16 in URL params/path
- `` — Internal IP 10.02.23.1 in URL params/path
- `` — Internal IP 192.168.188.1 in URL params/path
- `` — Internal IP 192.168.34.15 in URL params/path
- `` — Internal IP 192.168.34.15 in URL params/path
- `` — Internal IP 10.175.146.102 in URL params/path
- `` — Internal IP 10.147.74.203 in URL params/path
- ... and 5 more

### JWT_In_URL (55 findings)
- `account.krisp.ai` — JWT in URL: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzaWduIjoic3Ryb25nIiw...
- `account.krisp.ai` — JWT in URL: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpbnN0YWxsYXRpb25faWQ...
- `api.planet.com` — JWT in URL: eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTg0NzY1NTQ...
- `app.krisp.ai` — JWT in URL: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaWduIjoic3Ryb25nIiw...
- `console.byteplus.com` — JWT in URL: eyJhbGciOiJSUzI1NiIsImtpZCI6IjI1MDdmNTFhZjJhMTYyNDY3MDc0ODQ2...
- `www.capcut.com` — JWT in URL: eyJraWQiOiJmaDZCczhDIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwc...
- `cloud.elastic.co` — JWT in URL: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsZW5ndGgiOjMwfQ.G3Mg...
- `epicgames.com` — JWT in URL: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWNvdmVyeUlkIjoiQVI...
- `f-p-va.isnssdk.com` — JWT in URL: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGFuZGFyZF9jbGFpbXM...
- `f-p.sgsnssdk.com` — JWT in URL: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGFuZGFyZF9jbGFpbXM...
- ... and 45 more

### Token_Leak (180 findings)
- `account.krisp.ai` — JWT:jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzaWduIjoic...
- `account.krisp.ai` — JWT:jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpbnN0YWxsY...
- `api.planet.com` — JWT:token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3M...
- `cloud.elastic.co` — JWT:settings=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsZW5ndGgiO...
- `epicgames.com` — JWT:cancelToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWNvdmVye...
- `www.epicgames.com` — password=Aboussi660
- `www.epicgames.com` — JWT:token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0cmFja2luZ...
- `f-p-va.isnssdk.com` — JWT:fp_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGFuZGFyZ...
- `f-p.sgsnssdk.com` — JWT:fp_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGFuZGFyZ...
- `verification.kidswebservices.com` — JWT:token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6IC...
- ... and 170 more

---
## ⚪ Tier 3 — Low Priority
| Type | Count | Note |
|---|---|---|
| PII_Email_Leak | 398 | Mostly marketing/transactional email noise |
| IDOR_Endpoint | 100 | Requires manual verification of auth |
| Open_Redirect | 78 |  |
| Password_Reset_Token | 47 |  |
| Debug_Admin_Panel | 17 |  |
| Config_File_Exposed | 11 |  |
| PII_Data_Leak | 4 | Check if real PII or template |
| IDOR_Endpoints | 1 |  |

---
## ❌ Rejected (233 findings)
These match patterns HackerOne has consistently rejected:
- **Mobile attribution deep link**: 97 findings
- **Third-party email platform**: 64 findings
- **Email tracking link**: 49 findings
- **Invitation link (designed behavior)**: 20 findings
- **OAuth login_hint (standard)**: 3 findings
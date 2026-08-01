# 🎯 Deep Findings Triage Report

**Generated:** 2026-07-27 13:24
**Total findings:** 2434
**Exposed ports:** 3

## Summary
| Tier | Count | Action |
|---|---|---|
| 🔴 Tier 1 (Report Now) | 121 | Submit to HackerOne immediately |
| 🟡 Tier 2 (Verify First) | 1199 | Manually verify, then report |
| ⚪ Tier 3 (Low Priority) | 868 | Investigate if time permits |
| ❌ Rejected | 246 | Skip — HackerOne will reject |

---
## 🔴 Exposed Database & Infrastructure Ports (Tier 1)
> [!CAUTION]
> Unauthenticated database and management infrastructure ports (PostgreSQL, MySQL, Redis, MongoDB, Elastic, Docker API).

| IP | Port | Service | Domains |
|---|---|---|---|
| `35.71.185.205` | 5432 | PostgreSQL | rb-rivals-prod-p16.hmxservices.com, rb-rivals-prod.hmxservices.com |
| `89.161.254.244` | 5432 | PostgreSQL | kariera.itesco.cz |
| `35.214.204.16` | 5432 | PostgreSQL | blog.sketchfab.com |

---
## 🔴 Tier 1 — Report Now
> [!IMPORTANT]
> These findings have proven HackerOne acceptance. Report immediately.

### [VirusTotal Credential Submission] app.acorns.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: andrew@pianofutures.com:Tanker12`
- **URL:** `https://app.acorns.com/:andrew@pianofutures.com:Tanker12`

### [VirusTotal Credential Submission] signin.acorns.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: jarrodtr@buffalo.edu:Zbrother13`
- **URL:** `https://signin.acorns.com/:jarrodtr@buffalo.edu:Zbrother13`

### [VirusTotal Credential Submission] carrefour.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: fredi_lange@hotmail.com:carrefour3620`
- **URL:** `https://carrefour.com/:fredi_lange@hotmail.com:carrefour3620`

### [Plaintext Credentials] offex:znbhjl07s@soundcloud.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `BASIC_AUTH: offex:znbhjl07s`
- **URL:** `https://offex:znbhjl07s@soundcloud.com`

### [Plaintext Credentials] offex:znbhjl07s@soundcloud.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `BASIC_AUTH: offex:znbhjl07s`
- **URL:** `https://offex:znbhjl07s@soundcloud.com/.well-known/assetlinks.json`

### [OAuth Token] trello.com
- **Type:** `Token_Leak`
- **Severity:** CRITICAL
- **Evidence:** `oauth_token=2e4e3d9df6245c3172e673056b002cf3`
- **URL:** `https://trello.com/1/OAuthAuthorizeToken?expiration=never&name=FeatValue&oauth_token=2e4e3d9df6245c3172e673056b002cf3&response_type=fragment&scope=read%2Cwrite`

### [OAuth Token] trello.com
- **Type:** `Token_Leak`
- **Severity:** CRITICAL
- **Evidence:** `oauth_token=a3ad71e5bbf845897d9e2c0a42c44d58`
- **URL:** `https://trello.com/1/authorize?name=Favro&scope=read&expiration=never&oauth_token=a3ad71e5bbf845897d9e2c0a42c44d58`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: Wtonfernandes@hotmail.com:2675@1428`
- **URL:** `https://account.acronis.com/:Wtonfernandes@hotmail.com:2675@1428`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: accesyomama@gmail.com:Fluffy43961`
- **URL:** `https://account.acronis.com/:accesyomama@gmail.com:Fluffy43961`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: atabil@gmail.com:Ne23121964`
- **URL:** `https://account.acronis.com/:atabil@gmail.com:Ne23121964`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: gastoncomunello@hotmail.com:5030taviotos`
- **URL:** `https://account.acronis.com/:gastoncomunello@hotmail.com:5030taviotos`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: khalilmohtaratgannage@gmail.com:khalil@123456`
- **URL:** `https://account.acronis.com/:khalilmohtaratgannage@gmail.com:khalil@123456`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: p.vijesh@techgroup.ae:Pvv@2008`
- **URL:** `https://account.acronis.com/:p.vijesh@techgroup.ae:Pvv@2008`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: reginaldo.garibalde@gmail.com:@Regis2021`
- **URL:** `https://account.acronis.com/:reginaldo.garibalde@gmail.com:@Regis2021`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: will81279@gmail.com:.G$.tM726kE!XYe`
- **URL:** `https://account.acronis.com/:will81279@gmail.com:.G$.tM726kE!XYe`

### [VirusTotal Credential Submission] account.magento.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: alphadev@randevteam.com:Sasuke49505`
- **URL:** `https://account.magento.com/applications/customer/create/:alphadev@randevteam.com:Sasuke49505`

### [VirusTotal Credential Submission] account.magento.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: alexisemond09@gmail.com:thug-`
- **URL:** `https://account.magento.com/customer/account/create/:alexisemond09@gmail.com:thug-`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: Wtonfernandes@hotmail.com:2675@1428`
- **URL:** `https://account.acronis.com/:Wtonfernandes@hotmail.com:2675@1428`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: accesyomama@gmail.com:Fluffy43961`
- **URL:** `https://account.acronis.com/:accesyomama@gmail.com:Fluffy43961`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: atabil@gmail.com:Ne23121964`
- **URL:** `https://account.acronis.com/:atabil@gmail.com:Ne23121964`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: gastoncomunello@hotmail.com:5030taviotos`
- **URL:** `https://account.acronis.com/:gastoncomunello@hotmail.com:5030taviotos`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: khalilmohtaratgannage@gmail.com:khalil@123456`
- **URL:** `https://account.acronis.com/:khalilmohtaratgannage@gmail.com:khalil@123456`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: p.vijesh@techgroup.ae:Pvv@2008`
- **URL:** `https://account.acronis.com/:p.vijesh@techgroup.ae:Pvv@2008`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: reginaldo.garibalde@gmail.com:@Regis2021`
- **URL:** `https://account.acronis.com/:reginaldo.garibalde@gmail.com:@Regis2021`

### [VirusTotal Credential Submission] account.acronis.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: will81279@gmail.com:.G$.tM726kE!XYe`
- **URL:** `https://account.acronis.com/:will81279@gmail.com:.G$.tM726kE!XYe`

### [OAuth Token] api.x.com
- **Type:** `Token_Leak`
- **Severity:** CRITICAL
- **Evidence:** `oauth_token=DqHm5wAAAAABr2JBAAABnsjuoTk`
- **URL:** `https://api.x.com/oauth/authenticate?oauth_token=DqHm5wAAAAABr2JBAAABnsjuoTk`

### [VirusTotal Credential Submission] adobeid-na1.services.adobe.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: berghe.fuhrmann@googlemail.com:Maus2701`
- **URL:** `https://adobeid-na1.services.adobe.com/:berghe.fuhrmann@googlemail.com:Maus2701`

### [VirusTotal Credential Submission] adobeid-na1.services.adobe.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: eldrickkeona@gmail.com:0217758372aBc`
- **URL:** `https://adobeid-na1.services.adobe.com/:eldrickkeona@gmail.com:0217758372aBc`

### [VirusTotal Credential Submission] adobeid-na1.services.adobe.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: kzius84@gmail.com:Cromax2253`
- **URL:** `https://adobeid-na1.services.adobe.com/:kzius84@gmail.com:Cromax2253`

### [VirusTotal Credential Submission] adobeid-na1.services.adobe.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: tangoaalcarazopierorayso@gmail.com:28tangoa`
- **URL:** `https://adobeid-na1.services.adobe.com/:tangoaalcarazopierorayso@gmail.com:28tangoa`

### [VirusTotal Credential Submission] tr.airbnb.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: ken150505@outlook.com:**askimsibelugur**`
- **URL:** `https://tr.airbnb.com/:ken150505@outlook.com:**askimsibelugur**`

### [VirusTotal Credential Submission] www.airbnb.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: johnmichael_laurio@yahoo.com:lauri01234`
- **URL:** `https://www.airbnb.com/:johnmichael_laurio@yahoo.com:lauri01234`

### [VirusTotal Credential Submission] www.airbnb.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: orhan.sabanac@gmail.com:jackat-pyfqun-7hekQa`
- **URL:** `https://www.airbnb.com/:orhan.sabanac@gmail.com:jackat-pyfqun-7hekQa`

### [Password_Reset_UUID] zh.airbnb.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `UUID reset token in path: 29ca860e-8149-4076-bc1d-35daa840e9e9`
- **URL:** `https://zh.airbnb.com/wishlists/invite/29ca860e-8149-4076-bc1d-35daa840e9e9?s=67&unique_share_id=d27ed89d-297b-4905-bc9f-404e04290f09`

### [JWT on Auth/Reset Endpoint] api.mercadolibre.com
- **Type:** `JWT_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `JWT in URL: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsIml...`
- **URL:** `https://api.mercadolibre.com/scarif-public/v2/public/consultants/verify-it-contact?Authorization=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcyNzMzNjQwOSwianRpIjoiMzk5Y2JjZTQtYm`

### [Password_Reset_UUID] auth.ripio.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **URL:** `https://auth.ripio.com/api/users/reset-password/be1e2273-7030-4867-a042-b3fb97a76bd8`

### [Password_Reset_UUID] auth.ripio.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **URL:** `https://auth.ripio.com/api/users/reset-password/cd128512-6cf1-4d0a-af4d-d367ea377d12/?redirect_url=https://app.ripio.com`

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

### [VirusTotal Credential Submission] www.capcut.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: marketing@emvida.com:2546393`
- **URL:** `https://www.capcut.com/editor-graphic/:marketing@emvida.com:2546393`

### [VirusTotal Credential Submission] zh.chaturbate.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `PHONE_CRED_IN_PATH: 2162324301:hhzz200103011234`
- **URL:** `https://zh.chaturbate.com/:2162324301:hhzz200103011234`

### [VirusTotal Credential Submission] webmail.elisa.fi
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: tarja.elijoki@elisanet.fi:syrjala83`
- **URL:** `https://webmail.elisa.fi/:tarja.elijoki@elisanet.fi:syrjala83`

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

### [VirusTotal Credential Submission] intl.garena.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: dsmpunk1@gmail.com:fitlife1`
- **URL:** `http://intl.garena.com/login_ui/:dsmpunk1@gmail.com:fitlife1`

### [VirusTotal Credential Submission] account.garena.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: kitsakron2008@gmail.com:5357876899`
- **URL:** `https://account.garena.com/:kitsakron2008@gmail.com:5357876899`

### [VirusTotal Credential Submission] authgop.garena.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: apiwat1901@gmail.com:lopez44210`
- **URL:** `https://authgop.garena.com/:apiwat1901@gmail.com:lopez44210`

### [VirusTotal Credential Submission] authgop.garena.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: p0983669739@gmail.com:ks08190614`
- **URL:** `https://authgop.garena.com/:p0983669739@gmail.com:ks08190614`

### [Password_Reset_UUID] ge.betsson.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `UUID reset token in path: 40f410cb-8d60-4900-b45e-fc44b4534f78`
- **URL:** `https://ge.betsson.com/ka/reset-password/40f410cb-8d60-4900-b45e-fc44b4534f78`

### [Plaintext Credentials] adcdpv8:glpat-d0fi4mqxv0syyo3abz_chg86mqp1ojfpazek.01.1005140vn@gitlab.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `BASIC_AUTH: ADCDPV8:glpat-d0fI4mQXv0sYYO3abz_chG86`
- **URL:** `https://ADCDPV8:glpat-d0fI4mQXv0sYYO3abz_chG86MQp1OjFpazEK.01.1005140vn@gitlab.com/goo/goo-08/wealth-account-center.git`

### [VirusTotal Credential Submission] merchant.grab.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: beedv2565@gmail.com:a507b55`
- **URL:** `https://merchant.grab.com/:beedv2565@gmail.com:a507b55`

### [VirusTotal Credential Submission] merchant.grab.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: graburt293@gmail.com:51e00f1`
- **URL:** `https://merchant.grab.com/:graburt293@gmail.com:51e00f1`

### [Password_Reset_UUID] public.grab.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `token=60196bca-6f24-4d77-8886-a3af8290d062 (UUID reset token)`
- **URL:** `https://public.grab.com/emails/verify?lang=en&token=60196bca-6f24-4d77-8886-a3af8290d062`

### [Password_Reset_UUID] webauth.grab.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `token=efdc7562-8b34-4857-b927-6d9302b70f2b (UUID reset token)`
- **URL:** `https://webauth.grab.com/confirmations/report?lang=en&token=efdc7562-8b34-4857-b927-6d9302b70f2b`

### [Password_Reset_UUID] webauth.grab.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `token=bda502db-3a26-4464-a5c6-833b9101ccff (UUID reset token)`
- **URL:** `https://webauth.grab.com/confirmations/verify?lang=en&token=bda502db-3a26-4464-a5c6-833b9101ccff`

### [Password_Reset_UUID] webauth.grab.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `token=4db633fa-0006-4f80-828f-56a0c31ee1f7 (UUID reset token)`
- **URL:** `https://webauth.grab.com/emails/reset-pin?lang=en&token=4db633fa-0006-4f80-828f-56a0c31ee1f7`

### [Password_Reset_Param] intensedebate.com
- **Type:** `Password_Reset_Param`
- **Severity:** CRITICAL
- **Evidence:** `token=8aa2c19386a996fcf2b31188993207833a4e592f`
- **URL:** `https://intensedebate.com/reset-password?uid=41760500&token=8aa2c19386a996fcf2b31188993207833a4e592f`

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

### [Password_Reset_UUID] luckydays.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **Evidence:** `UUID reset token in path: d7e38f32-e565-4d5c-a239-6503cf812462`
- **URL:** `https://luckydays.com/reset-password/d7e38f32-e565-4d5c-a239-6503cf812462`

### [VirusTotal Credential Submission] account.magento.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: alphadev@randevteam.com:Sasuke49505`
- **URL:** `https://account.magento.com/applications/customer/create/:alphadev@randevteam.com:Sasuke49505`

### [VirusTotal Credential Submission] account.magento.com
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `EMAIL_CRED_IN_PATH: alexisemond09@gmail.com:thug-`
- **URL:** `https://account.magento.com/customer/account/create/:alexisemond09@gmail.com:thug-`

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

### [Password_Reset_UUID] auth.ripio.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **URL:** `https://auth.ripio.com/api/users/reset-password/be1e2273-7030-4867-a042-b3fb97a76bd8`

### [Password_Reset_UUID] auth.ripio.com
- **Type:** `Password_Reset_UUID`
- **Severity:** CRITICAL
- **URL:** `https://auth.ripio.com/api/users/reset-password/cd128512-6cf1-4d0a-af4d-d367ea377d12/?redirect_url=https://app.ripio.com`

### [Plaintext Credentials] secure.newegg.ca
- **Type:** `Credential_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `PATH_CRED: El3ctricfire@gmail.com:Guwan3400`
- **URL:** `https://secure.newegg.ca/:El3ctricfire@gmail.com:Guwan3400`

### [JWT on Auth/Reset Endpoint] api.adanalytics.spotify.com
- **Type:** `JWT_In_URL`
- **Severity:** CRITICAL
- **Evidence:** `JWT in URL: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl9pZCI6IjYyZTB...`
- **URL:** `https://api.adanalytics.spotify.com/verify?p=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl9pZCI6IjYyZTBjOTA2YzQ3ZDQxMjFiNTk0YjQzMjM1OTNjMmQzIn0.3YPLPQc1olyXG5vv3Y55s-yfq-hr4jk6gXXMCdW9teQ`

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

### [Cloud_Metadata_SSRF] unknown
- **Type:** `Cloud_Metadata_SSRF`
- **Severity:** CRITICAL
- **Evidence:** `AWS/Azure metadata endpoint`
- **URL:** `http://169.254.169.254/metadata/instance/compute/location`

### [Cloud_Metadata_SSRF] unknown
- **Type:** `Cloud_Metadata_SSRF`
- **Severity:** CRITICAL
- **Evidence:** `AWS/Azure metadata endpoint`
- **URL:** `http://169.254.169.254/metadata/instance/compute/location`

### [Cloud_Metadata_SSRF] unknown
- **Type:** `Cloud_Metadata_SSRF`
- **Severity:** CRITICAL
- **Evidence:** `AWS/Azure metadata endpoint`
- **URL:** `http://169.254.169.254/metadata/instance/compute/location`

### [Cloud_Metadata_SSRF] unknown
- **Type:** `Cloud_Metadata_SSRF`
- **Severity:** CRITICAL
- **Evidence:** `AWS/Azure metadata endpoint`
- **URL:** `http://169.254.169.254/metadata/instance/compute/location`

### [Cloud_Metadata_SSRF] unknown
- **Type:** `Cloud_Metadata_SSRF`
- **Severity:** CRITICAL
- **Evidence:** `AWS/Azure metadata endpoint`
- **URL:** `http://169.254.169.254/metadata/instance/compute/location`

### [Cloud_Metadata_SSRF] unknown
- **Type:** `Cloud_Metadata_SSRF`
- **Severity:** CRITICAL
- **Evidence:** `AWS/Azure metadata endpoint`
- **URL:** `http://169.254.169.254/metadata/instance/compute/location`

### [Cloud_Metadata_SSRF] unknown
- **Type:** `Cloud_Metadata_SSRF`
- **Severity:** CRITICAL
- **Evidence:** `AWS/Azure metadata endpoint`
- **URL:** `http://169.254.169.254/metadata/instance/compute/location`

### [Cloud_Metadata_SSRF] unknown
- **Type:** `Cloud_Metadata_SSRF`
- **Severity:** CRITICAL
- **Evidence:** `AWS/Azure metadata endpoint`
- **URL:** `http://169.254.169.254/metadata/instance/compute/location`

### [Cloud_Metadata_SSRF] unknown
- **Type:** `Cloud_Metadata_SSRF`
- **Severity:** CRITICAL
- **Evidence:** `AWS/Azure metadata endpoint`
- **URL:** `http://169.254.169.254/metadata/instance/compute/location`

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

### API_Spec_Exposed (19 findings)
- `advisories.gitlab.com` — API spec exposed: /swagger-ui
- `advisories.gitlab.com` — API spec exposed: /swagger-ui
- `demo.backstage.io` — API spec exposed: /api-docs
- `www.capcut.com` — API spec exposed: /openapi.yaml
- `nexum.clay.earth` — API spec exposed: /openapi.yaml
- `planet.clay.earth` — API spec exposed: /openapi.yaml
- `api.prime.coinbase.com` — API spec exposed: /openapi.yaml
- `gitlab.com` — API spec exposed: /openapi.yaml
- `petstore.swagger.io` — API spec exposed: /swagger.json
- `repo.humio.com` — API spec exposed: /swagger.json
- ... and 9 more

### Cloud_Storage_Exposure (3 findings)
- `s3-conveyor.didiglobal.com` — Pre-signed S3 URL (bucket: unknown)
- `s3-us01.didiglobal.com` — Pre-signed S3 URL (bucket: unknown)
- `s3-us01.didiglobal.com` — Pre-signed S3 URL (bucket: unknown)

### Internal_IP_Reference (70 findings)
- `` — Internal IP 10.105.255.137 in URL params/path
- `` — Internal IP 10.44.16.55 in URL params/path
- `` — Internal IP 10.44.17.105 in URL params/path
- `` — Internal IP 10.44.17.140 in URL params/path
- `` — Internal IP 10.44.16.216 in URL params/path
- `` — Internal IP 10.44.17.127 in URL params/path
- `` — Internal IP 10.44.16.55 in URL params/path
- `` — Internal IP 10.44.17.105 in URL params/path
- `` — Internal IP 10.44.17.140 in URL params/path
- `` — Internal IP 10.44.16.216 in URL params/path
- ... and 60 more

### JWT_In_URL (105 findings)
- `bank-docs.acorns.com` — JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b21lcklkIjoxMDA... | Expired 1
- `click.email.chipotle.com` — JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtaWQiOiI1MTQwMDA2ODU...
- `my.elementor.com` — JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpbnN0YW5jZUlkIjoiNmE...
- `click.email.empower.com` — JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtaWQiOiI2MzI1MzA0Iiw...
- `support-personalwealth.empower.com` — JWT: eyJhbGciOiJIUzI1NiJ9.eyJhY2NvdW50X2lkIjo4NDk1MiwidXNlcl9pZCI... | Expired 4
- `account.irobot.com` — JWT: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik9UQkNSamxETVVZ... | Expired 2
- `conta.nubank.com.br` — JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIwMTUtMTItMDRU... | Expired 1
- `click.email.personalcapital.com` — JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtaWQiOiI2NDI0OTUwIiw...
- `support.personalcapital.com` — JWT: eyJhbGciOiJIUzI1NiJ9.eyJhY2NvdW50X2lkIjo4NDk1MiwidXNlcl9pZCI... | Expired 1
- `stspg-jira-ops.statuspage.io` — JWT: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJxc2giOiI1YTc4ZmJkNDV... | Expired 1
- ... and 95 more

### Metrics_Endpoint (23 findings)
- `app.netlify.com` — /metrics (Prometheus -- may expose topology/secrets)
- `docs.bionic.ai` — /metrics (Prometheus -- may expose topology/secrets)
- `accounts.coinbase.com` — /metrics (Prometheus -- may expose topology/secrets)
- `app.analytics.coinbase.com` — /metrics (Prometheus -- may expose topology/secrets)
- `as.coinbase.com` — /metrics (Prometheus -- may expose topology/secrets)
- `cbam.coinbase.com` — /metrics (Prometheus -- may expose topology/secrets)
- `cca-lite.coinbase.com` — /metrics (Prometheus -- may expose topology/secrets)
- `cde.coinbase.com` — /metrics (Prometheus -- may expose topology/secrets)
- `exceptions.coinbase.com` — /metrics (Prometheus -- may expose topology/secrets)
- `exchange.coinbase.com` — /metrics (Prometheus -- may expose topology/secrets)
- ... and 13 more

### Staging_Environment (731 findings)
- `00000-okta-idp.blogmonboardingsandbox.test.build.acorns.com` — Staging/test environment: 00000-okta-idp.blogmonboardingsandbox.test.build.acorn
- `45.dev.00203-okta-idp.www.gac.build.acorns.com` — Staging/test environment: 45.dev.00203-okta-idp.www.gac.build.acorns.com (contai
- `qa-visit.acorns.com` — Staging/test environment: qa-visit.acorns.com (prefix: qa)
- `qa-visit.acorns.com` — Staging/test environment: qa-visit.acorns.com (prefix: qa)
- `qa-visit.acorns.com` — Staging/test environment: qa-visit.acorns.com (prefix: qa)
- `qa-visit.acorns.com` — Staging/test environment: qa-visit.acorns.com (prefix: qa)
- `qa-visit.acorns.com` — Staging/test environment: qa-visit.acorns.com (prefix: qa)
- `qa-visit.acorns.com` — Staging/test environment: qa-visit.acorns.com (prefix: qa)
- `qa-visit.acorns.com` — Staging/test environment: qa-visit.acorns.com (prefix: qa)
- `qa-visit.acorns.com` — Staging/test environment: qa-visit.acorns.com (prefix: qa)
- ... and 721 more

### Token_Leak (248 findings)
- `atlassian.zoom.us` — pwd=Nlc1S3ZMazkrUUp2VFlweHhXTndrZz
- `my.elementor.com` — JWT:state[access_jwt]=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpbnN0YW5jZ...
- `support-personalwealth.empower.com` — JWT:auth_token=eyJhbGciOiJIUzI1NiJ9.eyJhY2NvdW50X2lkIjo4NDk1Miwid...
- `account.irobot.com` — JWT:context=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik9UQk...
- `support.personalcapital.com` — JWT:auth_token=eyJhbGciOiJIUzI1NiJ9.eyJhY2NvdW50X2lkIjo4NDk1Miwid...
- `stspg-jira-ops.statuspage.io` — JWT:jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJxc2giOiI1Y...
- `trello.com` — JWT:signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE1O...
- `trello.com` — JWT:token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZE1lbWJlc...
- `www.viator.com` — JWT:raToken=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJlIjoiTUVNL...
- `wise.com` — JWT:preferences-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlZGl0YWJsZ...
- ... and 238 more

---
## ⚪ Tier 3 — Low Priority
| Type | Count | Note |
|---|---|---|
| PII_Email_Leak | 495 | Mostly marketing/transactional email noise |
| IDOR_Endpoint | 211 | Requires manual verification of auth |
| Open_Redirect | 78 |  |
| Password_Reset_Token | 47 |  |
| Debug_Admin_Panel | 17 |  |
| Config_File_Exposed | 11 |  |
| PII_Data_Leak | 8 | Check if real PII or template |
| IDOR_Endpoints | 1 |  |

---
## ❌ Rejected (246 findings)
These match patterns HackerOne has consistently rejected:
- **Mobile attribution deep link**: 97 findings
- **Third-party email platform**: 64 findings
- **Email tracking link**: 59 findings
- **Invitation link (designed behavior)**: 23 findings
- **OAuth login_hint (standard)**: 3 findings
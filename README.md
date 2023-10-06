# Kakaotalk 10.3.7 Analysis

- [Setup](#setup)
- [Recon](#recon)
- [Findings](#findings)

## Setup

See [here](SETUP.md).

## Recon

See [here](RECON.md).

## Findings

### TO-DOs

- Find a proxy Activity to start `MyProfileSettingsActivity` -> steal token
- Find a `setResult()` call to access `content://com.kakao.talk.FileProvider`
- Test Secret Chat interception with `mitmproxy` script
  * Use value from `pt` field to compute the nonce
  * Does a warning pop up?
  * What about the master secret?
- Test CFB bit flipping
- Create a `Plus Friend` or `Kakao Business` page or an `Open Chat Room` to deliver malicious JS
- Connect with Sergey Toshin
- Check out https://github.com/oversecured/ovaa
- I can load URLs in `CommerceShopperWebViewActivity` and `KGPopupActivity` -> check for vulns
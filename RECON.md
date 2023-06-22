# Recon

- [Related Work](#related-work)
- [Possible Vectors](#possible-attack-vectors)
  - [Registration and Login](#registration-and-login)
  - [Cloud](#cloud)
  - [LOCO Protocol Attackss](#loco-protocol-attacks)
  - [Message Parsing](#message-parsing-zero-click)
  - [Malicious App](#malicious-third-party-app)
  - [Operator-side Attacks](#operator-side-attacks)
- [General Infos](#general-infos)
- [Files](#files)
- [Rest APIs](#rest-apis)
- [WebViews](#webviews)
- [Firebase](#firebase)
- [Intents](#intents)
- [Native Libs](#native-libs)
- [Open-Source Libs](#open-source-libs)
- [Crypto](#crypto)
  - [E2E](#e2e)

## Related Work

How things work:

- [Kakaotalk Messaging Architecture](https://kth.diva-portal.org/smash/get/diva2:1046438/FULLTEXT01.pdf#page=75)
- [User Registration and Login](https://kth.diva-portal.org/smash/get/diva2:1046438/FULLTEXT01.pdf#page=79)
- [LOCO protocol](https://kth.diva-portal.org/smash/get/diva2:1046438/FULLTEXT01.pdf#page=77)

Flaws:

- [Protocol flaws](https://kth.diva-portal.org/smash/get/diva2:1046438/FULLTEXT01.pdf#page=100)
- [App security flaws](https://kth.diva-portal.org/smash/get/diva2:1046438/FULLTEXT01.pdf#page=105)

## Possible Attack Vectors

### Registration and Login

- Register an attacker's device to the victim's KakaoTalk account
    - Get victims account credentials email/pw (e.g., via a data dump on breached.vc)
    - Brute-force 4-digit pin
- Intercept SMS during registration to get the pincode (e.g., via SS7 access)
- Register an attacker's device via flaws in the LOCO protocol (`CHECKIN` and `LOGINLIST` commands?)
- Check out insecure REST API endpoints for authorization flaws
  - Code injection into insecure REST API endpoints
- QR Code login (`xm.a` and `vm.q` Java classes)
	- `/talk/account/qrCodeLogin/info.json?id=eyJwcm90b2NvbCI6InYxIiwiY2hhbGxlbmdlIjoiNlB6MFMzdkRQMmlFUTZoRXh5YW5mWGtOelNHU0RRIn0=`
	- `{"protocol":"v1","challenge":"6Pz0S3vDP2iEQ6hExyanfXkNzSGSDQ"}`
		- `m.w.R1` method computes a MAC of the challenge
		- The OAuth Refresh Token seems to be the MAC key
			- How to obtain them? How are they generated? How long do they live?
			- `ym.a` class builds the POST request
	- API endpoints in interface `e31.j`
- Test PW Reset Functionality

### Cloud

- Cloud back-up (weak password)
  - Secret Chat messages won’t be stored
- Tamper with plaintext asset downloads via HTTP (parser attacks on the client possible?)

### LOCO Protocol Attacks

- Spoof victim (`CHECKIN` packet)
  - Spoof victim’s device ID (**TODO**: How is it generated?)
- Spoof KakaoTalk server
  - Spoof legitimate KakaoTalk LOCO notifications and messages
  - Send the attacker's public key to the victim (maybe there’s a LOCO command for updating RSA public keys on the client?)
  - MITM traffic
- Tamper messages (CFB malleability —> [Efail](https://jaads.de/Bachelorthesis/Bachelorthesis_Jan_Arends.pdf))
  - [Owncloud CFB malleability bug](https://blog.hboeck.de/archives/880-Pwncloud-bad-crypto-in-the-Owncloud-encryption-module.html)
  - Use the `LOGINLIST` command with `chatDatas`, `attachment` or `code` JSON fields to run code on the client app?
- Replay messages
- Drop messages
- Sniff plaintext LOCO packets (`CHECKIN` packet)
- Downgrade attacks (maybe there's a way to fallback to unencrypted comms?)

### LOCO Message Parsing ("Zero Click")

- **TODO**: Build Kakaotalk Python app
- Send a chat message to a victim to retrieve the E2E encryption key -> code injection
  - URL rendering
  - Calendar invite rendering
  - Emojis
  - Button rendering
  - Intents
- Exploit (JSON) deserialization bugs

### Malicious third-party app

- Install a malcious app on the victim's device to retrieve the E2E key via IPC
  - Send malicious intents (code injection)
  - Spoof the Kakaotalk app

### Operator-side Attacks

- Operator-side MITM (e.g., by changing public keys)

## General App Infos

```
Package name: com.kakao.talk
Version: 10.1.7
SHA256: 8a27e29ba35a06ec9a997260bad6f28cd181fecd6fc9abb71986f2716d18232f
Main Activity: com.kakao.talk.activity.SplashActivity
```

## Files

File directories:

```
Name                    Path
----------------------  ----------------------------------------------------------
cacheDirectory          /data/user/0/com.kakao.talk/cache
codeCacheDirectory      /data/user/0/com.kakao.talk/code_cache
externalCacheDirectory  /storage/emulated/0/Android/data/com.kakao.talk/cache
filesDirectory          /data/user/0/com.kakao.talk/files
obbDir                  /storage/emulated/0/Android/obb/com.kakao.talk
packageCodePath         /data/app/com.kakao.talk-wRI5HzbljAi9o-6SZLN55g==/base.apk
```

Monitor file system access: `$ frida -U --codeshare FrenchYeti/android-file-system-access-hook -f com.kakao.talk`

Shared Preferences:

```
FirebaseHeartBeatW0RFRkFVTFRd+MTo1NTIzNjczMDMxMzc6YW5kcm9pZDpiNjUwZmVmOGI2MDY1MzVm.xml
KakaoTalk.Qr.preferences.xml
KakaoTalk.bg.perferences.xml
KakaoTalk.calendar.preferences.xml
KakaoTalk.drawer.preferences.xml
KakaoTalk.fcm.xml
KakaoTalk.hw.perferences.xml
KakaoTalk.jordy.preferences.xml
KakaoTalk.locoLog.xml
KakaoTalk.more.perferences.xml
KakaoTalk.multiprofile.preferences.xml
KakaoTalk.music.preferences.xml
KakaoTalk.notification.channel_revision.xml
KakaoTalk.plusfriend.preference.xml
KakaoTalk.profile.preferences.xml
KakaoTalk.search.preferences.xml
KakaoTalk.shop.perferences.xml
KakaoTalk.vox.perferences.xml
KakaoTalk.warehouse.preferences.xml
WebViewChromiumPrefs.xml
com.google.android.gms.appid.xml
com.google.android.gms.measurement.prefs.xml
com.google.firebase.crashlytics.xml
com.kakao.adfit.preference.xml
com.kakao.talk_tiara.xml
d0ede325b798076919f0012eba6dab8b.xml
kakao.talk.item.store.preferences.xml
kakao.talk.openlink.preferences.xml
kakaotalk.cache.xml
talk_pass_preferences.xml
tiaraAB.xml
voiceMode.xml
zzng.xml
```

Some values (e.g., OAuth tokens) in the Shared Preferences are encrypted with a static key which is derived from a hard-coded passphrase (can be found in class `SimpleCipher`).

**TO-DO**: Check Shared Prefs for sensitive information.

Trace Shared Prefs usage with this [Frida script](https://github.com/m0bilesecurity/Frida-Mobile-Scripts/blob/master/Android/shared_preferences_monitor.js). See [example trace](./recon/frida_trace_shared_prefs.log).

SQL databases (in `/data/user/0/com.kakao.talk/databases`):

```
KakaoTalk.db
KakaoTalk2.db                   
calendar_database
com.google.android.datatransport.events
crypto_database (password protected)
google_app_measurement_local.db
kakao_talk_pass.db
multi_profile_database.db
```

One can decrypt the contents of `KakaoTalk.db` and `KakaoTalk2.db` with this [script](https://github.com/jiru/kakaodecrypt).

**TO-DO**: Find the password for the `crypto_database`. Hook `TrustStore` or `sqlite3_key` after a fresh app install and before login. Implementation in `com.kakao.talk.database.CryptoDatabase`.

## Rest APIs

Most endpoints are HTTPS protected. Certs in the `assets/sdk` folder are used for certification pinning (see class `com.kakao.i.http.g.b`). 

Java interfaces with interesting Rest APIs (interface names generated by `jadx`): **TO-DO**: Add GET and POST requests. Use `sqlmap -r` to *fuzz* the Rest APIs.

Interesting classes:
```
com.kakao.p129i.appserver.AppApi
com.kakao.talk.net.retrofit.BackupRestoreService
com.kakao.talk.net.retrofit.service.AccountService
com.kakao.talk.net.retrofit.service.AccountTempTokenService
com.kakao.talk.net.retrofit.service.ChangePhoneNumberService
com.kakao.talk.net.retrofit.service.CreateAccountService
com.kakao.talk.net.retrofit.service.KakaoOAuthService
com.kakao.talk.net.retrofit.service.OAuth2Service
com.kakao.talk.net.retrofit.service.SettingsService
com.kakao.talk.net.retrofit.service.SubDeviceLoginService
e31.QRLoginService
e31.ReAuthService
p360hh.AuthApi
```

There are [Google API Keys](./recon/nuclei_keys_results.txt) which allow access to the Google Maps API. Unauthorized access might cost the company some money.

## WebViews

Cookies are encrypted with the hard-coded passphrase `KaKAOtalkForever`.

**TO-DO**: Check for interesting [WebViews](./recon/nuclei_android_results.txt).

## Firebase

Firebase Crashlytics files in `/data/data/com.kakao.talk/files/.com.google.firebase.crashlytics.files.v2:com.kakao.talk/` folder.

Tokens and URLs:

- AppID: `1:552367303137:android:b650fef8b606535f`
- X-Goog-Api-Key: `AIzaSyD_-GTX7erjDNQ1UhkdesbAu98lej9MfWs`
- X-Firebase-Client: `H4sIAAAAAAAAAKtWykhNLCpJSk0sKVayio7VUSpLLSrOzM9TslIyUqoFAFyivEQfAAAA`
- X-Android-Cert: `ECC45B902AC1E83C8BE1758A257E67492DE37456`
- https://api-project-552367303137.firebaseio.com
- https://firebaseinstallations.googleapis.com/v1/projects/api-project-552367303137/installations (main Java class -> `FirebaseInstallationServiceClient`)

Fetch the Firebase Installation config:

```bash
curl -i -s -k -X $'POST' \
    -H $'Content-Type: application/json' -H $'Accept: application/json' -H $'Content-Encoding: gzip' -H $'Cache-Control: no-cache' -H $'X-Android-Package: com.kakao.talk' -H $'x-firebase-client: H4sIAAAAAAAAAKtWykhNLCpJSk0sKVayio7VUSpLLSrOzM9TslIyUqoFAFyivEQfAAAA' -H $'X-Android-Cert: ECC45B902AC1E83C8BE1758A257E67492DE37456' -H $'x-goog-api-key: AIzaSyD_-GTX7erjDNQ1UhkdesbAu98lej9MfWs' -H $'User-Agent: Dalvik/2.1.0 (Linux; U; Android 11; sdk_gphone_arm64 Build/RSR1.210722.002)' -H $'Host: firebaseinstallations.googleapis.com' -H $'Connection: close' -H $'Accept-Encoding: gzip, deflate' -H $'Content-Length: 134' \
    --data-binary $'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00\xabVJ\xcbLQ\xb2RJK\xf1\xb1\x08,\xaap\x0c\x0at/(O\x0fJ\xf1\xf3\xb0L\x09\x0fW\xd2QJ,(\xf0\x04)0\xb4255263760646\xb7J\xccK)\xca\xcfL\xb1J235HKM\xb3H230356M\x03\xe9(-\xc9\x08K-*\xce\xcc\xcf\x03\xeas\xf3\x0c\x8e/3\x02\x0a\x17\xa7d#D\x13\xad\x0c\xcd\xf5\x0c\xf5\x0c\x94j\x01[|19\x81\x00\x00\x00' \
    $'https://firebaseinstallations.googleapis.com/v1/projects/api-project-552367303137/installations'
```

The returned token (`authToken` / `X-Goog-Firebase-Installations-Auth`) can be used to get another token from `https://android.apis.google.com/c2dm/register3`:

```bash
curl -i -s -k -X $'POST' \
    -H $'Authorization: AidLogin 3678923725820734353:3828286260350902544' -H $'app: com.kakao.talk' -H $'gcm_ver: 201817019' -H $'User-Agent: Android-GCM/1.5 (emulator_arm64 RSR1.210722.002)' -H $'Content-Length: 810' -H $'content-type: application/x-www-form-urlencoded' -H $'Host: android.apis.google.com' -H $'Connection: Keep-Alive' -H $'Accept-Encoding: gzip, deflate' \
    --data-binary $'X-subtype=552367303137&sender=552367303137&X-app_ver=2410170&X-osv=30&X-cliv=fcm-23.1.0&X-gmsv=201817019&X-appid=fdL8QrxARQGpwgRdNH9dWW&X-scope=*&X-Goog-Firebase-Installations-Auth=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBJZCI6IjE6NTUyMzY3MzAzMTM3OmFuZHJvaWQ6YjY1MGZlZjhiNjA2NTM1ZiIsImV4cCI6MTY4Nzk1ODU0OCwiZmlkIjoiZmRMOFFyeEFSUUdwd2dSZE5IOWRXVyIsInByb2plY3ROdW1iZXIiOjU1MjM2NzMwMzEzN30.AB2LPV8wRQIgV1u9VS6q7U_mBrGgJ0qAfP6qhujF2ID-KwCKKttnrowCIQDnJsxvUfFbDyIbiVdWB1q4yVgRPCCM5Cu41LRI9cbF2A&X-gmp_app_id=1%3A552367303137%3Aandroid%3Ab650fef8b606535f&X-firebase-app-name-hash=R1dAH9Ui7M-ynoznwBdw01tLxhI&X-app_ver_name=10.1.7&app=com.kakao.talk&device=3678923725820734353&app_ver=2410170&info=wzQNGm6LkccWQKri541rkWUlRk-YeRg&gcm_ver=201817019&plat=0&cert=ecc45b902ac1e83c8be1758a257e67492de37456&target_ver=31' \
    $'https://android.apis.google.com/c2dm/register3'
```

The Firebase Installation config is also stored locally in `/data/data/com.kakao.talk/files/PersistedInstallation.W0RFRkFVTFRd+MTo1NTIzNjczMDMxMzc6YW5kcm9pZDpiNjUwZmVmOGI2MDY1MzVm.json` file and exposed by `content://com.kakao.talk.FileProvider/onepass/PersistedInstallation.W0RFRkFVTFRd+MTo1NTIzNjczMDMxMzc6YW5kcm9pZDpiNjUwZmVmOGI2MDY1MzVm.json`.

KakaoTalk doesn't seem to use Firebase Remote Config (or they are using a different endpoint, e.g. `https://firebaseremoteconfig.googleapis.com/v1/projects/552367303137/remoteConfig`):

```bash
$ curl "https://firebaseremoteconfig.googleapis.com/v1/projects/552367303137/namespaces/firebase:fetch?key=AIzaSyD_-GTX7erjDNQ1UhkdesbAu98lej9MfWs" -H 'content-type:application/json' -d '{"appId": "1:552367303137:android:b650fef8b606535f","appInstanceId": "required_but_unused_value"}'
```

## Intents

**TO-DO**: Check for interesting [Intents](./recon/nuclei_android_results.txt).

There are many many (exported) Activities, Services, Content Providers and Broadcast Receivers.

## Native Libs

**TO-DO**: Check for memory corruption bugs in native libs (located in `/data/app/com.kakao.talk-wRI5HzbljAi9o-6SZLN55g==/lib/arm64`):

```bash
libACExternalCore.so            libc++_shared.so                libopencv_java4.so
libDSToolkitV30Jni.so           libdialoid-apklib.so            libpl_droidsonroids_gif.so
libDaumMapEngineApi.so          libdigitalitem_image_decoder.so librenderscript-toolkit.so
libFaceprintex.so               libdiskusage.so                 libsentry-android.so
libJniS1Pass.so                 libdream.so                     libsentry.so
libK3fAndroid.so                libed25519_android.so           libsgmain.so
libMagicMRSv2.so                libespider.so                   libsqlcipher.so
libNSaferJNI.so                 libfincubescanner.so            libtensorflowlite_jni.so
libSecOtp.so                    libglide-webp.so                libtinytraceroute.so
libVoxCore.so                   libjingle_peerconnection_so.so  libtoyger.so
libYaft.so                      libmcache.so
```

The code for `libed25519_android.so` can be found [here](https://github.com/dazoe/Android.Ed25519). Main implementation in `com.github.dazoe.android.Ed25519`.

Only `libdialoid-apklib.so`, `libdream.so`, and `libsqlcipher.so` seem to be actively loaded in idle state.

Trace calls to native libs with [jnitrace](https://github.com/chame1eon/jnitrace). See example [trace](./recon/jnitrace_output.json).

## Open-Source Libs

[See here](./recon/open_source_libs.txt).

## Crypto

Android KeyStore

Dump it with `https://codeshare.frida.re/@ceres-c/extract-keystore/`.

```
Alias                     Key   Certificate
------------------------  ----  -----------
talkpass_keystore         True  False
crypto_db_passphrase_key  True  False
```

The key in the `talkpass_keystore` KeyStore is used to encrypt another symmetric key and IV in the file `com.kakao.talk/shared_prefs/zzng.xml`.

The key in the `crypto_db_passphrase_key` KeyStore is used encrypt the database `com.kakao.talk/databases/crypto_database`.

There's also a BKS KeyStore `res/raw/kakao_c` in `kakaotalk_10.1.7.apk`. The password is `am_i_safe_now_kakaoteam`.

You can read the KeyStore with the `keytool` tool:

```bash
$ PROVIDER_PATH=usr/local/share/android-commandlinetools/cmdline-tools/latest/lib/external/org/bouncycastle/bcprov-jdk15on/1.67/bcprov-jdk15on-1.67.jar
$ keytool -list -v -keystore ./res/raw/kakao_c -storetype BKS -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath $PROVIDER_PATH -storepass am_i_safe_now_kakaoteam
```

Here are the contents of the `kakao_c` KeyStore:

```
Keystore type: BKS
Keystore provider: BC

Your keystore contains 6 entries

Alias name: AAA Certificate Services
Creation date: 23 Sept 2021
Entry type: trustedCertEntry

Owner: CN=AAA Certificate Services, O=Comodo CA Limited, L=Salford, ST=Greater Manchester, C=GB
Issuer: CN=AAA Certificate Services, O=Comodo CA Limited, L=Salford, ST=Greater Manchester, C=GB
Serial number: 1
Valid from: Thu Jan 01 01:00:00 CET 2004 until: Mon Jan 01 00:59:59 CET 2029
Certificate fingerprints:
	 SHA1: D1:EB:23:A4:6D:17:D6:8F:D9:25:64:C2:F1:F1:60:17:64:D8:E3:49
	 SHA256: D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4
Signature algorithm name: SHA1WITHRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3


*******************************************
*******************************************


Alias name: DigiCert Global Root CA
Creation date: 23 Sept 2021
Entry type: trustedCertEntry

Owner: CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
Issuer: CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
Serial number: 83be056904246b1a1756ac95991c74a
Valid from: Fri Nov 10 01:00:00 CET 2006 until: Mon Nov 10 01:00:00 CET 2031
Certificate fingerprints:
	 SHA1: A8:98:5D:3A:65:E5:E5:C4:B2:D7:D6:6D:40:C6:DD:2F:B1:9C:54:36
	 SHA256: 43:48:A0:E9:44:4C:78:CB:26:5E:05:8D:5E:89:44:B4:D8:4F:96:62:BD:26:DB:25:7F:89:34:A4:43:C7:01:61
Signature algorithm name: SHA1WITHRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3


*******************************************
*******************************************


Alias name: Digicert Global Root G2
Creation date: 2 Jan 2018
Entry type: trustedCertEntry

Owner: CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US
Issuer: CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US
Serial number: 33af1e6a711a9a0bb2864b11d09fae5
Valid from: Thu Aug 01 14:00:00 CEST 2013 until: Fri Jan 15 13:00:00 CET 2038
Certificate fingerprints:
	 SHA1: DF:3C:24:F9:BF:D6:66:76:1B:26:80:73:FE:06:D1:CC:8D:4F:82:A4
	 SHA256: CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE:47:FF:C3:5E:43:C1:14:4C:EA:27:D4:6A:5A:B1:CB:5F
Signature algorithm name: SHA256WITHRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3


*******************************************
*******************************************


Alias name: USERTrust RSA Certification Authority
Creation date: 23 Sept 2021
Entry type: trustedCertEntry

Owner: CN=USERTrust RSA Certification Authority, O=The USERTRUST Network, L=Jersey City, ST=New Jersey, C=US
Issuer: CN=USERTrust RSA Certification Authority, O=The USERTRUST Network, L=Jersey City, ST=New Jersey, C=US
Serial number: 1fd6d30fca3ca51a81bbc640e35032d
Valid from: Mon Feb 01 01:00:00 CET 2010 until: Tue Jan 19 00:59:59 CET 2038
Certificate fingerprints:
	 SHA1: 2B:8F:1B:57:33:0D:BB:A2:D0:7A:6C:51:F7:0E:E9:0D:DA:B9:AD:8E
	 SHA256: E7:93:C9:B0:2F:D8:AA:13:E2:1C:31:22:8A:CC:B0:81:19:64:3B:74:9C:89:89:64:B1:74:6D:46:C3:D4:CB:D2
Signature algorithm name: SHA384WITHRSA
Subject Public Key Algorithm: 4096-bit RSA key
Version: 3


*******************************************
*******************************************


Alias name: VeriSign Class 3 Public Primary Certification Authority - G5
Creation date: 4 May 2017
Entry type: trustedCertEntry

Owner: CN=VeriSign Class 3 Public Primary Certification Authority - G5, OU="(c) 2006 VeriSign, Inc. - For authorized use only", OU=VeriSign Trust Network, O="VeriSign, Inc.", C=US
Issuer: CN=VeriSign Class 3 Public Primary Certification Authority - G5, OU="(c) 2006 VeriSign, Inc. - For authorized use only", OU=VeriSign Trust Network, O="VeriSign, Inc.", C=US
Serial number: 18dad19e267de8bb4a2158cdcc6b3b4a
Valid from: Wed Nov 08 01:00:00 CET 2006 until: Thu Jul 17 01:59:59 CEST 2036
Certificate fingerprints:
	 SHA1: 4E:B6:D5:78:49:9B:1C:CF:5F:58:1E:AD:56:BE:3D:9B:67:44:A5:E5
	 SHA256: 9A:CF:AB:7E:43:C8:D8:80:D0:6B:26:2A:94:DE:EE:E4:B4:65:99:89:C3:D0:CA:F1:9B:AF:64:05:E4:1A:B7:DF
Signature algorithm name: SHA1WITHRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3


*******************************************
*******************************************


Alias name: mykey
Creation date: 30 Jun 2020
Entry type: trustedCertEntry

Owner: CN=Amazon, OU=Server CA 1B, O=Amazon, C=US
Issuer: CN=Amazon Root CA 1, O=Amazon, C=US
Serial number: 67f94578587e8ac77deb253325bbc998b560d
Valid from: Thu Oct 22 02:00:00 CEST 2015 until: Sun Oct 19 02:00:00 CEST 2025
Certificate fingerprints:
	 SHA1: 91:7E:73:2D:33:0F:9A:12:40:4F:73:D8:BE:A3:69:48:B9:29:DF:FC
	 SHA256: F5:5F:9F:FC:B8:3C:73:45:32:61:60:1C:7E:04:4D:B1:5A:0F:03:4B:93:C0:58:30:F2:86:35:EF:88:9C:F6:70
Signature algorithm name: SHA256WITHRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3


*******************************************
*******************************************
```

### E2E

E2E is opt-in only. Most people probably don’t use Secret Chat since `In a secret chatrooom, features including free calling, polls, events and chatroom album are currently not available`.

Main implementation in package `com.kakao.talk.secret` and the `LocoCipherHelper ` class.
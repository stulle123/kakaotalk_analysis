# Secret Chat

E2E is opt-in only. Most people probably don’t use Secret Chat since `In a secret chatrooom, features including free calling, polls, events and chatroom album are currently not available`.

Main implementation in package `com.kakao.talk.secret` and the `LocoCipherHelper ` class.

MITM PoC:

- Sender's RSA public key pair in `TalkKeyStore.preferences.xml`
- Receiver's public keys in `KakaoTalk.db`
- PoC how-to:
  - Delete all public keys from `KakaoTalk.db` database
  - Start mitmproxy and Frida script
  - Create new Secret Chat room
	  - `GETLPK` packet gets intercepted -> Maybe we don't need that?
	  - `SCREATE` packet gets intercepted (shouldn't include a shared secret, otherwise we remove it)
	  - Bad signature check of MITM public key doesn't seem to have any implications
    - Sender sends a `SETSK` packet (mitmproxy grabs shared secret)
    - Dump `SWRITE` packets

Questions:
- How to attack an already existing E2E chat room?
- How to fix maldformed `SCREATE` packets?
- Check public key fingerprints if they have changed

- Test CFB bit flipping
- Test Secret Chat interception with `mitmproxy` script
  * Use value from `pt` field to compute the nonce
  * Does a warning pop up?
  * What about the master secret?
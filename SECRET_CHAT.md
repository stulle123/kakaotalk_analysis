# Secret Chat

*Secret Chat* is KakaoTalk's E2E encryption feature. It was added on top of the existing [LOCO protocol](https://kth.diva-portal.org/smash/get/diva2:1046438/FULLTEXT01.pdf#page=77) which has a couple of [flaws](https://kth.diva-portal.org/smash/get/diva2:1046438/FULLTEXT01.pdf#page=100) including missing integrity protection of the ciphertext.

*Secret Chat* is opt-in only and not enabled by default in the KakaoTalk mobile app. Most users might not use *Secret Chat* as it doesn't have the same feature set as regular non-E2E encrypted chat rooms.

We've created a simple script to man-in-the-middle *Secret Chat* communications with `Frida` and `mitmproxy`. It demonstrates a well-known server-side attack in which the operator (i.e. KakaoTalk) can spoof a client's public key to intercept and read E2E encrypted chat messages. 

After the MITM attack there's no immediate warning message in the chat. Only if both parties go to `Chatroom Settings` -> `Public Key` and compare their public key fingerprints, the attack can be detected.

This is how one can run the PoC:

- Assumption: You've already set up your test environment (see setup description [here](./SETUP.md))
- Wipe all entries in the `public_key_info` and `secret_key_info` tables from the `KakaoTalk.db` database
- Start `mitmproxy`: `$ mitmdump -m wireguard -s mitm_secret_chat.py`
- Start `Frida`: `$ frida -U -l loco-tracer.js -f com.kakao.talk`
- Create new *Secret Chat* room in KakaoTalk app and sent a message
- View message in `mitmproxy` terminal window

How it works:

- Server-side `GETLPK` packet gets intercepted -> Inject MITM public key
- Server-side `SCREATE` packet gets intercepted -> Remove already existing shared secret (if any)
- Sender sends a `SETSK` packet -> `mitmproxy` script grabs shared secret and re-encrypts it with the recipient's original public key
- Using the shared secret, the script computes the E2E encryption key
- `MSG` and `SWRITE` packets are decrypted and dumped in the `mitmproxy` terminal

Known issues:

- Malformed `SCREATE` packets lead to parsing errors -> work-around: restart the script and try again :wink:
- Sometimes the shared secret can't be decrypted and the script fails with a `ValueError` exception (`Encryption/decryption failed`) -> just try again :wink:

Android implementation specifics:

- Main *Secret Chat* implementation in package `com.kakao.talk.secret` and in the `LocoCipherHelper ` class
- Sender's RSA public key pair in `TalkKeyStore.preferences.xml`
- Receiver's public keys in table `public_key_info` of `KakaoTalk.db` database
- Shared secret stored in table `secret_key_info` of `KakaoTalk.db` database

TO-DOS:

- How to attack an already existing E2E chat room?
- Check public key fingerprints if they have changed
- Reinstall the app and check whether a warning shows up
- What about the master secret? -> Remove it!
- Test CFB bit flipping

Demo:

![MITM](https://github.com/stulle123/kakaotalk_analysis/tree/main/scripts/mitmproxy/secret_chat_demo.gif?raw=true)
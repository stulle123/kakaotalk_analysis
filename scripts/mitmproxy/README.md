# mitmproxy Scripts

There are four `mitmproxy` scripts in this directory to play with LOCO traffic:

- `flip_ciphertext_bits.py` -> a POC for showing the CFB malleability of encrypted LOCO packets
- `replace_loco_message.py` -> Replace a LOCO message with another one to show missing integrity protection
- `mitm_single_tls_host.py` -> MITM a single TLS host only. Passthrough all other TLS traffic.
- `mitm_secret_chat.py` -> MITM end-to-end encrypted *SECRET CHAT* messages

To run the scripts, do the following:

1. Start mitmproxy script on your MITM host and copy the WireGuard config:

```bash
$ python3 -m venv venv
$ source venv/bin/activate
(venv) $ python3 -m pip install mitmproxy bson cryptography
(venv) $ mitmdump --mode wireguard --rawtcp -s replace_loco_message.py
```

2. Android device/emulator setup:

- Install the Kakaotalk app if not done already
- Install the WireGuard app
- Import mitmproxy's generated WireGuard config into the WireGuard app

If you run the Android Emulator on your MITM host, change the IP address to `10.0.2.2`. Example:

```
[Interface]
PrivateKey = MCCAFVMZQk+k+sbdXx0B4LG+Mij/UO7qyWa7IRqv/nA=
Address = 10.0.0.1/32
DNS = 10.0.0.53

[Peer]
PublicKey = K+t/qiGO8tlA9L7wjAOb8wqjnu/NuthHgLs2gOCIDgY=
AllowedIPs = 0.0.0.0/0
Endpoint = 10.0.2.2:51820
```

3. Start Frida on MITM host (see [setup instructions](../../doc/SETUP.md#setup-frida-to-disable-certificate-pinning))

```bash
# Start frida-server
$ adb root && adb shell /data/local/tmp/frida-server

# Start LOCO debugging script
$ frida -U -l loco-tracer.js -f com.kakao.talk
```

Optional: To run the unit tests for `mitm_secret_chat.py`:

- Install `pytest` and `pytest-datadir` via pip
- Run the tests: `$ pytest tests/test_loco_parser.py`
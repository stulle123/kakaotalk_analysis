# MITM Kakaotalk LOCO Packets

This is a simple script to man-in-the-middle LOCO packets with mitmproxy.

Setup on your MITM host:

```bash
$ python3 -m venv venv
$ source venv/bin/activate
(venv) $ python3 -m pip install mitmproxy bson cryptography
(venv) $ mitmdump --mode wireguard --rawtcp -s loco_mitm.py
```

Android emulator setup:

- Install the Kakaotalk app if not done already
- Install the WireGuard app
- Change the IP address in mitmproxy's generated WireGuard config to `10.0.2.2`. Example:
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
- Import the config into the WireGuard app

Back on your MITM host start Frida (see [setup instructions](../../SETUP.md#setup-frida-to-disable-certificate-pinning)):

```bash
# Start frida-server
$ adb root && adb shell /data/local/tmp/frida-server

# Start LOCO debugging script
$ frida -U -l loco-tracer.js -f com.kakao.talk
```

To run the unit tests:

- Install `pytest` and `pytest-datadir` via pip
- Run the tests: `$ pytest tests/test_loco_parser.py`
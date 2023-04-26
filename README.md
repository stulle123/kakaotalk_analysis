# Kakaotalk Analysis

## Setup

Prepare your `~/.bashrc` or `~/.zshrc`:

```bash
JAVA=/usr/local/opt/openjdk/bin
export PATH=$JAVA:$PATH
export ANDROID_HOME=/usr/local/share/android-commandlinetools
export PATH=$PATH:$ANDROID_HOME/emulator
```

Install Android Emulator on a MAC M1:

```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# Install Java
brew install openjdk
# Install Android SDK
brew install --cask android-commandlinetools
sdkmanager "emulator"
sdkmanager "platforms;android-30"
sdkmanager "system-images;android-30;google_apis;arm64-v8a"
# Install Platform Tools
brew install android-platform-tools
# Create AVD Image (without Google Play Store)
avdmanager create avd -n kakao -k "system-images;android-30;google_apis;arm64-v8a"
# Start the emulator once and shut it down (this will create the 'config.ini' file)
emulator @kakao
# Configure AVD Image
sed -i -r 's/hw.keyboard = no/hw.keyboard = yes/' ~/.android/avd/kakao.avd/config.ini
sed -i -r 's/hw.mainKeys = yes/hw.mainKeys = no/' ~/.android/avd/kakao.avd/config.ini
```

Install required tools:

- Get latest [jadx](https://github.com/skylot/jadx) (or install via `brew`)
- Get [Burp Suite](https://portswigger.net/burp/communitydownload)
- `$ brew install apktool nuclei radare2 sqlite db-browser-for-sqlite`
- `$ pip3 install --upgrade frida-tools objection`

### SSH

```bash
# Download Termux from https://github.com/termux/termux-app and install it, e.g.:
adb install termux-app_v0.118.0+github-debug_arm64-v8a.apk
# Install openssh in Termux
pkg upgrade
pkg install openssh
# Set a password for the SSH login in Termux
passwd
# Start SSH in Termux
sshd
# On your host set up redirection through the emulator console
cat ~/.emulator_console_auth_token
telnet localhost 5554
auth <your-emulator-token>
redir add tcp:4444:8022
exit
# SSH into the emulator (no need to specify a user name)
ssh -p 4444 localhost
```

### Configure Emulator to work with Burp Suite

- Export Burp's CA certificate in `DER` format
- Next, follow these steps:
```bash
# Convert DER to PEM
openssl x509 -inform DER -in burp_ca_cert.der -out burp_ca_cert.pem
# Get subject_hash_old
openssl x509 -inform PEM -subject_hash_old -in burp_ca_cert.pem | head -1
# Rename burp_ca_cert.pem to <hash>.0
mv burp_ca_cert.pem 9a5ba57.0
# Start emulator and copy certificate
emulator @kakao -writable-system -http-proxy 127.0.0.1:8080
adb root
adb remount
adb push 9a5ba57.0 /system/etc/security/cacerts/
adb shell "chmod 644 /system/etc/security/cacerts/9a5ba57.0"
adb reboot
```
**Note**, that you have to start the emulator with `-writable-system`. Otherwise, Burp's certificate doesn't show up in Androids's trusted CA store (`Settings` -> `Security` -> `Encryption and credentials` -> `Trusted credentials`) 🙈

### Setup Frida to disable Certificate Pinning

```bash
# Install Frida
pip3 install frida-tools
# Download frida-server from https://github.com/frida/frida/releases
# **The version of frida-tools and frida-server must match**
wget https://github.com/frida/frida/releases/download/16.0.15/frida-server-16.0.15-android-arm64.xz -O frida-server.xz
unxz frida-server.xz
adb root
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
# Start frida-server (this might hang, but frida-server is started anyways)
adb shell "/data/local/tmp/frida-server &"
# Quick test
frida-ps -U
# Export Burp's CA certificate in DER format and copy to emulator
adb push burp_ca_cert.der /data/local/tmp/cert-der.crt
# Disable Certificate Pinning
frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -U -f com.kakao.talk
```

### KakaoTalk Account Setup

- Grab a trash email account (e.g., from https://ulm-dsl.de/)
- Grab a trash phone number to receive SMS messages (e.g., https://onlinesim.io)
  - One phone number per account only
- Open a new Incognito window, go to https://accounts.kakao.com and create an account:
```
hans-erich.kober@ulm-dsl.de
peterock
kBB5mmmE

folkert.dachs@ulm-dsl.de
peterplan
fMcz2Jtr
```
- In the KakaoTalk app, login with your email address:
  - When prompted add your phone number
  - **Optional**: you may have to send a SMS including a base64 string (e.g., `KakaoTalk HgAAABIwAGgAQGQAAAAAAjEABwAAADE1Mjc2MAAA`) to a KakaoTalk phone number (you won't receive any SMS response back). After that, you need to tap/click the `Check verification` button in the app and the registration process should be completed.

<img width="318" alt="image" src="https://user-images.githubusercontent.com/14765446/233626988-8bf6be98-c855-4f29-99cb-77d2d44dcb60.png">

### Tools to play with

- https://github.com/skylot/jadx
  - It has a scripting engine, too.
- https://github.com/quark-engine/quark-engine
- Frida scripts
  - https://github.com/WithSecureLabs/android-keystore-audit
  - https://codeshare.frida.re/@fadeevab/intercept-android-apk-crypto-operations/
  - https://codeshare.frida.re/@dzonerzy/aesinfo/
- https://github.com/sensepost/objection
  - Run: `$ objection -g com.kakao.talk explore`
- https://github.com/MobSF/Mobile-Security-Framework-MobSF
- https://github.com/JakeWharton/pidcat
  - Hint: if only color codes are printed, try this [fix](https://github.com/JakeWharton/pidcat/issues/182)
- Nuclei
  - Download Android templates: `git clone https://github.com/optiv/mobile-nuclei-templates`
  - Run: `$ echo kakaotalk_apktool_decoded_folder | nuclei -t ~/mobile-nuclei-templates/Android -o nuclei_android_results.txt`

## Misc Commands

```bash
# Start KakaoTalk
adb shell am start com.kakao.talk
# Stop KakaoTalk
adb shell am force-stop com.kakao.talk
# Start Termux
adb shell am start com.termux/.HomeActivity
# List 3rd-party Packages
adb shell pm list packages -f -3
# Get Activities of an app
PACKAGE=com.termux
adb shell dumpsys package | grep -Eo $(printf "^[[:space:]]+[0-9a-f]+[[:space:]]+%s/[^[:space:]]+" "${PACKAGE}") | grep -oE "[^[:space:]]+$"
# Launch Settings
adb shell am start -a android.settings.SETTINGS
```

## Possible E2E Attack Vectors

- Register an attacker's device to the victim's KakaoTalk account
- MITM the protocol on the wire
- Operator-side MITM (e.g., by changing public keys)
- Tamper with the ciphertext on the wire -> code injection
- Send a chat message to a victim to retrieve the E2E encryption key -> code injection
- Install a malcious app on the victim's device to retrieve the E2E key via IPC

## Resources

- https://github.com/KiwiTalk/KiwiTalk
- https://github.com/jhleekr/kakao.py

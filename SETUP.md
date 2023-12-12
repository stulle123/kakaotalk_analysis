# Mac M1 Setup

- [Create KakaoTalk account](#kakaotalk-account-setup)
- [Install Tools](#install-tools)
  - [Setup Burp Suite](#configure-android-emulator-to-work-with-burp-suite)
  - [Setup Frida](#setup-frida-to-disable-certificate-pinning)
  - [SSH](#optional-setup-sshd-on-the-android-emulator)
  - [Tools to try](#tools-to-play-with)
- [Misc Commands](#misc-commands)
- [Resources](#resources)

## KakaoTalk Account Setup

- Grab a trash email account (e.g., from https://ulm-dsl.de/)
- Grab a trash phone number to receive SMS messages (e.g., https://onlinesim.io)
- Create a new account via the KakaoTalk mobile app or via https://accounts.kakao.com

## Install Tools

Prepare your `~/.bashrc` or `~/.zshrc`:

```bash
JAVA=/opt/homebrew/opt/openjdk/bin
export PATH=$JAVA:$PATH
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
export PATH=$PATH:$ANDROID_HOME/emulator
```

Install Android Emulator on a Mac M1:

```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# Install Java
brew install java
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

- Get latest [jadx](https://nightly.link/skylot/jadx/workflows/build-artifacts/master)
- Get [Burp Suite](https://portswigger.net/burp/communitydownload)
- Get [KakaoTalk for Windows/MacOS](https://www.kakaocorp.com/page/service/service/KakaoTalk?lang=en)
- `$ brew install apktool nuclei sqlite db-browser-for-sqlite`
- `$ pip3 install --upgrade frida-tools mitmproxy`

### Configure Android Emulator to work with Burp Suite

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

### Optional: Setup SSHD on the Android Emulator

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

### Tools to play with

- https://github.com/Ch0pin/medusa
- https://github.com/quark-engine/quark-engine
- Frida scripts
  - https://github.com/WithSecureLabs/android-keystore-audit
  - https://codeshare.frida.re/@fadeevab/intercept-android-apk-crypto-operations/
  - https://codeshare.frida.re/@dzonerzy/aesinfo/
- https://github.com/sensepost/objection
  - Run: `$ objection -g com.kakao.talk explore`
  - `com.kakao.talk on (Android: 9) [usb] # android hooking watch class com.kakao.talk.secret.LocoCipherHelper` (for me this only worked for SDK 28)
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
# Launch Settings
adb shell am start -a android.settings.SETTINGS
# List 3rd-party Packages
adb shell pm list packages -f -3
# Get Activities of an app
PACKAGE=com.termux
adb shell dumpsys package | grep -Eo $(printf "^[[:space:]]+[0-9a-f]+[[:space:]]+%s/[^[:space:]]+" "${PACKAGE}") | grep -oE "[^[:space:]]+$"
# Show current activity
adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp|mInputMethodTarget|mSurface'
# Show file system access
adb shell 'am start kakaotalk://main && ps -A | grep -m 1 "kakao" | tr -s " " | cut -d " " -f2 | xargs strace -f -p 2>&1 | grep -i /data'
```

Sign an app:
```bash
# Decompile
apktool d -rf my-app.apk
# Generate signing key
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
# Build APK
apktool b -f -d com.myapp
# Sign APK
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore com.myapp/dist/com.myapp.apk alias_name
```

## Resources

Open-Source KakaoTalk clients:

- https://github.com/KiwiTalk/KiwiTalk
- https://github.com/jhleekr/kakao.py
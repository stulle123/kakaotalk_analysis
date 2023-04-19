# Kakaotalk Analysis

## Setup

Prepare your `~/.bashrc` or `~/.zshrc`:

```bash
JAVA=/usr/local/opt/openjdk/bin
export ANDROID_HOME=/usr/local/share/android-commandlinetools
export PATH=$PATH:$ANDROID_HOME/emulator
export PATH=$PATH:$JAVA
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
# Create AVD Image
avdmanager create avd -n kakao -k "system-images;android-30;google_apis;arm64-v8a"
# Start the emulator once and shut it down (this will create the 'config.ini' file)
emulator @kakao
# Configure AVD Image
sed -i -r 's/hw.keyboard = no/hw.keyboard = yes/' ~/.android/avd/kakao.avd/config.ini
sed -i -r 's/hw.mainKeys = yes/hw.mainKeys = no/' ~/.android/avd/kakao.avd/config.ini
# Start the emulator
emulator @kakao
```

## SSH

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

## Misc Commands

```bash
# Start Termux
adb shell am start com.termux/.HomeActivity
# List 3rd-party Packages
adb shell pm list packages -f -3
# Get Activities of an app
PACKAGE=com.termux
adb shell dumpsys package | grep -Eo $(printf "^[[:space:]]+[0-9a-f]+[[:space:]]+%s/[^[:space:]]+" "${PACKAGE}") | grep -oE "[^[:space:]]+$"
```

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
# Start Emulator
emulator @kakao
```

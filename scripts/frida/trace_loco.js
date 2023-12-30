/*
Decrypt and print LOCO traffic of KakaoTalk 10.4.3.
*/

import { dumpByteArray, printStacktrace } from "./utils.js";

Java.perform(function () {
  hookDoFinal2();
  hookKeyGeneratorGenerateKey();
  hookSharedSecretStore();
  printLocoBody();
});

const locoKey = Java.array(
  "byte",
  [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
  ]
);

const locoFileNames = [
  "V2SLSink.kt",
  "V2SLSource.kt",
  "V2SLHandshake.kt",
  "LocoV2SLSocket.kt",
];

const patchLocoKey = true;
const printStacktrace = false;

function hookDoFinal2() {
  var cipherInit = Java.use("javax.crypto.Cipher")["doFinal"].overload("[B");

  cipherInit.implementation = function (byteArr) {
    var tmp = this.doFinal(byteArr);
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];

    if (locoFileNames.includes(caller.getFileName())) {
      console.log("[Cipher.doFinal2()]: " + "  cipherObj: " + this);
      console.log("Caller: " + caller.getFileName());
      dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
      dumpByteArray("Result", tmp);
      // var result_base64 = Java.use("android.util.Base64").encodeToString(tmp, 0);
      // console.log("Result in Base64: " + result_base64)

      if (printStacktrace) {
        printStacktrace();
      }

      console.log("##############################################");
    }

    return tmp;
  };
}

function hookKeyGeneratorGenerateKey() {
  var generateKey = Java.use("javax.crypto.KeyGenerator")[
    "generateKey"
  ].overload();

  generateKey.implementation = function () {
    var tmp = this.generateKey();
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    const secretKeySpec = Java.cast(
      tmp,
      Java.use("javax.crypto.spec.SecretKeySpec")
    );
    const encodedKey = secretKeySpec.getEncoded();

    if (locoFileNames.includes(caller.getFileName())) {
      // console.log("[KeyGenerator.generateKey()]: Object: " + tmp);
      console.log("Caller: " + caller.getFileName());
      // dumpByteArray("[KeyGenerator.generateKey()]: Key", encodedKey);
      var base64_key = Java.use("android.util.Base64").encodeToString(
        encodedKey,
        0
      );
      console.log("Generated key: " + base64_key);

      if (printStacktrace) {
        printStacktrace();
      }
    }

    if (patchLocoKey) {
      dumpByteArray("Patching LOCO AES key with key", locoKey);
      const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
      var fakeKey = SecretKeySpec.$new(locoKey, "AES");
      tmp = fakeKey;
    }
    console.log("##############################################");

    return tmp;
  };
}

function hookSharedSecretStore() {
  var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper$e")[
    "$init"
  ].overload("java.lang.String", "long");
  locoCipherHelper.implementation = function (arg0, arg1) {
    var tmp = this.$init(arg0, arg1);
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log("Secret Chat shared secret: " + arg0);
    console.log("Secret Chat seed for nonce: " + arg1);
    console.log(this.toString());
    console.log("Caller: " + caller.getFileName());
    console.log("##############################################");
  };
}

function printLocoBody() {
  Java.choose("com.kakao.talk.loco.protocol.LocoBody", {
    onMatch: function (instance) {
      if (instance) {
        console.log("LOCO body: " + instance);
      }
    },
    onComplete: function () {},
  });
}

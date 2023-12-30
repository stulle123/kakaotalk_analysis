/*
Hook various Secret Chat methods of KakaoTalk 10.4.3.
*/

import { printStacktrace, dumpByteArray } from "./utils.js";

Java.perform(function () {
  hookLocoCipherHelper();
  hookLocoCipherHelper_2();
  hookLocoCipherHelper_GenerateRSAPrivateKey();
  hookLocoCipherHelper_GenerateRSAPublicKey();
  hookSecretChatHelper();
  hookLocoPubKeyInfo();
  hookTalkLocoPKStore();
  hookTalkLocoPKStore_2();
  hookAESCTRHelper_GenerateIV();
  printAESCTRKeySet();
});

const printStacktrace = false;

function hookLocoCipherHelper() {
  var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper")[
    "s"
  ].overload("com.kakao.talk.secret.LocoCipherHelper$c", "[B", "[B");
  locoCipherHelper.implementation = function (arg0, arg1, arg2) {
    console.log("hookLocoCipherHelper2 called!");
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log(caller.getFileName());
    var ret = locoCipherHelper.call(this, arg0, arg1, arg2);
    console.log(ret);
    return locoCipherHelper.call(this, arg0, arg1, arg2);
  };
}

function hookLocoCipherHelper_2() {
  var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper$b")[
    "$init"
  ].overload(
    "com.kakao.talk.secret.LocoCipherHelper$d",
    "com.kakao.talk.secret.LocoCipherHelper$c"
  );
  locoCipherHelper.implementation = function (arg0, arg1) {
    var tmp = this.$init(arg0, arg1);
    console.log("hookLocoCipherHelper5 called!");
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log(caller.getFileName());
    console.log(arg0);
    console.log(arg1);
    console.log(this.toString());
    console.log("##############################################");
  };
}

function hookLocoCipherHelper_GenerateRSAPrivateKey() {
  var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper")[
    "e"
  ].overload("java.lang.String");
  locoCipherHelper.implementation = function (arg0) {
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log("Caller: " + caller.getFileName());
    // var private_key = locoCipherHelper.call(this, arg0);
    // var encoded_key = Java.use("android.util.Base64").encodeToString(private_key.getEncoded(), 0);
    console.log("Generate RSA private key from string: " + arg0);
    // console.log(encoded_key)
    console.log("##############################################");
    return locoCipherHelper.call(this, arg0);
  };
}

function hookLocoCipherHelper_GenerateRSAPublicKey() {
  var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper")[
    "f"
  ].overload("java.lang.String");
  locoCipherHelper.implementation = function (arg0) {
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    var ret = locoCipherHelper.call(this, arg0);
    console.log("Caller: " + caller.getFileName());
    console.log("Generate RSA public key from string: " + arg0);
    var public_key = locoCipherHelper.call(this, arg0);
    // var encoded_key = Java.use("android.util.Base64").encodeToString(public_key.getEncoded(), 0);
    // console.log(encoded_key);
    if (printStacktrace) {
      printStacktrace();
    }
    console.log("##############################################");
    return locoCipherHelper.call(this, arg0);
  };
}

function hookLocoPubKeyInfo() {
  var locoPubKeyInfo = Java.use("t41.n")["$init"].overload(
    "com.kakao.talk.loco.protocol.LocoBody"
  );
  locoPubKeyInfo.implementation = function (locoBody) {
    var tmp = this.$init(locoBody);
    console.log("locoPubKeyInfo called!");
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log(caller.getFileName());
    console.log(locoBody);
    console.log("##############################################");
  };
}

function hookSecretChatHelper() {
  var secretChatHelper = Java.use("com.kakao.talk.secret.b$e")["b"].overload(
    "com.kakao.talk.secret.b$d"
  );
  secretChatHelper.implementation = function (arg0) {
    console.log("secretChatHelper3 called!");
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log(caller.getFileName());
    console.log(this.a);
    console.log("##############################################");
    return secretChatHelper.call(this, arg0);
  };
}

function hookTalkLocoPKStore() {
  var talkLocoPKStore = Java.use("yl1.x3")["toString"].overload();
  talkLocoPKStore.implementation = function () {
    console.log("talkLocoPKStore called!");
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log(caller.getFileName());
    var ret = talkLocoPKStore.call(this);
    console.log(ret);
    console.log("##############################################");
    return talkLocoPKStore.call(this);
  };
}

function hookTalkLocoPKStore_2() {
  var talkLocoPKStore = Java.use("yl1.x3$a")["toString"].overload();
  talkLocoPKStore.implementation = function () {
    console.log("talkLocoPKStore2 called!");
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log(caller.getFileName());
    var ret = talkLocoPKStore.call(this);
    console.log(ret);
    console.log("##############################################");
    return talkLocoPKStore.call(this);
  };
}

function hookAESCTRHelper_GenerateIV() {
  var AESCTRHelper = Java.use("d20.a")["b"].overload(
    "java.lang.String",
    "[B",
    "int",
    "javax.crypto.spec.PBEKeySpec"
  );
  AESCTRHelper.implementation = function (arg0, arg1, arg2, arg3) {
    dumpByteArray("Generated IV", arg1);
    console.log("##############################################");
    return AESCTRHelper.call(this, arg0, arg1, arg2, arg3);
  };
}

function printAESCTRKeySet() {
  var AESCTRKeySet = Java.use("d20.b")["$init"].overload("[B", "[B", "[B");
  AESCTRKeySet.implementation = function (arg0, arg1, arg2) {
    dumpByteArray("Secret key", arg0);
    dumpByteArray("IV", arg1);
    dumpByteArray("arg2", arg2);
    console.log("##############################################");
    return AESCTRKeySet.call(this, arg0, arg1, arg2);
  };
}

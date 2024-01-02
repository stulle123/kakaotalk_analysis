/*
Hook various Secret Chat methods of KakaoTalk 10.4.3.
*/

const locoKey = Java.array(
  "byte",
  [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
  ]
);
const patchLocoKey = true;
const locoFileNames = [
  "V2SLSink.kt",
  "V2SLSource.kt",
  "V2SLHandshake.kt",
  "LocoV2SLSocket.kt",
];
const enableStacktracePrinting = false;
var StringCls = null;

Java.perform(function () {
  StringCls = Java.use("java.lang.String");
  hookKeyGeneratorGenerateKey();
  hookSharedSecretStore();
  hookLocoCipherHelper_GenerateRSAPrivateKey();
  hookLocoCipherHelper_GenerateRSAPublicKey();
  hookAESCTRHelper_GenerateIV();
  hookSecretChatHelper();
  hookLocoPubKeyInfo();
  hookTalkLocoPKStore();
  printAESCTRKeySet();
});

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

      if (enableStacktracePrinting) {
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

function hookLocoCipherHelper_GenerateRSAPrivateKey() {
  var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper")[
    "e"
  ].overload("java.lang.String");
  locoCipherHelper.implementation = function (arg0) {
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log("Caller: " + caller.getFileName());
    console.log("Generated RSA private key: " + arg0);
    if (enableStacktracePrinting) {
      printStacktrace();
    }
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
    console.log("Caller: " + caller.getFileName());
    console.log("Generated RSA public key: " + arg0);
    if (enableStacktracePrinting) {
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
    console.log("Caller: " + caller.getFileName());
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
  var talkLocoPKStore = Java.use("yl1.x3$a")["toString"].overload();
  talkLocoPKStore.implementation = function () {
    console.log("TalkLocoPKStore class called!");
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log("Caller: " + caller.getFileName());
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
    console.log("AESCTRHelper class called!");
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log("Caller: " + caller.getFileName());
    dumpByteArray("Generated IV", arg1);
    console.log("##############################################");
    return AESCTRHelper.call(this, arg0, arg1, arg2, arg3);
  };
}

function printAESCTRKeySet() {
  var AESCTRKeySet = Java.use("d20.b")["$init"].overload("[B", "[B", "[B");
  AESCTRKeySet.implementation = function (arg0, arg1, arg2) {
    console.log("AESCTRKeySet class called!");
    var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
    console.log("Caller: " + caller.getFileName());
    dumpByteArray("Secret key", arg0);
    dumpByteArray("IV", arg1);
    dumpByteArray("arg2", arg2);
    console.log("##############################################");
    return AESCTRKeySet.call(this, arg0, arg1, arg2);
  };
}

function printStacktrace() {
  var stacktrace = Java.use("android.util.Log")
    .getStackTraceString(Java.use("java.lang.Exception").$new())
    .replace("java.lang.Exception", "");
  console.log(stacktrace);
}

function dumpByteArray(title, byteArr) {
  if (byteArr != null) {
    try {
      var buff = new ArrayBuffer(byteArr.length);
      var dtv = new DataView(buff);
      for (var i = 0; i < byteArr.length; i++) {
        /*
        Frida sucks sometimes and returns different byteArr.length between ArrayBuffer(byteArr.length) and for(..; i < byteArr.length;..).
        It occurred even when Array.copyOf was done to work on copy.
        */
        dtv.setUint8(i, byteArr[i]);
      }
      console.log(title + ":\n");
      console.log(_hexdumpJS(dtv.buffer, 0, byteArr.length));
    } catch (error) {
      console.log("Exception has occured in hexdump");
    }
  } else {
    console.log("byteArr is null!");
  }
}

function _hexdumpJS(arrayBuffer, offset, length) {
  var view = new DataView(arrayBuffer);
  offset = offset || 0;
  length = length || arrayBuffer.byteLength;

  var out =
    _fillUp("Offset", 8, " ") +
    "  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n";
  var row = "";
  for (var i = 0; i < length; i += 16) {
    row += _fillUp(offset.toString(16).toUpperCase(), 8, "0") + "  ";
    var n = Math.min(16, length - offset);
    var string = "";
    for (var j = 0; j < 16; ++j) {
      if (j < n) {
        var value = view.getUint8(offset);
        string += value >= 32 && value < 128 ? String.fromCharCode(value) : ".";
        row += _fillUp(value.toString(16).toUpperCase(), 2, "0") + " ";
        offset++;
      } else {
        row += "   ";
        string += " ";
      }
    }
    row += " " + string + "\n";
  }
  out += row;
  return out;
}

function _fillUp(value, count, fillWith) {
  var l = count - value.length;
  var ret = "";
  while (--l > -1) ret += fillWith;
  return ret + value;
}

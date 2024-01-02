/*
Decrypt and print LOCO traffic of KakaoTalk 10.4.3.
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

Java.perform(function () {
  hookDoFinal2();
  hookKeyGeneratorGenerateKey();
  printLocoBody();
});

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

      if (enableStacktracePrinting) {
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

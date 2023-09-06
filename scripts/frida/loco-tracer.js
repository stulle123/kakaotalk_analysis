/*
TODO:
- Hook Ed25519 (verify and sign)
- AESCTRHelper
- CipherSpec
- Aes256Cipher
- SimpleCipher
- Hook Java Crypto APIs:
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import lc2.EdDSAEngine;
import lc2.EdDSAPrivateKey;
import lc2.EdDSAPublicKey;
import oc2.EdDSANamedCurveSpec;
import oc2.EdDSANamedCurveTable;
import oc2.EdDSAParameterSpec;
import oc2.EdDSAPrivateKeySpec;
import oc2.EdDSAPublicKeySpec;
*/

Java.perform(function () {
    /*
    hookCipherGetInstance(); // Kakaotalk
    hookCipherGetInstance2();
    hookCipherGetInstance3();
    hookCipherInit();
    hookCipherInit3();
    hookCipherInit5();
    hookCipherInit7();
    hookCipherInit8();
    hookUpdate();
    hookUpdate2();
    hookUpdate3();
    hookUpdate4();
    hookUpdate5();
    hookKeyGeneratorGetInstance(); // Kakaotalk
    hookKeyGeneratorGetInstance2();
    hookKeyGeneratorGetInstance3();
    hookKeyGeneratorInit(); // Kakaotalk
    hookKeyPairGeneratorGetInstance(); // Kakaotalk
    */
    // hookV2SLSinkInit(); // Kakaotalk
    hookCipherInit();
    hookCipherInit2(); // Kakaotalk
    // hookCipherInit3();
    // hookCipherInit4(); // Kakaotalk
    // hookCipherInit5();
    hookCipherInit6(); // Kakaotalk
    // hookCipherInit7();
    // hookCipherInit8();
    // hookPBEKeySpec();
    // hookPBEKeySpec2();    
    // hookPBEKeySpec3(); // Kakaotalk
    hookDoFinal();
    // hookDoFinal2(); // Kakaotalk
    hookDoFinal3();
    hookDoFinal4();
    hookDoFinal5();
    hookDoFinal7();
    // hookIVParameterSpecDefInit1(); // Kakaotalk
    // hookIVParameterSpecDefInit2(); // Kakaotalk
    // hookSecretKeySpecDefInit1(); // Kakaotalk
    // hookSecretKeySpecDefInit2(); // Kakaotalk
    hookKeyGeneratorGenerateKey(); // Kakaotalk
    hookLocoCipherHelper();
    // hookLocoCipherHelper_2();
    hookLocoCipherHelper_3();
    hookLocoCipherHelper_4();
    hookLocoCipherHelper_6();
    hookSecretChatHelper();
    hookSecretChatHelper_2();
    hookSecretChatHelper_3();
    hookLocoPubKeyInfo();
    // hookWTFbase64();
    // hookLocoCipherHelper_5();
    // hookLocoSKeyInfo();
    // hookTalkLocoPKStore();
    // hookTalkLocoPKStore_2();
    // hookAESCTRHelper();
    // hookAESCTRKeySet();
    // enableWebviewDebugging();
    // hookTest();
    // hookURIController();
    // deepLinkSniffer();
    // hookStrings();
});

const locoKey = Java.array("byte", [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
const doNotHookFileNames = ["SimpleCipher.kt", "AccountUpdater.kt", "DataBaseResourceCrypto.kt", "CookieContentEncryptor.java", "Aes256Cipher.kt", "V2SLSink.kt", "V2SLSource.kt", "V2SLHandshake.kt", "LocoV2SLSocket.kt"]
const patchKey = true;
const printStacktrace = true;
const hookAllClasses = false;

var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');
});

/*
    .overload("java.lang.String")
    .overload("java.lang.String", "java.security.Provider")
    .overload("java.lang.String", "java.lang.String")
*/
function hookCipherGetInstance() {
    var cipherGetInstance = Java.use("javax.crypto.Cipher")["getInstance"].overload("java.lang.String");
    cipherGetInstance.implementation = function (type) {
        var tmp = this.getInstance(type);
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log(caller.getFileName());
            console.log("[Cipher.getInstance()]: type: " + type);
            console.log("[Cipher.getInstance()]:  cipherObj: " + tmp);
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################")
        }
        return tmp;
    }
}

function hookCipherGetInstance2() {
    var cipherGetInstance = Java.use("javax.crypto.Cipher")["getInstance"].overload("java.lang.String", "java.security.Provider");
    cipherGetInstance.implementation = function (transformation, provider) {
        console.log("[Cipher.getInstance2()]: transformation: " + transformation + ",  provider: " + provider);
        var tmp = this.getInstance(transformation, provider);
        console.log("[Cipher.getInstance2()]:  cipherObj: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}

function hookCipherGetInstance3() {
    var cipherGetInstance = Java.use("javax.crypto.Cipher")["getInstance"].overload("java.lang.String", "java.lang.String");
    cipherGetInstance.implementation = function (transformation, provider) {
        console.log("[Cipher.getInstance3()]: transformation: " + transformation + ",  provider: " + provider);
        var tmp = this.getInstance(transformation, provider);
        console.log("[Cipher.getInstance3()]:  cipherObj: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}

/*
    .overload("int", "java.security.cert.Certificate")
    .overload("int", "java.security.Key")
    .overload("int", "java.security.Key", "java.security.AlgorithmParameters")
    .overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec")
    .overload("int", "java.security.cert.Certificate", "java.security.SecureRandom")
    .overload("int", "java.security.Key", "java.security.SecureRandom")
    .overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec", "java.security.SecureRandom")
    .overload("int", "java.security.Key", "java.security.AlgorithmParameters", "java.security.SecureRandom")
*/
function hookCipherInit() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.cert.Certificate");
    cipherInit.implementation = function (mode, cert) {
        console.log("[Cipher.init()]: mode: " + decodeMode(mode) + ", cert: " + cert + " , cipherObj: " + this);
        var tmp = this.init(mode, cert);
    }
}

function hookCipherInit2() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.Key");
    cipherInit.implementation = function (mode, secretKey) {
        var tmp = this.init(mode, secretKey);
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        var key = secretKey.getEncoded();
        console.log("[Cipher.init2()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " , cipherObj: " + this);
        console.log("Caller: " + caller.getFileName());
        // dumpByteArray("Secret key", key);
        var key_base64 = Java.use("android.util.Base64").encodeToString(key, 0);
        console.log("Base64 encoded key: " + key_base64);
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
            console.log(stacktrace);
        }
        console.log("##############################################")
        
    }
}

function hookCipherInit3() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.Key", "java.security.AlgorithmParameters");
    cipherInit.implementation = function (mode, secretKey, alParam) {
        var key = secretKey.getEncoded();
        dumpByteArray("Secret key", key);
        console.log("[Cipher.init3()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " alParam:" + alParam + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, alParam);
    }
}

function hookCipherInit4() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec");
    cipherInit.implementation = function (mode, secretKey, spec) {
        var tmp = this.init(mode, secretKey, spec);
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log(caller.getFileName());
            console.log("[Cipher.init4()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " spec:" + spec + " , cipherObj: " + this);
            var key = secretKey.getEncoded();
            dumpByteArray("Secret key", key);
            var ivParameterSpec = Java.cast(spec, Java.use("javax.crypto.spec.IvParameterSpec"));
            dumpByteArray("IV", ivParameterSpec.getIV());
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################")
        }
    }
}

function hookCipherInit5() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.cert.Certificate", "java.security.SecureRandom");
    cipherInit.implementation = function (mode, cert, secureRandom) {
        var key = secureRandom.getEncoded();
        dumpByteArray("Secret key", key);
        console.log("[Cipher.init5()]: mode: " + decodeMode(mode) + ", cert: " + cert + " secureRandom:" + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, cert, secureRandom);
    }
}

function hookCipherInit6() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.Key", "java.security.SecureRandom");
    cipherInit.implementation = function (mode, secretKey, secureRandom) {
        var tmp = this.init(mode, secretKey, secureRandom);
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            var key = secretKey.getEncoded();
            console.log("[Cipher.init6()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " secureRandom:" + secureRandom + " , cipherObj: " + this);
            console.log("Caller: " + caller.getFileName());
            // dumpByteArray("Secret key", key);
            var secret_key_base64 = Java.use("android.util.Base64").encodeToString(key, 0);
            console.log("Secret key: " + secret_key_base64)
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################")
        }
    }
}

function hookCipherInit7() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec", "java.security.SecureRandom");
    cipherInit.implementation = function (mode, secretKey, spec, secureRandom) {
        var key = secretKey.getEncoded();
        dumpByteArray("Secret key", key);
        console.log("[Cipher.init7()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " spec:" + spec + " secureRandom: " + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, spec, secureRandom);
    }
}

function hookCipherInit8() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.Key", "java.security.AlgorithmParameters", "java.security.SecureRandom");
    cipherInit.implementation = function (mode, secretKey, alParam, secureRandom) {
        var key = secretKey.getEncoded();
        dumpByteArray("Secret key", key);
        console.log("[Cipher.init8()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " alParam:" + alParam + " secureRandom: " + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, alParam, secureRandom);
    }
}

/*
    .overload()
    .overload("[B")
    .overload("[B", "int")
    .overload("java.nio.ByteBuffer", "java.nio.ByteBuffer")
    .overload("[B", "int", "int")
    .overload("[B", "int", "int", "[B")
    .overload("[B", "int", "int", "[B", "int")
*/
function hookDoFinal() {
    var cipherInit = Java.use("javax.crypto.Cipher")["doFinal"].overload();
    cipherInit.implementation = function () {
        console.log("[Cipher.doFinal()]: " + "  cipherObj: " + this);
        var tmp = this.doFinal();
        dumpByteArray("Result", tmp);
        return tmp;
    }
}

function hookDoFinal2() {
    var cipherInit = Java.use("javax.crypto.Cipher")["doFinal"].overload("[B");
    cipherInit.implementation = function (byteArr) {
        var tmp = this.doFinal(byteArr);
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log("[Cipher.doFinal2()]: " + "  cipherObj: " + this);
            console.log("Caller " + caller.getFileName())
            dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
            // dumpByteArray("Result", tmp);
            var result_base64 = Java.use("android.util.Base64").encodeToString(tmp, 0);
            console.log("Result in Base64: " + result_base64)
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################")
        }
        return tmp;
    }
}

function hookDoFinal3() {
    var cipherInit = Java.use("javax.crypto.Cipher")["doFinal"].overload("[B", "int");
    cipherInit.implementation = function (byteArr, a1) {
        console.log("[Cipher.doFinal3()]: " + "  cipherObj: " + this);
        dumpByteArray("Out buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
        var tmp = this.doFinal(byteArr, a1);
        dumpByteArray("Out buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
        return tmp;
    }
}

function hookDoFinal4() {
    var cipherInit = Java.use("javax.crypto.Cipher")["doFinal"].overload("java.nio.ByteBuffer", "java.nio.ByteBuffer");
    cipherInit.implementation = function (a1, a2) {
        console.log("[Cipher.doFinal4()]: " + "  cipherObj: " + this);
        dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", a1.array());
        var tmp = this.doFinal(a1, a2);
        dumpByteArray("Out buffer (cipher: " + this.getAlgorithm() + ")", a2.array());
        return tmp;
    }
}

function hookDoFinal5() {
    var cipherInit = Java.use("javax.crypto.Cipher")["doFinal"].overload("[B", "int", "int");
    cipherInit.implementation = function (byteArr, a1, a2) {
        console.log("[Cipher.doFinal5()]: " + "  cipherObj: " + this);
        dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
        var tmp = this.doFinal(byteArr, a1, a2);
        dumpByteArray("Out buffer (cipher: " + this.getAlgorithm() + ")", tmp);
        return tmp;
    }
}

function hookDoFinal6() {
    var cipherInit = Java.use("javax.crypto.Cipher")["doFinal"].overload("[B", "int", "int", "[B");
    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
        console.log("[Cipher.doFinal6()]: " + "  cipherObj: " + this);
        dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
        var tmp = this.doFinal(byteArr, a1, a2, outputArr);
        dumpByteArray("Out buffer (cipher: " + this.getAlgorithm() + ")", outputArr);

        return tmp;
    }
}

function hookDoFinal7() {
    var cipherInit = Java.use("javax.crypto.Cipher")["doFinal"].overload("[B", "int", "int", "[B", "int");
    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
        console.log("[Cipher.doFinal7()]: " + "  cipherObj: " + this);
        dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
        var tmp = this.doFinal(byteArr, a1, a2, outputArr, a4);
        dumpByteArray("Out buffer (cipher: " + this.getAlgorithm() + ")", outputArr);
        return tmp;
    }
}

/*
    .overload("[B")
    .overload("java.nio.ByteBuffer", "java.nio.ByteBuffer")
    .overload("[B", "int", "int")
    .overload("[B", "int", "int", "[B")
    .overload("[B", "int", "int", "[B", "int")
*/
function hookUpdate() {
    var cipherInit = Java.use("javax.crypto.Cipher")["update"].overload("[B");
    cipherInit.implementation = function (byteArr) {
        console.log("[Cipher.update()]: " + "  cipherObj: " + this);
        dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
        var tmp = this.update(byteArr);
        dumpByteArray("Out buffer (cipher: " + this.getAlgorithm() + ")", tmp);
        return tmp;
    }
}

function hookUpdate2() {
    var cipherInit = Java.use("javax.crypto.Cipher")["update"].overload("java.nio.ByteBuffer", "java.nio.ByteBuffer");
    cipherInit.implementation = function (byteArr, outputArr) {
        console.log("[Cipher.update2()]: " + "  cipherObj: " + this);
        dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", byteArr.array());
        var tmp = this.update(byteArr, outputArr);
        dumpByteArray("Out buffer (cipher: " + this.getAlgorithm() + ")", outputArr.array());
        return tmp;
    }
}

function hookUpdate3() {
    var cipherInit = Java.use("javax.crypto.Cipher")["update"].overload("[B", "int", "int");
    cipherInit.implementation = function (byteArr, a1, a2) {
        console.log("[Cipher.update3()]: " + "  cipherObj: " + this);
        dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
        var tmp = this.update(byteArr, a1, a2);
        dumpByteArray("Out buffer (cipher: " + this.getAlgorithm() + ")", tmp);
        return tmp;
    }
}

function hookUpdate4() {
    var cipherInit = Java.use("javax.crypto.Cipher")["update"].overload("[B", "int", "int", "[B");
    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
        console.log("[Cipher.update4()]: " + "  cipherObj: " + this);
        dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
        var tmp = this.update(byteArr, a1, a2, outputArr);
        dumpByteArray("Out buffer (cipher: " + this.getAlgorithm() + ")", outputArr);
        return tmp;
    }
}

function hookUpdate5() {
    var cipherInit = Java.use("javax.crypto.Cipher")["update"].overload("[B", "int", "int", "[B", "int");
    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
        console.log("[Cipher.update5()]: " + "  cipherObj: " + this);
        dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
        var tmp = this.update(byteArr, a1, a2, outputArr, a4);
        dumpByteArray("Out buffer (cipher: " + this.getAlgorithm() + ")", outputArr);
        return tmp;
    }
}

/*
    .overload("[B")
    .overload("[B", "int", "int")
*/
function hookIVParameterSpecDefInit1() {
    var ivParameterSpecDef = ivParameterSpecDef = Java.use("javax.crypto.spec.IvParameterSpec").$init.overload("[B");
    ivParameterSpecDef.implementation = function (arr) {
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log(caller.getFileName());
            dumpByteArray("IV", arr)
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################")
        }
        return ivParameterSpecDef.call(this, arr);
    }
}

function hookIVParameterSpecDefInit2() {
    var ivParameterSpecDef = ivParameterSpecDef = Java.use("javax.crypto.spec.IvParameterSpec").$init.overload("[B", "int", "int");
    ivParameterSpecDef.implementation = function (arr, off, len) {
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log(caller.getFileName())
            dumpByteArray("IV", arr)
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################")
        }
        return ivParameterSpecDef.call(this, arr, off, len);
    }
}

/*
    .overload("[B", java.lang.String)
    .overload("[B", "int", "int", "java.lang.String")
*/
function hookSecretKeySpecDefInit1() {
    var secretKeySpecDef = Java.use("javax.crypto.spec.SecretKeySpec").$init.overload("[B", "java.lang.String");
    secretKeySpecDef.implementation = function (arr, alg) {
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log(caller.getFileName())
            dumpByteArray(alg + " Secret Key", arr);
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################")
        }
        return secretKeySpecDef.call(this, arr, alg);
    }
}

function hookSecretKeySpecDefInit2() {
    var secretKeySpecDef = Java.use("javax.crypto.spec.SecretKeySpec").$init.overload("[B", "int", "int", "java.lang.String");
    secretKeySpecDef.implementation = function (arr, off, len, alg) {
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log(caller.getFileName())
            dumpByteArray(alg + " Secret Key", arr);
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################")
        }
        return secretKeySpecDef.call(this, arr, off, len, alg);
    }
}

/*
    .overload("java.lang.String")
    .overload("java.lang.String", "java.lang.String")
    .overload("java.lang.String", "java.security.Provider")
*/
function hookKeyGeneratorGetInstance() {
    var keyGeneratorInit = Java.use("javax.crypto.KeyGenerator")["getInstance"].overload("java.lang.String");
    keyGeneratorInit.implementation = function (type) {
        var tmp = this.getInstance(type);
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log(caller.getFileName());
            console.log("[KeyGenerator.getInstance()]: type: " + type);
            console.log("[KeyGenerator.getInstance()]: cipherObj: " + tmp);
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################");
        }
        return tmp;
    }
}

function hookKeyGeneratorGetInstance2() {
    var keyGeneratorInit = Java.use("javax.crypto.KeyGenerator")["getInstance"].overload("java.lang.String", "java.lang.String");
    keyGeneratorInit.implementation = function (alg, provider) {
        var tmp = this.getInstance(alg, provider);
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log(caller.getFileName());
            console.log("[KeyGenerator.getInstance2()]: Algorithm: " + alg);
            console.log("[KeyGenerator.getInstance2()]: Provider: " + provider);
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################");
        }
        return tmp;
    }
}

function hookKeyGeneratorGetInstance3() {
    var keyGeneratorInit = Java.use("javax.crypto.KeyGenerator")["getInstance"].overload("java.lang.String", "java.security.Provider");
    keyGeneratorInit.implementation = function (alg, provider) {
        var tmp = this.getInstance(alg, provider);
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log(caller.getFileName());
            console.log("[KeyGenerator.getInstance2()]: Algorithm: " + alg);
            console.log("[KeyGenerator.getInstance2()]: Provider: " + provider);
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################");
        }
        return tmp;
    }
}

/*
    .overload("int", "java.security.SecureRandom")
*/
function hookKeyGeneratorInit() {
    var keyGeneratorInit = Java.use("javax.crypto.KeyGenerator")["init"].overload("int", "java.security.SecureRandom");
    keyGeneratorInit.implementation = function (length, secureRandom) {
        var tmp = this.init(length, secureRandom);
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log(caller.getFileName());
            console.log("[KeyGenerator.init()]: secureRandom:" + secureRandom + " , cipherObj: " + this);
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################")
        }
    }
}

/*
    .overload()
*/
function hookKeyGeneratorGenerateKey() {
    var generateKey = Java.use("javax.crypto.KeyGenerator")["generateKey"].overload();
    generateKey.implementation = function () {
        var tmp = this.generateKey();
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        const secretKeySpec = Java.cast(tmp, Java.use("javax.crypto.spec.SecretKeySpec"));
        const encodedKey = secretKeySpec.getEncoded();
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log("[KeyGenerator.generateKey()]: Object: " + tmp);
            console.log("Caller: " + caller.getFileName());
            dumpByteArray("[KeyGenerator.generateKey()]: Key", encodedKey);
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
        }
        if (patchKey) {
            console.log("Patching LOCO AES key...")
            const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
            var fakeKey = SecretKeySpec.$new(locoKey, "AES");
            tmp = fakeKey
        }
        console.log("##############################################");
        return tmp;
    }
}

/*
    .overload("java.lang.String")
*/
function hookKeyPairGeneratorGetInstance() {
    var keyPairGetInstance = Java.use("java.security.KeyPairGenerator")["getInstance"].overload("java.lang.String");
    keyPairGetInstance.implementation = function (alg) {
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log(caller.getFileName());
        console.log("[KeyPairGenerator.getInstance()]: Algorithm:" + alg);
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
            console.log(stacktrace);
        }
        console.log("##############################################")
        return this.getInstance(alg);
    }
}

/*
    .overload('[C')
    .overload('[C', '[B', 'int')
    .overload('[C', '[B', 'int', 'int')
*/
function hookPBEKeySpec() {
    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C');
    PBEKeySpec.implementation = function (pass) {
        console.log("[PBEKeySpec.PBEKeySpec()]: password: " + charArrayToString(pass));
        return this.$init(pass);
    }
}

function hookPBEKeySpec2() {
    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C', '[B', 'int');
    PBEKeySpec.implementation = function (pass, salt, iter) {
        console.log("[PBEKeySpec.PBEKeySpec2()]: password: " + charArrayToString(pass) + " iter: " + iter);
        dumpByteArray("Salt", salt)
        return this.$init(pass, salt, iter);
    }
}

function hookPBEKeySpec3() {
    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C', '[B', 'int', 'int');
    PBEKeySpec.implementation = function (pass, salt, iter, keyLength) {
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log("[PBEKeySpec.PBEKeySpec3()]: iter: " + iter + " key length: " + keyLength);
        console.log(caller.getFileName());
        dumpByteArray("Password", charArrayToString(pass).getBytes());
        dumpByteArray("Salt", salt)
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
            console.log(stacktrace);
        }
        console.log("##############################################")
        return this.$init(pass, salt, iter, keyLength);
    }
}

/*
    .overload("xc2.b0", "java.security.Key")
*/
function hookV2SLSinkInit() {
    var V2SLSinkInit = Java.use("mw0.d")["$init"].overload("xc2.b0", "java.security.Key");
    V2SLSinkInit.implementation = function (arg0, arg1) {
        var tmp = this.$init(arg0, arg1);
        const secretKeySpec = Java.cast(arg1, Java.use("javax.crypto.spec.SecretKeySpec"));
        const encodedKey = secretKeySpec.getEncoded();
        dumpByteArray("V2SLSinkInit called with AES Key", encodedKey);
        console.log("##############################################")
    }
}

function hookLocoCipherHelper() {
    var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper$e")["$init"].overload("java.lang.String", "long");
    locoCipherHelper.implementation = function (arg0, arg1) {
        var tmp = this.$init(arg0, arg1);
        console.log("hookLocoCipherHelper called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log(caller.getFileName());
        console.log("Master key: " + arg0);
        console.log("Nonce: " + arg1);
        console.log(this.toString());
        console.log("##############################################")
    }
}

function hookLocoCipherHelper_2() {
    var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper")["s"].overload("com.kakao.talk.secret.LocoCipherHelper$c", "[B", "[B");
    locoCipherHelper.implementation = function (arg0, arg1, arg2) {
        console.log("hookLocoCipherHelper2 called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log(caller.getFileName());
        var ret = locoCipherHelper.call(this, arg0, arg1, arg2);
        console.log(ret)
        return locoCipherHelper.call(this, arg0, arg1, arg2);
    }
}

function hookLocoCipherHelper_3() {
    var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper")["e"].overload("java.lang.String");
    locoCipherHelper.implementation = function (arg0) {
        console.log("hookLocoCipherHelper3 called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log(caller.getFileName());
        var private_key = locoCipherHelper.call(this, arg0);
        // var encoded_key = Java.use("android.util.Base64").encodeToString(private_key.getEncoded(), 0);
        console.log("Generate RSA private key from string: " + arg0);
        // console.log(encoded_key)
        console.log("##############################################");
        return locoCipherHelper.call(this, arg0);
    }
}

function hookLocoCipherHelper_4() {
    var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper")["f"].overload("java.lang.String");
    locoCipherHelper.implementation = function (arg0) {
        console.log("hookLocoCipherHelper4 called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        var ret = locoCipherHelper.call(this, arg0);
        console.log("Caller " + caller.getFileName());
        console.log("Generate RSA public key from string: " + arg0);
        var public_key = locoCipherHelper.call(this, arg0);
        // var encoded_key = Java.use("android.util.Base64").encodeToString(public_key.getEncoded(), 0);
        // console.log(encoded_key);
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
            console.log(stacktrace);
        }
        console.log("##############################################");
        return locoCipherHelper.call(this, arg0);
    }
}

function hookLocoCipherHelper_5() {
    var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper$b")["$init"].overload("com.kakao.talk.secret.LocoCipherHelper$d", "com.kakao.talk.secret.LocoCipherHelper$c");
    locoCipherHelper.implementation = function (arg0, arg1) {
        var tmp = this.$init(arg0, arg1);
        console.log("hookLocoCipherHelper5 called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log(caller.getFileName());
        console.log(arg0);
        console.log(arg1);
        console.log(this.toString());
        console.log("##############################################")
    }
}

function hookLocoCipherHelper_6() {
    var locoCipherHelper = Java.use("com.kakao.talk.secret.LocoCipherHelper")["l"].overload();
    locoCipherHelper.implementation = function () {
        console.log("hookLocoCipherHelper6 called!");
        key = locoCipherHelper.call(this);
        dumpByteArray("Generated shared secret", key);
        console.log("##############################################")
        return locoCipherHelper.call(this);
    }
}

function hookLocoPubKeyInfo() {
    var locoPubKeyInfo = Java.use("tz0.n")["$init"].overload("com.kakao.talk.loco.protocol.LocoBody");
    locoPubKeyInfo.implementation = function (locoBody) {
        var tmp = this.$init(locoBody);
        console.log("locoPubKeyInfo called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log(caller.getFileName());
        console.log(locoBody);
        console.log("##############################################")
    }
}

function hookSecretChatHelper() {
    var secretChatHelper = Java.use("com.kakao.talk.secret.b")["k"].overload("long", "long");
    secretChatHelper.implementation = function (arg0, arg1) {
        console.log("secretChatHelper called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log(caller.getFileName());
        console.log("Long 1: " + arg0);
        console.log("Long 2: " + arg1);
        var ret = secretChatHelper.call(this, arg0, arg1);
        console.log("##############################################")
        return secretChatHelper.call(this, arg0, arg1);
    }
}

function hookSecretChatHelper_2() {
    var secretChatHelper = Java.use("com.kakao.talk.secret.b$e")["a"].overload("long", "long");
    secretChatHelper.implementation = function (arg0, arg1) {
        console.log("secretChatHelper2 called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log(caller.getFileName());
        console.log("Long 1: " + arg0);
        console.log("Long 2: " + arg1);
        var ret = secretChatHelper.call(this, arg0, arg1);
        console.log(ret);
        console.log(this.a);
        console.log("##############################################")
        return secretChatHelper.call(this, arg0, arg1);
    }
}

function hookSecretChatHelper_3() {
    var secretChatHelper = Java.use("com.kakao.talk.secret.b$e")["b"].overload("com.kakao.talk.secret.b$d");
    secretChatHelper.implementation = function (arg0) {
        console.log("secretChatHelper3 called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log(caller.getFileName());
        console.log(this.a);
        console.log("##############################################")
        return secretChatHelper.call(this, arg0);
    }
}

function hookWTFbase64() {
    var wtfBase64 = Java.use("com.kakao.talk.util.r")["a"].overload("java.lang.String");
    wtfBase64.implementation = function (arg0) {
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (!(doNotHookFileNames.includes(caller.getFileName())) || hookAllClasses) {
            console.log("WTF called");
            console.log("Caller: " + caller.getFileName());
            console.log("Base64 encoded: " + arg0);
            var ret = wtfBase64.call(this, arg0);
            dumpByteArray("Base64 decoded bytes", ret);
            console.log("##############################################")
        }
        return wtfBase64.call(this, arg0);
    }
}

function hookLocoSKeyInfo() {
    var locoSKeyInfo = Java.use("tz0.o")["$init"].overload("com.kakao.talk.loco.protocol.LocoBody");
    locoSKeyInfo.implementation = function (arg0) {
        var tmp = this.$init(arg0);
        console.log("hookLocoSKeyInfo called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log("au: " + this.a);
        console.log("sk: " + this.b);
        console.log("as: " + this.c);
        console.log("pt: " + this.d);
        console.log("apt: " + this.e);
        console.log("st: " + this.f);
        console.log("##############################################")
    }
}

function hookTalkLocoPKStore() {
    var talkLocoPKStore = Java.use("df1.e4")["toString"].overload();
    talkLocoPKStore.implementation = function () {
        console.log("talkLocoPKStore called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log(caller.getFileName())
        var ret = talkLocoPKStore.call(this);
        console.log(ret)
        console.log("##############################################")
        return talkLocoPKStore.call(this);
    }
}

function hookTalkLocoPKStore_2() {
    var talkLocoPKStore = Java.use("df1.e4$a")["toString"].overload();
    talkLocoPKStore.implementation = function () {
        console.log("talkLocoPKStore2 called!");
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        console.log(caller.getFileName())
        var ret = talkLocoPKStore.call(this);
        console.log(ret)
        console.log("##############################################")
        return talkLocoPKStore.call(this);
    }
}

function hookAESCTRHelper() {
    var AESCTRHelper = Java.use("sy.a")["b"].overload("java.lang.String", "[B", "int", "javax.crypto.spec.PBEKeySpec");
    AESCTRHelper.implementation = function (arg0, arg1, arg2, arg3) {
        console.log("hookAESCTRHelper called!");
        dumpByteArray("Generated IV", arg1);
        console.log("##############################################");
        return AESCTRHelper.call(this, arg0, arg1, arg2, arg3);
    }
}

function hookAESCTRKeySet() {
    var AESCTRKeySet = Java.use("sy.b")["$init"].overload("[B", "[B", "[B");
    AESCTRKeySet.implementation = function (arg0, arg1, arg2) {
        console.log("AESCTRKeySet called!");
        dumpByteArray("Secret key", arg0);
        dumpByteArray("IV", arg1);
        dumpByteArray("arg2", arg2);
        console.log("##############################################");
        return AESCTRKeySet.call(this, arg0, arg1, arg2);
    }
}

function enableWebviewDebugging() {
    var Webview = Java.use("android.webkit.WebView");
    Webview.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("\n[+]Loading URL from", url);
        console.log("[+]Setting the value of setWebContentsDebuggingEnabled() to TRUE");
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
            console.log(stacktrace);
        }
        var js = this.getSettings().getJavaScriptEnabled();
        console.log("[+]JS enabled: " + js);

        var mw = this.getSettings().supportMultipleWindows();
        console.log("[+]Mutliple windows?: " + mw);

        var fa = this.getSettings().getAllowFileAccess();
        console.log("[+]File access: " + fa);

        var uf = this.getSettings().getAllowUniversalAccessFromFileURLs();
        console.log("[+]Universal file access: " + uf);

        this.setWebContentsDebuggingEnabled(true);
        this.loadUrl.overload("java.lang.String").call(this, url);
    }

    Webview.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, additionalHttpHeaders) {
        console.log("\n[+]Loading URL from", url);
        console.log("[+]Additional Headers:");
        var headers = Java.cast(additionalHttpHeaders, Java.use("java.util.Map"));
        printMap(headers);
        console.log("[+]Setting the value of setWebContentsDebuggingEnabled() to TRUE");
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
            console.log(stacktrace);
        }
        var js = this.getSettings().getJavaScriptEnabled();
        console.log("[+]JS enabled: " + js);

        var mw = this.getSettings().supportMultipleWindows();
        console.log("[+]Mutliple windows?: " + mw);

        var fa = this.getSettings().getAllowFileAccess();
        console.log("[+]File access: " + fa);

        var uf = this.getSettings().getAllowUniversalAccessFromFileURLs();
        console.log("[+]Universal file access: " + uf);

        this.setWebContentsDebuggingEnabled(true);
        this.loadUrl.overload("java.lang.String", "java.util.Map").call(this, url, additionalHttpHeaders);
    }

    Webview.addJavascriptInterface.implementation = function (object, name) {
        console.log('[+]Javascript interface:' + object.$className + ' instantiated as: ' + name);
        this.addJavascriptInterface(object, name);
    }

    var WebviewClient = Java.use("android.webkit.WebViewClient");
    WebviewClient.onPageStarted.overload("android.webkit.WebView", "java.lang.String", "android.graphics.Bitmap").implementation = function (view, url, favicon) {
        console.log("onPageStarted URL: " + url);
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
            console.log(stacktrace);
        }
        this.onPageStarted.overload("android.webkit.WebView", "java.lang.String", "android.graphics.Bitmap").call(this, view, url, favicon);
    }

    var loadURL = Java.use("com.kakao.talk.gametab.widget.webview.KGWebViewLayout").j.overload("android.webkit.WebView", "java.lang.String", "java.util.Map");
    loadURL.implementation = function (arg0, arg1, arg2) {
        console.log("KGWebViewLayout loadURL START");
        console.log(arg0);
        console.log(arg1);
        printMap(arg2);
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
            console.log(stacktrace);
        }
        console.log("KGWebViewLayout loadURL  END");
        return this.j(arg0, arg1, arg2);
    }

    var webviewHelper = Java.use("com.kakao.talk.widget.webview.WebViewHelper");

    var downloadFile = webviewHelper.newDownloadFile.overload("java.lang.String");
    downloadFile.implementation = function (arg0) {
        console.log(arg0);
        var ret = this.newDownloadFile(arg0);
        console.log(ret);
        return ret;
    }

    var processDownload = webviewHelper.processDownload.overload("android.content.Context", "java.lang.String", "java.lang.String", "java.lang.String");
    processDownload.implementation = function (arg0, arg1, arg2, arg3) {
        console.log(arg0);
        console.log(arg1);
        console.log(arg2);
        console.log(arg3);
        var ret = this.processDownload(arg0, arg1, arg2, arg3);
        console.log(ret);
        return ret;
    }

    /*
    var hookHelp = Java.use("com.kakao.talk.webview.activity.HelpActivity").shouldOverrideUrlLoading.overload("android.webkit.WebView", "java.lang.String");
    hookHelp.implementation = function (arg0, arg1) {
        console.log("HELP START");
        console.log(arg0);
        console.log(arg1);
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
            console.log(stacktrace);
        }
        console.log("HELP END");
        return this.shouldOverrideUrlLoading(arg0, arg1);
    }
    */

    /*
    var hookHelp2 = Java.use("com.kakao.talk.webview.activity.HelpActivity")["a"].overload("java.lang.String");
    hookHelp2.implementation = function (arg0) {
        console.log("HELP START");
        console.log(arg0);
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
            console.log(stacktrace);
        }
        console.log("HELP END");
        return this.a(arg0);
    }
    */

    var hookHelp3 = Java.use("com.kakao.talk.webview.activity.HelpActivity")["loadUrl"].overload("java.lang.String", "java.util.Map");
    hookHelp3.implementation = function (arg0, arg1) {
        console.log("HELP START");
        console.log(arg0);
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
            console.log(stacktrace);
        }
        console.log("HELP END");
        return this.loadUrl(arg0, arg1);
    }
}

function hookTest() {
    var hookTest = Java.use("db2.q").O.overload("java.lang.String", "java.lang.String", "java.lang.Boolean");
    hookTest.implementation = function (arg0, arg1, arg2) {
        this.O.overload("java.lang.String", "java.lang.String", "java.lang.Boolean").call(this, arg0, arg1, arg2);
        console.log(arg0);
        console.log(arg1);
    }
}

function hookURIController() {
    var hookTest = Java.use("xv0.k").b.overload("android.content.Context", "android.net.Uri", "java.util.Map");
    hookTest.implementation = function (arg0, arg1, arg2) {
        console.log("URI Controller START");
        console.log(arg0);
        console.log(arg1);
        printMap(arg2);
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "");
            console.log(stacktrace);
        }
        console.log("URI Controller END");
        return this.b(arg0, arg1, arg2);
    }

    var hookTest2 = Java.use("xv0.k").a.overload("android.content.Context", "android.net.Uri", "java.util.Map");
    hookTest2.implementation = function (arg0, arg1, arg2) {
        console.log("URI Controller 2 START");
        console.log(arg0);
        console.log(arg1);
        printMap(arg2);
        if (printStacktrace) {
            var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "");
            console.log(stacktrace);
        }
        console.log("URI Controller 2 END");
        return this.a(arg0, arg1, arg2);
    }

    var hookStartIntent = Java.use("xv0.k").e.overload("android.content.Context", "java.lang.String");
    hookStartIntent.implementation = function (context, str) {
        console.log("Context: " + context);
        console.log("String: " + str);
        return this.e(context, str);
    }

    /*
    var hookIntentChecker = Java.use("xv0.k").d.overload("android.content.Context", "java.lang.String", "java.lang.Boolean");
    hookIntentChecker.implementation = function (context, str, bool) {
        console.log("Context: " + context);
        console.log("String: " + str);
        return this.d(context, str, bool);
    }
    */
}

function deepLinkSniffer() {
    var Intent = Java.use("android.content.Intent");
    Intent.getData.implementation = function () {
        var action = this.getAction() !== null ? this.getAction().toString() : false;
        if (action) {
            console.log("[*] Intent.getData() was called");
            console.log("[*] Activity: " + this.getComponent().getClassName());
            console.log("[*] Action: " + action);
            var uri = this.getData();

            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }

            var extra = this.getStringExtra("url");

            if (extra !== null) {
                console.log("Extra data: " + extra);
            }

            if (uri !== null) {
                console.log("\n[*] Data");
                uri.getScheme() && console.log("- Scheme:\t" + uri.getScheme() + "://");
                uri.getHost() && console.log("- Host:\t\t/" + uri.getHost());
                uri.getQuery() && console.log("- Params:\t" + uri.getQuery());
                uri.getFragment() && console.log("- Fragment:\t" + uri.getFragment());
                console.log("\n\n");
            } else {
                console.log("[-] No data supplied.");
            }
        }
        return this.getData();
    }
}

function hookStrings() {
    let StringBuilder = Java.use("java.lang.StringBuilder");
    StringBuilder.toString.overload().implementation = function () {
        let StringBuilderResult = this.toString.call(this);

        if (StringBuilderResult !== null && StringBuilderResult.indexOf("file:") != -1) {
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("[+] StringBuilder:\t", StringBuilderResult);
        }
        return StringBuilderResult;
    }

    let StringBuffer = Java.use("java.lang.StringBuffer");
    StringBuffer.toString.overload().implementation = function () {
        let StringBufferResult = this.toString.call(this);

        if (StringBufferResult !== null && StringBufferResult.indexOf("http") != -1) {
            console.log("[+] StringBuffer:\t", StringBufferResult);
        }
        return StringBufferResult;
    }
}

/* Utils */
function printMap(map) {
    var mapIter = map.entrySet().iterator();
    while (mapIter.hasNext()) {
        console.log(mapIter.next())
    }
}

function decodeMode(mode) {
    if (mode == 1)
        return "Encrypt mode";
    else if (mode == 2)
        return "Decrypt mode";
    else if (mode == 3)
        return "Wrap mode";
    else if (mode == 4)
        return "Unwrap mode";
}

function charArrayToString(charArray) {
    if (charArray == null)
        return '(null)';
    else
        return StringCls.$new(charArray);
}

/* All below is hexdump implementation */
function dumpByteArray(title, byteArr) {
    if (byteArr != null) {
        try {
            var buff = new ArrayBuffer(byteArr.length)
            var dtv = new DataView(buff)
            for (var i = 0; i < byteArr.length; i++) {
                dtv.setUint8(i, byteArr[i]); // Frida sucks sometimes and returns different byteArr.length between ArrayBuffer(byteArr.length) and for(..; i < byteArr.length;..). It occured even when Array.copyOf was done to work on copy.
            }
            console.log(title + ":\n");
            console.log(hexdumpJS(dtv.buffer, 0, byteArr.length))
        } catch (error) { console.log("Exception has occured in hexdump") }
    }
    else {
        console.log("byteArr is null!");
    }
}

function _fillUp(value, count, fillWith) {
    var l = count - value.length;
    var ret = "";
    while (--l > -1)
        ret += fillWith;
    return ret + value;
}

function hexdumpJS(arrayBuffer, offset, length) {

    var view = new DataView(arrayBuffer);
    offset = offset || 0;
    length = length || arrayBuffer.byteLength;

    var out = _fillUp("Offset", 8, " ") + "  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n";
    var row = "";
    for (var i = 0; i < length; i += 16) {
        row += _fillUp(offset.toString(16).toUpperCase(), 8, "0") + "  ";
        var n = Math.min(16, length - offset);
        var string = "";
        for (var j = 0; j < 16; ++j) {
            if (j < n) {
                var value = view.getUint8(offset);
                string += (value >= 32 && value < 128) ? String.fromCharCode(value) : ".";
                row += _fillUp(value.toString(16).toUpperCase(), 2, "0") + " ";
                offset++;
            }
            else {
                row += "   ";
                string += " ";
            }
        }
        row += " " + string + "\n";
    }
    out += row;
    return out;
};
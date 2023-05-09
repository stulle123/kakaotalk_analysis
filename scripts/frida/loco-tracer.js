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
    hookCipherInit2(); // Kakaotalk
    hookCipherInit3();
    hookCipherInit4(); // Kakaotalk
    hookCipherInit5();
    hookCipherInit6(); // Kakaotalk
    hookCipherInit7();
    hookCipherInit8();
    hookDoFinal();
    hookDoFinal2(); // Kakaotalk
    hookDoFinal3();
    hookDoFinal4();
    hookDoFinal5();
    hookDoFinal6();
    hookDoFinal7();
    hookUpdate();
    hookUpdate2();
    hookUpdate3();
    hookUpdate4();
    hookUpdate5();
    hookIVParameterSpecDefInit1(); // Kakaotalk
    hookIVParameterSpecDefInit2(); // Kakaotalk
    hookSecretKeySpecDefInit1(); // Kakaotalk
    hookSecretKeySpecDefInit2(); // Kakaotalk
    hookKeyGeneratorGetInstance(); // Kakaotalk
    hookKeyGeneratorGetInstance2();
    hookKeyGeneratorGetInstance3();
    hookKeyGeneratorInit(); // Kakaotalk
    hookKeyGeneratorGenerateKey(); // Kakaotalk
    hookKeyPairGeneratorGetInstance(); // Kakaotalk
    hookPBEKeySpec();
    hookPBEKeySpec2();
    hookPBEKeySpec3(); // Kakaotalk
    // hookV2SLSinkInit(); // Kakaotalk
    */
    hookDoFinal2(); // Kakaotalk
    hookKeyGeneratorGenerateKey(); // Kakaotalk
    // hookPBEKeySpec3(); // Kakaotalk
});

const locoClasses = ["c41.c", "cv.a", "cv.b", "mw0.a", "mw0.c", "mw0.d", "mw0.e", "com.android.org.conscrypt.KeyGeneratorImpl"];
const secretChatClasses = ["xa1.a", "xa1.i", "xa1.k", "LocoCipherHelper"];
const locoKey = Java.array("byte", [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
const patchKey = true;
const printStacktrace = false;
const hookAllClasses = false

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
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
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
    cipherGetInstance.implementation = function (transforamtion, provider) {
        console.log("[Cipher.getInstance2()]: transforamtion: " + transforamtion + ",  provider: " + provider);
        var tmp = this.getInstance(transforamtion, provider);
        console.log("[Cipher.getInstance2()]:  cipherObj: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}

function hookCipherGetInstance3() {
    var cipherGetInstance = Java.use("javax.crypto.Cipher")["getInstance"].overload("java.lang.String", "java.lang.String");
    cipherGetInstance.implementation = function (transforamtion, provider) {
        console.log("[Cipher.getInstance3()]: transforamtion: " + transforamtion + ",  provider: " + provider);
        var tmp = this.getInstance(transforamtion, provider);
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
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
            console.log("[Cipher.init2()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " , cipherObj: " + this);
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################")
        }
    }
}

function hookCipherInit3() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.Key", "java.security.AlgorithmParameters");
    cipherInit.implementation = function (mode, secretKey, alParam) {
        console.log("[Cipher.init3()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " alParam:" + alParam + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, alParam);
    }
}

function hookCipherInit4() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec");
    cipherInit.implementation = function (mode, secretKey, spec) {
        var tmp = this.init(mode, secretKey, spec);
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
            console.log("[Cipher.init4()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " spec:" + spec + " , cipherObj: " + this);
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
        console.log("[Cipher.init5()]: mode: " + decodeMode(mode) + ", cert: " + cert + " secureRandom:" + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, cert, secureRandom);
    }
}

function hookCipherInit6() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.Key", "java.security.SecureRandom");
    cipherInit.implementation = function (mode, secretKey, secureRandom) {
        var tmp = this.init(mode, secretKey, secureRandom);
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
            console.log("[Cipher.init6()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " secureRandom:" + secureRandom + " , cipherObj: " + this);
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
        console.log("[Cipher.init7()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " spec:" + spec + " secureRandom: " + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, spec, secureRandom);
    }
}

function hookCipherInit8() {
    var cipherInit = Java.use("javax.crypto.Cipher")["init"].overload("int", "java.security.Key", "java.security.AlgorithmParameters", "java.security.SecureRandom");
    cipherInit.implementation = function (mode, secretKey, alParam, secureRandom) {
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
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
            console.log("[Cipher.doFinal2()]: " + "  cipherObj: " + this);
            dumpByteArray("In buffer (cipher: " + this.getAlgorithm() + ")", byteArr);
            dumpByteArray("Result", tmp);
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
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
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
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
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
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
            dumpByteArray("Original " + alg + " Secret Key", arr);
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
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
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
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
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
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
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
        var caller = Java.use("java.lang.Exception").$new().getStackTrace()[1];
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
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
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
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
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
            const secretKeySpec = Java.cast(tmp, Java.use("javax.crypto.spec.SecretKeySpec"));
            const encodedKey = secretKeySpec.getEncoded();
            /*
            console.log("[KeyGenerator.generateKey()]: Object: " + tmp);
            dumpByteArray("[KeyGenerator.generateKey()]: Key:", encodedKey);
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            */
            if (patchKey) {
                const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
                var fakeKey = SecretKeySpec.$new(locoKey, "AES");
                tmp = fakeKey
            }
            console.log("##############################################");
        }
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
        if (locoClasses.includes(caller.getClassName()) || hookAllClasses) {
            console.log("[KeyPairGenerator.getInstance()]: Algorithm:" + alg);
            if (printStacktrace) {
                var stacktrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).replace("java.lang.Exception", "")
                console.log(stacktrace);
            }
            console.log("##############################################")
        }
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
        console.log("[PBEKeySpec.PBEKeySpec3()]: password: " + charArrayToString(pass) + " iter: " + iter + " key length: " + keyLength);
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

/* All below is hexdump implementation*/
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
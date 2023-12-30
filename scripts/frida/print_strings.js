/*
Print all Strings.
*/

import { printStacktrace } from "./utils.js";

Java.perform(function () {
  hookStrings();
});

const printStacktrace = false;
var StringCls = null;

Java.perform(function () {
  StringCls = Java.use("java.lang.String");
});

function hookStrings() {
  let StringBuilder = Java.use("java.lang.StringBuilder");
  StringBuilder.toString.overload().implementation = function () {
    let StringBuilderResult = this.toString.call(this);

    if (
      StringBuilderResult !== null &&
      StringBuilderResult.indexOf("file:") != -1
    ) {
      if (printStacktrace) {
        printStacktrace();
      }
      console.log("[+] StringBuilder:\t", StringBuilderResult);
    }
    return StringBuilderResult;
  };

  let StringBuffer = Java.use("java.lang.StringBuffer");
  StringBuffer.toString.overload().implementation = function () {
    let StringBufferResult = this.toString.call(this);

    if (
      StringBufferResult !== null &&
      StringBufferResult.indexOf("http") != -1
    ) {
      console.log("[+] StringBuffer:\t", StringBufferResult);
    }
    return StringBufferResult;
  };
}

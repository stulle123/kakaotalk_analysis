/*
Debug Deep Links.
*/

import { printStacktrace } from "./utils.js";

Java.perform(function () {
  deepLinkSniffer();
});

const printStacktrace = false;

function deepLinkSniffer() {
  var Intent = Java.use("android.content.Intent");
  Intent.getData.implementation = function () {
    var action =
      this.getAction() !== null ? this.getAction().toString() : false;
    if (action) {
      console.log("[*] Intent.getData() was called");
      console.log("[*] Activity: " + this.getComponent().getClassName());
      console.log("[*] Action: " + action);
      var uri = this.getData();

      if (printStacktrace) {
        printStacktrace();
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
  };
}

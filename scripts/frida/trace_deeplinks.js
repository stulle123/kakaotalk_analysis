/*
Debug Deep Links.
*/

const enableStacktracePrinting = false;

Java.perform(function () {
  deepLinkSniffer();
});

function deepLinkSniffer() {
  var Intent = Java.use("android.content.Intent");
  Intent.getData.implementation = function () {
    var action =
      this.getAction() !== null ? this.getAction().toString() : false;
    if (action) {
      console.log("[*] Intent.getData() was called");
      if (this.getComponent()) {
        console.log("[*] Activity: " + this.getComponent().getClassName());
      }
      console.log("[*] Action: " + action);
      var uri = this.getData();

      if (enableStacktracePrinting) {
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

function printStacktrace() {
  var stacktrace = Java.use("android.util.Log")
    .getStackTraceString(Java.use("java.lang.Exception").$new())
    .replace("java.lang.Exception", "");
  console.log(stacktrace);
}

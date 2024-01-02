/*
Debug WebViews.
*/

const enableStacktracePrinting = false;

Java.perform(function () {
  enableWebviewDebugging();
});

function enableWebviewDebugging() {
  var Webview = Java.use("android.webkit.WebView");

  Webview.loadUrl.overload("java.lang.String").implementation = function (url) {
    console.log("\n[+] Loading URL from", url);
    console.log(
      "[+] Setting the value of setWebContentsDebuggingEnabled() to TRUE"
    );
    if (enableStacktracePrinting) {
      printStacktrace();
    }
    var js = this.getSettings().getJavaScriptEnabled();
    console.log("[+] JS enabled: " + js);

    var mw = this.getSettings().supportMultipleWindows();
    console.log("[+] Multiple windows?: " + mw);

    var fa = this.getSettings().getAllowFileAccess();
    console.log("[+] File access: " + fa);

    var uf = this.getSettings().getAllowUniversalAccessFromFileURLs();
    console.log("[+] Universal file access: " + uf);

    this.setWebContentsDebuggingEnabled(true);
    this.loadUrl.overload("java.lang.String").call(this, url);
  };

  Webview.loadUrl.overload("java.lang.String", "java.util.Map").implementation =
    function (url, additionalHttpHeaders) {
      console.log("\n[+] Loading URL from", url);
      console.log("[+] Additional Headers:");
      var headers = Java.cast(additionalHttpHeaders, Java.use("java.util.Map"));
      printMap(headers);
      console.log(
        "[+] Setting the value of setWebContentsDebuggingEnabled() to TRUE"
      );

      if (enableStacktracePrinting) {
        printStacktrace();
      }

      var js = this.getSettings().getJavaScriptEnabled();
      console.log("[+] JS enabled: " + js);

      var mw = this.getSettings().supportMultipleWindows();
      console.log("[+] Multiple windows?: " + mw);

      var fa = this.getSettings().getAllowFileAccess();
      console.log("[+] File access: " + fa);

      var uf = this.getSettings().getAllowUniversalAccessFromFileURLs();
      console.log("[+] Universal file access: " + uf);

      this.setWebContentsDebuggingEnabled(true);
      this.loadUrl
        .overload("java.lang.String", "java.util.Map")
        .call(this, url, additionalHttpHeaders);
    };

  Webview.addJavascriptInterface.implementation = function (object, name) {
    console.log(
      "[+] Javascript interface:" +
        object.$className +
        " instantiated as: " +
        name
    );
    this.addJavascriptInterface(object, name);
  };

  var WebviewClient = Java.use("android.webkit.WebViewClient");
  WebviewClient.onPageStarted.overload(
    "android.webkit.WebView",
    "java.lang.String",
    "android.graphics.Bitmap"
  ).implementation = function (view, url, favicon) {
    console.log("onPageStarted URL: " + url);
    if (enableStacktracePrinting) {
      printStacktrace();
    }
    this.onPageStarted
      .overload(
        "android.webkit.WebView",
        "java.lang.String",
        "android.graphics.Bitmap"
      )
      .call(this, view, url, favicon);
  };

  var webviewHelper = Java.use("com.kakao.talk.widget.webview.WebViewHelper");

  var downloadFile = webviewHelper.newDownloadFile.overload("java.lang.String");
  downloadFile.implementation = function (arg0) {
    console.log(arg0);
    var ret = this.newDownloadFile(arg0);
    console.log(ret);
    return ret;
  };

  var processDownload = webviewHelper.processDownload.overload(
    "android.content.Context",
    "java.lang.String",
    "java.lang.String",
    "java.lang.String"
  );
  processDownload.implementation = function (arg0, arg1, arg2, arg3) {
    console.log(arg0);
    console.log(arg1);
    console.log(arg2);
    console.log(arg3);
    var ret = this.processDownload(arg0, arg1, arg2, arg3);
    console.log(ret);
    return ret;
  };
}

function printStacktrace() {
  var stacktrace = Java.use("android.util.Log")
    .getStackTraceString(Java.use("java.lang.Exception").$new())
    .replace("java.lang.Exception", "");
  console.log(stacktrace);
}

function printMap(map) {
  var mapIter = map.entrySet().iterator();
  while (mapIter.hasNext()) {
    console.log(mapIter.next());
  }
}

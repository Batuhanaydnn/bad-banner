Java.perform(function () {
    var WebViewClient = Java.use('android.webkit.WebViewClient');
  
    WebViewClient.shouldInterceptRequest.overload(
      'android.webkit.WebView', 'android.webkit.WebResourceRequest'
    ).implementation = function (webView, request) {
      var url = request.getUrl().toString();
      send({ endpoint: url });
      return this.shouldInterceptRequest(webView, request);
    };
  });
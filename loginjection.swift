import example

// x2

class LogViewController: UIViewController { 

    func foo6(webView: WKWebView, navigationAction: WKNavigationAction) {
        let urlStr = navigationAction.request.url?.absoluteString
        let components = URLComponents(url: urlStr, resolvingAgainstBaseURL: false)
        // vuln log injection
        NSLog("Query value = %@", components.query)
        NSLog("Host value = %@", components.host)
    }
}

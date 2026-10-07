// SA-IOS-03: Modern WKWebView with navigation delegate
import UIKit
import WebKit

class ModernWebViewController: UIViewController, WKNavigationDelegate {
    lazy var webView: WKWebView = {
        let config = WKWebViewConfiguration()
        let wv = WKWebView(frame: .zero, configuration: config)
        wv.navigationDelegate = self
        return wv
    }()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.addSubview(webView)
        webView.frame = view.bounds
        let url = URL(string: "https://example.com")!
        webView.load(URLRequest(url: url))
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let host = navigationAction.request.url?.host,
              host == "example.com" else {
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }
}

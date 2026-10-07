// SA-IOS-03: Deprecated UIWebView usage
import UIKit

class LegacyWebViewController: UIViewController {
    let webView = UIWebView()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.addSubview(webView)
        webView.frame = view.bounds
        let url = URL(string: "https://example.com")!
        webView.loadRequest(URLRequest(url: url))
    }
}

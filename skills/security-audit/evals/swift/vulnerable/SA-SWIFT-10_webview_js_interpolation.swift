import UIKit
import WebKit

final class ProfileViewController: UIViewController {
    @IBOutlet weak var webView: WKWebView!

    func showGreeting(for userName: String) {
        // vulnerable: a display name like ');document.location='https://evil.example'//
        // becomes executable script inside the page
        webView.evaluateJavaScript("renderGreeting('\(userName)')")
    }

    func showSearchResults(_ query: String) {
        webView.evaluateJavaScript("renderResults('\(query)', true)")
    }
}

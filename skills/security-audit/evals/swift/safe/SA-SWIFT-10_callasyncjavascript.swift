import WebKit

final class HelpCenterViewController {
    let webView = WKWebView()

    // Highlights the user-entered search term inside the help article.
    func highlightSearchTerm(_ term: String) {
        // safe: the value crosses the bridge as a typed argument, so it
        // can never be parsed as JavaScript source
        webView.callAsyncJavaScript(
            "highlightAll(term)",
            arguments: ["term": term],
            in: nil,
            in: .page,
            completionHandler: nil)
    }

    func refreshLayout() {
        // safe: static script text with no interpolated input
        webView.evaluateJavaScript("window.dispatchEvent(new Event('resize'))")
    }
}

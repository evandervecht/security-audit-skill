import Foundation

final class ApiClient: NSObject, URLSessionDelegate {
    lazy var session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // vulnerable: blindly wrapping serverTrust in a credential accepts
        // ANY certificate, including one minted by an on-path attacker
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }

    func fetchProfile() async throws -> Data {
        let (data, _) = try await session.data(from: URL(string: "https://api.example.com/me")!)
        return data
    }
}

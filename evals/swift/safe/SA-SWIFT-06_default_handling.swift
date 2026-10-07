import Foundation
import Security

final class ApiClient: NSObject, URLSessionDelegate {
    private let clientIdentity: SecIdentity
    lazy var session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)

    init(clientIdentity: SecIdentity) {
        self.clientIdentity = clientIdentity
        super.init()
    }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodClientCertificate:
            // safe: presents the mTLS client identity; this does not
            // weaken validation of the server certificate
            let credential = URLCredential(identity: clientIdentity,
                                           certificates: nil,
                                           persistence: .forSession)
            completionHandler(.useCredential, credential)
        default:
            // safe: defer to the operating system's full chain validation
            // instead of handing the server trust back unverified
            completionHandler(.performDefaultHandling, nil)
        }
    }

    func fetchProfile() async throws -> Data {
        let (data, _) = try await session.data(from: URL(string: "https://api.example.com/me")!)
        return data
    }
}

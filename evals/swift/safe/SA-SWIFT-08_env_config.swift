import Foundation

struct PaymentConfig {
    enum ConfigError: Error {
        case missingCredential(String)
    }

    // safe: identifiers that merely mention a sensitive word are not
    // credentials - URLs, UI placeholders, and Keychain lookup keys
    static let tokenEndpoint = "https://api.stripe.com/v1/oauth/token"
    static let passwordPlaceholder = "Enter your password"
    static let tokenKeychainService = "com.example.app.refresh-token"

    let stripeApiKey: String
    let webhookSecret: String

    // safe: credentials are injected at runtime from the process
    // environment (server) or fetched from the Keychain (app); nothing
    // sensitive is compiled into the binary
    init(environment: [String: String] = ProcessInfo.processInfo.environment) throws {
        guard let key = environment["STRIPE_API_KEY"] else {
            throw ConfigError.missingCredential("STRIPE_API_KEY")
        }
        guard let webhook = environment["STRIPE_WEBHOOK_SECRET"] else {
            throw ConfigError.missingCredential("STRIPE_WEBHOOK_SECRET")
        }
        stripeApiKey = key
        webhookSecret = webhook
    }
}

final class PaymentGateway {
    let config: PaymentConfig

    init(config: PaymentConfig) {
        self.config = config
    }

    func authorize(amountCents: Int) async throws {
        var request = URLRequest(url: URL(string: "https://api.stripe.com/v1/charges")!)
        request.httpMethod = "POST"
        request.setValue("Bearer " + config.stripeApiKey, forHTTPHeaderField: "Authorization")
        request.httpBody = Data("amount=\(amountCents)&currency=eur".utf8)
        _ = try await URLSession.shared.data(for: request)
    }
}

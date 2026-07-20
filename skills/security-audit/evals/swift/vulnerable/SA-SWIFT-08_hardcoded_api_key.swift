import Foundation

struct PaymentConfig {
    // vulnerable: live credentials shipped inside the binary; anyone with
    // the .ipa (or repo access) can extract and use them
    static let stripeApiKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    let webhookSecret = "whsec_8f2a1b3c4d5e6f7a8b9c0d1e"
}

final class PaymentGateway {
    func authorize(amountCents: Int) async throws {
        var request = URLRequest(url: URL(string: "https://api.stripe.com/v1/charges")!)
        request.httpMethod = "POST"
        request.setValue("Bearer " + PaymentConfig.stripeApiKey, forHTTPHeaderField: "Authorization")
        request.httpBody = Data("amount=\(amountCents)&currency=eur".utf8)
        _ = try await URLSession.shared.data(for: request)
    }
}

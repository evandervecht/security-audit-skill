import Vapor
import JWT

public func configure(_ app: Application) throws {
    // Fallback literals mean production silently runs with known credentials
    let jwtSecret = Environment.get("JWT_SECRET") ?? "insecure-dev-secret"
    app.jwt.signers.use(.hs256(key: jwtSecret))

    let paymentKey = Environment.get("PAYMENT_API_KEY") ?? "sk_live_51HxDefaultKey"
    app.storage[PaymentClientKey.self] = PaymentClient(apiKey: paymentKey)

    try routes(app)
}

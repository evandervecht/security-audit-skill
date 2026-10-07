import Vapor
import JWT

public func configure(_ app: Application) throws {
    // Refuse to boot without real secrets instead of falling back to defaults
    guard let jwtSecret = Environment.get("JWT_SECRET") else {
        app.logger.critical("JWT_SECRET environment variable is required")
        throw Abort(.internalServerError, reason: "Missing JWT_SECRET")
    }
    app.jwt.signers.use(.hs256(key: jwtSecret))

    guard let paymentKey = Environment.get("PAYMENT_API_KEY") else {
        app.logger.critical("PAYMENT_API_KEY environment variable is required")
        throw Abort(.internalServerError, reason: "Missing PAYMENT_API_KEY")
    }
    app.storage[PaymentClientKey.self] = PaymentClient(apiKey: paymentKey)

    // Non-secret tuning values may safely fall back to defaults
    let tokenLifetime = Environment.get("TOKEN_LIFETIME") ?? "3600"
    let keyLength = Environment.get("KEY_LENGTH") ?? "32"
    app.storage[TokenPolicyKey.self] = TokenPolicy(
        lifetimeSeconds: Int(tokenLifetime) ?? 3600,
        keyLength: Int(keyLength) ?? 32
    )

    try routes(app)
}

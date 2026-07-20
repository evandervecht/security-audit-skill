import Vapor

public func configure(_ app: Application) throws {
    // Explicit allowlist of first-party origins; credentials stay scoped to them
    let corsConfiguration = CORSMiddleware.Configuration(
        allowedOrigin: .any(["https://app.example.com", "https://admin.example.com"]),
        allowedMethods: [.GET, .POST, .PUT, .DELETE, .OPTIONS],
        allowedHeaders: [.accept, .authorization, .contentType, .origin],
        allowCredentials: true
    )
    app.middleware.use(CORSMiddleware(configuration: corsConfiguration), at: .beginning)

    app.middleware.use(app.sessions.middleware)
    try routes(app)
}

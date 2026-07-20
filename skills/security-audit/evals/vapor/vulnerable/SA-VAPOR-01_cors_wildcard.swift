import Vapor

public func configure(_ app: Application) throws {
    // CORS opened up "temporarily" so the mobile team could test from anywhere
    let corsConfiguration = CORSMiddleware.Configuration(
        allowedOrigin: .all,
        allowedMethods: [.GET, .POST, .PUT, .DELETE, .OPTIONS],
        allowedHeaders: [.accept, .authorization, .contentType, .origin],
        allowCredentials: true
    )
    app.middleware.use(CORSMiddleware(configuration: corsConfiguration), at: .beginning)

    app.middleware.use(app.sessions.middleware)
    try routes(app)
}

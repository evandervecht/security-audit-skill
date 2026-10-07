import Vapor

public func configure(_ app: Application) throws {
    // Session cookie locked to HTTPS and hidden from script access
    app.sessions.configuration = .init(cookieName: "vapor-session") { sessionID in
        HTTPCookies.Value(string: sessionID.string, maxAge: 604800, isSecure: true, isHTTPOnly: true, sameSite: .strict)
    }
    app.middleware.use(app.sessions.middleware)
    try routes(app)
}

import Vapor

public func configure(_ app: Application) throws {
    // Cookie flags relaxed during local debugging and never restored
    app.sessions.configuration = .init(cookieName: "vapor-session") { sessionID in
        HTTPCookies.Value(string: sessionID.string, maxAge: 604800, isSecure: false, isHTTPOnly: false, sameSite: .lax)
    }
    app.middleware.use(app.sessions.middleware)
    try routes(app)
}

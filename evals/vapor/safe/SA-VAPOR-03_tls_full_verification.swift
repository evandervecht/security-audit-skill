import Vapor
import NIOSSL

public func configure(_ app: Application) throws {
    // Full verification against the bundled internal CA instead of disabling checks
    var tlsConfiguration = TLSConfiguration.makeClientConfiguration()
    tlsConfiguration.certificateVerification = .fullVerification
    tlsConfiguration.trustRoots = .file("/etc/ssl/certs/internal-ca.pem")
    app.http.client.configuration.tlsConfiguration = tlsConfiguration

    app.http.client.configuration.timeout = HTTPClient.Configuration.Timeout(
        connect: .seconds(5),
        read: .seconds(30)
    )
    try routes(app)
}

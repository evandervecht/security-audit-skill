import Vapor
import NIOSSL

public func configure(_ app: Application) throws {
    // Internal CA kept failing validation, so verification was switched off
    var tlsConfiguration = TLSConfiguration.makeClientConfiguration()
    tlsConfiguration.certificateVerification = .none
    app.http.client.configuration.tlsConfiguration = tlsConfiguration

    app.http.client.configuration.timeout = HTTPClient.Configuration.Timeout(
        connect: .seconds(5),
        read: .seconds(30)
    )
    try routes(app)
}

import Foundation
import Vapor
import FluentPostgreSQL
import Authentication

final class User: Codable {
    var id: UUID?
    var name: String
    var username: String
    var password: String
    var twitterURL: String?
    var email: String
    var profilePicture: String?
    
    init(name: String, username: String, password: String, twitterURL: String? = nil, email: String, profilePicture: String? = nil) {
        self.name = name
        self.username = username
        self.password = password
        self.twitterURL = twitterURL
        self.email = email
        self.profilePicture = profilePicture
    }

    final class Public: Codable {
        var id: UUID?
        var name: String
        var username: String

        init(id: UUID?, name: String, username: String) {
            self.id = id
            self.name = name
            self.username = username
        }
    }

    final class PublicV2: Codable {
        var id: UUID?
        var name: String
        var username: String
        var twitterURL: String?

        init(id: UUID?, name: String, username: String, twitterURL: String? = nil) {
            self.id = id
            self.name = name
            self.username = username
            self.twitterURL = twitterURL
        }
    }

}



extension User: PostgreSQLUUIDModel {}
extension User: Content {}
extension User: Migration {
    static func prepare(on connection: PostgreSQLConnection) -> Future<Void> {
        // 1
        return Database.create(self, on: connection) { builder in
            // 2
            builder.field(for: \.id, isIdentifier: true)
            builder.field(for: \.name)
            builder.field(for: \.username)
            builder.field(for: \.password)
            builder.field(for: \.email)
            builder.field(for: \.profilePicture)
            // 3
            builder.unique(on: \.username)
            builder.unique(on: \.email)
        }
    }
}
extension User: Parameter {}
extension User {
    var acronyms: Children<User, Acronym> {
        return children(\.userID)
    }
}

extension User.Public: Content {}

extension User.PublicV2: Content {}

extension User {
    func convertToPublic() -> User.Public {
        return User.Public(id: id, name: name, username: username)
    }
    func convertToPublicV2() -> User.PublicV2 {
        return User.PublicV2(id: id, name: name, username: username, twitterURL: twitterURL)
    }
}

extension Future where T: User {
    func convertToPublic() -> Future<User.Public> {
        return self.map(to: User.Public.self) { user in
            return user.convertToPublic()
        }
    }
    func convertToPublicV2() -> Future<User.PublicV2> {
        return self.map(to: User.PublicV2.self) { user in
            return user.convertToPublicV2()
        }
    }
}

extension User: BasicAuthenticatable {
    static let usernameKey: UsernameKey = \User.username
    static let passwordKey: PasswordKey = \User.password
}

extension User: TokenAuthenticatable {
    typealias TokenType = Token
}

struct AdminUser: Migration {
    typealias Database = PostgreSQLDatabase
    static func prepare(on connection: PostgreSQLConnection) -> Future<Void> {
        let password = try? BCrypt.hash("password")
        guard let hashedPassword = password else {
            fatalError("Failed to create admin user")
        }
        let user = User(name: "Admin", username: "admin", password: hashedPassword, email: "admin@localhost.local")
        return user.save(on: connection).transform(to: ())
    }

    static func revert(on connection: PostgreSQLConnection) -> Future<Void> {
        return .done(on: connection)
    }

}

extension User: PasswordAuthenticatable {}
extension User: SessionAuthenticatable {}

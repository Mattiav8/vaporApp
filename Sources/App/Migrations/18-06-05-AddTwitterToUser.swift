import FluentPostgreSQL
import Vapor


// 1
struct AddTwitterURLToUser: Migration {
    // 2
    typealias Database = PostgreSQLDatabase
    // 3
    static func prepare(on connection: PostgreSQLConnection) -> Future<Void> {
        // 4
        return Database.update(User.self, on: connection) { builder in
            // 5
            builder.field(for: \.twitterURL)
        }
    }
    // 6
    static func revert(on connection: PostgreSQLConnection) -> Future<Void> {
        // 7
        return Database.update(User.self, on: connection) { builder in
            // 8
            builder.deleteField(for: \.twitterURL)
        }
    }
}

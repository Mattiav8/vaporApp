import FluentPostgreSQL
import Vapor

// 1
struct MakeCategoriesUnique: Migration {
    // 2
    typealias Database = PostgreSQLDatabase
    // 3
    static func prepare(on connection: PostgreSQLConnection) -> Future<Void> {
        // 4
        return Database.update(Category.self, on: connection) { builder in
            // 5
            builder.unique(on: \.name)
        }
    }
    // 6
    static func revert(on connection: PostgreSQLConnection) -> Future<Void> {
        // 7
        return Database.update(Category.self, on: connection) { builder in
            // 8
            builder.deleteUnique(from: \.name)
        }
    }
}

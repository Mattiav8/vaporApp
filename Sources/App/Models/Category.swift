import Vapor
import FluentPostgreSQL

final class Category: Codable {
    var id: Int?
    var name: String
    
    init(name: String) {
        self.name = name
    }
}

extension Category: PostgreSQLModel {}
extension Category: Content {}
extension Category: Migration {}
extension Category: Parameter {}
extension Category {
    var acronyms: Siblings<Category, Acronym, AcronymCategoryPivot> {
        return siblings()
    }
    static func addCategory(_ name: String, to acronym: Acronym, on req: Request) throws -> Future<Void> {
        // 1
        return Category.query(on: req)
            .filter(\.name == name)
            .first()
            .flatMap(to: Void.self) { foundCategory in
                if let existingCategory = foundCategory {
                    // 2
                    return acronym.categories
                        .attach(existingCategory, on: req)
                        .transform(to: ())
                } else {
                    // 3
                    let category = Category(name: name)
                    // 4
                    return category.save(on: req)
                        .flatMap(to: Void.self) { savedCategory in
                            // 5
                            return acronym.categories
                                .attach(savedCategory, on: req)
                                .transform(to: ())
                    }
                }
        }
    }
}

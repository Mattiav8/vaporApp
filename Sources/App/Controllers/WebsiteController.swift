import Vapor
import Leaf
import Fluent
import Authentication
import SendGrid

// 1
struct WebsiteController: RouteCollection {
    let imageFolder = "ProfilePictures/"
    // 2
    func boot(router: Router) throws {
        // 3
        let authSessionRoutes = router.grouped(User.authSessionsMiddleware())
        authSessionRoutes.get(use: indexHandler)
        authSessionRoutes.get("acronyms", Acronym.parameter, use: acronymHandler)
        authSessionRoutes.get("users", User.parameter, use: userHandler)
        authSessionRoutes.get("users", use: allUsersHandler)
        authSessionRoutes.get("categories", use: allCategoriesHandler)
        authSessionRoutes.get("categories", Category.parameter, use: categoryHandler)
        authSessionRoutes.get("login", use: loginHandler)
        authSessionRoutes.post(LoginPostData.self, at: "login", use: loginPostHandler)
        authSessionRoutes.post("logout", use: logoutHandler)
        authSessionRoutes.get("register", use: registerHandler)
        authSessionRoutes.post(RegisterData.self, at: "register", use: registerPostHandler)
        authSessionRoutes.get("forgottenPassword", use: forgottenPasswordHandler)
        authSessionRoutes.post("forgottenPassword", use: forgottenPasswordPostHandler)
        authSessionRoutes.get("resetPassword", use: resetPasswordHandler)
        authSessionRoutes.post(ResetPasswordData.self, at: "resetPassword", use: resetPasswordPostHandler)
        authSessionRoutes.get("users", User.parameter, "profilePicture", use: getUsersProfilePictureHandler)
        let protectedRoutes = authSessionRoutes.grouped(RedirectMiddleware<User>(path: "/login"))
        protectedRoutes.get("acronyms", "create", use: createAcronymHandler)
        protectedRoutes.post(CreateAcronymData.self, at: "acronyms", "create", use: createAcronymPostHandler)
        protectedRoutes.get("acronyms", Acronym.parameter, "edit", use: editAcronymHandler)
        protectedRoutes.post("acronyms", Acronym.parameter, "edit", use: editAcronymPostHandler)
        protectedRoutes.post("acronyms", Acronym.parameter, "delete", use: deleteAcronymHandler)
        protectedRoutes.get("users", User.parameter, "addProfilePicture", use: addProfilePictureHandler)
        protectedRoutes.post("users", User.parameter, "addProfilePicture", use: addProfilePicturePostHandler)
    }

    // 4
    func indexHandler(_ req: Request) throws -> Future<View> {
        // 1
        return Acronym.query(on: req).all()
                                     .flatMap(to: View.self) { acronyms in
            // 2
            let acronymsData = acronyms.isEmpty ? nil : acronyms
            let userLoggedIn = try req.isAuthenticated(User.self)
            let showCookieMessage = req.http.cookies["cookies-accepted"] == nil
                                        let context = IndexContext(title: "Homepage", acronyms: acronymsData, userLoggedIn: userLoggedIn, showCookieMessage: showCookieMessage)
            return try req.view().render("index", context)
        }
    }

    // 1
    func acronymHandler(_ req: Request) throws -> Future<View> {
        // 2
        return try req.parameters.next(Acronym.self).flatMap(to: View.self) { acronym in
            // 3
            return acronym.user.get(on: req)
                .flatMap(to: View.self) { user in
                    // 4
                    let categories = try acronym.categories.query(on: req).all()
                    let context = AcronymContext(title: acronym.short, acronym: acronym, user: user, categories: categories)
                    return try req.view().render("acronym", context)
            }
        }
    }

    func userHandler(_ req: Request) throws -> Future<View> {
        // 2
        return try req.parameters.next(User.self).flatMap(to: View.self) { user in
            // 3
            return try user.acronyms.query(on: req)
                                    .all()
                                    .flatMap(to: View.self) { acronyms in
                                        // 4
                                        let loggedInUser = try req.authenticated(User.self)
                                        let context = UserContext(title: user.name, user: user, acronyms: acronyms, authenticatedUser: loggedInUser)
                                        return try req.view().render("user", context)
            }
        }
    }
    // 1
    func allUsersHandler(_ req: Request) throws -> Future<View> {
        // 2
        return User.query(on: req)
            .all()
            .flatMap(to: View.self) { users in
                // 3
                let context = AllUsersContext(title: "All Users", users: users)
                return try req.view().render("allUsers", context)
        }
    }

    func allCategoriesHandler(_ req: Request) throws -> Future<View> {
        // 1
        let categories = Category.query(on: req).all()
        let context = AllCategoriesContext(categories: categories)
        // 2
        return try req.view().render("allCategories", context)
    }

    func categoryHandler(_ req: Request) throws -> Future<View> {
        // 1
        return try req.parameters.next(Category.self).flatMap(to: View.self) { category in
            // 2
            let acronyms = try category.acronyms.query(on: req).all()
            // 3
            let context = CategoryContext(title: category.name, category: category, acronyms: acronyms)
            // 4
            return try req.view().render("category", context)
        }
    }

    func createAcronymHandler(_ req: Request) throws -> Future<View> {
        // 1
        let token = try CryptoRandom().generateData(count: 16).base64EncodedString()
        let context = CreateAcronymContext(csrfToken: token)
        try req.session()["CSRF_TOKEN"] = token
        // 2
        return try req.view().render("createAcronym", context)
    }
    // 1
    func createAcronymPostHandler(_ req: Request, data: CreateAcronymData) throws -> Future<Response> {
        let expectedToken = try req.session()["CSRF_TOKEN"]
        try req.session()["CSRF_TOKEN"] = nil
        guard expectedToken == data.csrfToken else {
            throw Abort(.badRequest)
        }
        // 2
        let user = try req.requireAuthenticated(User.self)
        let acronym = try Acronym(short: data.short, long: data.long, userID: user.requireID())
        // 3
        return acronym.save(on: req).flatMap(to: Response.self) { acronym in
            guard let id = acronym.id else {
                throw Abort(.internalServerError)
            }
            // 4
            var categorySaves: [Future<Void>] = []
            // 5
            for category in data.categories ?? [] {
                try categorySaves.append(Category.addCategory(category, to: acronym, on: req))
            }
            // 6
            let redirect = req.redirect(to: "/acronyms/\(id)")
            return categorySaves.flatten(on: req).transform(to: redirect)
        }
    }

    func editAcronymHandler(_ req: Request) throws -> Future<View> {
        // 1
        return try req.parameters.next(Acronym.self).flatMap(to: View.self) { acronym in
            // 2
            let categories = try acronym.categories.query(on: req).all()
            let context = EditAcronymContext(acronym: acronym, categories: categories)
            // 3
            return try req.view().render("createAcronym", context)
        }
    }

    func editAcronymPostHandler(_ req: Request) throws -> Future<Response> {
        // 1
        return try flatMap(to: Response.self, req.parameters.next(Acronym.self), req.content.decode(CreateAcronymData.self)) { acronym, data in
            let user = try req.requireAuthenticated(User.self)
            acronym.short = data.short
            acronym.long = data.long
            acronym.userID = try user.requireID()
            // 2
            return acronym.save(on: req).flatMap(to: Response.self) { savedAcronym in
                guard let id = savedAcronym.id else {
                    throw Abort(.internalServerError)
                }
                // 3
                return try acronym.categories.query(on: req).all().flatMap(to: Response.self) { existingCategories in
                    // 4
                    let existingStringArray = existingCategories.map { $0.name }
                    // 5
                    let existingSet = Set<String>(existingStringArray)
                    let newSet = Set<String>(data.categories ?? [])
                    // 6
                    let categoriesToAdd = newSet.subtracting(existingSet)
                    let categoriesToRemove = existingSet.subtracting(newSet)
                    // 7
                    var categoryResults: [Future<Void>] = []
                    // 8
                    for newCategory in categoriesToAdd {
                        categoryResults.append(try Category.addCategory(newCategory, to: acronym, on: req))
                    }
                    // 9
                    for categoryNameToRemove in categoriesToRemove {
                        // 10
                        let categoryToRemove = existingCategories.first {
                            $0.name == categoryNameToRemove
                        }
                        // 11
                        if let category = categoryToRemove {
                            categoryResults.append(acronym.categories.detach(category, on: req))
                        }
                    }
                    // 12
                    return categoryResults
                        .flatten(on: req)
                        .transform(to: req.redirect(to: "/acronyms/\(id)"))
                }
            }
        }
    }

    func deleteAcronymHandler(_ req: Request) throws -> Future<Response> {
        return try req.parameters.next(Acronym.self).delete(on: req).transform(to: req.redirect(to: "/"))
    }

    func loginHandler(_ req: Request) throws -> Future<View> {
        let context: LoginContext
        if req.query[Bool.self, at: "error"] != nil {
            context = LoginContext(loginError: true)
        } else {
            context = LoginContext()
        }
        return try req.view().render("login", context)
    }

    func loginPostHandler(_ req: Request, userData: LoginPostData) throws -> Future<Response> {
        return User.authenticate(username: userData.username, password: userData.password, using: BCryptDigest(), on: req).map(to: Response.self) { user in
            guard let user = user else {
                return req.redirect(to: "/login?error")
            }
            try req.authenticateSession(user)
            return req.redirect(to: "/")
        }
    }

    func logoutHandler(_ req: Request) throws -> Response {
        try req.unauthenticateSession(User.self)
        return req.redirect(to: "/")
    }

    func registerHandler(_ req: Request) throws -> Future<View> {
        let context: RegisterContext
        if let message = req.query[String.self, at: "message"] {
            context = RegisterContext(message: message)
        } else {
            context = RegisterContext()
        }
        return try req.view().render("register", context)
    }
    // 1
    func registerPostHandler(_ req: Request, data: RegisterData) throws -> Future<Response> {
        do {
            try data.validate()
        } catch (let error) {
            let redirect: String
            if let error = error as? ValidationError, let message = error.reason.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) {
                redirect = "/register?message=\(message)"
            } else {
                redirect = "/register?message=Unknown+error"
            }
            return req.future(req.redirect(to: redirect))
        }
        // 2
        let password = try BCrypt.hash(data.password)
        // 3
        var twitterURL: String?
        if let twitter = data.twitterURL, !twitter.isEmpty {
            twitterURL = twitter
        }
        let user = User(name: data.name, username: data.username, password: password, twitterURL: twitterURL, email: data.emailAddress)
        // 4
        return user.save(on: req).map(to: Response.self) { user in
            // 5
            try req.authenticateSession(user)
            // 6
            return req.redirect(to: "/")
        }
    }
    // 1
    func forgottenPasswordHandler(_ req: Request) throws -> Future<View> {
        // 2
        return try req.view().render("forgottenPassword", ["title": "Reset Your Passowrd"])
    }

    // 1
    func forgottenPasswordPostHandler(_ req: Request) throws -> Future<View> {
        // 2
        let email = try req.content.syncGet(String.self, at: "email")
        // 3
        return User.query(on: req).filter(\.email == email).first().flatMap(to: View.self) { user in
            // 1
            guard let user = user else {
                return try req.view().render("forgottenPasswordConfirmed", ["title": "Password Reset Email Sent"])
            }
            // 2
            let resetTokenString = try CryptoRandom().generateData(count: 32).base32EncodedString()
            // 3
            let resetToken = try ResetPasswordToken(token: resetTokenString, userID: user.requireID())
            // 4
            return resetToken.save(on: req).flatMap(to: View.self) { _ in
                // 5
                let emailContent = """
                <p>You've requested to reset your passowrd. <a
                href="http://localhost:8080/resetPassword?\
                token=\(resetTokenString)">
                Click here</a> to reset your password.</p>
                """
                // 6
                let emailAddress = EmailAddress(email: user.email, name: user.name)
                let fromEmail = EmailAddress(email: "mattia-viotto@outlook.com", name: "Vapor TIL")
                // 7
                let emailConfig = Personalization(to: [emailAddress], subject: "Reset Your Password")
                // 8
                let email = SendGridEmail(personalizations: [emailConfig], from: fromEmail, content: [["type": "text/html", "value": emailContent]])
                // 9
                let sendGridClient = try req.make(SendGridClient.self)
                return try sendGridClient.send([email], on: req.eventLoop).flatMap(to: View.self) { _ in
                    // 10
                    return try req.view().render("forgottenPasswordConfirmed", ["title": "Password Reset Email Sent"])
                }
            }
        }
    }

    func resetPasswordHandler(_ req: Request) throws -> Future<View> {
        // 1
        guard let token = req.query[String.self, at: "token"] else {
            return try req.view().render("resetPassword", ResetPasswordContext(error: true))
        }
        // 2
        return ResetPasswordToken.query(on: req).filter(\.token == token).first().map(to: ResetPasswordToken.self) { token in
            // 3
            guard let token = token else {
                throw Abort.redirect(to: "/")
            }
            return token
            }.flatMap { token in
                // 4
                return token.user.get(on: req).flatMap { user in
                    try req.session().set("ResetPasswordUser", to: user)
                    // 5
                    return token.delete(on: req)
                }
            }.flatMap {
                // 6
                try req.view().render("resetPassword", ResetPasswordContext())
        }
    }

    // 1
    func resetPasswordPostHandler(_ req: Request, data: ResetPasswordData) throws -> Future<Response> {
        // 2
        guard data.password == data.confirmPassword else {
            return try req.view().render("resetPassword", ResetPasswordContext(error: true)).encode(for: req)
        }
        // 3
        let resetPasswordUser = try req.session().get("ResetPasswordUser", as: User.self)
        try req.session()["ResetPasswordUser"] = nil
        // 4
        let newPassword = try BCrypt.hash(data.password)
        resetPasswordUser.password = newPassword
        // 5
        return resetPasswordUser.save(on: req).transform(to: req.redirect(to: "/login"))
    }

    func addProfilePictureHandler(_ req: Request) throws -> Future<View> {
        return try req.parameters.next(User.self).flatMap { user in
            try req.view().render("addProfilePicture", ["title": "Add Profile Picture", "username": user.name])
        }
    }

    func addProfilePicturePostHandler(_ req: Request) throws -> Future<Response> {
        // 1
        return try flatMap(to: Response.self, req.parameters.next(User.self), req.content.decode(ImageUploadData.self)) { user, imageData in
            // 2
            let workPath = try req.make(DirectoryConfig.self).workDir
            // 3
            let name = try "\(user.requireID())-\(UUID().uuidString).jpg"
            // 4
            let path = workPath + self.imageFolder + name
            // 5
            FileManager().createFile(atPath: path, contents: imageData.picture, attributes: nil)
            // 6
            user.profilePicture = name
            // 7
            let redirect = try req.redirect(to: "/users/\(user.requireID())")
            return user.save(on: req).transform(to: redirect)
        }
    }

    func getUsersProfilePictureHandler(_ req: Request) throws -> Future<Response> {
        // 1
        return try req.parameters.next(User.self).flatMap(to: Response.self) { user in
            // 2
            guard let filename = user.profilePicture else {
                throw Abort(.notFound)
            }
            // 3
            let path = try req.make(DirectoryConfig.self).workDir + self.imageFolder + filename
            // 4
            return try req.streamFile(at: path)
        }
    }
}

struct IndexContext: Encodable {
    let title: String
    let acronyms: [Acronym]?
    let userLoggedIn: Bool
    let showCookieMessage: Bool
}

struct AcronymContext: Encodable {
    let title: String
    let acronym: Acronym
    let user: User
    let categories: Future<[Category]>
}

struct UserContext: Encodable {
    let title: String
    let user: User
    let acronyms: [Acronym]
    let authenticatedUser: User?
}

struct AllUsersContext: Encodable {
    let title: String
    let users: [User]
}

struct AllCategoriesContext: Encodable {
    let title = "All Categories"
    let categories: Future<[Category]>
}

struct CategoryContext: Encodable {
    let title: String
    let category: Category
    let acronyms: Future<[Acronym]>
}

struct CreateAcronymContext: Encodable {
    let title = "Create An Acronym"
    let csrfToken: String
}

struct EditAcronymContext: Encodable {
    // 1
    let title = "Edit Acronym"
    // 2
    let acronym: Acronym
    // 3
    // 4
    let editing = true
    let categories: Future<[Category]>
}

struct CreateAcronymData: Content {
    let short: String
    let long: String
    let categories: [String]?
    let csrfToken: String
}

struct LoginContext: Encodable {
    let title = "Log In"
    let loginError: Bool
    init(loginError: Bool = false) {
        self.loginError = loginError
    }
}

struct LoginPostData: Content {
    let username: String
    let password: String
}

struct RegisterContext: Encodable {
    let title = "Register"
    let message: String?
    init(message: String? = nil) {
        self.message = message
    }
}

struct RegisterData: Content {
    let name: String
    let username: String
    let password: String
    let confirmPassword: String
    let emailAddress: String
    let twitterURL: String?
}
// 1
extension RegisterData: Validatable, Reflectable {
    // 2
    static func validations() throws -> Validations<RegisterData> {
        // 3
        var validations = Validations(RegisterData.self)
        // 4
        try validations.add(\.name, .ascii)
        // 5
        try validations.add(\.username, .alphanumeric && .count(3...))
        // 6
        try validations.add(\.password, .count(8...))
        validations.add("passwords match") { model in
            guard model.password == model.confirmPassword else {
                throw BasicValidationError("passwords don't match")
            }
        }
        try validations.add(\.emailAddress, .email)
        // 7
        return validations
    }
}

struct ResetPasswordContext: Encodable {
    let title = "Reset Password"
    let error: Bool?

    init(error: Bool? = false) {
        self.error = error
    }
}

struct ResetPasswordData: Content {
    let password: String
    let confirmPassword: String
}

struct ImageUploadData: Content {
    var picture: Data
}

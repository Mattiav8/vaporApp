import Vapor
import Imperial
import Authentication

struct ImperialController: RouteCollection {
    func boot(router: Router) throws {
        guard let googleCallbackURL = Environment.get("GOOGLE_CALLBACK_URL") else {
            fatalError("Google callback URL not set")
        }
        try router.oAuth(from: Google.self, authenticate: "login-google", callback: googleCallbackURL, scope: ["profile", "email"], completion: processGoogleLogin)

        guard let githubCallbackURL = Environment.get("GITHUB_CALLBACK_URL") else {
            fatalError("GitHub callback URL not set")
        }
        try router.oAuth(from: GitHub.self, authenticate: "login-github", callback: githubCallbackURL, scope: ["user:email"], completion: processGitHubLogin)
    }

    func processGoogleLogin(request: Request, token: String) throws -> Future<ResponseEncodable> {
        // 1
        return try Google.getUser(on: request).flatMap(to: ResponseEncodable.self) { userInfo in
            // 2
            return User.query(on: request).filter(\.username == userInfo.email).first().flatMap(to: ResponseEncodable.self) { foundUser in
                guard let existingUser = foundUser else {
                    // 3
                    let user = User(name: userInfo.name, username: userInfo.email, password: UUID().uuidString, email: userInfo.email)
                    // 4
                    return user.save(on: request).map(to: ResponseEncodable.self) { user in
                        // 5
                        try request.authenticateSession(user)
                        return request.redirect(to: "/")
                    }
                }
                // 6
                try request.authenticateSession(existingUser)
                return request.future(request.redirect(to: "/"))
            }
        }
    }

    func processGitHubLogin(request: Request, token: String) throws -> Future<ResponseEncodable> {
        // 1
        return try flatMap(to: ResponseEncodable.self, GitHub.getUser(on: request), GitHub.getEmails(on: request)) { userInfo, emailInfo in
            return User.query(on: request).filter(\.username == userInfo.login)
                .first().flatMap(to: ResponseEncodable.self) { foundUser in
                    guard let existingUser = foundUser else {
                        // 2
                        let user = User(name: userInfo.name, username: userInfo.login, password: UUID().uuidString, email: emailInfo[0].email)
                        return user.save(on: request).map(to: ResponseEncodable.self) { user in
                            try request.authenticateSession(user)
                            return request.redirect(to: "/")
                        }
                    }
                    try request.authenticateSession(existingUser)
                    return request.future(request.redirect(to: "/"))
            }

        }
    }



}

struct GoogleUserInfo: Content {
    let email: String
    let name: String
}

extension Google {
    // 1
    static func getUser(on request: Request) throws -> Future<GoogleUserInfo> {
        // 2
        var headers = HTTPHeaders()
        headers.bearerAuthorization = try BearerAuthorization(token: request.accessToken())
        // 3
        let googleAPIURL = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json"
        // 4
        return try request.client().get(googleAPIURL, headers: headers).map(to: GoogleUserInfo.self) { response in
            // 5
            guard response.http.status == .ok else {
                // 6
                if response.http.status == .unauthorized {
                    throw Abort.redirect(to: "/login-google")
                } else {
                    throw Abort(.internalServerError)
                }
            }
            // 7
            return try response.content.syncDecode(GoogleUserInfo.self)
        }
    }
}

struct GitHubUserInfo: Content {
    let name: String
    let login: String
}

struct GitHubEmailInfo: Content {
    let email: String
}

extension GitHub {
    // 1
    static func getUser(on request: Request) throws -> Future<GitHubUserInfo> {
        // 2
        var headers = HTTPHeaders()
        headers.bearerAuthorization = try BearerAuthorization(token: request.accessToken())
        // 3
        let githubUserAPIURL = "https://api.github.com/user"
        // 4
        return try request.client().get(githubUserAPIURL, headers: headers).map(to: GitHubUserInfo.self) { response in
            // 5
            guard response.http.status == .ok else {
                // 6
                if response.http.status == .unauthorized {
                    throw Abort.redirect(to: "/login-github")
                } else {
                    throw Abort(.internalServerError)
                }
            }
            // 7
            return try response.content.syncDecode(GitHubUserInfo.self)
        }
    }

    // 1
    static func getEmails(on request: Request) throws -> Future<[GitHubEmailInfo]> {
        // 2
        var headers = HTTPHeaders()
        headers.bearerAuthorization = try BearerAuthorization(token: request.accessToken())

        // 3
        let githubUserAPIURL = "https://api/github.com/user/emails"
        return try request.client().get(githubUserAPIURL, headers: headers).map(to: [GitHubEmailInfo].self) { response in
            // 4
            guard response.http.status == .ok else {
                // 5
                if response.http.status == .unauthorized {
                    throw Abort.redirect(to: "/login-github")
                } else {
                    throw Abort(.internalServerError)
                }
            }
            // 6
            return try response.content.syncDecode([GitHubEmailInfo].self)
        }
    }
}

import Foundation

import OAuth2

/// Response to retrieving authentication token
///
/// - token: Successful response will contain the authentication token
/// - error: Unsuccessful response will contain the error
public enum AuthResponse {
  case token(String)
  case error(Error)
}

/// Handles authenticating a service account
public struct BigQueryAuthProvider {
  /// Set scope to be BigQuery
  private let scopes = [
    "https://www.googleapis.com/auth/bigquery",
    "https://www.googleapis.com/auth/bigquery.insertdata",
  ]

  private let tokenURL: URL

  public init(tokenURL: URL) {
    self.tokenURL = tokenURL
  }

  /// Get an authentication token to be used in API calls.
  /// The credentials file is expected to be in the same directory as the
  /// running binary (ie. $pwd/credentials.json)
  ///
  /// - Parameter completionHandler: Called upon completion
  /// - Throws: If JWT creation fails
  public func getAuthenticationToken(completionHandler: @escaping (AuthResponse) -> Void) throws {
    guard let tokenProvider = ServiceAccountTokenProvider(
      credentialsURL: tokenURL,
      scopes:scopes
    ) else {
      fatalError("Failed to create token provider")
    }
    // Request token
    try tokenProvider.withToken { (token, error) in
      if let token = token {
        completionHandler(.token(token.AccessToken!))
      } else {
        completionHandler(.error(error!))
      }
    }
  }
}

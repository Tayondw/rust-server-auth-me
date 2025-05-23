// pub async fn verify_email_handler(
//     State(state): State<Arc<AppState>>,
//     Query(query): Query<VerifyQuery>
// ) -> Result<impl IntoResponse, HttpError> {
//     let mut conn = state.conn()?;

//     // Look up user by token
//     let result = diesel
//         ::update(users.filter(verification_token.eq(&query.token)))
//         .set((
//             is_verified.eq(true),
//             verification_token.eq::<Option<String>>(None),
//             updated_at.eq(Utc::now().naive_utc()),
//         ))
//         .get_result::<User>(&mut conn);

//     match result {
//         Ok(user) =>
//             Ok(
//                 Json(
//                     json!({
//             "message": "Email verified successfully",
//             "user_id": user.id
//         })
//                 )
//             ),
//         Err(_) => Err(HttpError::not_found("Invalid or expired token")),
//     }
// }

// pub async fn login_handler(
//     State(state): State<Arc<AppState>>,
//     Json(body): Json<LoginRequest>
// ) -> Result<impl IntoResponse, HttpError> {
//     body.validate().map_err(|e| HttpError::bad_request(e.to_string()))?;

//     let result = state.config.database
//         .get_user(UserQuery::Email(&body.email))
//         .map_err(|e| HttpError::server_error(e.to_string()))?;

//     let user = result.ok_or(HttpError::bad_request(ErrorMessage::WrongCredentials.to_string()))?;

//     let password_matched = password
//         ::compare(&body.password, &user.password)
//         .map_err(|_| HttpError::bad_request(ErrorMessage::WrongCredentials.to_string()))?;

//     if password_matched {
//         let token = create_token(
//             &user.id.to_string(),
//             &state.config.database.jwt_secret.as_bytes(),
//             state.config.database.jwt_expires_in
//         ).map_err(|e| HttpError::server_error(e.to_string()))?;

//         let cookie_duration = TimeDuration::minutes(state.config.database.jwt_expires_in * 60);
//         let mut cookie = Cookie::new("token", token.clone());
//         cookie.set_path("/");
//         cookie.set_max_age(cookie_duration);
//         cookie.set_http_only(true);
//         cookie.secure();

//         let response = Json(UserLoginResponse {
//             status: "success".to_string(),
//             token,
//         });

//         let mut headers = HeaderMap::new();
//         headers.append(header::SET_COOKIE, cookie.to_string().parse().unwrap());

//         let mut response = response.into_response();
//         response.headers_mut().extend(headers);

//         Ok(response)
//     } else {
//         Err(HttpError::bad_request(ErrorMessage::WrongCredentials.to_string()))
//     }
// }

// pub async fn login_handler(
//     State(auth_service): State<Arc<AuthService>>,
//     cookies: Cookies,
//     Json(credentials): Json<LoginRequest>
// ) -> impl IntoResponse {
//     match auth_service.validate_credentials(&credentials.email, &credentials.password).await {
//         Ok(user) => {
//             let user_id = user.id.to_string();
//             match auth_service.generate_access_token(&user_id) {
//                 Ok(access_token) => {
//                     match auth_service.generate_refresh_token(&user_id) {
//                         Ok(refresh_token) => {
//                             set_access_token(&cookies, access_token, auth_service.config());
//                             set_refresh_token(&cookies, refresh_token, auth_service.config());

//                             (
//                                 StatusCode::OK,
//                                 Json(
//                                     json!({
//                                     "status": "success",
//                                     "message": "Successfully logged in",
//                                     "user": {
//                                         "id": user.id,
//                                         "username": user.username,
//                                         "name": user.name,
//                                         "email": user.email
//                                     }
//                                 })
//                                 ),
//                             )
//                         }
//                         Err(_) =>
//                             (
//                                 StatusCode::INTERNAL_SERVER_ERROR,
//                                 Json(
//                                     json!({
//                                 "status": "error",
//                                 "message": "Failed to generate refresh token"
//                             })
//                                 ),
//                             ),
//                     }
//                 }
//                 Err(_) =>
//                     (
//                         StatusCode::INTERNAL_SERVER_ERROR,
//                         Json(
//                             json!({
//                         "status": "error",
//                         "message": "Failed to generate access token"
//                     })
//                         ),
//                     ),
//             }
//         }
//         Err(_) =>
//             (
//                 StatusCode::UNAUTHORIZED,
//                 Json(
//                     json!({
//                 "status": "error",
//                 "message": "Invalid username or password"
//             })
//                 ),
//             ),
//     }
// }

// pub async fn refresh_token_handler(
//     State(auth_service): State<Arc<AuthService>>,
//     cookies: Cookies
// ) -> impl IntoResponse {
//     let Some(refresh_token) = get_refresh_token(&cookies) else {
//         return unauthorized("No refresh token found");
//     };

//     let claims = match auth_service.verify_refresh_token(&refresh_token) {
//         Ok(claims) => claims,
//         Err(_) => {
//             remove_auth_cookies(&cookies);
//             return unauthorized("Invalid refresh token");
//         }
//     };

//     let new_access_token = match auth_service.generate_access_token(&claims.sub) {
//         Ok(token) => token,
//         Err(_) => {
//             return internal_error("Failed to generate new access token");
//         }
//     };

//     let new_refresh_token = match auth_service.generate_refresh_token(&claims.sub) {
//         Ok(token) => token,
//         Err(_) => {
//             return internal_error("Failed to generate new refresh token");
//         }
//     };

//     set_access_token(&cookies, new_access_token, auth_service.config());
//     set_refresh_token(&cookies, new_refresh_token, auth_service.config());

//     (
//         StatusCode::OK,
//         Json(
//             json!({
//             "status": "success",
//             "message": "Tokens refreshed successfully"
//         })
//         ),
//     )
// }

// fn unauthorized(message: &str) -> (StatusCode, Json<serde_json::Value>) {
//     (StatusCode::UNAUTHORIZED, Json(json!({ "status": "error", "message": message })))
// }

// fn internal_error(message: &str) -> (StatusCode, Json<serde_json::Value>) {
//     (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": message })))
// }

// pub async fn refresh_token_handler(
//     State(auth_service): State<Arc<AuthService>>,
//     cookies: Cookies
// ) -> impl IntoResponse {
//     match get_refresh_token(&cookies) {
//         Some(refresh_token) => {
//             match auth_service.verify_refresh_token(&refresh_token) {
//                 Ok(claims) => {
//                     // Generate new access token and refresh token
//                     match auth_service.generate_access_token(&claims.sub) {
//                         Ok(new_access_token) => {
//                             match auth_service.generate_refresh_token(&claims.sub) {
//                                 Ok(new_refresh_token) => {
//                                     // Set both new tokens in cookies
//                                     set_access_token(
//                                         &cookies,
//                                         new_access_token,
//                                         auth_service.config()
//                                     );
//                                     set_refresh_token(
//                                         &cookies,
//                                         new_refresh_token,
//                                         auth_service.config()
//                                     );

//                                     (
//                                         StatusCode::OK,
//                                         Json(
//                                             json!({
//                                             "status": "success",
//                                             "message": "Tokens refreshed successfully"
//                                         })
//                                         ),
//                                     )
//                                 }
//                                 Err(_) =>
//                                     (
//                                         StatusCode::INTERNAL_SERVER_ERROR,
//                                         Json(
//                                             json!({
//                                         "status": "error",
//                                         "message": "Failed to generate new refresh token"
//                                     })
//                                         ),
//                                     ),
//                             }
//                         }
//                         Err(_) =>
//                             (
//                                 StatusCode::INTERNAL_SERVER_ERROR,
//                                 Json(
//                                     json!({
//                                 "status": "error",
//                                 "message": "Failed to generate new access token"
//                             })
//                                 ),
//                             ),
//                     }
//                 }
//                 Err(_) => {
//                     remove_auth_cookies(&cookies);
//                     (
//                         StatusCode::UNAUTHORIZED,
//                         Json(
//                             json!({
//                             "status": "error",
//                             "message": "Invalid refresh token"
//                         })
//                         ),
//                     )
//                 }
//             }
//         }
//         None =>
//             (
//                 StatusCode::UNAUTHORIZED,
//                 Json(
//                     json!({
//                 "status": "error",
//                 "message": "No refresh token found"
//             })
//                 ),
//             ),
//     }
// }

// pub fn authentication_routes(
//     config: &Config,
//     pool: Pool<ConnectionManager<PgConnection>>
// ) -> Router<Arc<AppState>> {
//     let authentication_service: Arc<AuthService> = Arc::new(AuthService::new(config, pool));

//     // Create protected routes
//     let protected_routes = Router::new()
//         .route("/protected", get(protected_handler))
//         .route("/refresh", post(refresh_token_handler))
//         .route("/logout", post(logout_handler))
//         .layer(middleware::from_fn_with_state(authentication_service.clone(), auth_middleware));

//     // Combine with public routes
//     Router::new()
//         .route("/login", post(login_handler))
//         .merge(protected_routes)
//         .with_state(authentication_service)
//         .layer(cookie_layer())
// }

// pub async fn auth_middleware(
//     cookies: Cookies,
//     State(state): State<Arc<AppState>>,
//     request: Request<Body>,
//     next: Next
// ) -> Response {
//     let access_token = match get_access_token(&cookies) {
//         Some(token) => token,
//         None => {
//             return Response::builder()
//                 .status(StatusCode::UNAUTHORIZED)
//                 .body(Body::from("Unauthorized: No access token"))
//                 .unwrap();
//         }
//     };

//     let auth_service = AuthService::new(&state.config, state.db_pool.clone());

//     match auth_service.verify_access_token(&access_token) {
//         Ok(_) => next.run(request).await,
//         Err(_) =>
//             Response::builder()
//                 .status(StatusCode::UNAUTHORIZED)
//                 .body(Body::from("Unauthorized: Invalid token"))
//                 .unwrap(),
//     }
// }

// pub async fn auth_middleware(
//     cookies: Cookies,
//     State(auth_service): State<Arc<AuthService>>,
//     request: Request<Body>,
//     next: Next
// ) -> Response {
//     let access_token: String = match get_access_token(&cookies) {
//         Some(token) => token,
//         None => {
//             return Response::builder()
//                 .status(StatusCode::UNAUTHORIZED)
//                 .body(Body::from("Unauthorized: No access token"))
//                 .unwrap();
//         }
//     };

//     match auth_service.verify_access_token(&access_token) {
//         Ok(_claims) => next.run(request).await,
//         Err(_) =>
//             Response::builder()
//                 .status(StatusCode::UNAUTHORIZED)
//                 .body(Body::from("Unauthorized: Invalid token"))
//                 .unwrap(),
//     }
// }

// pub fn remove_auth_cookies(cookies: &Cookies) {
//     let mut access_cookie = Cookie::new(ACCESS_COOKIE_NAME, "");
//     access_cookie.set_path("/api");
//     access_cookie.set_max_age(Duration::seconds(0));

//     let mut refresh_cookie = Cookie::new(REFRESH_COOKIE_NAME, "");
//     refresh_cookie.set_path("/api/auth/refresh");
//     refresh_cookie.set_max_age(Duration::seconds(0));

//     cookies.add(access_cookie);
//     cookies.add(refresh_cookie);
// }

// pub fn set_refresh_token(cookies: &Cookies, token: String, config: &Config) {
//     let expires_in = if config.database.jwt_refresh_expires_in <= 0 {
//         DEFAULT_REFRESH_TOKEN_EXPIRES
//     } else {
//         config.database.jwt_refresh_expires_in
//     };

//     let options = TokenCookieOptions {
//         path: "/api/auth/refresh".to_string(),
//         max_age: Some(TimeDuration::seconds(expires_in)),
//         ..Default::default()
//     };
//     set_token_cookie(cookies, REFRESH_COOKIE_NAME.to_string(), token, options);
// }

// pub fn get_access_token(cookies: &Cookies) -> Option<String> {
//     cookies.get(ACCESS_COOKIE_NAME).map(|c| c.value().to_string())
// }

// pub fn set_access_token(cookies: &Cookies, token: String, config: &Config) {
//     let expires_in = if config.database.jwt_expires_in <= 0 {
//         DEFAULT_ACCESS_TOKEN_EXPIRES
//     } else {
//         config.database.jwt_expires_in
//     };

//     let options = TokenCookieOptions {
//         path: "/api".to_string(),
//         max_age: Some(TimeDuration::seconds(expires_in)),
//         ..Default::default()
//     };
//     set_token_cookie(cookies, ACCESS_COOKIE_NAME.to_string(), token, options);
// }

// pub fn set_token_cookie(
//     cookies: &Cookies,
//     name: String, // Take ownership of the name
//     token: String, // Take ownership of the token
//     options: TokenCookieOptions
// ) {
//     let mut cookie = Cookie::new(name, token);
//     cookie.set_http_only(options.http_only);
//     cookie.set_secure(options.secure);
//     cookie.set_same_site(options.same_site);
//     cookie.set_path(options.path);

//     if let Some(max_age) = options.max_age {
//         cookie.set_max_age(max_age);
//     }

//     cookies.add(cookie);
// }

// use crate::config::Config;

// const ACCESS_COOKIE_NAME: &'static str = "access_token";
// const REFRESH_COOKIE_NAME: &'static str = "refresh_token";
// const DEFAULT_ACCESS_TOKEN_EXPIRES: i64 = 900; // 15 minutes in seconds
// const DEFAULT_REFRESH_TOKEN_EXPIRES: i64 = 604800; // 7 days in seconds

// pub struct TokenCookieOptions {
//     pub http_only: bool,
//     pub secure: bool,
//     pub same_site: SameSite,
//     pub path: String,
//     pub max_age: Option<TimeDuration>,
// }

// impl Default for TokenCookieOptions {
//     fn default() -> Self {
//         Self {
//             http_only: true,
//             secure: true,
//             same_site: SameSite::Strict,
//             path: "/".to_string(),
//             max_age: None,
//         }
//     }
// }

// pub async fn send_email(
//     to_email: &str,
//     subject: &str,
//     template_path: &str,
//     placeholders: &[(String, String)]
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let smtp_username = env::var("SMTP_USERNAME")?;
//     let smtp_password = env::var("SMTP_PASSWORD")?;
//     let smtp_server = env::var("SMTP_SERVER")?;
//     let smtp_port: u16 = env::var("SMTP_PORT")?.parse()?;

//     let mut html_template = fs::read_to_string(template_path)?;

//     for (key, value) in placeholders {
//         html_template = html_template.replace(key, value);
//     }

//     let email = Message::builder()
//         .from(smtp_username.parse()?)
//         .to(to_email.parse()?)
//         .subject(subject)
//         .header(header::ContentType::TEXT_HTML)
//         .singlepart(
//             SinglePart::builder().header(header::ContentType::TEXT_HTML).body(html_template)
//         )?;

//     let creds = Credentials::new(smtp_username.clone(), smtp_password.clone());
//     let mailer = SmtpTransport::starttls_relay(&smtp_server)?
//         .credentials(creds)
//         .port(smtp_port)
//         .build();

//     let result = mailer.send(&email);

//     match result {
//         Ok(_) => println!("Email sent successfully!"),
//         Err(e) => println!("Failed to send email: {:?}", e),
//     }

//     Ok(())
// }

use jsonwebtoken::{ encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm };
// use serde::{ Deserialize, Serialize };
// use time::{ OffsetDateTime, Duration };
// use uuid::Uuid;
// use diesel::{ PgConnection, r2d2::{ Pool, ConnectionManager }, prelude::* };
// use crate::{ config::Config, models::User, errors::{ HttpError, ErrorMessage } };

// #[derive(Debug, Serialize, Deserialize)]
// pub struct TokenClaims {
//     pub sub: String,
//     pub exp: i64,
//     pub iat: i64,
//     pub jti: String,
// }

// #[derive(Debug, thiserror::Error)]
// pub enum ServiceError {
//     #[error(transparent)] HttpError(#[from] HttpError),

//     #[error("Database error: {0}")] DatabaseError(#[from] diesel::result::Error),

//     #[error("Password hash error: {0}")] BcryptError(#[from] bcrypt::BcryptError),

//     #[error("Connection pool error: {0}")] PoolError(#[from] diesel::r2d2::PoolError),

//     #[error("Token error: {0}")] TokenError(#[from] jsonwebtoken::errors::Error),
// }

// pub struct AuthService {
//     access_secret: String,
//     refresh_secret: String,
//     pool: Pool<ConnectionManager<PgConnection>>,
//     config: Config,
// }

// impl AuthService {
//     pub fn config(&self) -> &Config {
//         &self.config
//     }

//     pub fn new(config: &Config, pool: Pool<ConnectionManager<PgConnection>>) -> Self {
//         Self {
//             access_secret: config.database.jwt_secret.clone(),
//             refresh_secret: config.database.jwt_refresh_secret.clone(),
//             pool,
//             config: config.clone(),
//         }
//     }

//     pub async fn validate_credentials(
//         &self,
//         email_param: &str,
//         password_input: &str
//     ) -> Result<User, ServiceError> {
//         use crate::schema::users::dsl::*;

//         let mut conn = self.pool.get()?;

//         let user = users
//             .filter(email.eq(email_param))
//             .first::<User>(&mut conn)
//             .map_err(|_| {
//                 ServiceError::HttpError(
//                     HttpError::unauthorized(ErrorMessage::WrongCredentials.to_string())
//                 )
//             })?;

//         match crate::utils::password::compare(password_input, &user.password) {
//             Ok(true) => Ok(user),
//             Ok(false) =>
//                 Err(
//                     ServiceError::HttpError(
//                         HttpError::unauthorized(ErrorMessage::WrongCredentials.to_string())
//                     )
//                 ),
//             Err(_) =>
//                 Err(
//                     ServiceError::HttpError(
//                         HttpError::server_error("Password comparison error".to_string())
//                     )
//                 ),
//         }
//     }

//     pub fn generate_access_token(
//         &self,
//         user_id: &str
//     ) -> Result<String, jsonwebtoken::errors::Error> {
//         let now = OffsetDateTime::now_utc();
//         let claims = TokenClaims {
//             sub: user_id.to_string(),
//             exp: (now + Duration::minutes(15)).unix_timestamp(),
//             iat: now.unix_timestamp(),
//             jti: Uuid::new_v4().to_string(),
//         };

//         encode(
//             &Header::default(),
//             &claims,
//             &EncodingKey::from_secret(self.access_secret.as_bytes())
//         )
//     }

//     pub fn generate_refresh_token(
//         &self,
//         user_id: &str
//     ) -> Result<String, jsonwebtoken::errors::Error> {
//         let now = OffsetDateTime::now_utc();
//         let claims = TokenClaims {
//             sub: user_id.to_string(),
//             exp: (now + Duration::days(7)).unix_timestamp(),
//             iat: now.unix_timestamp(),
//             jti: Uuid::new_v4().to_string(),
//         };

//         encode(
//             &Header::default(),
//             &claims,
//             &EncodingKey::from_secret(self.refresh_secret.as_bytes())
//         )
//     }

//     pub fn verify_access_token(
//         &self,
//         token: &str
//     ) -> Result<TokenClaims, jsonwebtoken::errors::Error> {
//         let validation = Validation::new(Algorithm::HS256);
//         let token_data = decode::<TokenClaims>(
//             token,
//             &DecodingKey::from_secret(self.access_secret.as_bytes()),
//             &validation
//         )?;
//         Ok(token_data.claims)
//     }

//     pub fn verify_refresh_token(
//         &self,
//         token: &str
//     ) -> Result<TokenClaims, jsonwebtoken::errors::Error> {
//         let validation = Validation::new(Algorithm::HS256);
//         let token_data = decode::<TokenClaims>(
//             token,
//             &DecodingKey::from_secret(self.refresh_secret.as_bytes()),
//             &validation
//         )?;
//         Ok(token_data.claims)
//     }
// }

// impl DatabaseConfig {
//     pub fn new() -> Result<Self, ConfigError> {
//         let database_url = env
//             ::var("DATABASE_URL")
//             .map_err(|_| ConfigError::Other("DATABASE_URL must be set".to_string()))?;

//         // Create a connection pool
//         let pool = Pool::builder()
//             .build(ConnectionManager::<PgConnection>::new(&database_url))
//             .map_err(|_| ConfigError::Other("Failed to create pool".to_string()))?;

//         Ok(DatabaseConfig {
//             database_url,
//             jwt_secret: env
//                 ::var("JWT_SECRET")
//                 .map_err(|_| ConfigError::Other("JWT_SECRET must be set".to_string()))?,
//             jwt_refresh_secret: env
//                 ::var("JWT_REFRESH_SECRET")
//                 .map_err(|_| ConfigError::Other("JWT_REFRESH_SECRET must be set".to_string()))?,
//             rust_log: env
//                 ::var("RUST_LOG")
//                 .map_err(|_| ConfigError::Other("RUST_LOG must be set".to_string()))?,
//             jwt_expires_in: env
//                 ::var("JWT_EXPIRES_IN")
//                 .map_err(|_| ConfigError::Other("JWT_EXPIRES_IN must be set".to_string()))?
//                 .parse()
//                 .map_err(|_| ConfigError::Other("Invalid JWT_EXPIRES_IN".to_string()))?,
//             jwt_refresh_expires_in: env
//                 ::var("JWT_REFRESH_EXPIRES_IN")
//                 .map_err(|_| ConfigError::Other("JWT_REFRESH_EXPIRES_IN must be set".to_string()))?
//                 .parse()
//                 .map_err(|_| ConfigError::Other("Invalid JWT_REFRESH_EXPIRES_IN".to_string()))?,
//             schema: env
//                 ::var("SCHEMA")
//                 .map_err(|_| ConfigError::Other("SCHEMA must be set".to_string()))?,
//             pool,
//         })
//     }

//     pub fn get_user_by_email(
//         &self,
//         email_str: &str
//     ) -> Result<Option<User>, diesel::result::Error> {
//         let mut conn = self.pool.get().map_err(|e| {
//             // Optionally convert to a Diesel error or log the error
//             diesel::result::Error::DatabaseError(
//                 diesel::result::DatabaseErrorKind::UnableToSendCommand,
//                 Box::new(e.to_string())
//             )
//         })?;

//         use crate::schema::users::dsl::*;

//         let user = users.filter(email.eq(email_str)).first::<User>(&mut conn).optional()?; // returns Ok(Some(User)) or Ok(None)

//         Ok(user)
//     }
// }

// pub fn authentication_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
//     // Creating the auth_service and wrapping it in an Arc for shared ownership
//     let auth_service = Arc::new(AuthService::new(&state.config, state.db_pool.clone()));

//     // Protected routes that require authentication
//     let protected_routes = Router::new()
//         .route("/protected", get(protected_handler))
//         .route(
//             "/refresh",
//             post({
//                 let auth_service_clone = auth_service.clone();
//                 move |cookies: Cookies| {
//                     refresh_token_handler(Extension(auth_service_clone.clone()), cookies)
//                 }
//             })
//         )
//         .route("/logout", post(logout_handler))
//         .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

//     // Main router, with a login route and the protected routes merged
//     Router::new()
//         .route("/login", post(login_handler))
//         .merge(protected_routes)
//         .with_state(state)
//         .layer(cookie_layer())
//         .layer(
//             from_fn(move |mut req: Request<Body>, next: Next| {
//                 let auth_service = auth_service.clone(); // Clone `auth_service` here
//                 async move {
//                     req.extensions_mut().insert(auth_service);
//                     // Forward the request with the extension
//                     next.run(req).await
//                 }
//             })
//         )
// }

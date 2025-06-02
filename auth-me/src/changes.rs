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

// GET ALL USERS
// pub async fn get_users(State(state): State<Arc<AppState>>) -> Result<Json<Vec<User>>, HttpError> {
//     let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

//     // Execute the query (directly, no interact needed)
//     let users_result: Result<Vec<User>, Error> = users::table
//         .select(User::as_select())
//         .load(&mut *conn);

//     match users_result {
//         Ok(users) => Ok(Json(users)),
//         Err(_) => Err(HttpError::server_error(ErrorMessage::DatabaseError.to_string())),
//     }
// }

// pub async fn get_user_by_id(
//     State(state): State<Arc<AppState>>,
//     Path(user_id): Path<Uuid>
// ) -> Result<Json<User>, HttpError> {
//     let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

//     // Query the database for the user
//     let user_result = users::table
//         .find(user_id) // Using find for primary key lookup
//         .select(User::as_select())
//         .first(&mut *conn)
//         .map_err(|e| {
//             match e {
//                 Error::NotFound => {
//                     HttpError::new(
//                         ErrorMessage::UserNoLongerExists.to_string(),
//                         StatusCode::NOT_FOUND
//                     )
//                 }
//                 _ => HttpError::server_error(ErrorMessage::DatabaseError.to_string()),
//             }
//         })?;

//     Ok(Json(user_result))
// }

// ----------------------------------- DATABASE CONFIG IMPL -----------------------------------------------

//  pub fn get_user(&self, query: UserQuery) -> Result<Option<User>, ConfigError> {
//         let mut conn = self.pool.get()?;

//         let result = match query {
//             UserQuery::Id(user_id) =>
//                 users.filter(id.eq(user_id)).first::<User>(&mut conn).optional()?,
//             UserQuery::Email(email_str) =>
//                 users.filter(email.eq(email_str)).first::<User>(&mut conn).optional()?,
//             UserQuery::Name(name_str) =>
//                 users.filter(name.eq(name_str)).first::<User>(&mut conn).optional()?,
//             UserQuery::Username(name_str) =>
//                 users.filter(username.eq(name_str)).first::<User>(&mut conn).optional()?,
//             UserQuery::Token(token_str) =>
//                 users.filter(verification_token.eq(token_str)).first::<User>(&mut conn).optional()?,
//             UserQuery::Role(role_str) =>
//                 users.filter(verification_token.eq(role_str)).first::<User>(&mut conn).optional()?,
//         };

//         Ok(result)
//     }
// pub fn get_users_paginated(
//         &self,
//         page: usize,
//         limit: usize
//     ) -> Result<(Vec<User>, i64), ConfigError> {
//         let mut conn = self.pool.get()?;
//         let offset = (page - 1) * limit;

//         // Get paginated users - use the table from schema module
//         let user_list = users::table
//             .select(User::as_select())
//             .limit(limit as i64)
//             .offset(offset as i64)
//             .order(users::created_at.desc()) // Use the column from schema module
//             .load(&mut conn)?;

//         // Get total count
//         let total_count: i64 = users::table.count().get_result(&mut conn)?;

//         Ok((user_list, total_count))
//     }
// pub fn search_users(
//     &self,
//     page: usize,
//     limit: usize,
//     search_term: Option<&str>,
//     role_filter: Option<UserRole>,
//     verified_filter: Option<bool>
// ) -> Result<(Vec<User>, i64), ConfigError> {
//     let mut conn = self.pool.get()?;
//     let offset = (page - 1) * limit;

//     // Create the search pattern that will live for the entire function
//     let search_pattern = search_term.map(|search| format!("%{}%", search));

//     // Build dynamic query - use users::table, not users::table
//     let mut query = users::table.into_boxed();
//     let mut count_query = users::table.into_boxed();

//     if let Some(ref pattern) = search_pattern {
//         // Use the columns from the schema module
//         let search_filter = users::name
//             .ilike(pattern)
//             .or(users::email.ilike(pattern))
//             .or(users::username.ilike(pattern));

//         query = query.filter(search_filter.clone());
//         count_query = count_query.filter(search_filter);
//     }

//     if let Some(user_role) = role_filter {
//         query = query.filter(users::role.eq(role));
//         count_query = count_query.filter(users::role.eq(user_role));
//     }

//     if let Some(is_verified) = verified_filter {
//         query = query.filter(users::verified.eq(verified));
//         count_query = count_query.filter(users::verified.eq(is_verified));
//     }

//     // Execute queries
//     let user_list = query
//         .select(User::as_select())
//         .limit(limit as i64)
//         .offset(offset as i64)
//         .order(users::created_at.desc())
//         .load(&mut conn)?;

//     let total_count: i64 = count_query.count().get_result(&mut conn)?;

//     Ok((user_list, total_count))
// }
// pub fn verified_token(&self, token_str: &str) -> Result<(), ConfigError> {
//         let mut conn = self.pool.get()?;

//         let now = Utc::now().naive_utc();

//         let target_user = users
//             .filter(verification_token.eq(Some(token_str.to_string())))
//             .filter(token_expires_at.gt(now))
//             .first::<User>(&mut conn)
//             .optional()?;

//         if let Some(user) = target_user {
//             diesel
//                 ::update(users.filter(id.eq(user.id)))
//                 .set((
//                     verified.eq(true),
//                     verification_token.eq::<Option<String>>(None),
//                     token_expires_at.eq::<Option<NaiveDateTime>>(None),
//                     updated_at.eq(now),
//                 ))
//                 .execute(&mut conn)?;
//             Ok(())
//         } else {
//             Err(ConfigError::NotFound)
//         }
//     }

//     pub fn add_verified_token(
//         &self,
//         user_id: Uuid,
//         token: String,
//         expires_at: NaiveDateTime
//     ) -> Result<(), ConfigError> {
//         let mut conn = self.pool.get()?;

//         diesel
//             ::update(users.filter(id.eq(user_id)))
//             .set((
//                 verification_token.eq(Some(token)),
//                 token_expires_at.eq(Some(expires_at)),
//                 updated_at.eq(Utc::now().naive_utc()),
//             ))
//             .execute(&mut conn)?;

//         Ok(())
//     }

//     pub fn update_user_password(
//         &self,
//         user_id: Uuid,
//         new_hashed_password: String
//     ) -> Result<(), ConfigError> {
//         let mut conn = self.pool.get()?;

//         diesel
//             ::update(users.filter(id.eq(user_id)))
//             .set((password.eq(new_hashed_password), updated_at.eq(Utc::now().naive_utc())))
//             .execute(&mut conn)?;

//         Ok(())
//     }
//   Self {
//       database_url: "".into(),
//       jwt_secret: "".into(),
//       jwt_refresh_secret: "".into(),
//       rust_log: "".into(),
//       schema: "".into(),
//       jwt_expires_in: 0,
//       jwt_refresh_expires_in: 0,
//       pool,
//       redis_url: "".into(),
//       port: 0,
//       rate_limit_requests_per_minute: 0,
//   }

// ------------------------------------ USER OPERATIONS -------------------------------
// use diesel::prelude::*;
// use uuid::Uuid;
// use chrono::NaiveDateTime;

// use crate::{ models::{ NewUser, User, UserRole }, schema::users::{ self } };
// CREATE USER
// pub fn create_user(
//     conn: &mut PgConnection,
//     name: String,
//     email: String,
//     username: String,
//     password: String,
//     verified: bool,
//     token_expires_at: Option<NaiveDateTime>,
//     role: UserRole
// ) -> Result<User, Box<dyn std::error::Error>> {
//     let token: Option<String> = Some(Uuid::new_v4().to_string());

//     let new_user: NewUser = NewUser {
//         name,
//         email,
//         username,
//         password,
//         verified,
//         verification_token: token,
//         token_expires_at,
//         role,
//     };

//     let user: User = diesel::insert_into(users::table).values(&new_user).get_result(conn)?;

//     Ok(user)
// }
// UPDATE USER
// pub fn update_user(
//     conn: &mut PgConnection,
//     user_id: Uuid,
//     name: String,
//     email: String,
//     username: String,
//     password: String,
//     verified: bool,
//     role: UserRole,
//     updated_at: NaiveDateTime
// ) -> Result<User, Box<dyn std::error::Error>> {
//     let update_user: UpdateUser = UpdateUser {
//         email,
//         name,
//         username,
//         password,
//         verified,
//         role,
//         updated_at
//     };

//     let updated_user: User = diesel
//         ::update(users::table)
//         .filter(users::id.eq(user_id))
//         .set(&update_user)
//         .get_result(conn)?;

//     Ok(updated_user)
// }

// DELETE USER
// pub async fn delete_user(
//     conn: &mut PgConnection,
//     user_id: Uuid
// ) -> Result<(), diesel::result::Error> {
//     use crate::schema::users::dsl::*;

//     diesel::delete(users.find(user_id)).execute(conn)?;

//     Ok(())
// }

// ----------------------------- USER HANDLERS --------------------------

// CREATE NEW USER
// pub async fn create_user_handler(
//     State(state): State<Arc<AppState>>,
//     Json(user_data): Json<CreateUserRequest>
// ) -> Result<Json<User>, HttpError> {
//     let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

//     create_user(
//         &mut conn,
//         user_data.name,
//         user_data.email,
//         user_data.username,
//         user_data.password,
//         user_data.verified,
//         user_data.token_expires_at,
//         user_data.role
//     )
//         .map(Json)
//         .map_err(|e| {
//             if e.to_string().contains("UNIQUE constraint failed") {
//                 HttpError::unique_constraint_validation(ErrorMessage::UserCreationError.to_string())
//             } else {
//                 HttpError::server_error(ErrorMessage::UserCreationError.to_string())
//             }
//         })
// }

// pub async fn get_users(
//     Query(query_params): Query<RequestQuery>,
//     State(state): State<Arc<AppState>>
// ) -> Result<Json<UserListResponse>, HttpError> {
//     // Validate input
//     query_params
//         .validate()
//         .map_err(|e| HttpError::bad_request(format!("Validation error: {}", e)))?;

//     let page = query_params.page.unwrap_or(1);
//     let limit = query_params.limit.unwrap_or(10);

//     // Generate cache key for pagination
//     let cache_service = CacheService::new(state.config.cache.clone());
//     let cache_key = format!("users_paginated:{}:{}", page, limit);

//     // Try to get from cache first
//     if let Some(cached_response) = cache_service.get::<UserListResponse>(&cache_key).await {
//         return Ok(Json(cached_response));
//     }

//     // If not in cache, get from database using repository
//     let (users, total_count) = UserRepository::get_users_paginated(
//         &state.config.database.pool,
//         page,
//         limit
//     ).map_err(|e| HttpError::server_error(e.to_string()))?;

//     let total_pages = (((total_count as usize) + limit - 1) / limit).max(1);

//     // Return filtered response (no raw models exposed)
//     let response = UserListResponse {
//         status: "success".to_string(),
//         users: FilterUser::filter_users(&users), // This filters out sensitive data
//         results: total_count as usize,
//         page,
//         limit,
//         total_pages,
//     };

//     // Cache the response
//     cache_service.set(&cache_key, &response, USER_LIST_CACHE_TTL).await;

//     Ok(Json(response))
// }

// pub async fn get_user_by_id(
//     State(state): State<Arc<AppState>>,
//     Path(user_id): Path<Uuid>
// ) -> Result<Json<SingleUserResponse>, HttpError> {
//     let cache_service = CacheService::new(state.config.cache.clone());
//     let cache_key = format!("user:{}", user_id);

//     // Try to get from cache first
//     if let Some(cached_response) = cache_service.get::<SingleUserResponse>(&cache_key).await {
//         return Ok(Json(cached_response));
//     }

//     // If not in cache, get from database using repository
//     let user = UserRepository::get_user(&state.config.database.pool, UserQuery::Id(user_id))
//         .map_err(|e| {
//             match e {
//                 ConfigError::NotFound =>
//                     HttpError::new(
//                         ErrorMessage::UserNoLongerExists.to_string(),
//                         StatusCode::NOT_FOUND
//                     ),
//                 _ => HttpError::server_error(e.to_string()),
//             }
//         })?
//         .ok_or_else(|| {
//             HttpError::new(ErrorMessage::UserNoLongerExists.to_string(), StatusCode::NOT_FOUND)
//         })?;

//     // Create response
//     let response = SingleUserResponse {
//         status: "success".to_string(),
//         data: UserData {
//             user: FilterUser::filter_user(&user),
//         },
//     };

//     // Cache the response
//     cache_service.set(&cache_key, &response, USER_CACHE_TTL).await;

//     Ok(Json(response))
// }

// pub async fn search_users(
//     Query(query_params): Query<UserSearchQuery>,
//     State(state): State<Arc<AppState>>
// ) -> Result<Json<UserListResponse>, HttpError> {
//     query_params
//         .validate()
//         .map_err(|e| HttpError::bad_request(format!("Validation error: {}", e)))?;

//     let page = query_params.page.unwrap_or(1);
//     let limit = query_params.limit.unwrap_or(10);

//     // Generate cache key for search
//     let cache_service = CacheService::new(state.config.cache.clone());
//     let cache_key = format!(
//         "users_search:{}:{}:{}:{}:{}",
//         page,
//         limit,
//         query_params.search.as_deref().unwrap_or(""),
//         query_params.role
//             .as_ref()
//             .map(|r| format!("{:?}", r))
//             .unwrap_or_default(),
//         query_params.verified.map(|v| v.to_string()).unwrap_or_default()
//     );

//     // Try to get from cache first
//     if let Some(cached_response) = cache_service.get::<UserListResponse>(&cache_key).await {
//         return Ok(Json(cached_response));
//     }

//     // If not in cache, search in database using repository
//     let (users, total_count) = UserRepository::search_users(
//         &state.config.database.pool,
//         page,
//         limit,
//         query_params.search.as_deref(),
//         query_params.role,
//         query_params.verified
//     ).map_err(|e| HttpError::server_error(e.to_string()))?;

//     let total_pages = (((total_count as usize) + limit - 1) / limit).max(1);

//     // Create response
//     let response = UserListResponse {
//         status: "success".to_string(),
//         users: FilterUser::filter_users(&users),
//         results: total_count as usize,
//         page,
//         limit,
//         total_pages,
//     };

//     // Cache the response (shorter TTL for search results)
//     cache_service.set(&cache_key, &response, 30).await; // 30 seconds

//     Ok(Json(response))
// }

// DELETE USER BY ID
// pub async fn delete_user_handler(
//     State(state): State<Arc<AppState>>,
//     Path(user_id): Path<Uuid>
// ) -> Result<StatusCode, HttpError> {
//     let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

//     match delete_user(&mut conn, user_id).await {
//         Ok(_) => Ok(StatusCode::NO_CONTENT), // If successful, return No Content status
//         Err(Error::NotFound) => {
//             // If user is not found, return Not Found status with a specific message
//             Err(HttpError::not_found(ErrorMessage::UserNotFound.to_string()))
//         }
//         Err(_) => {
//             // For any other errors, return Internal Server Error with a message
//             Err(HttpError::server_error(ErrorMessage::DeleteUserError.to_string()))
//         }
//     }
// }

// ------------------------------------ AUTHENTICATION HANDLERS ----------------------------
// FROM SIGNUP HANDLER
// Wrap in a transaction

// // Hash password with argon2 before storing
// let hashed_password = match hash(signup_data.password.clone()) {
//     Ok(hash) => hash,
//     Err(e) => {
//         tracing::error!("Password hashing error: {:?}", e);
//         return Err(HttpError::server_error("Failed to process password".to_string()));
//     }
// };

// // Set verification token to expire in 1 hour
// let token_expiration = chrono::Utc::now().naive_utc() + chrono::Duration::hours(1);
// let user_result = conn.transaction::<User, DieselError, _>(|conn| {
//     // Create user with the hashed password
//     let user = UserRepository::create_user(conn, SignupRequest {
//         name: signup_data.name.clone(),
//         email: signup_data.email.clone(),
//         username: signup_data.username.clone(),
//         password: hashed_password,
//         password_confirm: String::new(), // Not used in creation
//         verified: signup_data.verified,
//         token_expires_at: Some(token_expiration),
//         terms_accepted: true, // Assuming they accepted during signup
//         role: signup_data.role,
//     }).map_err(|e| {
//         tracing::error!("Error creating user: {}", e);
//         DieselError::RollbackTransaction
//     })?;

//     // Send email inside the blocking context
//     if let Some(token) = &user.verification_token {
//         let email_str = user.email.clone();
//         let username_str = user.username.clone();
//         let token = token.clone();

//         // Diesel transactions are sync, so block on the async send
//         let result = tokio::task::block_in_place(move || {
//             tokio::runtime::Handle
//                 ::current()
//                 .block_on(send_verification_email(&email_str, &username_str, &token))
//         });

//         if let Err(e) = result {
//             tracing::error!("send_verification_email failed: {}", e);
//             return Err(DieselError::RollbackTransaction); // triggers rollback
//         }
//     }

//     Ok(user)
// });

// pub async fn signup_handler(
//     State(state): State<Arc<AppState>>,
//     Json(signup_data): Json<SignupRequest>
// ) -> Result<impl IntoResponse, HttpError> {
//     // Validate input
//     if let Err(validation_errors) = signup_data.validate() {
//         return Err(HttpError::validation_error(validation_errors.to_string()));
//     }

//     // Check if user already exists in both tables
//     let (email_exists, username_exists) = PendingUserRepository::check_user_exists_comprehensive(
//         &state.config.database.pool,
//         &signup_data.email,
//         &signup_data.username
//     ).map_err(|e| HttpError::server_error(e.to_string()))?;

//     if email_exists {
//         return Err(HttpError::unique_constraint_validation(ErrorMessage::EmailExists.to_string()));
//     }

//     if username_exists {
//         return Err(
//             HttpError::unique_constraint_validation(ErrorMessage::UsernameExists.to_string())
//         );
//     }

//     let mut conn = state.conn()?; // PooledConnection

//     // Use transaction for user creation
//     let user_result = conn.transaction::<User, DieselError, _>(|conn| {
//         // Use the service layer for consistent user creation
//         let user = tokio::task
//             ::block_in_place(move || {
//                 tokio::runtime::Handle
//                     ::current()
//                     .block_on(UserService::create_user_signup(conn, signup_data, &state))
//             })
//             .map_err(|_| DieselError::RollbackTransaction)?;

//         Ok(user)
//     });

//     match user_result {
//         Ok(_) =>
//             Ok(
//                 Json(
//                     serde_json::json!({
//             "message": "User created successfully. Please verify your email."
//         })
//                 )
//             ),
//         Err(DieselError::RollbackTransaction) => {
//             Err(HttpError::server_error(ErrorMessage::EmailVerificationError.to_string()))
//         }
//         Err(e) => {
//             error!("Database error: {}", e);
//             Err(HttpError::server_error(ErrorMessage::UserCreationError.to_string()))
//         }
//     }
// }

// pub async fn verify_email_handler(
//     State(state): State<Arc<AppState>>,
//     Query(query): Query<VerifyEmailQuery>
// ) -> Result<impl IntoResponse, HttpError> {
//     // Step 1: Validate query
//     query.validate().map_err(|e| HttpError::bad_request(e.to_string()))?;

//     // Step 2: Get the verified user
//     let user = UserRepository::get_user(
//         &state.config.database.pool,
//         UserQuery::Token(query.token.clone())
//     )
//         .map_err(|e| HttpError::server_error(e.to_string()))?
//         .ok_or_else(|| HttpError::not_found(ErrorMessage::UserNotFound.to_string()))?;

//     // Step 3: Use repository to verify token
//     UserRepository::verify_token(&state.config.database.pool, &query.token).map_err(|e| {
//         match e {
//             crate::config::ConfigError::NotFound =>
//                 HttpError::unauthorized(ErrorMessage::InvalidToken.to_string()),
//             _ => HttpError::server_error(e.to_string()),
//         }
//     })?;

//     // Step 4: Send welcome email
//     if let Err(e) = send_welcome_email(&user.email, &user.name).await {
//         eprintln!("Failed to send welcome email: {}", e);
//     }

//     // Step 5: Generate JWT token
//     let auth_service = AuthService::new(&state.config, state.config.database.pool.clone());
//     let jwt = auth_service
//         .generate_access_token(&user.id.to_string())
//         .map_err(|e| HttpError::server_error(e.to_string()))?;

//     // Step 6: Set Cookie
//     let cookie_duration = time::Duration::minutes(state.config.database.jwt_expires_in * 60);
//     let cookie = Cookie::build(("token", jwt.clone()))
//         .path("/")
//         .max_age(cookie_duration)
//         .http_only(true)
//         .build();

//     let mut headers = HeaderMap::new();
//     headers.append(
//         header::SET_COOKIE,
//         cookie
//             .to_string()
//             .parse()
//             .map_err(|_| HttpError::server_error("Failed to parse cookie".to_string()))?
//     );

//     // Step 7: Return success with cookie header
//     let response = (
//         headers,
//         Json(
//             json!({
//             "message": "Email verified successfully",
//             "user_id": user.id,
//             "creation_type": if user.created_by.is_some() { 
//                 "AdminCreated" 
//             } else { 
//                 "SelfSignup" 
//             }
//         })
//         ),
//     );

//     Ok(response)
// }

// ----------------------------------------------- AUTH MIDDLEWARE ----------------------------------------------
// pub async fn auth_middleware(
//     Extension(auth_service): Extension<Arc<AuthService>>,
//     Extension(database_config): Extension<Arc<DatabaseConfig>>,
//     cookies: Cookies,
//     mut request: Request,
//     next: Next
// ) -> Result<Response, StatusCode> {
//     // Extract token from cookies or Authorization header
//     let token: String = extract_token(&request, &cookies)?;

//     // Decode token to get user ID using your existing function
//     let user_id: String = auth_service
//         .extract_user_id_from_token(&token, false)
//         .map_err(|_| StatusCode::UNAUTHORIZED)?;

//     // Fetch the full user from database
//     let user = get_user_from_db(&database_config, &user_id).await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
//         .ok_or(StatusCode::UNAUTHORIZED)?; // User no longer exists

//     // Add the user ID to request extensions
//     request.extensions_mut().insert(AuthenticatedUser::from(user));

//     // Continue with the request
//     Ok(next.run(request).await)
// }

// pub async fn role_check_middleware(
//     Extension(_auth_service): Extension<Arc<AuthService>>,
//     Extension(database_config): Extension<Arc<DatabaseConfig>>,
//     mut request: Request,
//     next: Next,
//     required_roles: Vec<UserRole>
// ) -> Result<Response, StatusCode> {
//     // Get the authenticated user id from the previous middleware
//     let auth_user: &AuthUser = request
//         .extensions()
//         .get::<AuthUser>()
//         .ok_or(StatusCode::UNAUTHORIZED)?;

//     // Fetch the full user from database using your DatabaseConfig
//     let user: User = get_user_from_db(&database_config, &auth_user.user_id).await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
//         .ok_or(StatusCode::UNAUTHORIZED)?; // User no longer exists

//     // Check if user has required role
//     if !required_roles.contains(&user.role) {
//         return Err(StatusCode::FORBIDDEN);
//     }

//     // Add full user info to extensions for handlers that need it
//     request.extensions_mut().insert(AuthenticatedUser::from(user));

//     Ok(next.run(request).await)
// }

// ---------------------------------------------------- MAIN ----------------------------------------
// use diesel::{ prelude::*, r2d2::{ ConnectionManager, Pool } };

    // Initialize logger first
    //     let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    //     env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&rust_log)).init();

    //     // Set up database connection pool
//     let manager: ConnectionManager<PgConnection> = ConnectionManager::<PgConnection>::new(
//         &config.database.database_url
//     );
//     let pool: Pool<ConnectionManager<PgConnection>> = Pool::builder()
//         .build(manager)
//         .map_err(|e| HttpError::server_error(format!("Failed to create pool: {}", e)))?;
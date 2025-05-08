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
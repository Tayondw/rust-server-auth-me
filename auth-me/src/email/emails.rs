use super::send_email::send_email;
use crate::errors::HttpError;
use axum::{ http::StatusCode, response::IntoResponse };

pub async fn send_verification_email(
    to_email: &str,
    username: &str,
    token: &str,
) -> Result<(), HttpError> {
    let subject = "Email Verification";
    let template_path = "src/email/templates/verification-email.html";
    let base_url = "http://localhost:8080/api/auth/verify";
    let verification_link = create_verification_link(base_url, token);
    let placeholders = vec![
        ("{{username}}".to_string(), username.to_string()),
        ("{{verification_link}}".to_string(), verification_link),
    ];

    send_email(to_email, subject, template_path, &placeholders)
        .await
        .map_err(|e| {
            tracing::error!("Failed to send verification email: {}", e);
            HttpError::server_error("Failed to send verification email".to_string())
        })?;

    Ok(())
}

/// Creates a verification link with the token appended as a query parameter
fn create_verification_link(base_url: &str, token: &str) -> String {
    format!("{}?token={}", base_url, token)
}

// pub async fn send_welcome_email(
//     to_email: &str,
//     username: &str
// ) -> Result<(), HttpError> {
//     let subject = "Welcome to Application";
//     let template_path = "src/mail/templates/Welcome-email.html";
//     let placeholders = vec![("{{username}}".to_string(), username.to_string())];

//     send_email(to_email, subject, template_path, &placeholders).await
// }

// /// Sends a password reset email to a user who has forgotten their password
// ///
// /// # Arguments
// /// * `to_email` - The email address of the recipient
// /// * `rest_link` - The link for resetting the password
// /// * `username` - The username of the recipient
// ///
// /// # Returns
// /// * `Result<(), Box<dyn std::error::Error>>` - Success or an error
// pub async fn send_forgot_password_email(
//     to_email: &str,
//     rest_link: &str,
//     username: &str
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let subject = "Reset your Password";
//     let template_path = "src/mail/templates/RestPassword-email.html";
//     let placeholders = vec![
//         ("{{username}}".to_string(), username.to_string()),
//         ("{{rest_link}}".to_string(), rest_link.to_string())
//     ];

//     send_email(to_email, subject, template_path, &placeholders).await
// }

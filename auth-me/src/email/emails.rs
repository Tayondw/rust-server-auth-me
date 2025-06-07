use std::sync::Arc;

use tracing::debug;
use crate::{ errors::{ HttpError, ErrorMessage }, services::email_services::EnhancedEmailService };

/// Sends a verification email to a user who has attempted to sign up
///
/// # Arguments
/// * `email_service` - The enhanced email service instance
/// * `to_email` - The email address of the recipient
/// * `username` - The username of the recipient
/// * `token` - The verification token
///
/// # Returns
/// * `Result<(), HttpError>` - Success or an error
pub async fn send_verification_email(
    email_service: &Arc<EnhancedEmailService>,
    to_email: &str,
    username: &str,
    token: &str
) -> Result<(), HttpError> {
    let subject = "Email Verification";
    let template_path = "src/email/templates/verification-email.html";
    let base_url = "http://localhost:8080/auth/verify";
    let verification_link = create_verification_link(base_url, token);
    let placeholders = vec![
        ("{{username}}".to_string(), username.to_string()),
        ("{{verification_link}}".to_string(), verification_link)
    ];

    email_service.send_email(to_email, subject, template_path, &placeholders).await.map_err(|e| {
        tracing::error!("Failed to send verification email: {}", e);
        HttpError::server_error(ErrorMessage::EmailVerificationError.to_string())
    })?;

    Ok(())
}

/// Creates a verification link with the token appended as a query parameter
pub fn create_verification_link(base_url: &str, token: &str) -> String {
    let link = format!("{}?token={}", base_url, token);
    debug!("Created verification link: {}", link);
    link
}

/// Sends a welcome email to a user who has verified their account when clicking on the link in the email
///
/// # Arguments
/// * `email_service` - The enhanced email service instance
/// * `to_email` - The email address of the recipient
/// * `username` - The username of the recipient
///
/// # Returns
/// * `Result<(), HttpError>` - Success or an error
pub async fn send_welcome_email(
    email_service: &Arc<EnhancedEmailService>,
    to_email: &str,
    username: &str
) -> Result<(), HttpError> {
    let subject = "Welcome to Application";
    let template_path = "src/email/templates/welcome-email.html";
    let placeholders = vec![("{{username}}".to_string(), username.to_string())];

    email_service.send_email(to_email, subject, template_path, &placeholders).await.map_err(|e| {
        tracing::error!("Failed to send welcome email: {}", e);
        HttpError::server_error("Failed to send welcome email".to_string())
    })
}

/// Send email to admin-created user with credentials
///
/// # Arguments
/// * `email_service` - The enhanced email service instance
/// * `email` - The email address of the recipient
/// * `username` - The username of the recipient
/// * `temporary_password` - The temporary password of the recipient
///
/// # Returns
/// * `Result<(), HttpError>` - Success or an error
pub async fn send_admin_created_user_email(
    email_service: &Arc<EnhancedEmailService>,
    email: &str,
    username: &str,
    temporary_password: Option<&str>
) -> Result<(), HttpError> {
    let base_url = "http://localhost:8080/auth/login"; // or get from config/env
    let login_link = create_verification_link(base_url, ""); // Empty token for login link
    let (subject, template_path, placeholders) = if temporary_password.is_some() {
        (
            "Welcome! Your account has been created",
            "src/email/templates/admin-created-user-with-password.html",
            vec![
                ("{{username}}".to_string(), username.to_string()),
                ("{{email}}".to_string(), email.to_string()),
                (
                    "{{temporary_password}}".to_string(),
                    temporary_password.unwrap_or("").to_string(),
                ),
                ("{{login_link}}".to_string(), login_link.clone())
            ],
        )
    } else {
        (
            "Welcome! Your account has been created",
            "src/email/templates/admin-created-user-without-password.html",
            vec![
                ("{{username}}".to_string(), username.to_string()),
                ("{{email}}".to_string(), email.to_string()),
                ("{{login_link}}".to_string(), login_link.clone())
            ],
        )
    };

    email_service.send_email(email, subject, template_path, &placeholders).await.map_err(|e| {
        tracing::error!("Failed to send admin-created user email: {}", e);
        HttpError::server_error("Failed to send admin-created user email".to_string())
    })?;

    Ok(())
}

/// Sends a password reset email to a user who has forgotten their password
///
/// # Arguments
/// * `email_service` - The enhanced email service instance
/// * `to_email` - The email address of the recipient
/// * `reset_link` - The link for resetting the password
/// * `username` - The username of the recipient
///
/// # Returns
/// * `Result<(), HttpError>` - Success or an error
pub async fn send_forgot_password_email(
    email_service: &Arc<EnhancedEmailService>,
    to_email: &str,
    reset_link: &str,
    username: &str
) -> Result<(), HttpError> {
    let subject = "Reset your Password";
    let template_path = "src/email/templates/reset-password-email.html";
    let placeholders = vec![
        ("{{username}}".to_string(), username.to_string()),
        ("{{reset_link}}".to_string(), reset_link.to_string())
    ];

    email_service.send_email(to_email, subject, template_path, &placeholders).await.map_err(|e| {
        tracing::error!("Failed to send password reset email: {}", e);
        HttpError::server_error("Failed to send password reset email".to_string())
    })
}

/// Send password reset notification for admin-created users
///
/// # Arguments
/// * `email_service` - The enhanced email service instance
/// * `email` - The email address of the recipient
/// * `username` - The username of the recipient
/// * `new_temp_password` - The new temporary password
///
/// # Returns
/// * `Result<(), HttpError>` - Success or an error
pub async fn send_admin_password_reset_email(
    email_service: &Arc<EnhancedEmailService>,
    email: &str,
    username: &str,
    new_temp_password: &str
) -> Result<(), HttpError> {
    let subject = "Password Reset";
    let template_path = "src/email/templates/admin-password-reset.html";
    let base_url = "http://localhost:8080/auth/login";
    let login_link = create_verification_link(base_url, "");
    let placeholders = vec![
        ("{{username}}".to_string(), username.to_string()),
        ("{{new_temp_password}}".to_string(), new_temp_password.to_string()),
        ("{{login_link}}".to_string(), login_link)
    ];

    email_service.send_email(email, subject, template_path, &placeholders).await.map_err(|e| {
        tracing::error!("Failed to send admin password reset email: {}", e);
        HttpError::server_error("Failed to send admin password reset email".to_string())
    })?;

    Ok(())
}

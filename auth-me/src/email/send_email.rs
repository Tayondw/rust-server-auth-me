use std::{ env, fs };
use lettre::{
    message::{ header, SinglePart },
    transport::smtp::authentication::Credentials,
    Message,
    SmtpTransport,
    Transport,
};

use crate::{
    dto::email_dtos::EmailRequest,
    errors::{ HttpError, ErrorMessage },
    services::email_services::EnhancedEmailService,
};

/// SEND EMAIL
/// Sends an HTML email using SMTP with template-based content.
///
/// This function reads an HTML template file, performs placeholder substitution,
/// and sends the resulting email via SMTP. It handles all aspects of email
/// composition and delivery including SMTP authentication and connection management.
///
/// # Arguments
///
/// * `to_email` - The recipient's email address as a string slice. Must be a valid
///   email format (e.g., "user@example.com").
/// * `subject` - The email subject line as a string slice.
/// * `template_path` - Path to the HTML template file as a string slice. The file
///   must be readable and contain valid HTML content.
/// * `placeholders` - A slice of tuples containing (key, value) pairs for template
///   substitution. Each key in the template will be replaced with its corresponding
///   value using simple string replacement.
///
/// # Environment Variables
///
/// This function requires the following environment variables to be set:
/// * `SMTP_USERNAME` - Username for SMTP authentication
/// * `SMTP_FROM_ADDRESS` - The sender's email address (must be valid email format)
/// * `SMTP_PASSWORD` - Password for SMTP authentication
/// * `SMTP_SERVER` - SMTP server hostname or IP address
/// * `SMTP_PORT` - SMTP server port number (must be a valid u16)
///
/// # Returns
///
/// * `Ok(())` - Email was successfully sent
/// * `Err(HttpError)` - An error occurred during the email sending process
///
/// # Errors
///
/// This function will return an error if:
/// * Any required environment variable is missing or invalid
/// * The template file cannot be read or doesn't exist
/// * The sender or recipient email addresses are malformed
/// * SMTP connection fails (network issues, wrong server/port, etc.)
/// * SMTP authentication fails (invalid credentials)
/// * Email composition fails (malformed content)
/// * Email transmission fails (server rejection, network timeout, etc.)
///
/// Error types returned:
/// * `HttpError::server_error` - For infrastructure issues (missing env vars, file I/O, SMTP connection)
/// * `HttpError::bad_request` - For malformed email addresses
///
/// # Template Processing
///
/// The function performs simple string replacement on the HTML template:
/// * Each key from the `placeholders` slice is searched for in the template
/// * All occurrences of each key are replaced with the corresponding value
/// * Replacement is done using exact string matching (case-sensitive)
/// * No HTML escaping is performed on the replacement values
///
/// # SMTP Configuration
///
/// * Uses STARTTLS for secure connection
/// * Supports standard SMTP authentication with username/password
/// * Sends HTML-formatted emails only
/// * Connection is established fresh for each email (no connection pooling)
///
/// # Example
///
/// ```rust
/// use std::env;
/// 
/// // Set required environment variables
/// env::set_var("SMTP_USERNAME", "your-username");
/// env::set_var("SMTP_FROM_ADDRESS", "sender@example.com");
/// env::set_var("SMTP_PASSWORD", "your-password");
/// env::set_var("SMTP_SERVER", "smtp.gmail.com");
/// env::set_var("SMTP_PORT", "587");
///
/// // Define template placeholders
/// let placeholders = vec![
///     ("{{name}}".to_string(), "John Doe".to_string()),
///     ("{{company}}".to_string(), "Acme Corp".to_string()),
/// ];
///
/// // Send email
/// match send_email(
///     "recipient@example.com",
///     "Welcome to our service",
///     "templates/welcome.html",
///     &placeholders
/// ).await {
///     Ok(()) => println!("Email sent successfully"),
///     Err(e) => eprintln!("Failed to send email: {}", e),
/// }
/// ```
///
/// # Security Considerations
///
/// * SMTP credentials are read from environment variables - ensure these are
///   properly secured in your deployment environment
/// * No input validation is performed on placeholder values - ensure they
///   don't contain malicious HTML if sourced from user input
/// * Template files should be stored in a secure location with appropriate
///   file permissions
///
/// # Performance Notes
///
/// * File I/O is performed synchronously for template reading
/// * SMTP connection is established fresh for each email
/// * String replacement is performed for each placeholder sequentially
/// * Consider caching templates and connection pooling for high-volume scenarios
pub async fn send_email(
    to_email: &str,
    subject: &str,
    template_path: &str,
    placeholders: &[(String, String)]
) -> Result<(), HttpError> {
    let smtp_username = env
        ::var("SMTP_USERNAME")
        .map_err(|_| HttpError::server_error("Missing SMTP_USERNAME env variable"))?;
    let smtp_from_address = env
        ::var("SMTP_FROM_ADDRESS")
        .map_err(|_| HttpError::server_error("Missing SMTP_FROM_ADDRESS env variable"))?;
    let smtp_password = env
        ::var("SMTP_PASSWORD")
        .map_err(|_| HttpError::server_error("Missing SMTP_PASSWORD env variable"))?;
    let smtp_server = env
        ::var("SMTP_SERVER")
        .map_err(|_| HttpError::server_error("Missing SMTP_SERVER env variable"))?;
    let smtp_port: u16 = env
        ::var("SMTP_PORT")
        .map_err(|_| HttpError::server_error("Missing SMTP_PORT env variable"))?
        .parse()
        .map_err(|_| HttpError::server_error("Invalid SMTP_PORT value"))?;

    let mut html_template = fs
        ::read_to_string(template_path)
        .map_err(|_| HttpError::server_error("Failed to read email template"))?;

    for (key, value) in placeholders {
        html_template = html_template.replace(key, value);
    }

    let email = Message::builder()
        .from(
            smtp_from_address
                .parse()
                .map_err(|_|
                    HttpError::bad_request(ErrorMessage::InvalidFromEmailFormat.to_string())
                )?
        )
        .to(
            to_email
                .parse()
                .map_err(|_|
                    HttpError::bad_request(ErrorMessage::InvalidRecipientEmailFormat.to_string())
                )?
        )
        .subject(subject)
        .header(header::ContentType::TEXT_HTML)
        .singlepart(
            SinglePart::builder().header(header::ContentType::TEXT_HTML).body(html_template)
        )
        .map_err(|_| HttpError::server_error("Failed to build email content"))?;

    let credits = Credentials::new(smtp_username.clone(), smtp_password.clone());

    let mailer = SmtpTransport::starttls_relay(&smtp_server)
        .map_err(|_| HttpError::server_error("Failed to connect to SMTP server"))?
        .credentials(credits)
        .port(smtp_port)
        .build();

    mailer
        .send(&email)
        .map_err(|e| HttpError::server_error(format!("Failed to send email: {}", e)))?;

    Ok(())
}

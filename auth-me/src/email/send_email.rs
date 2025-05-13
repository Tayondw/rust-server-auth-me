use std::{ env, fs };
use lettre::{
    message::{ header, SinglePart },
    transport::smtp::authentication::Credentials,
    Message,
    SmtpTransport,
    Transport,
};

use crate::errors::{HttpError, ErrorMessage};

pub async fn send_email(
    to_email: &str,
    subject: &str,
    template_path: &str,
    placeholders: &[(String, String)]
) -> Result<(), HttpError> {
    let smtp_username = env
        ::var("SMTP_USERNAME")
        .map_err(|_| HttpError::server_error("Missing SMTP_USERNAME env variable"))?;
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
            smtp_username.parse().map_err(|_| HttpError::bad_request(ErrorMessage::InvalidFromEmailFormat.to_string()))?
        )
        .to(to_email.parse().map_err(|_| HttpError::bad_request(ErrorMessage::InvalidRecipientEmailFormat.to_string()))?)
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
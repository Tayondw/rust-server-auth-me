use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::sleep;
use lettre::{ SmtpTransport, transport::smtp::authentication::Credentials };
use crate::config::email::EmailConfig;

pub struct ConnectionPool {
    connections: Arc<Mutex<Vec<SmtpTransport>>>,
    config: EmailConfig,
    current_size: Arc<Mutex<usize>>,
}

impl ConnectionPool {
    pub fn new(config: EmailConfig) -> Self {
        Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            config,
            current_size: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn get_connection(&self) -> Result<SmtpTransport, String> {
        {
            let mut connections = self.connections.lock().await;
            if let Some(connection) = connections.pop() {
                return Ok(connection);
            }
        }

        {
            let mut current_size = self.current_size.lock().await;
            if *current_size < self.config.max_pool_size {
                *current_size += 1;
                drop(current_size);
                return self.create_connection().await;
            }
        }

        sleep(std::time::Duration::from_millis(10)).await;
        Box::pin(self.get_connection()).await
    }

    pub async fn return_connection(&self, connection: SmtpTransport) {
        let mut connections = self.connections.lock().await;
        if connections.len() < self.config.max_pool_size {
            connections.push(connection);
        } else {
            let mut current_size = self.current_size.lock().await;
            *current_size -= 1;
        }
    }

    pub async fn create_connection(&self) -> Result<SmtpTransport, String> {
        let credentials = Credentials::new(
            self.config.smtp_username.clone(),
            self.config.smtp_password.clone()
        );

        let transport = SmtpTransport::starttls_relay(&self.config.smtp_server)
            .map_err(|e| format!("Failed to connect to SMTP server: {}", e))?
            .credentials(credentials)
            .port(self.config.smtp_port)
            .timeout(Some(self.config.connection_timeout))
            .build();

        Ok(transport)
    }

    pub async fn warmup(&self, connections: usize) -> Result<(), String> {
        let connections = connections.min(self.config.max_pool_size);

        for _ in 0..connections {
            let connection = self.create_connection().await?;
            self.return_connection(connection).await;
        }

        Ok(())
    }
}

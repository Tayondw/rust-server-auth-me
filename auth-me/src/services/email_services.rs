use std::sync::Arc;
use lettre::{ Message, message::header, message::SinglePart, Transport };
use futures::stream::{ self, StreamExt };
use crate::{
    config::{ Config, email::EmailConfig },
    connection::email::ConnectionPool,
    dto::email_dtos::{ EmailRequest, EnhancedCacheStats },
    email::template_cache::TemplateCache,
    services::enhanced_cache_services::EnhancedCacheService,
};

pub struct EnhancedEmailService {
    template_cache: TemplateCache,
    connection_pool: Arc<ConnectionPool>,
    config: EmailConfig,
}

impl EnhancedEmailService {
    pub async fn new(
        email_config: EmailConfig,
        app_config: Option<Config>
    ) -> Result<Self, String> {
        email_config.validate()?;

        let redis_cache = if email_config.enable_redis_cache {
            if let Some(config) = app_config {
                let cache_service = crate::services::cache_services::CacheService::new(
                    config.cache.clone()
                );
                let enhanced_cache = EnhancedCacheService::new(cache_service);
                Some(Arc::new(enhanced_cache))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            template_cache: TemplateCache::new(email_config.clone(), redis_cache),
            connection_pool: Arc::new(ConnectionPool::new(email_config.clone())),
            config: email_config,
        })
    }

    pub async fn from_env_with_redis() -> Result<Self, String> {
        let email_config = EmailConfig::from_env()?;
        let app_config = Config::new().await.map_err(|e|
            format!("Failed to load app config: {:?}", e)
        )?;

        Self::new(email_config, Some(app_config)).await
    }

    pub async fn from_env_memory_only() -> Result<Self, String> {
        let email_config = EmailConfig::from_env()?;
        Self::new(email_config, None).await
    }

    pub async fn send_email(
        &self,
        to_email: &str,
        subject: &str,
        template_path: &str,
        placeholders: &[(String, String)]
    ) -> Result<(), String> {
        let template_content = self.template_cache.get_template(template_path).await?;

        let mut html_content = template_content;
        for (key, value) in placeholders {
            html_content = html_content.replace(key, value);
        }

        let email = Message::builder()
            .from(self.config.smtp_from_address.parse().map_err(|_| "Invalid from email format")?)
            .to(to_email.parse().map_err(|_| "Invalid recipient email format")?)
            .subject(subject)
            .header(header::ContentType::TEXT_HTML)
            .singlepart(
                SinglePart::builder().header(header::ContentType::TEXT_HTML).body(html_content)
            )
            .map_err(|_| "Failed to build email content")?;

        let connection = self.connection_pool.get_connection().await?;
        let result = connection.send(&email).map_err(|e| format!("Failed to send email: {}", e));
        self.connection_pool.return_connection(connection).await;

        result.map(|_| ())
    }

    pub async fn send_emails_batch(
        &self,
        emails: Vec<EmailRequest>,
        max_concurrent: usize
    ) -> Vec<Result<(), String>> {
        // Pre-warm template cache
        let unique_templates: std::collections::HashSet<String> = emails
            .iter()
            .map(|e| e.template_path.clone())
            .collect();

        for template_path in unique_templates {
            let _ = self.template_cache.get_template(&template_path).await;
        }

        stream
            ::iter(emails)
            .map(|email_req| async move {
                self.send_email(
                    &email_req.to_email,
                    &email_req.subject,
                    &email_req.template_path,
                    &email_req.placeholders
                ).await
            })
            .buffer_unordered(max_concurrent)
            .collect::<Vec<_>>().await
    }

    // Delegation methods for cache management
    pub async fn invalidate_template_cache(&self, template_path: &str) -> Result<usize, String> {
        self.template_cache.invalidate_template(template_path).await
    }

    pub async fn invalidate_all_template_caches(&self) -> Result<usize, String> {
        self.template_cache.invalidate_all().await
    }

    pub async fn get_cache_stats(&self) -> EnhancedCacheStats {
        self.template_cache.get_stats().await
    }

    pub async fn cleanup_all_caches(&self) -> Result<usize, String> {
        self.template_cache.cleanup_memory().await;
        Ok(0) // Could add Redis cleanup here
    }

    pub async fn warmup_pool(&self, connections: usize) -> Result<(), String> {
        self.connection_pool.warmup(connections).await
    }
}

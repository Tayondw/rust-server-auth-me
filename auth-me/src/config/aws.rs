// use aws_config::meta::region::RegionProviderChain;
// use aws_sdk_s3::{Client, Config};
// use dotenvy::dotenv;
// use std::env;

// #[derive(Debug)]
// pub struct AwsConfig {
//     pub region: String,
//     pub bucket_name: String,
//     pub client: Client,
// }

// impl AwsConfig {
//     pub async fn new() -> Self {
//         // Load environment variables
//         dotenv().ok();

//         // Get region, fallback to default if not set
//         let region = env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());

//         // Load AWS configuration from environment variables
//         let shared_config = aws_config::load_from_env().await;
//         let s3_client = Client::new(&shared_config);

//         Self {
//             region,
//             bucket_name: env::var("AWS_BUCKET_NAME").expect("AWS_BUCKET_NAME must be set"),
//             client: s3_client,
//         }
//     }
// }


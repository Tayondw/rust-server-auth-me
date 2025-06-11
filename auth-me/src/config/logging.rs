use tracing_subscriber::{ layer::SubscriberExt, util::SubscriberInitExt };

pub fn init_logging() {
    // Create the base registry that will coordinate all logging layers
    // The registry acts as a dispatcher, routing tracing events to all registered layers
    tracing_subscriber
        ::registry()

        // Add the environment-based filtering layer
        // This layer determines which events should be processed based on their verbosity level
        .with(
            tracing_subscriber::EnvFilter
                ::try_from_default_env()
                // Attempt to read filter configuration from RUST_LOG environment variable

                .unwrap_or_else(|_|
                    // Fallback configuration when RUST_LOG is not set or invalid
                    // "info" = default log level for most code
                    // "diesel=warn" = specifically reduce noise from Diesel ORM database queries
                    // This prevents excessive SQL query logging while maintaining visibility
                    // into application logic and important database errors
                    "info,diesel=warn".into()
                )
        )

        // Add the formatting layer that handles the actual output
        // This layer:
        // - Formats log messages in a human-readable way
        // - Includes timestamps, log levels, module names, and messages
        .with(tracing_subscriber::fmt::layer())
        // Initialize and install this subscriber as the global default
        // After this call:
        // - All tracing::* macros will route through this subscriber
        // - The configuration becomes immutable for the program's lifetime
        // - Any previous subscriber is replaced (should only be called once)
        .init();
}

use tracing_subscriber::{ layer::SubscriberExt, util::SubscriberInitExt };

/// Initializes the application's logging and tracing infrastructure.
///
/// This function sets up a structured logging system using the `tracing` ecosystem,
/// which provides powerful observability capabilities including structured logging,
/// spans for tracking request flows, and configurable output formatting.
///
/// # Architecture Overview
/// The function builds a layered subscriber architecture:
/// 1. **Registry**: Acts as the foundation that coordinates multiple layers
/// 2. **EnvFilter Layer**: Controls which log messages are displayed based on verbosity levels
/// 3. **Formatting Layer**: Handles the actual output formatting and writing to stdout
///
/// # Environment Variable Configuration
/// The logging level can be controlled via the `RUST_LOG` environment variable:
/// - `RUST_LOG=debug` - Shows all debug, info, warn, and error messages
/// - `RUST_LOG=info` - Shows info, warn, and error messages (default)
/// - `RUST_LOG=warn` - Shows only warnings and errors
/// - `RUST_LOG=error` - Shows only error messages
/// - `RUST_LOG=my_crate=debug,other_crate=warn` - Per-crate log level control
///
/// # Default Filtering Behavior
/// If no `RUST_LOG` environment variable is set, the function falls back to:
/// - `info` level for most modules (shows info, warn, error)
/// - `warn` level specifically for `diesel` crate (reduces database query noise)
///
/// # Performance Considerations
/// - Filtering happens at compile time when possible for zero-cost abstractions
/// - The registry pattern allows for efficient event dispatch to multiple subscribers
/// - Structured data is lazily formatted only when actually being output
///
/// # Usage Example
/// ```rust
/// fn main() {
///     init_logging();
///
///     tracing::info!("Application starting");
///     tracing::warn!("This is a warning");
///     tracing::error!("Something went wrong: {}", error_msg);
/// }
/// ```
///
/// # Thread Safety
/// This function should be called exactly once, typically at the start of main().
/// The subscriber it creates is thread-safe and will handle concurrent logging
/// from multiple threads correctly.
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

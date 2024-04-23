pub type AsyncResult<T> =
    std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

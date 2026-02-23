use thiserror::Error;

#[derive(Debug, Error)]
pub enum SafeDockerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yml::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Path resolution error: {0}")]
    PathResolution(String),

    #[error("Docker argument parse error: {0}")]
    DockerArgs(String),

    #[error("Compose parse error: {0}")]
    ComposeParse(String),

    #[error("Input too large: {0} bytes")]
    InputTooLarge(usize),
}

pub type Result<T> = std::result::Result<T, SafeDockerError>;

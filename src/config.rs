#[derive(Debug)]
pub struct Config {
    pub address: String,
    pub static_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:8080".to_string(),
            static_dir: "./static".to_string(),
        }
    }
}

//! Container-only YAML overrides, kept in memory so read-only mounts work.
use crate::config::{hex16, Config};
use anyhow::{Context, Result};
use serde_yaml::{Mapping, Value};
use std::path::Path;

pub fn load_config(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("无法读取容器配置 {}", path.display()))?;
    let variable = |name: &str| -> Result<Option<String>> {
        match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(error).with_context(|| format!("环境变量 {name} 必须是 UTF-8")),
        }
    };
    let secret = variable("SECRET")?;
    let domain = variable("DOMAIN")?;
    let tag = variable("TAG")?;
    parse_config(&text, secret.as_deref(), domain.as_deref(), tag.as_deref())
}

pub fn parse_config(
    text: &str,
    secret: Option<&str>,
    domain: Option<&str>,
    tag: Option<&str>,
) -> Result<Config> {
    let mut overrides = Mapping::new();
    let insert = |fields: &mut Mapping, key: &str, value: Value| {
        fields.insert(Value::String(key.into()), value);
    };
    if let Some(secret) = secret.filter(|s| !s.is_empty()) {
        hex16(secret, "SECRET 环境变量")?;
        insert(&mut overrides, "SECRET", Value::String(secret.into()));
    }
    if let Some(domain) = domain.filter(|s| !s.is_empty()) {
        insert(&mut overrides, "MODES_CLASSIC", Value::Bool(false));
        insert(&mut overrides, "MODES_SECURE", Value::Bool(false));
        insert(&mut overrides, "MODES_TLS", Value::Bool(true));
        insert(&mut overrides, "TLS_DOMAIN", Value::String(domain.into()));
    } else if secret.is_some_and(|s| !s.is_empty()) {
        insert(&mut overrides, "MODES_CLASSIC", Value::Bool(false));
        insert(&mut overrides, "MODES_SECURE", Value::Bool(true));
        insert(&mut overrides, "MODES_TLS", Value::Bool(false));
    }
    // An absent TAG preserves the mounted configuration. An explicitly empty
    // TAG clears it, which is useful for disabling the optional advertisement.
    if let Some(tag) = tag {
        if !tag.is_empty() {
            hex16(tag, "TAG 环境变量")?;
        }
        insert(&mut overrides, "AD_TAG", Value::String(tag.into()));
    }
    Config::parse_with_overrides(text, overrides)
}

#[cfg(test)]
mod tests {
    use super::*;
    const YAML: &str = "LOG_LEVEL: info\nPORT: \"8443\"\nSECRET: \"0123456789abcdef0123456789abcdef\"\nMODES_CLASSIC: false\nMODES_SECURE: true\nMODES_TLS: false\n# TLS_DOMAIN: itunes.apple.com\n# AD_TAG: \"\"\n";
    #[test]
    fn example_without_env_is_unchanged() {
        let c = parse_config(YAML, None, None, None).unwrap();
        assert_eq!(c.port, 8443);
        assert!(c.secure && !c.tls && !c.classic);
        assert_eq!(
            c.secrets[0],
            hex16("0123456789abcdef0123456789abcdef", "SECRET").unwrap()
        );
    }
    #[test]
    fn environment_combinations_are_complete() {
        for secret in [None, Some("fedcba9876543210fedcba9876543210")] {
            for domain in [None, Some("itunes.apple.com")] {
                for tag in [None, Some("11111111111111111111111111111111")] {
                    let c = parse_config(YAML, secret, domain, tag).unwrap();
                    assert_eq!(c.tls, domain.is_some());
                    assert_eq!(c.secure, domain.is_none());
                    assert_eq!(c.middle, tag.is_some());
                    if domain.is_some() {
                        assert_eq!(c.mask_host, "itunes.apple.com");
                    }
                }
            }
        }
    }
    #[test]
    fn preserves_multiple_secrets_and_optional_fields() {
        let input = format!("{YAML}SECRET_1: \"22222222222222222222222222222222\"\nMASK_HOST: custom.example.com\nAD_TAG: \"33333333333333333333333333333333\"\n");
        let c = parse_config(
            &input,
            Some("44444444444444444444444444444444"),
            Some("itunes.apple.com"),
            None,
        )
        .unwrap();
        assert_eq!(c.secrets.len(), 2);
        assert_eq!(c.secrets[1], [0x22; 16]);
        assert_eq!(c.mask_host, "custom.example.com");
        assert_eq!(c.ad_tag, Some([0x33; 16]));
        let c = parse_config(&input, None, None, Some("")).unwrap();
        assert!(c.ad_tag.is_none() && !c.middle);
    }
    #[test]
    fn rejects_bad_environment_values() {
        assert!(parse_config(YAML, Some("bad"), None, None).is_err());
        assert!(parse_config(YAML, None, None, Some("bad")).is_err());
        assert!(parse_config(YAML, None, Some("a\nSECRET: bad"), None).is_err());
    }
}

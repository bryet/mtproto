use crate::{config::Config, crypto, server, state::State};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;

pub async fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut path = PathBuf::from("config.yaml");
    let mut check = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => path = args.next().context("--config 需要文件路径")?.into(),
            "--check-config" => check = true,
            "-s" | "--secret" => {
                println!("{}", hex::encode(crypto::random::<16>()));
                return Ok(());
            }
            "-h" | "--help" => {
                println!("mtproto [-c <config.yaml>] [-s|--secret] [--check-config]\n\n默认配置：当前目录/config.yaml\n-s, --secret         生成 16 字节随机 SECRET\n--check-config       仅验证配置，不监听、不访问网络\nSIGUSR2              重载配置（端口变更需要重启）\nSIGINT / SIGTERM     关闭服务");
                return Ok(());
            }
            "-v" | "--version" => {
                println!("mtproto {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ => bail!("未知参数 {arg}；使用 --help 查看帮助"),
        }
    }
    let config = Config::load(&path)?;
    if check {
        println!(
            "配置有效：{}；{} 个 secret",
            path.display(),
            config.secrets.len()
        );
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| config.log_level.clone().into()),
        )
        .with_writer(std::io::stderr)
        .init();
    crate::system::setup_file_limit();
    server::run(State::new(config), path).await
}

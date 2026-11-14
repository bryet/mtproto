use crate::{config::Config, crypto, server, state::State};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;

pub async fn run(container: bool) -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut path = if container {
        std::env::var_os("CONFIG_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/mtproto/config.yaml"))
    } else {
        PathBuf::from("config.yaml")
    };
    let mut check = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => path = args.next().context("--config 需要文件路径")?.into(),
            "--check-config" => check = true,
            "--generate-secret" => {
                println!("{}", hex::encode(crypto::random::<16>()));
                return Ok(());
            }
            "-h" | "--help" => {
                println!("mtproto [-c <config.yaml>] [--check-config]\n\n默认配置：当前目录/config.yaml\n--generate-secret   生成 16 字节随机 SECRET\n--check-config      仅验证配置，不监听、不访问网络\nSIGUSR2             重载配置（端口变更需要重启）\nSIGINT / SIGTERM    关闭服务");
                return Ok(());
            }
            "-V" | "--version" => {
                println!("mtproto {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ => bail!("未知参数 {arg}；使用 --help 查看帮助"),
        }
    }
    let loader: server::ConfigLoader = if container {
        crate::container::load_config
    } else {
        Config::load
    };
    let config = loader(&path)?;
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
    server::run_with_loader(State::new(config), path, loader).await
}

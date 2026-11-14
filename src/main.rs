#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mtproto::cli::run().await
}

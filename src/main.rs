#[tokio::main]
async fn main() -> anyhow::Result<()> {
    eal_web_server::run().await
}

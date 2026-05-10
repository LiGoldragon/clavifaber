use clavifaber::error::Result;
use clavifaber::request::CommandLine;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let request = CommandLine::from_env().parse_request()?;
    let response = request.execute().await?;
    println!("{}", response.to_nota()?);
    Ok(())
}

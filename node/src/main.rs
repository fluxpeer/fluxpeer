//! `fp-node` binary — thin wrapper over the `fluxpeer-node` library (which the
//! unified `fluxpeer` binary also calls). See lib.rs for the data plane.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("keygen") => fluxpeer_node::keygen()?,
        Some("run") => {
            let cfg = args.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "usage: fp-node run <config.json>"))?;
            fluxpeer_node::run(&cfg).await?;
        }
        _ => {
            eprintln!("usage: fp-node keygen | fp-node run <config.json>");
            std::process::exit(2);
        }
    }
    Ok(())
}

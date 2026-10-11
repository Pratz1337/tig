fn main() {
    if let Err(err) = tig_cli::cmd::run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

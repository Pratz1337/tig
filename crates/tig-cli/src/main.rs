fn main() {
    let result = {
        let _total = tig_cli::trace::span("total");
        tig_cli::cmd::run()
    };
    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

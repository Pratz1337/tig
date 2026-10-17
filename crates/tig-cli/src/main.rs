fn main() {
    let result = {
        let _total = tig_cli::trace::span("total");
        tig_cli::cmd::run()
    };
    if let Err(err) = result {
        if let Some(code) = err.child_exit_code() {
            std::process::exit(code);
        }
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

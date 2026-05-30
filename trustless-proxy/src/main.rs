fn main() {
    match trustless_proxy::LocalTrustlessCli::run_from_args(std::env::args()) {
        Ok(summary) => {
            println!("{summary}");
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

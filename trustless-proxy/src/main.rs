fn main() {
    match trustless_proxy::LocalTrustlessCli::prepare_from_args(std::env::args()) {
        Ok(prepared) => {
            println!("{}", prepared.summary);
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let command = args.get(1).map(String::as_str);

    let result = match command {
        Some("local-proxy-config" | "local-proxy-start-scaffold") => {
            trustless_proxy::LocalTrustlessCli::prepare_from_args(args)
                .map(|prepared| prepared.summary)
        }
        _ => trustless_proxy::LocalTrustlessCli::run_from_args(args),
    };

    match result {
        Ok(summary) => {
            println!("{summary}");
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

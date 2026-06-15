use clap::Parser;
use colored::Colorize;
use serde::Deserialize;
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;
use tokio::task;

// ASCII Art banner displayed on execution
const BANNER: &str = r#"
$$\       $$$$$$\  $$\    $$\ $$$$$$\ $$$$$$$$\ $$\      $$\         $$\   $$\  $$$$$$\  
$$ |     $$  __$$\ $$ |   $$ |\_$$  _|$$  _____|$$ | $\  $$ |        $$$\  $$ |$$  __$$\ 
$$ |     $$ /  \__|$$ |   $$ |  $$ |  $$ |      $$ |$$$\ $$ |        $$$$\ $$ |$$ /  \__|
$$ |     $$ |$$$$\ \$$\  $$  |  $$ |  $$$$$\    $$ $$ $$\$$ |$$$$$$\ $$ $$\$$ |$$ |$$$$\ 
$$ |     $$ |\_$$ | \$$\$$  /   $$ |  $$  __|   $$$$  _$$$$ |\______|$$ \$$$$ |$$ |\_$$ |
$$ |     $$ |  $$ |  \$$$  /    $$ |  $$ |      $$$  / \$$$ |        $$ |\$$$ |$$ |  $$ |
$$$$$$$$\\$$$$$$  |   \$  /   $$$$$$\ $$$$$$$$\ $$  /   \$$ |        $$ | \$$ |\$$$$$$  |
\________|\______/     \_/    \______|\________|\__/     \__|        \__|  \__| \______/ "#;

/// Command line arguments struct managed by Clap
#[derive(Parser, Debug)]
#[command(name = "lgview-ng")]
#[command(about = "Checks for BGP prefix leaks in DDoS mitigation setups using Looking Glass servers", long_about = None)]
struct Args {
    /// The IP prefix to check (IPv4 /24 or IPv6 /48)
    #[arg(long, required = true)]
    prefix: String,

    /// ASN of the mitigation provider (e.g. 264409)
    #[arg(long, required = true)]
    asn_mitigation: u32,

    /// ASN of the prefix owner (e.g. 65001)
    #[arg(long, required = true)]
    asn_mitigated: u32,

    /// Path to config TOML file (defaults to config.toml)
    #[arg(long, default_value = "config.toml")]
    config: String,
}

#[derive(Deserialize, Debug, Clone)]
struct Config {
    looking_glasses: Vec<LookingGlassConfig>,
}

#[derive(Deserialize, Debug, Clone)]
struct LookingGlassConfig {
    name: String,
    host: String,
    username: Option<String>,
    password: Option<String>,
    prompt_suffix: Option<String>,
}

#[derive(Debug, Clone)]
struct QueryResult {
    lg_name: String,
    as_paths: Vec<Vec<u32>>,
    error: Option<String>,
}

/// Helper function to perform clean reading from Telnet stream until prompt appears
fn read_until_telnet(stream: &mut telnet::Telnet, expected: &str, timeout: Duration) -> Result<String, String> {
    let mut buffer = Vec::new();
    let start_time = std::time::Instant::now();

    loop {
        if start_time.elapsed() > timeout {
            return Err(format!("Timeout reading from Telnet. Expected suffix: '{}'", expected));
        }

        match stream.read_nonblocking() {
            Ok(telnet::Event::Data(data)) => {
                buffer.extend_from_slice(&data);
                let current_str = String::from_utf8_lossy(&buffer);
                if current_str.contains(expected) {
                    return Ok(current_str.into_owned());
                }
            }
            Ok(telnet::Event::TimedOut) => {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(_) => {}
            Err(e) => return Err(format!("Telnet read error: {}", e)),
        }
    }
}

/// Helper to parse CLI output from show ip bgp and extract AS paths ending with target AS
fn extract_as_paths(output: &str, target_origin: u32) -> Vec<Vec<u32>> {
    let mut paths = Vec::new();
    let target_str = target_origin.to_string();

    for line in output.lines() {
        if line.contains(&target_str) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let mut current_path = Vec::new();
            for part in &parts {
                if part.contains(':') {
                    continue;
                }
                let clean_part = part.trim_matches(|c: char| !c.is_numeric());
                if let Ok(asn) = clean_part.parse::<u32>() {
                    current_path.push(asn);
                } else if !current_path.is_empty() {
                    break;
                }
            }

            if !current_path.is_empty() && current_path.last() == Some(&target_origin) {
                paths.push(current_path);
            }
        }
    }

    paths.sort();
    paths.dedup();
    paths
}

/// Connects to a Cisco/IOS-like Looking Glass via Telnet, disables pagination, and queries bgp routes
async fn query_telnet_lg(lg: LookingGlassConfig, prefix: String, target_origin: u32) -> QueryResult {
    let name_clone = lg.name.clone();
    let name_err_clone = lg.name.clone();
    task::spawn_blocking(move || {
        let addr = match format!("{}:23", lg.host).to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some("Could not resolve address".to_string()) }
            },
            Err(e) => return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some(format!("DNS Resolve error: {}", e)) }
        };

        let stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(s) => s,
            Err(e) => return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some(format!("Connection timeout/error: {}", e)) }
        };

        // Box the stream to satisfy the Box<dyn Stream> parameter required by telnet crate
        let boxed_stream: Box<dyn telnet::Stream> = Box::new(stream);
        let mut telnet_client = telnet::Telnet::from_stream(boxed_stream, 2048);

        // Handle custom username prompt if specified
        if let Some(ref user) = lg.username {
            let mut prompt_found = false;
            let start_time = std::time::Instant::now();
            let mut buffer = Vec::new();

            while start_time.elapsed() < Duration::from_secs(8) {
                match telnet_client.read_nonblocking() {
                    Ok(telnet::Event::Data(data)) => {
                        buffer.extend_from_slice(&data);
                        let current_str = String::from_utf8_lossy(&buffer);
                        if current_str.contains("Username:") || current_str.contains("login:") {
                            prompt_found = true;
                            break;
                        }
                    }
                    Ok(telnet::Event::TimedOut) => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Ok(_) => {}
                    Err(e) => return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some(format!("Telnet read error: {}", e)) },
                }
            }

            if !prompt_found {
                return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some("Failed to reach login prompt".to_string()) };
            }
            let _ = telnet_client.write(format!("{}\n", user).as_bytes());
        }

        // Handle custom password prompt if specified
        if let Some(ref pass) = lg.password {
            if let Err(e) = read_until_telnet(&mut telnet_client, "Password:", Duration::from_secs(8)) {
                return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some(format!("Failed to reach password prompt: {}", e)) };
            }
            let _ = telnet_client.write(format!("{}\n", pass).as_bytes());
        }

        // Wait for first router prompt (defaulting to ">" if not customized)
        let prompt = lg.prompt_suffix.unwrap_or_else(|| ">".to_string());
        let output = match read_until_telnet(&mut telnet_client, &prompt, Duration::from_secs(10)) {
            Ok(out) => out,
            Err(e) => return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some(format!("Failed to reach prompt: {}", e)) }
        };

        // If host name contains ix.br or route-views, disable Cisco paging
        let is_cisco = output.contains(">") || name_clone.contains("IX.br") || name_clone.contains("Route Views") || name_clone.contains("AT&T") || name_clone.contains("HE");

        if is_cisco {
            let _ = telnet_client.write(b"terminal length 0\n");
            let _ = read_until_telnet(&mut telnet_client, &prompt, Duration::from_secs(3));
        }

        // Query prefix
        let query_cmd = format!("show ip bgp {}\n", prefix);
        let _ = telnet_client.write(query_cmd.as_bytes());

        match read_until_telnet(&mut telnet_client, &prompt, Duration::from_secs(15)) {
            Ok(result) => {
                let paths = extract_as_paths(&result, target_origin);
                QueryResult {
                    lg_name: name_clone,
                    as_paths: paths,
                    error: None,
                }
            }
            Err(e) => QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some(format!("Query read timeout/error: {}", e)) }
        }
    }).await.unwrap_or_else(|e| QueryResult {
        lg_name: name_err_clone,
        as_paths: Vec::new(),
        error: Some(format!("Task execution failed: {}", e)),
    })
}

fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!("{}", BANNER.cyan());
    println!("{}", "https://ispfocus.net.br".underline().bright_black());
    println!("Version: {}\n", version.green());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_banner();

    let args = Args::parse();

    println!("Checking prefix: {}", args.prefix.yellow());
    println!(
        "Expected ending path: {} {}\n",
        args.asn_mitigation, args.asn_mitigated
    );

    // Read and parse the config.toml file
    println!("Loading configuration from: {}", args.config.blue());
    let config_content = match fs::read_to_string(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", format!("Error: Failed to read config file '{}': {}", args.config, e).red());
            std::process::exit(1);
        }
    };

    let config: Config = match toml::from_str(&config_content) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{}", format!("Error: Failed to parse TOML configuration: {}", e).red());
            std::process::exit(1);
        }
    };

    println!("Initiating concurrent Looking Glass checks on {} servers...", config.looking_glasses.len().to_string().cyan());

    // Create parallel tasks for each Looking Glass configured in config.toml
    let mut futures = Vec::new();
    for lg in config.looking_glasses {
        let prefix = args.prefix.clone();
        let target_origin = args.asn_mitigated;
        futures.push(task::spawn(async move {
            query_telnet_lg(lg, prefix, target_origin).await
        }));
    }

    // Await all futures concurrently
    let results_raw = futures_util::future::join_all(futures).await;
    let mut results = Vec::new();
    for res in results_raw {
        if let Ok(query_res) = res {
            results.push(query_res);
        }
    }

    let mut total_paths = 0;
    let mut leaks_count = 0;
    let mut valid_count = 0;

    let lg_col_width = 25;
    let status_width = 20;

    println!("\n{:<lg_width$} | {:<status_width$} | {}", "Looking Glass", "Status", "AS-PATH", lg_width = lg_col_width, status_width = status_width);
    println!("{}", "-".repeat(lg_col_width + status_width + 6 + 35));

    for res in results {
        if let Some(err) = res.error {
            println!(
                "{:<lg_width$} | {:<status_width$} | {}",
                res.lg_name,
                "ERROR".yellow().bold(),
                err.red(),
                lg_width = lg_col_width,
                status_width = status_width
            );
            continue;
        }

        if res.as_paths.is_empty() {
            println!(
                "{:<lg_width$} | {:<status_width$} | {}",
                res.lg_name,
                "NO PATHS".yellow().bold(),
                "No announcements containing target mitigated ASN found".bright_black(),
                lg_width = lg_col_width,
                status_width = status_width
            );
            continue;
        }

        for path in res.as_paths {
            total_paths += 1;
            let path_len = path.len();
            let is_valid = if path_len >= 2 {
                path[path_len - 2] == args.asn_mitigation && path[path_len - 1] == args.asn_mitigated
            } else {
                false
            };

            let path_str = path
                .iter()
                .map(|asn| asn.to_string())
                .collect::<Vec<String>>()
                .join(" ");

            if is_valid {
                valid_count += 1;
                println!(
                    "{:<lg_width$} | {:<status_width$} | {}",
                    res.lg_name,
                    "VALID".green().bold(),
                    path_str.green(),
                    lg_width = lg_col_width,
                    status_width = status_width
                );
            } else {
                leaks_count += 1;
                println!(
                    "{:<lg_width$} | {:<status_width$} | {}",
                    res.lg_name,
                    "LEAK / ANOMALOUS".red().bold(),
                    path_str.red(),
                    lg_width = lg_col_width,
                    status_width = status_width
                );
            }
        }
    }

    println!("\n{}", "Summary Report:".bold());
    println!("Total checked paths: {}", total_paths);
    println!("Valid paths        : {}", valid_count.to_string().green());
    println!("Anomalous / Leaks  : {}", leaks_count.to_string().red());

    if leaks_count > 0 {
        println!("\n{}", "WARNING: Prefix leaks detected!".red().bold());
        std::process::exit(1);
    } else if total_paths == 0 {
        println!("\n{}", "WARNING: No active path advertisements checked.".yellow().bold());
        std::process::exit(1);
    } else {
        println!(
            "\n{}",
            "SUCCESS: All paths are correctly routed via the mitigation provider!"
                .green()
                .bold()
        );
    }

    Ok(())
}

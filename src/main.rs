mod config;

use clap::Parser;
use colored::Colorize;
use config::{Config, LookingGlassConfig};
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
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

/// Telnet read polling interval — reduced from 50ms to 10ms (PERF-03)
const TELNET_POLL_MS: u64 = 10;

/// Maximum HTTP response body size accepted from Alice-LG APIs (SEC-02)
const MAX_HTTP_RESPONSE_BYTES: usize = 50 * 1024 * 1024; // 50 MB

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

/// SEC-01: Validates that a string is a well-formed CIDR prefix (IPv4 or IPv6).
/// Rejects any input containing control characters or shell metacharacters to
/// prevent command injection via Telnet queries.
fn validate_cidr_prefix(prefix: &str) -> bool {
    // Reject control characters and common shell metacharacters
    if prefix.chars().any(|c| {
        c.is_control() || matches!(c, ';' | '|' | '&' | '`' | '$' | '>' | '<' | '!' | '\\' | '\'' | '"' | '(' | ')' | '*' | '?' | '[' | ']' | '#' | '~')
    }) {
        return false;
    }

    let parts: Vec<&str> = prefix.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let ip_str = parts[0];
    let len_str = parts[1];

    let prefix_len: u8 = match len_str.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    if ip_str.parse::<std::net::Ipv4Addr>().is_ok() {
        return prefix_len <= 32;
    }
    if ip_str.parse::<std::net::Ipv6Addr>().is_ok() {
        return prefix_len <= 128;
    }
    false
}

#[derive(Debug, Clone)]
struct QueryResult {
    lg_name: String,
    as_paths: Vec<Vec<u32>>,
    error: Option<String>,
}

/// Helper to read non-blocking from Telnet and automatically reply to negotiations
fn read_nonblocking_negotiate(stream: &mut telnet::Telnet) -> Result<Option<Vec<u8>>, String> {
    match stream.read_nonblocking() {
        Ok(telnet::Event::Data(data)) => Ok(Some(data.into_vec())),
        Ok(telnet::Event::Negotiation(action, opt)) => {
            let reply = match action {
                telnet::Action::Do => Some(telnet::Action::Wont),
                telnet::Action::Will => Some(telnet::Action::Dont),
                _ => None,
            };
            if let Some(reply_action) = reply {
                let _ = stream.negotiate(&reply_action, opt);
            }
            Ok(None)
        }
        Ok(telnet::Event::TimedOut) => Ok(None),
        Ok(_) => Ok(None),
        Err(e) => Err(format!("Telnet read error: {}", e)),
    }
}

/// Helper function to perform clean reading from Telnet stream until prompt appears
fn read_until_telnet(stream: &mut telnet::Telnet, expected: &str, timeout: Duration) -> Result<String, String> {
    let mut buffer = Vec::new();
    let start_time = std::time::Instant::now();

    loop {
        if start_time.elapsed() > timeout {
            return Err(format!("Timeout reading from Telnet. Expected suffix: '{}'", expected));
        }

        match read_nonblocking_negotiate(stream) {
            Ok(Some(data)) => {
                buffer.extend_from_slice(&data);
                let current_str = String::from_utf8_lossy(&buffer);
                if current_str.contains(expected) {
                    return Ok(current_str.into_owned());
                }
            }
            Ok(None) => {
                // PERF-03: Reduced from 50ms to TELNET_POLL_MS (10ms)
                thread::sleep(Duration::from_millis(TELNET_POLL_MS));
            }
            Err(e) => return Err(e),
        }
    }
}

/// BUG-02: Parses CLI output from `show ip bgp` and extracts AS-PATHs ending with the target ASN.
///
/// Improvements over the previous version:
/// - Only tokens composed **entirely** of ASCII digits are treated as ASNs, preventing
///   numeric substrings of mixed tokens (e.g., "64:65001", "Metric", "100i") from being
///   misidentified as ASNs.
/// - Tokens wrapped in `{}` (AS-SET notation, e.g. `{65001,65002}`) are explicitly skipped.
/// - ASN 0 is rejected as it is not a valid assignable ASN.
fn extract_as_paths(output: &str, target_origin: u32) -> Vec<Vec<u32>> {
    let mut paths = Vec::new();
    let target_str = target_origin.to_string();

    for line in output.lines() {
        if !line.contains(&target_str) {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let mut current_path: Vec<u32> = Vec::new();
        for part in &parts {
            // Skip IPv6 addresses and community/attribute tokens (e.g., "64496:100")
            if part.contains(':') {
                continue;
            }
            // Skip AS-SET notation tokens (e.g., "{65001,65002}" or "65001,65002}")
            if part.starts_with('{') || part.ends_with('}') || part.contains(',') {
                continue;
            }
            // Only accept tokens that consist entirely of ASCII digits (no mixed chars)
            if part.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(asn) = part.parse::<u32>() {
                    if asn > 0 {
                        current_path.push(asn);
                    }
                }
            } else if !current_path.is_empty() {
                // Non-numeric token after we've started collecting: stop this line
                break;
            }
        }

        if !current_path.is_empty() && current_path.last() == Some(&target_origin) {
            paths.push(current_path);
        }
    }

    paths.sort();
    paths.dedup();
    paths
}

/// Connects to a Cisco/IOS-like Looking Glass via Telnet, disables pagination, and queries bgp routes.
/// The `prefix` argument must have been validated via `validate_cidr_prefix` before calling this function.
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

            while start_time.elapsed() < Duration::from_secs(15) {
                match read_nonblocking_negotiate(&mut telnet_client) {
                    Ok(Some(data)) => {
                        buffer.extend_from_slice(&data);
                        let current_str = String::from_utf8_lossy(&buffer);
                        let trimmed = current_str.trim_end().to_lowercase();
                        if trimmed.ends_with("username:") || trimmed.ends_with("login:") {
                            prompt_found = true;
                            break;
                        }
                    }
                    Ok(None) => {
                        thread::sleep(Duration::from_millis(TELNET_POLL_MS));
                    }
                    Err(e) => return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some(e) },
                }
            }

            if !prompt_found {
                return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some("Failed to reach login prompt".to_string()) };
            }
            let _ = telnet_client.write(format!("{}\n", user).as_bytes());
        }

        // Handle custom password prompt if specified
        if let Some(ref pass) = lg.password {
            let mut prompt_found = false;
            let start_time = std::time::Instant::now();
            let mut buffer = Vec::new();

            while start_time.elapsed() < Duration::from_secs(15) {
                match read_nonblocking_negotiate(&mut telnet_client) {
                    Ok(Some(data)) => {
                        buffer.extend_from_slice(&data);
                        let current_str = String::from_utf8_lossy(&buffer);
                        let trimmed = current_str.trim_end().to_lowercase();
                        if trimmed.ends_with("password:") {
                            prompt_found = true;
                            break;
                        }
                    }
                    Ok(None) => {
                        thread::sleep(Duration::from_millis(TELNET_POLL_MS));
                    }
                    Err(e) => return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some(e) },
                }
            }

            if !prompt_found {
                return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some("Failed to reach password prompt".to_string()) };
            }
            let _ = telnet_client.write(format!("{}\n", pass).as_bytes());
        }

        // Wait for first router prompt (defaulting to ">" if not customized)
        let prompt = lg.prompt_suffix.as_deref().unwrap_or(">").to_string();
        let _output = match read_until_telnet(&mut telnet_client, &prompt, Duration::from_secs(10)) {
            Ok(out) => out,
            Err(e) => return QueryResult { lg_name: name_clone, as_paths: Vec::new(), error: Some(format!("Failed to reach prompt: {}", e)) }
        };

        // Disable paging
        if let Some(pager) = lg.resolve_pager_cmd() {
            let _ = telnet_client.write(format!("{}\n", pager).as_bytes());
            let _ = read_until_telnet(&mut telnet_client, &prompt, Duration::from_secs(3));
        }

        // Query prefix — SEC-01: prefix was validated as strict CIDR before entry, safe to interpolate
        let cmd_tpl = lg.resolve_cmd_template();
        let query_cmd = format!("{}\n", cmd_tpl.replace("{prefix}", &prefix));
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

#[derive(serde::Deserialize, Clone, Debug)]
struct AliceBgp {
    as_path: Option<Vec<u32>>,
}

#[derive(serde::Deserialize, Clone, Debug)]
struct AliceRouteServer {
    name: Option<String>,
}

#[derive(serde::Deserialize, Clone, Debug)]
struct AliceRoute {
    bgp: Option<AliceBgp>,
    routeserver: Option<AliceRouteServer>,
}

#[derive(serde::Deserialize, Clone, Debug)]
struct AliceImported {
    routes: Option<Vec<AliceRoute>>,
}

#[derive(serde::Deserialize, Clone, Debug)]
struct AliceLookupResponse {
    imported: Option<AliceImported>,
}

/// Fetches all routes for a prefix from an Alice-LG API endpoint.
///
/// PERF-02: Accepts a shared `Arc<reqwest::Client>` to reuse the connection pool
///          across all concurrent host fetches instead of creating a new client per call.
///
/// SEC-02: Reads the response body as raw bytes and enforces a size limit before
///         deserializing to prevent OOM from oversized or malicious responses.
async fn fetch_alice_routes(
    client: Arc<reqwest::Client>,
    host: String,
    prefix: String,
) -> Result<Vec<AliceRoute>, String> {
    let url = format!("https://{}/api/v1/lookup/prefix?q={}", host, prefix);
    let res = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            // Fallback to plain HTTP if HTTPS fails
            let http_url = format!("http://{}/api/v1/lookup/prefix?q={}", host, prefix);
            match client.get(&http_url).send().await {
                Ok(r) => r,
                Err(err) => {
                    return Err(format!("HTTP error: {} (HTTPS error: {})", err, e));
                }
            }
        }
    };

    if !res.status().is_success() {
        return Err(format!("HTTP status error: {}", res.status()));
    }

    // SEC-02: Read body as bytes first and enforce size limit before deserialization
    let bytes = match res.bytes().await {
        Ok(b) => b,
        Err(e) => return Err(format!("Failed to read response body: {}", e)),
    };

    if bytes.len() > MAX_HTTP_RESPONSE_BYTES {
        return Err(format!(
            "Response too large: {} bytes (limit: {}MB)",
            bytes.len(),
            MAX_HTTP_RESPONSE_BYTES / 1024 / 1024
        ));
    }

    let response_data: AliceLookupResponse = match serde_json::from_slice(&bytes) {
        Ok(json) => json,
        Err(e) => return Err(format!("JSON parsing error: {}", e)),
    };

    Ok(response_data.imported.and_then(|imp| imp.routes).unwrap_or_default())
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

    // SEC-01: Validate the prefix strictly as CIDR before any further use.
    // This prevents command injection via Telnet for malformed or malicious --prefix values.
    if !validate_cidr_prefix(&args.prefix) {
        eprintln!(
            "{}",
            format!(
                "Error: '{}' is not a valid CIDR prefix. Expected format: X.X.X.X/Y (IPv4) or X:X::/Y (IPv6).",
                args.prefix
            )
            .red()
        );
        std::process::exit(1);
    }

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

    // BUG-04: Validate that all Looking Glass names are unique.
    // Duplicate names cause double-counting of AS-PATHs in the final report,
    // producing inflated valid/leak counts without any visible warning.
    {
        let mut seen_names = std::collections::HashSet::new();
        for lg in &config.looking_glasses {
            if !seen_names.insert(lg.name.as_str()) {
                eprintln!(
                    "{}",
                    format!(
                        "Error: Duplicate Looking Glass name '{}' found in config. All names must be unique.",
                        lg.name
                    )
                    .red()
                );
                std::process::exit(1);
            }
        }
    }

    // BUG-01: Determine which Alice-LG hosts serve multiple LGs (need route-server name filtering).
    //
    // Previously, filtering was hardcoded to only `lg.ix.br`. This approach is fragile:
    // any other centralized Alice-LG host (DE-CIX, LINX, etc.) would silently accept all
    // routes without discrimination, potentially producing incorrect results.
    //
    // New approach: dynamically detect hosts that appear more than once in config.
    // - Hosts with multiple LGs: filter routes by `routeserver.name` == `lg.name`
    // - Hosts with a single LG: accept all routes from the response (no ambiguity)
    // - If `routeserver.name` is absent even on a multi-LG host: accept conservatively
    let multi_lg_hosts: std::collections::HashSet<String> = {
        let mut host_count: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for lg in &config.looking_glasses {
            if lg.template.as_deref() == Some("alice") {
                *host_count.entry(lg.host.clone()).or_insert(0) += 1;
            }
        }
        host_count
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(host, _)| host)
            .collect()
    };

    // PERF-02: Create a single shared HTTP client with connection pooling.
    // Previously a new client was instantiated per fetch call, wasting TLS handshakes.
    let http_client = Arc::new(
        match reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{}", format!("Error: Failed to build HTTP client: {}", e).red());
                std::process::exit(1);
            }
        },
    );

    // 1. Identify all unique Alice-LG hosts and fetch their route lookups once
    //    to prevent rate limiting (HTTP 429) on centralized endpoints like lg.ix.br.
    let mut alice_hosts: Vec<String> = config
        .looking_glasses
        .iter()
        .filter(|lg| lg.template.as_deref() == Some("alice"))
        .map(|lg| lg.host.clone())
        .collect();
    alice_hosts.sort();
    alice_hosts.dedup();

    let mut alice_futures = Vec::new();
    for host in alice_hosts {
        let prefix = args.prefix.clone();
        let client = http_client.clone();
        alice_futures.push(task::spawn(async move {
            let res = fetch_alice_routes(client, host.clone(), prefix).await;
            (host, res)
        }));
    }

    let alice_results_raw = futures_util::future::join_all(alice_futures).await;
    let mut alice_cache = std::collections::HashMap::new();
    for item in alice_results_raw {
        if let Ok((host, res)) = item {
            alice_cache.insert(host, res);
        }
    }

    println!(
        "Initiating concurrent Looking Glass checks on {} servers...",
        config.looking_glasses.len().to_string().cyan()
    );

    // 2. Create parallel tasks for each Looking Glass.
    //    BUG-03: Track the LG name alongside each JoinHandle so that if a task panics,
    //    we can still attribute the failure to the correct LG in the output table
    //    instead of silently dropping it.
    let mut named_futures: Vec<(String, task::JoinHandle<QueryResult>)> = Vec::new();

    for lg in config.looking_glasses {
        let prefix = args.prefix.clone();
        let target_origin = args.asn_mitigated;
        let lg_name_for_error = lg.name.clone();

        if lg.template.as_deref() == Some("alice") {
            let cached_res = alice_cache.get(&lg.host).cloned();
            // BUG-01: Use dynamic detection — filter only if this host has multiple LGs
            let needs_rs_filter = multi_lg_hosts.contains(&lg.host);

            let handle = task::spawn(async move {
                let routes = match cached_res {
                    Some(Ok(r)) => r,
                    Some(Err(e)) => {
                        return QueryResult {
                            lg_name: lg.name,
                            as_paths: Vec::new(),
                            error: Some(e),
                        }
                    }
                    None => {
                        return QueryResult {
                            lg_name: lg.name,
                            as_paths: Vec::new(),
                            error: Some("Host result not cached".to_string()),
                        }
                    }
                };

                let mut paths = Vec::new();
                for route in routes {
                    // BUG-01: Generic route-server filtering logic
                    let matches_routeserver = if needs_rs_filter {
                        // Multi-LG host: match by routeserver.name; accept if field is absent
                        match route.routeserver.as_ref().and_then(|rs| rs.name.as_deref()) {
                            Some(rs_name) => {
                                lg.name.trim().to_lowercase() == rs_name.trim().to_lowercase()
                            }
                            None => true, // routeserver field absent: accept conservatively
                        }
                    } else {
                        // Single-LG host: accept all routes unconditionally
                        true
                    };

                    if matches_routeserver {
                        if let Some(bgp) = route.bgp {
                            if let Some(as_path) = bgp.as_path {
                                if !as_path.is_empty() && as_path.last() == Some(&target_origin) {
                                    paths.push(as_path);
                                }
                            }
                        }
                    }
                }

                paths.sort();
                paths.dedup();

                QueryResult {
                    lg_name: lg.name,
                    as_paths: paths,
                    error: None,
                }
            });
            named_futures.push((lg_name_for_error, handle));
        } else {
            let handle = task::spawn(async move { query_telnet_lg(lg, prefix, target_origin).await });
            named_futures.push((lg_name_for_error, handle));
        }
    }

    // BUG-03: Collect results. JoinErrors (task panics) are now surfaced as ERROR rows
    // in the output table, making failures visible instead of silently omitted.
    let (names, handles): (Vec<String>, Vec<_>) = named_futures.into_iter().unzip();
    let results_raw = futures_util::future::join_all(handles).await;

    let mut results = Vec::new();
    for (name, res) in names.into_iter().zip(results_raw.into_iter()) {
        match res {
            Ok(query_res) => results.push(query_res),
            Err(e) => results.push(QueryResult {
                lg_name: name,
                as_paths: Vec::new(),
                error: Some(format!("Internal task failure: {}", e)),
            }),
        }
    }

    let mut total_paths = 0;
    let mut leaks_count = 0;
    let mut valid_count = 0;

    let mut lg_col_width = 25;
    for res in &results {
        if res.lg_name.len() > lg_col_width {
            lg_col_width = res.lg_name.len();
        }
    }
    let status_width = 20;

    println!(
        "\n{:<lg_width$} | {:<status_width$} | {}",
        "Looking Glass",
        "Status",
        "AS-PATH",
        lg_width = lg_col_width,
        status_width = status_width
    );
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

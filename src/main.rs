use clap::Parser;
use colored::Colorize;
use serde::Deserialize;
use std::collections::HashMap;

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
#[command(about = "Checks for BGP prefix leaks in DDoS mitigation setups", long_about = None)]
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
}

/// Serde structs mapping JSON responses from the RIPEstat BGP-state API
#[derive(Deserialize, Debug)]
struct RipeStateResponse {
    data: RipeStateData,
}

#[derive(Deserialize, Debug)]
struct RipeStateData {
    bgp_state: Vec<BgpRoute>,
    timestamp: String,
}

#[derive(Deserialize, Debug)]
struct BgpRoute {
    path: Vec<u32>,
    source_id: String,
}

/// Serde structs mapping JSON responses from the RIPEstat BGP-updates API
#[derive(Deserialize, Debug)]
struct RipeUpdatesResponse {
    data: RipeUpdatesData,
}

#[derive(Deserialize, Debug)]
struct RipeUpdatesData {
    updates: Vec<BgpUpdate>,
}

#[derive(Deserialize, Debug)]
struct BgpUpdate {
    #[serde(rename = "type")]
    update_type: String, // "A" for announcements, "W" for withdrawals
    attrs: Option<BgpUpdateAttrs>,
}

#[derive(Deserialize, Debug)]
struct BgpUpdateAttrs {
    source_id: String,
    path: Option<Vec<u32>>,
}

/// Prints the ASCII Art banner, the product URL, and the Cargo project version
fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!("{}", BANNER.cyan());
    println!("{}", "https://ispfocus.net.br".underline().bright_black());
    println!("Version: {}\n", version.green());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_banner();

    // Parse command line arguments
    let args = Args::parse();

    println!("Checking prefix: {}", args.prefix.yellow());
    println!(
        "Expected ending path: {} {}\n",
        args.asn_mitigation, args.asn_mitigated
    );

    let client = reqwest::Client::new();

    // 1. Fetch the BGP baseline state (the most recent full RIB dump)
    println!("{}", "Fetching BGP state baseline...".blue());
    let state_url = format!(
        "https://stat.ripe.net/data/bgp-state/data.json?resource={}",
        args.prefix
    );
    let state_res = client
        .get(&state_url)
        .header("User-Agent", "lgview-ng/1.0 (https://ispfocus.net.br)")
        .send()
        .await?;

    if !state_res.status().is_success() {
        eprintln!(
            "{}",
            format!("Error: RIPEstat API returned HTTP status {} for state request", state_res.status()).red()
        );
        std::process::exit(1);
    }

    let state_data: RipeStateResponse = state_res.json().await?;
    let baseline_timestamp = state_data.data.timestamp;

    // Load active paths from state baseline
    // Map: source_id -> path
    let mut peer_paths: HashMap<String, Vec<u32>> = HashMap::new();
    for route in state_data.data.bgp_state {
        peer_paths.insert(route.source_id, route.path);
    }

    println!(
        "Loaded {} active baseline paths (snapshot from {} UTC).",
        peer_paths.len().to_string().cyan(),
        baseline_timestamp.green()
    );

    // 2. Fetch the BGP updates since the baseline timestamp up to now
    println!("{}", "Fetching BGP updates for real-time adjustments...".blue());
    let updates_url = format!(
        "https://stat.ripe.net/data/bgp-updates/data.json?resource={}&starttime={}",
        args.prefix, baseline_timestamp
    );
    let updates_res = client
        .get(&updates_url)
        .header("User-Agent", "lgview-ng/1.0 (https://ispfocus.net.br)")
        .send()
        .await?;

    if !updates_res.status().is_success() {
        eprintln!(
            "{}",
            format!("Error: RIPEstat API returned HTTP status {} for updates request", updates_res.status()).red()
        );
        std::process::exit(1);
    }

    let updates_data: RipeUpdatesResponse = updates_res.json().await?;
    let updates = updates_data.data.updates;

    println!(
        "Processing {} BGP updates for real-time corrections.",
        updates.len().to_string().cyan()
    );

    // Apply BGP updates incrementally on top of the baseline
    for update in updates {
        if let Some(attrs) = update.attrs {
            if update.update_type == "A" {
                // If it is an announcement, insert or overwrite path
                if let Some(path) = attrs.path {
                    peer_paths.insert(attrs.source_id, path);
                }
            } else if update.update_type == "W" {
                // If it is a withdrawal, remove the path
                peer_paths.remove(&attrs.source_id);
            }
        }
    }

    // Convert peer paths back to a sorted list
    let mut active_paths: Vec<(String, Vec<u32>)> = peer_paths.into_iter().collect();
    active_paths.sort_by(|a, b| a.0.cmp(&b.0));

    if active_paths.is_empty() {
        println!("{}", "No active BGP routing paths found for this prefix.".yellow());
        return Ok(());
    }

    let mut leaks_count = 0;
    let mut valid_count = 0;

    // Calculate maximum length of Source ID dynamically to ensure perfect alignment
    let max_source_id_len = active_paths
        .iter()
        .map(|(source_id, _)| source_id.len())
        .max()
        .unwrap_or(25)
        .max(25); // Minimum width of 25 to match header

    let status_width = 20;

    println!("\n{:<source_width$} | {:<status_width$} | {}", "Source ID (RRC)", "Status", "AS-PATH", source_width = max_source_id_len, status_width = status_width);
    println!("{}", "-".repeat(max_source_id_len + status_width + 6 + 25));

    // Iterate through computed active BGP paths
    for (source_id, path) in active_paths {
        let path_len = path.len();
        // Check if the AS-PATH ends with: <asn_mitigation> <asn_mitigated>
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
                "{:<source_width$} | {:<status_width$} | {}",
                source_id,
                "VALID".green().bold(),
                path_str.green(),
                source_width = max_source_id_len,
                status_width = status_width
            );
        } else {
            leaks_count += 1;
            println!(
                "{:<source_width$} | {:<status_width$} | {}",
                source_id,
                "LEAK / ANOMALOUS".red().bold(),
                path_str.red(),
                source_width = max_source_id_len,
                status_width = status_width
            );
        }
    }

    // Print final summary report
    println!("\n{}", "Summary Report:".bold());
    println!("Total checked paths: {}", valid_count + leaks_count);
    println!("Valid paths        : {}", valid_count.to_string().green());
    println!("Anomalous / Leaks  : {}", leaks_count.to_string().red());

    // Exit with code 1 if any leak was found to assist automation integration
    if leaks_count > 0 {
        println!("\n{}", "WARNING: Prefix leaks detected!".red().bold());
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

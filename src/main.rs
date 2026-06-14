use chrono::{Duration, Utc};
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

    /// Timeframe window in minutes to search BGP updates (default is 15 minutes)
    #[arg(long, default_value = "15")]
    timeframe: i64,
}

/// Serde structs mapping JSON responses from the RIPEstat BGP-updates API
#[derive(Deserialize, Debug)]
struct RipeResponse {
    data: RipeData,
}

#[derive(Deserialize, Debug)]
struct RipeData {
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

    // Calculate the start time based on the timeframe window
    let start_time = Utc::now() - Duration::minutes(args.timeframe);
    let start_time_str = start_time.format("%Y-%m-%dT%H:%M:%S").to_string();

    println!(
        "Querying BGP updates since (UTC): {}\n",
        start_time_str.blue()
    );

    // Call RIPE NCC RIS API for BGP updates over the timeframe window
    let url = format!(
        "https://stat.ripe.net/data/bgp-updates/data.json?resource={}&starttime={}",
        args.prefix, start_time_str
    );

    let client = reqwest::Client::new();
    let res = client
        .get(&url)
        .header("User-Agent", "lgview-ng/1.0 (https://ispfocus.net.br)")
        .send()
        .await?;

    if !res.status().is_success() {
        eprintln!(
            "{}",
            format!("Error: RIPEstat API returned HTTP status {}", res.status()).red()
        );
        std::process::exit(1);
    }

    let ripe_data: RipeResponse = res.json().await?;
    let updates = ripe_data.data.updates;

    // Filter to obtain only the latest announcement state per peer (source_id)
    // Map: source_id -> Option<Vec<u32>> (None if last update is a withdrawal, Some(path) if announcement)
    let mut latest_peer_states: HashMap<String, Option<Vec<u32>>> = HashMap::new();

    for update in &updates {
        if let Some(ref attrs) = update.attrs {
            if update.update_type == "A" {
                if let Some(ref path) = attrs.path {
                    latest_peer_states.insert(attrs.source_id.clone(), Some(path.clone()));
                }
            } else if update.update_type == "W" {
                latest_peer_states.insert(attrs.source_id.clone(), None);
            }
        }
    }

    // Keep only active BGP paths (filtering out peers whose latest state is withdrawal)
    let active_paths: Vec<(String, Vec<u32>)> = latest_peer_states
        .into_iter()
        .filter_map(|(source_id, path_opt)| path_opt.map(|path| (source_id, path)))
        .collect();

    if active_paths.is_empty() {
        println!(
            "{}",
            "No active BGP announcements found for this prefix in the last query window."
                .yellow()
        );
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

    // Print table header
    println!(
        "{:<source_width$} | {:<status_width$} | {}",
        "Source ID (RRC)",
        "Status",
        "AS-PATH",
        source_width = max_source_id_len,
        status_width = status_width
    );
    println!("{}", "-".repeat(max_source_id_len + status_width + 6 + 25));

    // Iterate through BGP routing paths gathered from updates
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

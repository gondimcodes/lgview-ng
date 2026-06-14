use clap::Parser;
use colored::Colorize;
use serde::Deserialize;

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
struct RipeResponse {
    data: RipeData,
}

#[derive(Deserialize, Debug)]
struct RipeData {
    bgp_state: Vec<BgpRoute>,
}

#[derive(Deserialize, Debug)]
struct BgpRoute {
    #[serde(rename = "target_prefix")]
    _target_prefix: String,
    path: Vec<u32>,
    source_id: String,
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

    // Call RIPE NCC RIS API for current BGP routing states
    let url = format!(
        "https://stat.ripe.net/data/bgp-state/data.json?resource={}",
        args.prefix
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
    let routes = ripe_data.data.bgp_state;

    if routes.is_empty() {
        println!("{}", "No BGP routes found for this prefix.".yellow());
        return Ok(());
    }

    let mut leaks_count = 0;
    let mut valid_count = 0;

    // Calculate maximum length of Source ID dynamically to ensure perfect alignment
    let max_source_id_len = routes
        .iter()
        .map(|r| r.source_id.len())
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

    // Iterate through BGP routing paths gathered from global collectors
    for route in routes {
        let path_len = route.path.len();
        // Check if the AS-PATH ends with: <asn_mitigation> <asn_mitigated>
        let is_valid = if path_len >= 2 {
            route.path[path_len - 2] == args.asn_mitigation
                && route.path[path_len - 1] == args.asn_mitigated
        } else {
            false
        };

        let path_str = route
            .path
            .iter()
            .map(|asn| asn.to_string())
            .collect::<Vec<String>>()
            .join(" ");

        if is_valid {
            valid_count += 1;
            println!(
                "{:<source_width$} | {:<status_width$} | {}",
                route.source_id,
                "VALID".green().bold(),
                path_str.green(),
                source_width = max_source_id_len,
                status_width = status_width
            );
        } else {
            leaks_count += 1;
            println!(
                "{:<source_width$} | {:<status_width$} | {}",
                route.source_id,
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

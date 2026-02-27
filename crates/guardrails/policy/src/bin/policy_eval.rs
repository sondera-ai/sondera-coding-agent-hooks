use std::path::PathBuf;
use std::process;

use clap::Parser;
use sondera_policy::{PolicyModel, PolicyModelConfig};

#[derive(Parser)]
#[command(
    name = "policy-eval",
    about = "Evaluate file content against policy templates"
)]
struct Cli {
    /// File whose content to evaluate.
    input: PathBuf,

    /// Path to the policies TOML file.
    #[arg(short, long, default_value = "policies/policies.toml")]
    policies: PathBuf,

    /// Ollama host URL.
    #[arg(long, default_value = "http://localhost")]
    host: String,

    /// Ollama port.
    #[arg(long, default_value_t = 11434)]
    port: u16,

    /// Model name.
    #[arg(long, default_value = "gpt-oss-safeguard:20b")]
    model: String,

    /// Output raw JSON instead of a pretty report.
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Read input file.
    let content = match std::fs::read_to_string(&cli.input) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", cli.input.display(), e);
            process::exit(1);
        }
    };

    if content.is_empty() {
        eprintln!("Error: {} is empty", cli.input.display());
        process::exit(1);
    }

    // Load policy templates.
    let policies = match sondera_policy::PolicyTemplate::load_from_toml(&cli.policies) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "Error loading policies from {}: {}",
                cli.policies.display(),
                e
            );
            process::exit(1);
        }
    };

    let config = PolicyModelConfig {
        host: cli.host,
        port: cli.port,
        model: cli.model,
        temperature: 0.0,
    };

    let model = PolicyModel::with_config(policies, config);

    // Evaluate.
    let classification = match model.evaluate_content(&content).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Policy evaluation failed: {}", e);
            process::exit(1);
        }
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&classification).unwrap());
        process::exit(if classification.compliant { 0 } else { 1 });
    }

    // Pretty report.
    print_report(&cli.input, &content, &classification);

    if !classification.compliant {
        process::exit(1);
    }
}

fn print_report(
    path: &std::path::Path,
    content: &str,
    classification: &sondera_policy::PolicyClassification,
) {
    let line_count = content.lines().count();
    let char_count = content.len();

    println!();
    println!("  Policy Evaluation Report");
    println!("  ========================");
    println!();
    println!("  File:    {}", path.display());
    println!("  Size:    {} lines, {} bytes", line_count, char_count);
    println!();

    if classification.compliant {
        println!("  Result:  COMPLIANT");
        println!();
        println!("  No policy violations detected.");
    } else {
        println!(
            "  Result:  NON-COMPLIANT ({} violation{})",
            classification.violations.len(),
            if classification.violations.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        println!();
        println!("  Violations:");
        println!("  -----------");

        for (i, v) in classification.violations.iter().enumerate() {
            println!();
            println!("  {}. [{}] {}", i + 1, v.rule, v.category);
            println!("     {}", v.description);
        }
    }

    println!();
}

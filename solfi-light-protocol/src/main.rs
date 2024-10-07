// 🏗️ Developed by: Baturalp Güvenç 

/* Gerekli kütüphaneleri kullanıyoruz: rusqlite (SQLite işlemleri için), url (URL ayrıştırma için), serde_json (JSON işlemleri için) ve Rust standart kütüphanesinden çeşitli modüller.
HistoryAnalyzer adında bir struct tanımlıyoruz. Bu struct, linkleri ve kelime sayımlarını tutar.
get_chrome_history_path fonksiyonu, farklı işletim sistemleri için Chrome geçmiş dosyasının konumunu belirler.
extract_links_from_chrome metodu, Chrome'un geçmiş veritabanından son 5 URL'yi çeker.
analyze_link metodu, her bir linki ayrıştırır ve içindeki anlamlı kelimeleri (özellikle blockchain ağı isimlerini) sayar.
get_most_common_word ve to_json metotları, en sık kullanılan kelimeyi bulur ve JSON formatında çıktı üretir.
run metodu, sürekli çalışan bir döngü içinde her 60 saniyede bir yeni linkleri kontrol eder. */




use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
// use std::thread;
use std::time::Duration;
use serde_json::{json, Value};
use rusqlite::Connection;
use url::Url;
use solana_sdk::{
    signature::{Keypair, Signer},
    transaction::Transaction,
    pubkey::Pubkey,
};
// use solana_client::rpc_client::RpcClient;
use std::fs::File;
use std::io::Write;
use std::process::Command;

use light_sdk::{
    compressed_account::{CompressedAccount, CompressedAccountData},
    instruction::{create_invoke_instruction, InstructionDataInvoke},
    merkle_context::MerkleContext,
    proof::CompressedProof,
    stateless::Rpc,
    ID,
};



const BLOCKCHAIN_NETWORKS: [&str; 20] = [
    "bitcoin", "ethereum", "scroll", "polkadot", "solana", "zk-lokomotive", "cosmos",
    "algorand", "mina", "chainlink", "superteam", "aave", "compound", "maker",
    "polygon", "binance", "tron", "wormhole", "stellar", "filecoin"
];

const IGNORED_WORDS: [&str; 18] = [
    "http", "https", "www", "com", "org", "net", "search", "google", "?", "q", "=", "xyz", "&", "%", "#", "oq", "://", ":UTF-8"
];

fn get_chrome_history_path() -> PathBuf {
    let home = dirs::home_dir().expect("Unable to find home directory");
    if cfg!(target_os = "windows") {
        home.join(r"AppData\Local\Google\Chrome\User Data\Default\History")
    } else if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Google/Chrome/Default/History")
    } else {
        home.join(".config/google-chrome/Default/History")
    }
}

fn extract_links_from_chrome() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let history_path = get_chrome_history_path();
    let temp_path = history_path.with_extension("tmp");

    fs::copy(&history_path, &temp_path)?;

    let conn = Connection::open(&temp_path)?;
    let mut stmt = conn.prepare("SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT 5")?;
    
    let urls: Vec<String> = stmt.query_map([], |row| row.get(0))?
        .filter_map(Result::ok)
        .collect();

    fs::remove_file(temp_path)?;

    Ok(urls)
}

fn extract_keywords_from_url(url: &str) -> Vec<String> {
    let ignored_words: HashSet<_> = IGNORED_WORDS.iter().map(|&s| s.to_string()).collect();
    
    if let Ok(parsed_url) = Url::parse(url) {
        let domain = parsed_url.domain().unwrap_or("");
        let path = parsed_url.path();
        
        domain.split('.')
            .chain(path.split('/'))
            .filter_map(|segment| {
                let lowercase_segment = segment.to_lowercase();
                if segment.is_empty() || ignored_words.contains(&lowercase_segment) {
                    None
                } else {
                    Some(lowercase_segment)
                }
            })
            .collect()
    } else {
        Vec::new()
    }
}

fn analyze_link(link: &str, word_counter: &mut HashMap<String, u32>) {
    let keywords = extract_keywords_from_url(link);

    for word in keywords {
        if BLOCKCHAIN_NETWORKS.contains(&word.as_str()) || word.len() > 3 {
            *word_counter.entry(word).or_insert(0) += 1;
        }
    }
}

fn get_most_common_word(word_counter: &HashMap<String, u32>) -> Option<(String, u32)> {
    word_counter.iter()
        .max_by_key(|&(_, count)| count)
        .map(|(word, count)| (word.clone(), *count))
}

async fn zk_compress(data: &str, client: &Rpc, payer: &Keypair) -> Result<CompressedAccount, Box<dyn std::error::Error>> {
    let compressed_account = CompressedAccount {
        owner: payer.pubkey(),
        lamports: 0,
        address: None,
        data: Some(CompressedAccountData {
            discriminator: [0; 8],  
            data: data.as_bytes().to_vec(),
            data_hash: [0; 32], 
        }),
    };

    Ok(compressed_account)
}



async fn zk_decompress(compressed_account: &CompressedAccount) -> Result<String, Box<dyn std::error::Error>> {
    match &compressed_account.data {
        Some(data) => Ok(String::from_utf8(data.data.clone())?),
        None => Err("No data in compressed account".into()),
    }
}

fn create_solana_account() -> Keypair {
    Keypair::new()
}

async fn airdrop_sol(client: &Rpc, pubkey: &Pubkey, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
    let sig = client.request_airdrop(pubkey, amount).await?;
    client.confirm_transaction(&sig).await?;
    println!("✈️ Airdrop request sent for {} lamports", amount);
    
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    let balance = client.get_balance(pubkey).await?;
    println!("Current balance after airdrop: {} lamports", balance);
    
    if balance == 0 {
        return Err("Airdrop failed: Balance is still 0".into());
    }
    
    Ok(())
}

async fn ensure_minimum_balance(client: &Rpc, pubkey: &Pubkey, minimum_balance: u64) -> Result<(), Box<dyn std::error::Error>> {    
    let mut attempts = 0;
    while attempts < 3 {
        let balance = client.get_balance(pubkey).await?;
        if balance >= minimum_balance {
            println!("Sufficient balance: {} lamports", balance);
            return Ok(());
        }
        
        println!("Insufficient balance: {} lamports. Attempting airdrop...", balance);
        if let Err(e) = airdrop_sol(client, pubkey, minimum_balance - balance).await {
            println!("Airdrop attempt failed: {}. Retrying...", e);
        }
        
        attempts += 1;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    
    Err("Failed to ensure minimum balance after multiple attempts".into())
}


// fn retrieve_and_decompress_hash(client: &RpcClient, signature: &Signature) -> Result<Value, Box<dyn std::error::Error>> {
//     let transaction = client.get_transaction(signature, UiTransactionEncoding::Json)?;
    
//     if let Some(meta) = transaction.transaction.meta {
//         if let OptionSerializer::Some(log_messages) = meta.log_messages {
//             for log in log_messages {
//                 println!("Processing log: {}", log);  
//                 if log.starts_with("Program log: Memo") {
//                     if let Some(start_index) = log.find("): ") {
//                         let compressed_hash = &log[start_index + 3..];
//                         println!("Compressed hash: {}", compressed_hash);  
//                         match zk_decompress(compressed_hash) {
//                             Ok(decompressed_hash) => {
//                                 println!("Decompressed hash: {}", decompressed_hash);  
//                                 match serde_json::from_str(&decompressed_hash) {
//                                     Ok(json_data) => {
//                                         print_formatted_json(&json_data, "Retrieved ");
//                                         return Ok(json_data);
//                                     },
//                                     Err(e) => println!("Error parsing JSON: {}. Raw data: {}", e, decompressed_hash),  
//                                 }
//                             },
//                             Err(e) => println!("Error decompressing: {}. Raw data: {}", e, compressed_hash),  
//                         }
//                     }
//                 }
//             }
//         }
//     }

//     Err("Could not find or process memo in transaction logs".into())
// }

async fn transfer_compressed_hash(
    client: &Rpc,
    payer: &Keypair,
    to: &Pubkey,
    compressed_account: &CompressedAccount,
    original_json: &Value,
) -> Result<String, Box<dyn std::error::Error>> {
    ensure_minimum_balance(client, &payer.pubkey(), 1_000_000_000).await?;

    let merkle_tree_pubkey = Pubkey::new_unique();
    let merkle_context = MerkleContext {
        merkle_tree_pubkey,
        nullifier_queue_pubkey: Pubkey::new_unique(),
        leaf_index: 0,
        queue_index: None,
    };

    let input_compressed_accounts = vec![];
    let output_compressed_accounts = vec![compressed_account.clone()];
    let proof = CompressedProof::new();
    
    let instruction = create_invoke_instruction(
        &payer.pubkey(),
        &payer.pubkey(),
        &input_compressed_accounts,
        &output_compressed_accounts,
        &[merkle_context],
        &[merkle_tree_pubkey],
        &[0],
        &[],
        Some(proof),
        None,
        false,
        None,
        true,
    );

    let recent_blockhash = client.get_latest_blockhash().await?;
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[payer],
        recent_blockhash,
    );
    
    let signature = client.send_and_confirm_transaction(&transaction).await?;
    println!("✅ Successfully transferred compressed hash. Transaction signature: {}", signature);
    println!("⛓️⛓️ Transaction link: https://explorer.solana.com/tx/{}?cluster=custom", signature);

    print_formatted_json(original_json, "Original ");

    Ok(signature.to_string())
}

async fn retrieve_and_decompress_hash(client: &Rpc, signature: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let transaction = client.get_transaction(&signature.parse()?).await?;
    
    let compressed_account = find_compressed_account_in_transaction(&transaction)?;

    let decompressed_data = zk_decompress(&compressed_account).await?;
    let json_data: Value = serde_json::from_str(&decompressed_data)?;

    print_formatted_json(&json_data, "Retrieved ");
    Ok(json_data)
}

fn find_compressed_account_in_transaction(transaction: &Transaction) -> Result<CompressedAccount, Box<dyn std::error::Error>> {
    for instruction in &transaction.message.instructions {
        if instruction.program_id(&transaction.message.account_keys) == ID {
            if let Some(compressed_account_data) = instruction.data.get(..32) {

                let compressed_account = CompressedAccount {
                    owner: Pubkey::try_from(&compressed_account_data[0..32]).unwrap_or_default(),
                    lamports: 0,
                    address: None,
                    data: None,
                };
                return Ok(compressed_account);
            }
        }
    }
    Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "No compressed account found in transaction"
    )))
}




fn print_formatted_json(json_value: &Value, prefix: &str) {
    println!("{}JSON data:", prefix);
    println!("{}{}", prefix, serde_json::to_string_pretty(json_value).unwrap());
}

fn save_json_to_file(json_data: &Value, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(filename)?;
    let json_string = serde_json::to_string_pretty(json_data)?;
    file.write_all(json_string.as_bytes())?;
    println!("JSON data saved to {}", filename);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Solphi with Light Protocol");

    let client = Rpc::new("http://localhost:8899".to_string());
    
    let account1 = Keypair::new();
    let account2 = Keypair::new();
    
    println!("Account 1 public key: {}", account1.pubkey());
    println!("Account 2 public key: {}", account2.pubkey());
    
    ensure_minimum_balance(&client, &account1.pubkey(), 1_000_000_000).await?;    

    let mut links = Vec::new();
    let mut word_counter = HashMap::new();

    loop {
        match extract_links_from_chrome() {
            Ok(urls) if !urls.is_empty() => {
                for url in urls {
                    if !links.contains(&url) {
                        links.push(url.clone());
                        analyze_link(&url, &mut word_counter);
                        println!("Analyzed new link: {}", url);

                        if links.len() >= 5 {
                            let result = if let Some((word, count)) = get_most_common_word(&word_counter) {
                                json!({
                                    "most_common_word": word,
                                    "count": count
                                })
                            } else {
                                json!({"error": "No words analyzed yet"})
                            };

                            print_formatted_json(&result, "Original ");

                            let json_string = result.to_string();
                            let compressed_result = zk_compress(&json_string, &client, &account1).await?;
                            println!("\nSolfhe Result (ZK compressed):");
                            println!("{:?}", compressed_result);

                            match transfer_compressed_hash(&client, &account1, &account2.pubkey(), &compressed_result, &result).await {
                                Ok(signature) => {
                                    println!("Successfully transferred hash");
                                    match retrieve_and_decompress_hash(&client, &signature).await {
                                        Ok(decompressed_json) => {
                                            println!("Retrieved and decompressed JSON data:");
                                            println!("{}", serde_json::to_string_pretty(&decompressed_json)?);
                                            
                                            if let Err(e) = save_json_to_file(&decompressed_json, "solfhe.json") {
                                                println!("Error saving JSON to file: {}", e);
                                            }

                                            // Python script execution remains the same
                                            match Command::new("python3")
                                                .arg("blink-matcher.py")
                                                .status() {
                                                Ok(status) => println!("Python script executed with status: {}", status),
                                                Err(e) => println!("Failed to execute Python script: {}", e),
                                            }
                                        },
                                        Err(e) => println!("Error retrieving and decompressing hash: {}", e),
                                    }
                                },
                                Err(e) => println!("Error during hash transfer: {}", e),
                            }

                            links.clear();
                            word_counter.clear();
                        }
                    }
                }
            },
            Ok(_) => println!("No new links found"),
            Err(e) => println!("Error extracting links from Chrome: {}", e),
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
use mimalloc::MiMalloc;
// The architecture of this app will be very similar to the architecture of both rshare and dropshare, deliberately,
//so that I can change and borrow the best parts
use axum_server::tls_rustls::RustlsConfig;
use chrono;
use core::f64;
use once_cell::sync::Lazy;
use std::{
    env, fs,
    io::{self, Write},
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{Arc, RwLock},
}; //standard

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::Method,
    middleware,
    routing::{get, post},
}; //axum
use dotenvy;
use rand::{Rng, distributions::Alphanumeric, thread_rng};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore; // BufReader added for streaming
use tower_http::cors::{Any, CorsLayer};
//-----------------------------------------------------------------------------------------------
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc; //I really hate it, but the app does likely need mimalloc for linux users. glibc frags out and craps itself in the HTML runtime
/*
while mimalloc is terrible for windows, bumping the memory up to 55MB, it does seem to clear memory during runtime.
Let's see for linux though.
*/
mod functions;
static THUMBNAIL_SEMAPHORE: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(4)));

///Call the app password file, called PASSWORD.env
static APP_PASSWORD: Lazy<String> = Lazy::new(|| {
    dotenvy::from_filename("PASSWORD.env").ok(); // load file
    env::var("APP_PASSWORD").expect("APP_PASSWORD not set")
});
//-----------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct AppConfig {
    pub max_upload_size: u64,
    pub upload_speed_bps: u64,
    // Add any other settings here
}

#[derive(Deserialize)]
struct DeleteRequest {
    pub path: String, // e.g., "Photos/Vacation/beach.jpg" or just "Photos/Vacation"
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    pub sub: String, // Subject (who this is - e.g., "admin")
    pub exp: usize,  // Expiration time (when this token dies)
}

#[derive(Deserialize)]
pub struct DownloadQuery {
    _preview: Option<bool>,
}

#[derive(Deserialize)]
struct ListQuery {
    pub path: Option<String>,
}

#[derive(Serialize)]
struct FileInfo {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified: u64,
}

#[derive(RustEmbed)]
#[folder = "web_ui/"]
struct WebAssets;

#[derive(Deserialize)]
struct FolderRequest {
    pub path: String, // e.g., "Photos/Vacation/Hawaii"
}

#[derive(Deserialize)]
struct MoveRequest {
    pub source_path: String,      // e.g., "Downloads/movie.mp4"
    pub destination_path: String, // e.g., "Movies/movie.mp4"
}

///this is a struct for the password.
#[derive(Deserialize)]
struct LoginForm {
    pub password: String,
}

//-------------------------------------------------------------------------------------------------------

//this generates a random 32 bit string for the secret key, saved into memory.
static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    let random_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32) // 32 characters is a highly secure length for a JWT secret
        .map(char::from)
        .collect();

    println!("🔐 Security: Generated a temporary, in-memory JWT Secret for this session.");

    random_string
});

static CONFIG: Lazy<RwLock<AppConfig>> = Lazy::new(|| {
    let config_path = "config.ini";

    let mut current_config = AppConfig {
        max_upload_size: 20024 * 1024 * 1024,
        upload_speed_bps: 0,
    };

    if !std::path::Path::new(config_path).exists() {
        println!("Config file not found. Creating {}...", config_path);
        let mut file = std::fs::File::create(config_path).expect("Failed to create config file");

        writeln!(file, "[Settings]").unwrap();
        writeln!(file, "# Set max upload size in bytes").unwrap();
        writeln!(
            file,
            "# default upload size is 1024*1024*1024 bytes || 1 GB"
        )
        .unwrap();
        writeln!(
            file,
            "# Set max upload speed in bytes per second (0 = unlimited), 1024*1024 = 1MB "
        )
        .unwrap();
        writeln!(file, "file_Size= 1024*1024*1024").unwrap();
        writeln!(file, "upload_speed= 0").unwrap();

        // 2. Wrap the return in RwLock::new()
        return RwLock::new(current_config);
    }

    let content = std::fs::read_to_string(config_path).unwrap_or_default();

    for line in content.lines() {
        if line.trim().starts_with('#') {
            continue;
        }

        if let Some(val) = line.strip_prefix("file_Size=") {
            current_config.max_upload_size = parse_math_string(val, current_config.max_upload_size);
        } else if let Some(val) = line.strip_prefix("upload_speed=") {
            current_config.upload_speed_bps =
                parse_math_string(val, current_config.upload_speed_bps);
        }
    }

    // Wrap the final return in RwLock::new()
    RwLock::new(current_config)
});

///This function parses the math strings found in the config
///
/// * `input` - the input string from the config file
/// * `default_size` - The default size made by me. it can be found in the AppConfig as a default.
/// * `parsed_anything` - The boolean that asks if the program could actually read the string from the user
/// * `total` - The u64 value returned if the function works and returns a proper value.
fn parse_math_string(input: &str, default_size: u64) -> u64 {
    let mut total: u64 = 1;
    let mut parsed_anything = false;
    // Split the string by the asterisk
    for part in input.split('*') {
        let clean_part = part.trim();
        // Skip empty parts (e.g., if someone typed "1024 * ")
        if clean_part.is_empty() {
            continue;
        }
        // Try to parse the chunk into a number
        match clean_part.parse::<u64>() {
            Ok(num) => {
                // saturating_mul prevents the server from crashing if a user
                // types a number so big it overflows Rust's u64 limit!
                total = total.saturating_mul(num);
                //println!("cleanpart true {}",total);
                //println!("{}",default_size);
                parsed_anything = true;
            }
            Err(_) => {
                // If they typed letters like "1024 * apples", give up and return default
                println!("Warning: Invalid math in config. Falling back to default.");
                return default_size;
            }
        }
    }

    if parsed_anything { total } else { default_size }
}

///Ensures certificates for HTTPS by looking for certificates, and creating them if they don't exist.
///  - This is necessary for initialization
///
/// * `cert_path` - The path of the certificates
/// * `key_path` - The path of the key
/// * `pem_serialized` - the serialied cerificate
/// * `key_serialized` - the serialied key
fn ensure_certificates() -> Result<(), Box<dyn std::error::Error>> {
    let cert_path = PathBuf::from("cert.pem");
    let key_path = PathBuf::from("key.pem");

    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    //feedback
    println!("Generating self-signed certificates...");

    // Generate a certificate for "localhost" and the local IP
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]);

    // Attempt to add the actual LAN IP to the cert SANs (Subject Alternative Names)
    if let Some(ip) = get_local_ip() {
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(ip.parse()?));
    }
    //define and write certificates
    let cert = rcgen::Certificate::from_params(params)?;

    //should these be put into a struct? will that save on memory?
    let pem_serialized = cert.serialize_pem()?;
    let key_serialized = cert.serialize_private_key_pem();

    fs::write(&cert_path, pem_serialized)?;
    fs::write(&key_path, key_serialized)?;

    println!("Certificates generated successfully!");
    Ok(())
}

///Ensures the password file exists, creating it if not
///
/// * `env_path` - the path of the PASSWORD.env file
/// * `new_password` - The new password string
/// * `content` - represents the new_password in a format readily written to a fresh PASSWORD.env file
fn ensure_password() -> Result<(), Box<dyn std::error::Error>> {
    //ensure the passwords are there.
    let env_path = PathBuf::from("PASSWORD.env");

    if env_path.exists() {
        return Ok(());
    }

    println!("!--------------------------------------------------!");
    println!("First time setup: No password found.");
    println!("Please enter a password for rShare: ");
    println!("?--------------------------------------------------?\n");
    io::stdout().flush()?; // Ensure the prompt prints immediately

    let mut new_password = String::new();
    io::stdin().read_line(&mut new_password)?;
    let new_password = new_password.trim(); // Remove the newline character (needed because of the enter button pressed.)

    //cheeky error message
    if new_password.is_empty() {
        return Err("Password cannot be empty. You don't want that.".into());
    }

    // Save the new password to file
    let content = format!("APP_PASSWORD={}", new_password);
    fs::write(&env_path, content)?;

    println!("Password saved to 'PASSWORD.env'.");
    println!("~--------------------------------------------------~\n");

    // load the env file immediately.
    dotenvy::from_filename("PASSWORD.env").ok();

    Ok(())
}

///Grabs the local IP to bind the socket
///
/// * `sock` - the IP address of the computer
/// * `Option<String>` - the string of "sock"
fn get_local_ip() -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?; //connects to the IP address of the user (this computer)
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string()) //strings the IP
}

///Returns the current time of user
///
/// * `time` - The local time of the user in string
/// Changed to only grab the first 19 Characters in order to stop the time stamp from being too accurate and annoying.
fn get_time() -> String {
    let mut time = chrono::offset::Local::now().to_string();
    time.truncate(19);
    return time;
}

#[tokio::main]
async fn main() {
    // [Optional but highly recommended]
    // Initialize async tracing here in the future:
    // tracing_subscriber::fmt::init();
    //all the old calls should work for now.

    std::fs::create_dir_all("FileStorage").expect("Failed to create FileStorage folder");

    // 2. Ensure certificates exist before starting the router.
    if let Err(e) = ensure_certificates() {
        eprintln!("Error generating certificates: {}", e);
        return;
    }
    //3. Make sure that there is a browser password before starting the router, too.

    if let Err(e) = ensure_password() {
        eprintln!("Error setting password: {}", e);
        return;
    }
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    //define the routes that the "website" allows
    let current_max = CONFIG.read().unwrap().max_upload_size;
    let api_routes = Router::new()
        .route("/files", get(functions::api_list_files))
        .route("/upload", post(functions::api_upload))
        .route("/upload_chunk", post(functions::api_upload_chunk))
        .route("/download/{*path}", get(functions::api_download))
        .route(
            "/config",
            get(functions::get_config).post(functions::update_config),
        )
        .route("/folders", post(functions::api_create_folder))
        .route("/move", post(functions::api_move))
        .route("/delete", post(functions::api_delete))
        .route_layer(middleware::from_fn(functions::api_require_auth))
        .route("/auth", post(functions::api_login))
        .layer(DefaultBodyLimit::max(current_max as usize));

    let app = Router::new()
        // Anything starting with /api goes to the API router
        .nest("/api", api_routes)
        // Anything else (like a browser asking for the website) gets served static files
        .fallback(functions::serve_embedded_assets)
        .layer(cors);
    // 1. Load the certificate and private key
    // Ensure cert.pem and key.pem are GENERATED!
    let config = RustlsConfig::from_pem_file(PathBuf::from("cert.pem"), PathBuf::from("key.pem"))
        .await
        .expect("Failed to load TLS certificates! Run the openssl command first.");

    let lan_ip = get_local_ip().unwrap_or_else(|| "unknown".into());
    let port = 8080;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("\nWelcome to SolNAS");
    println!("   SolNAS sarting up server");
    //println!("  Localhost  -> https://localhost:{}/login", port);
    println!(
        "    Website Connection   -> https://{}:{}/login [CTRL+CLK]",
        &lan_ip, port
    );
    println!("       Enter {} into client login ", &lan_ip);
    println!("\n   Current Server Settings");

    //make some pretty values for the user.
    let maxsize = CONFIG.read().unwrap().max_upload_size;
    let maxspeed = CONFIG.read().unwrap().upload_speed_bps;
    let pretty_max_size = maxsize as f64 / (1024.0 * 1024.0 * 1024.0);
    let pretty_upload_speed = maxspeed as f64 / (1024.0 * 1024.0);

    println!("   [Max File Size Set To {:.2} GB]", pretty_max_size);

    if pretty_upload_speed <= 0.0 {
        println!("   [Upload Speed is set to Infinite]");
    } else {
        println!("   [Upload Speed : {:.2}MB/s]", pretty_upload_speed);
    }
    //look cute
    println!("     Values can be changed using Client app\n");
    println!("     Shut down using ctrl+C");
    println!("===========================");
    println!("Active Processes");
    println!("===========================\n");

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();

    tokio::spawn(async move {
        // Wait for the user to press Ctrl+C
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        println!("\n[SolNAS] Gracefully shutting down SolNAS Server...");

        // Give the server time to shut down gracefully.
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(15)));
    });
    // 2. Bind using axum-server with the TLS config
    axum_server::bind_rustls(addr, config)
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// Notice we use Json<LoginForm> instead of Form<LoginForm>.
// The client will send a JSON body: {"password": "mypassword"}

// The architecture of this app will be very similar to the architecture of both rshare and dropshare, deliberately, 
//so that I can change and borrow the best parts
use core::f64;
use chrono;
use std::{
    env,
    fs,
    net::{SocketAddr, UdpSocket},
    path::{Path,PathBuf,Component},
    io::{self, Write},
    time::{Instant,SystemTime,UNIX_EPOCH},
    
};//standard
use axum_server::tls_rustls::RustlsConfig;
use once_cell::sync::Lazy;
use mime_guess;


use tokio::{
    fs::File,
    io::{AsyncWriteExt, BufReader,BufWriter},   // BufReader added for streaming  
};
use dotenvy;
use tokio_util::io::ReaderStream; 
use axum::{
    body::Body,
    extract::{DefaultBodyLimit,Multipart, Path as AxumPath,Request,Query,RawQuery},
    http::{header, HeaderMap,Uri, StatusCode,HeaderValue,Method},
    middleware::Next,
    middleware,
    response::{IntoResponse,Response},
    routing::{get, post},
    Json,
    Router,
    
};//axum
use serde_json::{Value, json};
use tower_http::{
    cors::{Any,CorsLayer}
};
use serde::{Serialize,Deserialize};
use jsonwebtoken::{
    encode, 
    decode, 
    Header, 
    Validation, 
    EncodingKey, 
    DecodingKey
};
use rand::{
    thread_rng,
    Rng,
    distributions::Alphanumeric
};

use rust_embed::RustEmbed;

//-----------------------------------------------------------------------------------------------
pub struct AppConfig {
    pub max_upload_size: u64,
    pub upload_speed_bps: u64,   // 0 means unlimited
    
}

#[derive(Deserialize)]
struct DeleteRequest {
    path: String, // e.g., "Photos/Vacation/beach.jpg" or just "Photos/Vacation"
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // Subject (who this is - e.g., "admin")
    exp: usize,  // Expiration time (when this token dies)
}

#[derive(Deserialize)]
struct ListQuery {
    path: Option<String>,
}

#[derive(Serialize)]
struct FileInfo {
    name: String,
    size: u64,
    is_dir: bool,
}

#[derive(RustEmbed)]
#[folder = "web_ui/"] 
struct WebAssets;

#[derive(Deserialize)]
struct FolderRequest {
    path: String, // e.g., "Photos/Vacation/Hawaii"
}

#[derive(Deserialize)]
struct MoveRequest {
    source_path: String,      // e.g., "Downloads/movie.mp4"
    destination_path: String, // e.g., "Movies/movie.mp4"
}

///this is a struct for the password.
#[derive(Deserialize)]
struct LoginForm { password: String }




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

//Let's create a config for users. 
static CONFIG: Lazy<AppConfig> = Lazy::new(|| {
    let config_path = "config.ini";
    
    // Set your defaults here
    let mut current_config = AppConfig {
        max_upload_size: 1024 * 1024 * 1024, // 1GB
        upload_speed_bps: 1024*1024,                 // 1 MB default
        
    };

    if !std::path::Path::new(config_path).exists() {
        println!("Config file not found. Creating {}...", config_path);
        let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
        //rewrite this so that it can use multipliers.
        //now it should be able to parse itself...
        writeln!(file, "[Settings]").unwrap();
        writeln!(file, "# Set max upload size in bytes. 1024*1024*1024 = 1GB").unwrap();
        writeln!(file, "# default is 1024*1024*1024 bytes").unwrap();
        writeln!(file, "# Set max upload/download speed in bytes per second (0 = unlimited), 1024*1024 = 1MB Default").unwrap();
        writeln!(file, "file_Size= 1024*1024*1024").unwrap();
        writeln!(file, "upload_speed= 1024*1024").unwrap();
        
        
        return current_config;
    }
    //I want users to be able to input multipliers.
    //this parses strings and returns the bit size for the program.

    // Read the file and update the struct if values are found
    let content = std::fs::read_to_string(config_path).unwrap_or_default();
    //for all the lines...
    for line in content.lines() {
        // Ignore lines that start with '#' (comments)
        if line.trim().starts_with('#') {
            //println!("trimmer works");
            continue; 
        }

        if let Some(val) = line.strip_prefix("file_Size=") {
            //println!("eval upload size");
            current_config.max_upload_size = parse_math_string(val, current_config.max_upload_size);
            
        } else if let Some(val) = line.strip_prefix("upload_speed=") {
            //println!("eval upload speed");
            current_config.upload_speed_bps = parse_math_string(val, current_config.upload_speed_bps);
            
        }
    }
    
    current_config
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

    if parsed_anything {
        total
    } else {
        default_size
    }
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
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]);
    
    // Attempt to add the actual LAN IP to the cert SANs (Subject Alternative Names)
    if let Some(ip) = get_local_ip() {
        params.subject_alt_names.push(rcgen::SanType::IpAddress(ip.parse()?));
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
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;//connects to the IP address of the user (this computer)
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())//strings the IP
}

///Returns the current time of user
/// 
/// * `time` - The local time of the user in string
/// Changed to only grab the first 19 Characters in order to stop the time stamp from being too accurate and annoying.
fn get_time() -> String{
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
   let api_routes = Router::new()
        .route("/files", get(api_list_files))
        .route("/upload", post(api_upload))
        .route("/download/{*path}", get(api_download))
        .route("/folders", post(api_create_folder))
        .route("/move", post(api_move))
        .route("/delete", post(api_delete))

        .route_layer(middleware::from_fn(api_require_auth)) // The protected routes are protected by authentication

        .route("/auth", post(api_login))

        .layer(DefaultBodyLimit::max(CONFIG.max_upload_size as usize));

    

    let app = Router::new()
        // Anything starting with /api goes to the API router
        .nest("/api", api_routes) 
        // Anything else (like a browser asking for the website) gets served static files
        .fallback(serve_embedded_assets)
        .layer(cors);
        // 1. Load the certificate and private key
        // Ensure cert.pem and key.pem are GENERATED!
    let config = RustlsConfig::from_pem_file(
        PathBuf::from("cert.pem"), 
        PathBuf::from("key.pem")
    
    )
    
    .await
    .expect("Failed to load TLS certificates! Run the openssl command first.");
    
    let lan_ip = get_local_ip().unwrap_or_else(|| "unknown".into());
    let port = 8080;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    println!(" rShare running (HTTPS):");
    println!("  Local  -> https://localhost:{}/login", port);
    println!("  LAN    -> https://{}:{}/login", lan_ip, port);
    println!("  !Note: Accept the browser warning to proceed, connection is secure!");

    //make some pretty values for the user.

    let pretty_max_size = CONFIG.max_upload_size as f64 / (1024.0*1024.0*1024.0);
    let pretty_upload_speed =CONFIG.upload_speed_bps as f64 / (1024.0*1024.0);
    

    println!("\n   Upload Speed : {:.2}MB/s",pretty_upload_speed);
    println!("-~ Max File Size Set To {:.2} GB | This Can Be Changed In Config.ini ~-\n",pretty_max_size);

    //give a special message if upload or download are maximum.
    if pretty_upload_speed <=0.0{println!("!~`Upload Speed is set to Maximum`~!");
    }
    println!("-------------------------------------------------------------------------------------");

    //new stuff: 
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();

    tokio::spawn(async move {
        // Wait for the user to press Ctrl+C
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        println!("\n[System] Gracefully shutting down SolNAS tool...");
    
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


///Call the app password file, called PASSWORD.env
static APP_PASSWORD: Lazy<String> = Lazy::new(|| {
    dotenvy::from_filename("PASSWORD.env").ok(); // load file
    env::var("APP_PASSWORD").expect("APP_PASSWORD not set")
});




// Notice we use Json<LoginForm> instead of Form<LoginForm>. 
// The client will send a JSON body: {"password": "mypassword"}
async fn api_login(Json(data): Json<LoginForm>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if data.password == *APP_PASSWORD {
        println!("Successful API login generated on {}", get_time());

        // Set expiration for 24 hours from now
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize + (24 * 3600);

        let claims = Claims {
            sub: "admin".to_owned(),
            exp: expiration,
        };

        // Create the actual token string
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
        ).unwrap();

        // Return the token to the client app
        Ok(Json(json!({
            "status": "success",
            "token": token
        })))
    } else {
        println!("Failed API login attempt with password '{}'", data.password);
        
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "message": "Invalid password"}))
        ))
    }
}

///accept or reject users based on login or cookies.
/// 
async fn api_require_auth(
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<Value>)> {
    
    // 1. Extract the "Authorization" header
    let auth_header = req.headers().get(header::AUTHORIZATION);
    
    let auth_header = match auth_header {
        Some(header) => header.to_str().unwrap_or(""),
        None => {
            println!("System denied API entry: Missing Auth Header on {}", get_time());
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"status": "error", "message": "Missing Authorization header"}))
            ));
        }
    };

    // 2. Ensure it starts with "Bearer " and grab the token part
    if !auth_header.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "message": "Invalid Authorization format. Use 'Bearer <token>'"}))
        ));
    }
    
    let token = &auth_header[7..]; // Strip off "Bearer "

    // 3. Decode and verify the token cryptographically
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    );

    match token_data {
        Ok(_) => {
            // Token is valid and not expired! Let the request through to upload/download/list
            Ok(next.run(req).await)
        }
        Err(_) => {
            println!("System denied API entry: Invalid or Expired Token on {}", get_time());
            Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"status": "error", "message": "Invalid or expired token"}))
            ))
        }
    }
}

// Safely combines the base storage directory with a user-provided path.
/// It strips out any attempts to navigate UP the directory tree (like "..").
fn resolve_safe_path(user_path: &str) -> Result<PathBuf, String> {
    let base_dir = PathBuf::from("FileStorage");
    let mut final_path = base_dir.clone();

    // Iterate through every piece of the path the user sent
    for component in Path::new(user_path).components() {
        match component {
            // If it's a normal folder/file name, add it to our path
            Component::Normal(name) => final_path.push(name),
            // If they try to go up a directory (..), or use root (/), reject it!
            _ => return Err("Invalid or malicious path detected.".to_string()),
        }
    }

    Ok(final_path)
}



///handles FileStorage from server to device
/// 
/// * `file` - new user file
/// * `path` - the path to the new upload. located in the FileStorage folder.
/// * `chunk_size` - the speed from config file
/// * `headers` - Give the ability to grab the size of the file before writing.
/// 
async fn api_upload(headers: HeaderMap, mut multipart: Multipart) -> impl IntoResponse {

    let total_request_size: u64 = headers

        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|val| val.to_str().ok())
        .and_then(|val| val.parse().ok())
        .unwrap_or(0);

        if total_request_size > CONFIG.max_upload_size {
                    println!("file too large.");
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "status": "error", 
                "message": "File exceeds maximum allowed upload size."
            })),
        ).into_response();
        }

                let mut global_written : u64 = 0; //this is to keep everything normal
                println!("\nBeginning Upload Now...\n");

                //track all the names of the successful files
                let mut uploaded_files=Vec::new();

    while let Some(mut field) = multipart.next_field().await.unwrap() {
        if let Some(filename) = field.file_name().map(|s| s.to_string()) {

            //add the new stuff in
            //safe path variable
            let full_path = match resolve_safe_path(&filename) {
                Ok(path) => path,
                Err(e) => {
                    println!("WARNING: Malicious or invalid path blocked: {}", filename);
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"status": "error", "message": e}))
                    ).into_response();
                }
            };
            //parent directory creator
            if let Some(parent_dir) = full_path.parent() {
                if let Err(e) = tokio::fs::create_dir_all(parent_dir).await {
                    println!("ERROR: Failed to create directories for '{}': {}", filename, e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"status": "error", "message": "Server error creating parent folders."}))
                    ).into_response();
                }
            }
            //finally, create the file with the full path and set it in.
            let file = match tokio::fs::File::create(&full_path).await {
                Ok(f) => f,
                Err(e) => {
                    println!("ERROR: Failed to create file '{}': {}", filename, e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"status": "error", "message": "Server error creating file."}))
                    ).into_response();
                }
            };

           
            let chunk_size = 128*1024; //128KB Keep it static to use less data
            let mut buf_writer = BufWriter::with_capacity(chunk_size, file);
            let mut last_print=Instant::now();

           loop {
            // We match the Result and the Option at the same time
            let chunk = match field.chunk().await {
            Ok(Some(data)) => data, // Success! 'chunk' is now cleanly of type `bytes::Bytes`
            Ok(None) => break,      // End of the file stream. Break out of the loop.
                Err(e) => {             // Network error handling
                    println!("ERROR: Network chunk failed: {}", e);
                    return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": "error", "message": "Upload interrupted by network error."}))
                            ).into_response();
                }
            };
                
                global_written += chunk.len() as u64;
                //added a progress tracker here.
            use std::io::Write; // Required for the flush() command below

                let write_size = global_written as f64/(1024.0*1024.0);
                let percentage = if total_request_size > 0 {
                    (global_written as f64 / total_request_size as f64) * 100.0
                } else {
                    0.0
                };

                // -- APPLYING THE UPLOAD SPEED LIMIT --
                if CONFIG.upload_speed_bps > 0 {
                
                let seconds_for_chunk = chunk.len() as f64 / CONFIG.upload_speed_bps as f64;
                let sleep_duration = std::time::Duration::from_secs_f64(seconds_for_chunk);
        
                // Force the server to pause, effectively throttling the upload
                tokio::time::sleep(sleep_duration).await;
            }
                // Write the network chunk into RAM buffer. 
                buf_writer.write_all(&chunk).await.unwrap();


                if last_print.elapsed().as_millis()>200{
                    print!("\rUploading '{}' || {:.2} Megabytes Written  {:.2}%",filename,write_size,percentage);
                    
                    std::io::stdout().flush().unwrap();
                    last_print=Instant::now();
                }
                
            }
            
            //flush the writer if it's done.
            buf_writer.flush().await.unwrap();
            
            //added some pretty diagnostic stuff.
            println!("\n   ⬆️ Uploaded '{}' to the dashboard on {}",filename,get_time());
            uploaded_files.push(filename);
        }
    }
    (
        StatusCode::OK,
        Json(json!({
            "status": "success", 
            "message": "Upload complete", 
            "files": uploaded_files
        }))
    ).into_response()
}



async fn api_list_files(Query(query): Query<ListQuery>) -> Response {
    
    // 1. Get the requested path, or default to the root if they didn't provide one
    let target_subpath = query.path.unwrap_or_else(|| "".to_string());

    // 2. Sanitize it using the helper we built earlier
    let safe_path = match resolve_safe_path(&target_subpath) {
        Ok(path) => path,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": e}))
            ).into_response();
        }
    };

    // 3. Ensure the requested folder actually exists
    if !safe_path.exists() || !safe_path.is_dir() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": "error", "message": "Directory not found."}))
        ).into_response();
    }

    // 4. Read the target directory (not just the root FileStorage)
    let mut entries: tokio::fs::ReadDir = match tokio::fs::read_dir(&safe_path).await {
        Ok(dir) => dir,
        Err(e) => {
            println!("ERROR: Failed to read directory '{:?}': {}", safe_path, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "Failed to read storage directory."}))
            ).into_response(); 
        }
    };

    let mut files = Vec::new();

    // 5. Asynchronously iterate over the directory entries
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Ok(metadata) = entry.metadata().await {
            if let Some(name) = entry.file_name().to_str() {
                
                let is_directory = metadata.is_dir();
                
                // Folders don't have a reliable "size" without deep-scanning them, 
                // so we just report 0 for folders to save server processing power.
                let size = if is_directory { 0 } else { metadata.len() };

                files.push(FileInfo {
                    name: name.to_string(),
                    size,
                    is_dir: is_directory,
                });
            }
        }
    }

    // Return the structured JSON array
    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            // We can return the current path so the UI knows where it is!
            "current_path": target_subpath, 
            "files": files
        }))
    ).into_response()
}

///Handles downloads from the program into the browser downloader.
/// 
/// * `name` - the name of the file as defined by the names section.
/// * `response` - Hopefully resolves successfully.
async fn api_download(
    AxumPath(path): AxumPath<String>,
    RawQuery(query): RawQuery
) -> impl IntoResponse {

    // 1. Sanitize the path (Allows folders, but blocks malicious "../" attacks)
    let full_path = match resolve_safe_path(&path) {
        Ok(p) => p,
        Err(e) => {
            println!("WARNING: Malicious path traversal attempt blocked: {}", path);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": e}))
            ).into_response();
        }
    };


    //the file must exist.
    if !full_path.exists() {
        println!("ERROR! Path does not exist!\n");
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": "error", "message": "File not found."}))
        ).into_response();
    }

    // 3. Ensure it's actually a file, not a directory!
    if full_path.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "Cannot download a directory as a file."}))
        ).into_response();
    }

    //the file must be accessible.
    let file = match File::open(&full_path).await {
        Ok(f) => f,
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => {
                println!("Download failed: File '{}' not found.", path);
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"status": "error", "message": "File not found."}))
                ).into_response();
            }
            _ => {
                println!("Download failed: File '{}' inaccessible. Error: {}", path, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": "error", "message": "Server error opening file."}))
                ).into_response();
            }
        },
    };

    let file_size = match file.metadata().await {
        Ok(meta) => meta.len(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "Server error reading file metadata."}))
            ).into_response();
        }
    };
   
    //splitting the file up.
    let chunk_size = 128*1024; //now controlled properly
    let buf_reader = BufReader::with_capacity(chunk_size, file);

    //have the stream adapt to the values it is given.

    let stream = ReaderStream::new(buf_reader);
    let body = Body::from_stream(stream);

    // Guess MIME type (or fallback to binary)
    let mime = mime_guess::from_path(&path).first_or_octet_stream();
    let mut headers = HeaderMap::new();

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime.as_ref()).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );

    // 4. Extract JUST the filename for the browser's save prompt
    let actual_filename = full_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("downloaded_file");

    let disposition = format!("attachment; filename=\"{}\"", actual_filename);
    if let Ok(header_value) = HeaderValue::from_str(&disposition) {
        headers.insert(header::CONTENT_DISPOSITION, header_value);
    }
    //give the terminal some feedback for downloads
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(file_size)); //give a file size to the browser so that it can use its own time evaluation.
    let is_preview = query.as_deref().unwrap_or("").contains("preview=true");
    
    if !is_preview{
        println!("⬇️ User downloaded '{}' from the dashboard on {}",path,get_time());
    }
    (headers, body).into_response()
    
}

//define API tools here for use with the client app

async fn api_create_folder(Json(payload): Json<FolderRequest>) -> impl IntoResponse {
    // 1. Sanitize the requested path
    let target_path = match resolve_safe_path(&payload.path) {
        Ok(path) => path,
        Err(e) => return (
            StatusCode::BAD_REQUEST, 
            Json(json!({"status": "error", "message": e}))
        ).into_response(),
    };

    // 2. Use Tokio to create the directory (and any parent directories if needed)
    match tokio::fs::create_dir_all(&target_path).await {
        Ok(_) => {
            println!("📁 Created new folder: {}", payload.path);
            (
                StatusCode::OK,
                Json(json!({"status": "success", "message": "Folder created"}))
            ).into_response()
        }
        Err(e) => {
            println!("ERROR: Failed to create folder '{}': {}", payload.path, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "Could not create folder"}))
            ).into_response()
        }
    }
}

async fn api_move(Json(payload): Json<MoveRequest>) -> impl IntoResponse {
    // 1. Sanitize BOTH paths
    let safe_source = match resolve_safe_path(&payload.source_path) {
        Ok(path) => path,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"status": "error", "message": e}))).into_response(),
    };
    
    let safe_dest = match resolve_safe_path(&payload.destination_path) {
        Ok(path) => path,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"status": "error", "message": e}))).into_response(),
    };

    // 2. Ensure the source actually exists before moving
    if !safe_source.exists() {
        return (
            StatusCode::NOT_FOUND, 
            Json(json!({"status": "error", "message": "Source file or folder not found"}))
        ).into_response();
    }

    // 3. Move/Rename the file asynchronously
    match tokio::fs::rename(&safe_source, &safe_dest).await {
        Ok(_) => {
            println!("🔄 Moved '{}' -> '{}'", payload.source_path, payload.destination_path);
            (
                StatusCode::OK,
                Json(json!({"status": "success", "message": "Moved successfully"}))
            ).into_response()
        }
        Err(e) => {
            println!("ERROR: Failed to move file: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "Failed to move file. Ensure target folder exists."}))
            ).into_response()
        }
    }
}

async fn api_delete(Json(payload): Json<DeleteRequest>) -> impl IntoResponse {
    // 1. Sanitize the path
    let safe_path = match resolve_safe_path(&payload.path) {
        Ok(path) => path,
        Err(e) => return (
            StatusCode::BAD_REQUEST, 
            Json(json!({"status": "error", "message": e}))
        ).into_response(),
    };

    // 2. Ensure it exists
    if !safe_path.exists() {
        return (
            StatusCode::NOT_FOUND, 
            Json(json!({"status": "error", "message": "File or folder not found"}))
        ).into_response();
    }

    // 3. Delete it (Tokio requires different functions for files vs folders)
    if safe_path.is_dir() {
        // remove_dir_all acts like `rm -rf`, safely wiping the folder and everything inside it
        match tokio::fs::remove_dir_all(&safe_path).await {
            Ok(_) => {
                println!("🗑️ Deleted folder: {}", payload.path);
                (StatusCode::OK, Json(json!({"status": "success", "message": "Folder deleted."}))).into_response()
            }
            Err(e) => {
                println!("ERROR: Failed to delete folder '{}': {}", payload.path, e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"status": "error", "message": "Failed to delete folder."}))).into_response()
            }
        }
    } else {
        match tokio::fs::remove_file(&safe_path).await {
            Ok(_) => {
                println!("🗑️ Deleted file: {}", payload.path);
                (StatusCode::OK, Json(json!({"status": "success", "message": "File deleted."}))).into_response()
            }
            Err(e) => {
                println!("ERROR: Failed to delete file '{}': {}", payload.path, e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"status": "error", "message": "Failed to delete file."}))).into_response()
            }
        }
    }
}

async fn serve_embedded_assets(uri: Uri) -> impl IntoResponse {
    // 1. Clean up the path requested by the browser
    let mut path = uri.path().trim_start_matches('/').to_string();

    // 2. If they hit the root "/", default to index.html
    if path.is_empty() {
        path = "index.html".to_string();
    }

    // DEBUG: Print out exactly what the binary is looking for in its internal memory
    println!("Web UI searching for embedded asset: '{}'", path);

    // 3. Attempt to find the specific file requested
    match WebAssets::get(path.as_str()) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
        }
        None => {
            // 4. SPA FALLBACK: If the specific file wasn't found, try serving index.html 
            // instead of a 404. This allows frontend routers to work!
            match WebAssets::get("index.html") {
                Some(index_content) => {
                    let mime = mime_guess::from_path("index.html").first_or_octet_stream();
                    ([(header::CONTENT_TYPE, mime.as_ref())], index_content.data).into_response()
                }
                None => {
                    // This only hits if "index.html" is missing entirely from the web_ui folder
                    (StatusCode::NOT_FOUND, "Critical Error: index.html not found in embedded assets!").into_response()
                }
            }
        }
    }
}
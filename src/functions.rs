use axum::{
    Json,
    body::Body,
    extract::{Multipart, Path as AxumPath, Query, RawQuery, Request},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    middleware::Next,
    response::{IntoResponse, Response},
}; //axum
use core::f64;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use mime_guess;
use serde_json::{Value, json};
use std::{
    io::{Cursor, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncSeekExt, AsyncWriteExt, BufWriter},
};
use tokio_util::bytes;
//pulled all of the dependencies and plopped them here.
// Pull shared structs, statics, and helpers from main.rs
use crate::{
    APP_PASSWORD, AppConfig, CONFIG, Claims, DeleteRequest, FileInfo, FolderRequest, JWT_SECRET,
    ListQuery, LoginForm, MoveRequest, THUMBNAIL_SEMAPHORE, WebAssets, get_time,
};

pub async fn api_login(
    Json(data): Json<LoginForm>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if data.password == *APP_PASSWORD {
        println!("Successful API login generated on {}", get_time());

        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
            + (4 * 60 * 60);

        let claims = Claims {
            sub: "admin".to_owned(),
            exp: expiration,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
        )
        .unwrap();

        Ok(Json(json!({
            "status": "success",
            "token": token
        })))
    } else {
        println!("Failed API login attempt with password '{}'", data.password);

        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "message": "Invalid password"})),
        ))
    }
}

///### Demands to see authentication cookies
///
/// Should be pretty simple
/// The JWT key is dynamically loaded to memory, so the password can't likely be found in the RAM.
pub async fn api_require_auth(
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<Value>)> {
    // Extract the "Authorization" header
    let auth_header = req.headers().get(header::AUTHORIZATION);

    let auth_header = match auth_header {
        Some(header) => header.to_str().unwrap_or(""),
        None => {
            println!(
                "System denied API entry: Missing Auth Header on {}",
                get_time()
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"status": "error", "message": "Missing Authorization header"})),
            ));
        }
    };

    // 2. Ensure it starts with "Bearer " and grab the token part
    if !auth_header.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                json!({"status": "error", "message": "Invalid Authorization format. Use 'Bearer <token>'"}),
            ),
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
            println!(
                "System denied API entry: Invalid or Expired Token on {}",
                get_time()
            );
            Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"status": "error", "message": "Invalid or expired token"})),
            ))
        }
    }
}

///handles FileStorage from server to device
///
/// * `file` - new user file
/// * `path` - the path to the new upload. located in the FileStorage folder.
/// * `chunk_size` - the speed from config file
/// * `headers` - Give the ability to grab the size of the file before writing.
///
pub async fn api_upload(headers: HeaderMap, mut multipart: Multipart) -> impl IntoResponse {
    let total_request_size: u64 = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|val| val.to_str().ok())
        .and_then(|val| val.parse().ok())
        .unwrap_or(0);
    let current_max = CONFIG.read().unwrap().max_upload_size;
    if total_request_size > current_max {
        println!("file too large.");
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "status": "error",
                "message": "File exceeds maximum allowed upload size."
            })),
        )
            .into_response();
    }

    let mut global_written: u64 = 0; //this is to keep everything normal
    println!("   Began upload at {}", get_time());

    //track all the names of the successful files
    let mut uploaded_files = Vec::new();

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
                        Json(json!({"status": "error", "message": e})),
                    )
                        .into_response();
                }
            };
            //parent directory creator
            if let Some(parent_dir) = full_path.parent() {
                if let Err(e) = tokio::fs::create_dir_all(parent_dir).await {
                    println!(
                        "ERROR: Failed to create directories for '{}': {}",
                        filename, e
                    );
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
                        Json(json!({"status": "error", "message": "Server error creating file."})),
                    )
                        .into_response();
                }
            };

            let chunk_size = 128 * 1024; //128KB Keep it static to use less data
            let mut buf_writer = BufWriter::with_capacity(chunk_size, file);
            let mut last_print = Instant::now();

            loop {
                // We match the Result and the Option at the same time
                let chunk = match field.chunk().await {
                    Ok(Some(data)) => data, // Success! 'chunk' is now cleanly of type `bytes::Bytes`
                    Ok(None) => break,      // End of the file stream. Break out of the loop.
                    Err(e) => {
                        // Network error handling
                        println!("ERROR: Network chunk failed: {}", e);

                        drop(buf_writer); // drop the file lock

                        let _ = tokio::fs::remove_file(&full_path).await;
                        println!("🧹 Cleaned up corrupted partial file: {}", filename); //get rid of the corrupted file.

                        return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": "error", "message": "Upload interrupted by network error."}))
                            ).into_response();
                    }
                };

                global_written += chunk.len() as u64;
                //added a progress tracker here.
                use std::io::Write; // Required for the flush() command below

                let write_size = global_written as f64 / (1024.0 * 1024.0);
                let percentage = if total_request_size > 0 {
                    (global_written as f64 / total_request_size as f64) * 100.0
                } else {
                    0.0
                };

                // -- APPLYING THE UPLOAD SPEED LIMIT --
                let maxspeed = CONFIG.read().unwrap().upload_speed_bps;
                let current_speed = maxspeed;
                if current_speed > 0 {
                    let seconds_for_chunk = chunk.len() as f64 / current_speed as f64;
                    let sleep_duration = std::time::Duration::from_secs_f64(seconds_for_chunk);

                    // Force the server to pause, effectively throttling the upload
                    tokio::time::sleep(sleep_duration).await;
                }
                // Write the network chunk into RAM buffer.
                buf_writer.write_all(&chunk).await.unwrap();

                if last_print.elapsed().as_millis() > 200 {
                    print!(
                        "\rUploading '{}' || {:.2} Megabytes Written  {:.2}%",
                        filename, write_size, percentage
                    );

                    std::io::stdout().flush().unwrap();
                    last_print = Instant::now();
                }
            }

            //flush the writer if it's done.
            buf_writer.flush().await.unwrap();

            //added some pretty diagnostic stuff.
            println!(
                "\n   ⬆️ Uploaded '{}' to the dashboard on {}",
                filename,
                get_time()
            );
            uploaded_files.push(filename);
        }
    }
    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "message": "Upload complete",
            "files": uploaded_files
        })),
    )
        .into_response()
}

pub async fn api_list_files(Query(query): Query<ListQuery>) -> Response {
    //Get the requested path, or default to the root if they didn't provide one
    let target_subpath = query.path.unwrap_or_else(|| "".to_string());

    //Sanitize it using the helper built earlier
    let safe_path = match resolve_safe_path(&target_subpath) {
        Ok(path) => path,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": e})),
            )
                .into_response();
        }
    };

    // 3. Ensure the requested folder actually exists
    if !safe_path.exists() || !safe_path.is_dir() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": "error", "message": "Directory not found."})),
        )
            .into_response();
    }

    // 4. Read the target directory (not just the root FileStorage)
    let mut entries: tokio::fs::ReadDir = match tokio::fs::read_dir(&safe_path).await {
        Ok(dir) => dir,
        Err(e) => {
            println!("ERROR: Failed to read directory '{:?}': {}", safe_path, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "Failed to read storage directory."})),
            )
                .into_response();
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

                // Extract the last-modified timestamp in Unix seconds
                let modified = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                files.push(FileInfo {
                    name: name.to_string(),
                    size,
                    is_dir: is_directory,
                    modified,
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
        })),
    )
        .into_response()
}

///Handles downloads from the program into the browser downloader.
///
/// * `name` - the name of the file as defined by the names section.
/// * `response` - Hopefully resolves successfully.
pub async fn api_download(
    AxumPath(path): AxumPath<String>,
    RawQuery(query): RawQuery,
) -> impl IntoResponse {
    // 1. Sanitize the path (Allows folders, but blocks malicious "../" attacks)
    let full_path = match resolve_safe_path(&path) {
        Ok(p) => p,
        Err(e) => {
            println!(
                "WARNING: Malicious path traversal attempt blocked: {}",
                path
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": e})),
            )
                .into_response();
        }
    };

    //the file must exist.
    if !full_path.exists() {
        println!("ERROR! Path does not exist!\n");
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": "error", "message": "File not found."})),
        )
            .into_response();
    }

    // Ensure it's actually a file, not a directory
    if full_path.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "Cannot download a directory as a file."})),
        )
            .into_response();
    }

    //  Thumbnailing Update
    let is_preview = query.as_deref().unwrap_or("").contains("preview=true");
    let extension = full_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let is_image = matches!(extension.as_str(), "png" | "jpg" | "jpeg" | "gif" | "webp");
    let is_video = matches!(extension.as_str(), "mp4" | "mov" | "mkv" | "avi" | "webm"); //now includes videos.
    if is_preview && is_image {
        // Wait in line until one of the 4 permits is free
        let _permit = THUMBNAIL_SEMAPHORE.acquire().await.unwrap();

        // Read the raw file bytes from the NAS disk
        if let Ok(bytes) = tokio::fs::read(&full_path).await {
            // Offload the heavy decoding and resizing to a blocking thread so the server doesn't freeze
            let thumbnail_result = tokio::task::spawn_blocking(move || {
                let img = image::load_from_memory(&bytes).map_err(|_| "Failed to load image")?;

                // Shrink it down dramatically
                let thumb = img.thumbnail(256, 256);

                // Encode the new thumbnail back to JPEG bytes in memory
                let mut buffer = Cursor::new(Vec::new());
                thumb
                    .write_to(&mut buffer, image::ImageOutputFormat::Jpeg(80))
                    .map_err(|_| "Failed to encode thumbnail")?;

                Ok::<Vec<u8>, &'static str>(buffer.into_inner())
            })
            .await
            .unwrap_or(Err("Thread panic"));

            if let Ok(thumb_bytes) = thumbnail_result {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
                return (headers, Body::from(thumb_bytes)).into_response();
            }
        }
        // `_permit` is automatically dropped here (or on `return`), freeing the slot
    }
    if is_preview && is_video {
        // Wait for a semaphore permit so we don't spawn 50 FFmpeg processes at once
        let _permit = THUMBNAIL_SEMAPHORE.acquire().await.unwrap();

        let output = tokio::process::Command::new("ffmpeg")
            .args([
                "-ss", "00:00:01", // Fast-seek to 1 second in (avoids black intro frames)
                "-i",
            ])
            .arg(&full_path) // Pass PathBuf directly (handles spaces/special chars safely)
            .args([
                "-frames:v",
                "1", // Grab exactly 1 frame
                "-vf",
                "scale=256:-1", // Resize to 256px wide, preserving aspect ratio
                "-q:v",
                "5", // Lightweight JPEG quality (2 = highest, 31 = lowest)
                "-f",
                "image2pipe", // Output raw image stream...
                "-vcodec",
                "mjpeg",  // ...encoded as JPEG...
                "pipe:1", // ...directly to stdout (no temp files on disk)
            ])
            .output()
            .await;

        if let Ok(out) = output {
            if out.status.success() && !out.stdout.is_empty() {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
                return (headers, Body::from(out.stdout)).into_response();
            }
        }
    }

    //the file must be accessible.
    let file = match File::open(&full_path).await {
        Ok(f) => f,
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => {
                println!("Download failed: File '{}' not found.", path);
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"status": "error", "message": "File not found."})),
                )
                    .into_response();
            }
            _ => {
                println!(
                    "Download failed: File '{}' inaccessible. Error: {}",
                    path, e
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": "error", "message": "Server error opening file."})),
                )
                    .into_response();
            }
        },
    };

    let file_size = match file.metadata().await {
        Ok(meta) => meta.len(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "Server error reading file metadata."})),
            )
                .into_response();
        }
    };

    //splitting the file up.
    let chunk_size = 8 * 1024 * 1024; //now controlled properly //EDIT 2: Increase chunk size heavily! => Huge time save. 8 * 1024 *1024 vs 128 * 1024 =>
    //lower chunk size + no change = 52 seconds ||Changes + bigger chunk size = 32 seconds => both done on 7GB file,
    // Therefore, this change should save 20 seconds every 7 GB, or save about 3 seconds every Gigabyte.
    //let buf_reader = BufReader::with_capacity(chunk_size, file); //test  me!

    //have the stream adapt to the values it is given.
    let stream = tokio_util::io::ReaderStream::with_capacity(file, chunk_size); //test me!
    //let stream = ReaderStream::new(buf_reader); //test me!
    let body = Body::from_stream(stream); //stay the same

    // Guess MIME type (or fallback to binary)
    let mime = mime_guess::from_path(&path).first_or_octet_stream();
    let mut headers = HeaderMap::new();

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime.as_ref())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
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

    if !is_preview {
        println!(
            "⬇️ User downloaded '{}' from the dashboard on {}",
            path,
            get_time()
        );
    }
    (headers, body).into_response()
}

///#### Creates folders (CLIENT ONLY)
pub async fn api_create_folder(Json(payload): Json<FolderRequest>) -> impl IntoResponse {
    let target_path = match resolve_safe_path(&payload.path) {
        Ok(path) => path,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": e})),
            )
                .into_response();
        }
    };

    // 2. Use Tokio to create the directory (and any parent directories if needed)
    match tokio::fs::create_dir_all(&target_path).await {
        Ok(_) => {
            println!("📁 Created new folder: {}", payload.path);
            (
                StatusCode::OK,
                Json(json!({"status": "success", "message": "Folder created"})),
            )
                .into_response()
        }
        Err(e) => {
            println!("ERROR: Failed to create folder '{}': {}", payload.path, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "Could not create folder"})),
            )
                .into_response()
        }
    }
}

pub async fn api_move(Json(payload): Json<MoveRequest>) -> impl IntoResponse {
    // 1. Sanitize BOTH paths
    let safe_source = match resolve_safe_path(&payload.source_path) {
        Ok(path) => path,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": e})),
            )
                .into_response();
        }
    };

    let safe_dest = match resolve_safe_path(&payload.destination_path) {
        Ok(path) => path,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": e})),
            )
                .into_response();
        }
    };

    // 2. Ensure the source actually exists before moving
    if !safe_source.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": "error", "message": "Source file or folder not found"})),
        )
            .into_response();
    }

    // 3. Move/Rename the file asynchronously
    match tokio::fs::rename(&safe_source, &safe_dest).await {
        Ok(_) => {
            println!(
                "🔄 Moved '{}' -> '{}'",
                payload.source_path, payload.destination_path
            );
            (
                StatusCode::OK,
                Json(json!({"status": "success", "message": "Moved successfully"})),
            )
                .into_response()
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

pub async fn api_delete(Json(payload): Json<DeleteRequest>) -> impl IntoResponse {
    // 1. Sanitize the path
    let safe_path = match resolve_safe_path(&payload.path) {
        Ok(path) => path,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": e})),
            )
                .into_response();
        }
    };

    // 2. Ensure it exists
    if !safe_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": "error", "message": "File or folder not found"})),
        )
            .into_response();
    }

    // 3. Delete it (Tokio requires different functions for files vs folders)
    if safe_path.is_dir() {
        // remove_dir_all acts like `rm -rf`, safely wiping the folder and everything inside it
        match tokio::fs::remove_dir_all(&safe_path).await {
            Ok(_) => {
                println!("🗑️ Deleted folder: {}", payload.path);
                (
                    StatusCode::OK,
                    Json(json!({"status": "success", "message": "Folder deleted."})),
                )
                    .into_response()
            }
            Err(e) => {
                println!("ERROR: Failed to delete folder '{}': {}", payload.path, e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": "error", "message": "Failed to delete folder."})),
                )
                    .into_response()
            }
        }
    } else {
        match tokio::fs::remove_file(&safe_path).await {
            Ok(_) => {
                println!("🗑️ Deleted file: {}", payload.path);
                (
                    StatusCode::OK,
                    Json(json!({"status": "success", "message": "File deleted."})),
                )
                    .into_response()
            }
            Err(e) => {
                println!("ERROR: Failed to delete file '{}': {}", payload.path, e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": "error", "message": "Failed to delete file."})),
                )
                    .into_response()
            }
        }
    }
}
pub async fn serve_embedded_assets(uri: Uri) -> impl IntoResponse {
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
                    (
                        StatusCode::NOT_FOUND,
                        "Critical Error: index.html not found in embedded assets!",
                    )
                        .into_response()
                }
            }
        }
    }
}
/// ## API Upload Chunk
///
/// A brand new function that (hopefully) greatly improves the speed of the transfer
/// Maybe there will be an upgrade to this.
///
pub async fn api_upload_chunk(mut multipart: Multipart) -> impl IntoResponse {
    let mut target_filename = String::new();
    let mut chunk_index: u64 = 0;
    let mut total_chunks: u64 = 0;
    let mut offset: u64 = 0; // tracks the new offset.
    let mut chunk_data: Option<bytes::Bytes> = None;

    // 1. Extract the metadata and the file bytes from the multipart form
    while let Some(field) = multipart.next_field().await.unwrap() {
        match field.name() {
            Some("filename") => target_filename = field.text().await.unwrap_or_default(),
            Some("chunk_index") => {
                chunk_index = field.text().await.unwrap_or_default().parse().unwrap_or(0)
            }
            Some("total_chunks") => {
                total_chunks = field.text().await.unwrap_or_default().parse().unwrap_or(1)
            }
            Some("offset") => offset = field.text().await.unwrap_or_default().parse().unwrap_or(0), // NEW: Parse offset
            Some("file") => chunk_data = Some(field.bytes().await.unwrap()),
            _ => {}
        }
    }

    if chunk_data.is_none() || target_filename.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "Missing file data or filename."})),
        )
            .into_response();
    }

    // 2. Sanitize the path perfectly
    let full_path = match resolve_safe_path(&target_filename) {
        Ok(path) => path,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": e})),
            )
                .into_response();
        }
    };

    // Create parent directories if they don't exist
    if let Some(parent_dir) = full_path.parent() {
        let _ = tokio::fs::create_dir_all(parent_dir).await;
    }

    let data = chunk_data.unwrap();

    // 3. The Magic: Overwrite if it's the first chunk, Append if it's the rest!
    let mut file = match OpenOptions::new()
        .create(true)
        .write(true)
        .open(&full_path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": e.to_string()})),
            )
                .into_response();
        }
    }; //first

    //This is second. Finds the correct spot to put the chunk.
    if let Err(e) = file.seek(SeekFrom::Start(offset)).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error", "message": e.to_string()})),
        )
            .into_response();
    }
    //  Write the chunk to the hard drive, this is third
    if let Err(e) = file.write_all(&data).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error", "message": e.to_string()})),
        )
            .into_response();
    }

    // If this was the final chunk, log the success
    if chunk_index == total_chunks - 1 {
        println!(
            "✅ Reassembled and saved '{}' successfully!",
            target_filename
        );
    }

    (StatusCode::OK, Json(json!({"status": "success"}))).into_response()
}

//More new stuff
pub async fn update_config(Json(new_config): Json<AppConfig>) -> impl IntoResponse {
    // 1. Update the live memory immediately
    {
        let mut config_lock = CONFIG.write().unwrap();
        *config_lock = new_config.clone();
    }

    // 2. Overwrite the INI file with the new values so they persist on reboot
    let config_path = "config.ini";
    if let Ok(mut file) = std::fs::File::create(config_path) {
        writeln!(file, "[Settings]").unwrap();
        writeln!(file, "# Set max upload size in bytes").unwrap();
        writeln!(file, "# Please Use The Client App To Update These Values").unwrap();
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

        // Inject the newly updated numbers!
        writeln!(file, "file_Size= {}", new_config.max_upload_size).unwrap();
        writeln!(file, "upload_speed= {}", new_config.upload_speed_bps).unwrap();
    }

    println!("⚙ Server configuration updated remotely and saved to config.ini!");
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "success"})),
    )
        .into_response()
}
pub async fn get_config() -> impl IntoResponse {
    let current_config = CONFIG.read().unwrap().clone();
    (StatusCode::OK, axum::Json(current_config)).into_response()
}

//Larger Helper functions are defined here: --------------------------------------------------

/// Safely combines the base storage directory with a user-provided path.
/// It strips out any attempts to navigate UP the directory tree (like "..").
pub fn resolve_safe_path(user_path: &str) -> Result<PathBuf, String> {
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

pub mod acme;
pub mod commands;
pub mod crypto;
pub mod db;
pub mod deploy;
pub mod dns;
pub mod dns_api;
pub mod eab_api;
pub mod vault;


use commands::*;
use db::Database;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let db = Database::new().expect("Failed to initialize SQLite database");
    let session = Arc::new(Mutex::new(None));

    let state = AppState { db, session };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_profiles,
            save_profile,
            delete_profile,
            get_history,
            delete_history_item,
            start_acme_request,
            check_dns,
            finalize_certificate,
            select_directory,
            open_folder,
            select_json_file,
            select_key_file,
            fetch_google_eab,

            fetch_zerossl_eab,
            add_dns_txt_record,
            delete_dns_txt_record,
            deploy_certificate,
            get_app_settings,
            save_app_settings,
            get_app_info
        ])







        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

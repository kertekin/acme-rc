use std::fs;
use std::path::Path;

fn main() {
    let current_version = env!("CARGO_PKG_VERSION");
    let counter_path = Path::new(".build_counter");
    
    let mut build_num: u32 = 1;
    if let Ok(content) = fs::read_to_string(counter_path) {
        let parts: Vec<&str> = content.trim().split(':').collect();
        if parts.len() == 2 {
            let saved_ver = parts[0];
            let saved_cnt: u32 = parts[1].parse().unwrap_or(0);
            if saved_ver == current_version {
                build_num = saved_cnt + 1;
            } else {
                // Version changed, reset build number to 1
                build_num = 1;
            }
        }
    }

    let _ = fs::write(counter_path, format!("{}:{}", current_version, build_num));
    
    println!("cargo:rustc-env=APP_BUILD_NUMBER={}", build_num);
    println!("cargo:rustc-env=APP_VERSION_FULL=v{} (build {})", current_version, build_num);

    tauri_build::build();
}

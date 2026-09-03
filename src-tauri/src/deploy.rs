use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeployConfig {
    pub target: String, // "none", "local_nginx", "local_apache", "local_plesk", "local_custom", "remote_ssh"
    pub custom_path: Option<String>,
    pub hook_cmd: Option<String>,
    pub ssh_host: Option<String>,
    pub ssh_port: Option<u16>,
    pub ssh_user: Option<String>,
    pub ssh_key: Option<String>,
    pub ssh_pass: Option<String>,
}

#[cfg(unix)]
fn set_permissions(path: &Path, is_private_key: bool) {
    use std::os::unix::fs::PermissionsExt;
    let mode = if is_private_key { 0o600 } else { 0o644 };
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_permissions(_path: &Path, _is_private_key: bool) {}

/// Resolves the default destination path for known local targets
fn resolve_target_dir(domain: &str, target: &str, custom_path: Option<&str>) -> Result<PathBuf, String> {
    match target {
        "local_nginx" => Ok(PathBuf::from(format!("/etc/nginx/ssl/{}", domain))),
        "local_apache" => Ok(PathBuf::from(format!("/etc/ssl/certs/{}", domain))),
        "local_plesk" => Ok(PathBuf::from(format!("/var/www/vhosts/{}/certificates", domain))),
        "local_custom" => {
            let p = custom_path.unwrap_or("").trim();
            if p.is_empty() {
                Err("Custom target directory path cannot be empty".to_string())
            } else if p.chars().any(|c| matches!(c, ';' | '&' | '|' | '\'' | '"' | '$' | '`' | '\n' | '\r')) {
                Err("Custom target path contains invalid characters (;, &, |, ', \", $, `, newlines are not allowed)".to_string())
            } else {
                let replaced = p.replace("{domain}", domain);
                Ok(PathBuf::from(replaced))
            }
        }
        _ => Err(format!("Unsupported local target: {}", target)),
    }
}

/// Resolves default reload command for local web servers if none specified
fn resolve_default_hook(target: &str, custom_hook: Option<&str>) -> Option<String> {
    if let Some(cmd) = custom_hook.filter(|s| !s.trim().is_empty()) {
        return Some(cmd.trim().to_string());
    }

    match target {
        "local_nginx" => Some("sudo systemctl reload nginx 2>/dev/null || systemctl reload nginx 2>/dev/null || nginx -s reload".to_string()),
        "local_apache" => Some("sudo systemctl reload apache2 2>/dev/null || systemctl reload apache2 2>/dev/null || sudo systemctl reload httpd 2>/dev/null || systemctl reload httpd".to_string()),
        _ => None,
    }
}

#[cfg(unix)]
async fn run_elevated_copy(
    cert_dir: &Path,
    dest_dir: &Path,
    hook_cmd: Option<&str>,
    domain: &str,
    target: &str,
) -> Result<String, String> {
    let cert_dir_str = cert_dir.display().to_string().replace('\'', "'\\''");
    let dest_dir_str = dest_dir.display().to_string().replace('\'', "'\\''");

    let base_script = if target == "local_plesk" {
        format!(
            "mkdir -p '{dest}' && (cp -f '{src}/plesk/'* '{dest}/' 2>/dev/null || cp -f '{src}/'{domain}* '{dest}/' 2>/dev/null || cp -f '{src}/'*.key '{src}/'*.crt '{src}/'*.cer '{dest}/' 2>/dev/null) && (chmod 600 '{dest}/'*.key 2>/dev/null || true) && (chmod 644 '{dest}/'*.crt '{dest}/'*.cer 2>/dev/null || true)",
            dest = dest_dir_str,
            src = cert_dir_str,
            domain = domain
        )
    } else {
        // Nginx, Apache, or Custom: deploy only clean standard PEM files directly into target directory (no extra subfolders)
        format!(
            "mkdir -p '{dest}' && (cp -f '{src}/fullchain.pem' '{src}/privkey.pem' '{src}/cert.pem' '{src}/chain.pem' '{dest}/' 2>/dev/null || cp -f '{src}/nginx_apache/'* '{dest}/' 2>/dev/null || cp -f '{src}/'*.pem '{dest}/' 2>/dev/null) && (chmod 600 '{dest}/privkey.pem' 2>/dev/null || true) && (chmod 644 '{dest}/'*.pem 2>/dev/null || true)",
            dest = dest_dir_str,
            src = cert_dir_str
        )
    };

    let mut script = base_script;
    if let Some(hook) = hook_cmd.filter(|s| !s.trim().is_empty()) {
        let hook_clean = hook.replace("{domain}", domain);
        script.push_str(&format!("; ({}) 2>/dev/null || true", hook_clean));
    }

    let prompt = format!("ACME.rc requires administrator password to deploy SSL certificates to '{}':", dest_dir_str);

    // 1. Try pkexec with full GUI environment variables
    let mut pk_cmd = tokio::process::Command::new("pkexec");
    pk_cmd.args(["sh", "-c", &script]);
    if let Ok(disp) = std::env::var("DISPLAY") {
        pk_cmd.env("DISPLAY", disp);
    }
    if let Ok(wld) = std::env::var("WAYLAND_DISPLAY") {
        pk_cmd.env("WAYLAND_DISPLAY", wld);
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        pk_cmd.env("XDG_RUNTIME_DIR", xdg);
    }
    if let Ok(xauth) = std::env::var("XAUTHORITY") {
        pk_cmd.env("XAUTHORITY", xauth);
    }

    if let Ok(out) = pk_cmd.output().await {
        if out.status.success() || dest_dir.exists() {
            return Ok(format!(
                "Successfully deployed certificates to '{}' (elevated with pkexec)",
                dest_dir_str
            ));
        }
    }

    // 2. Try KDE kdialog GUI password prompt
    if let Ok(kd_out) = tokio::process::Command::new("kdialog")
        .args(["--password", &prompt])
        .output()
        .await
    {
        if kd_out.status.success() {
            let password = String::from_utf8_lossy(&kd_out.stdout).trim_end_matches('\n').to_string();
            if !password.is_empty() {
                use tokio::io::AsyncWriteExt;
                if let Ok(mut sudo_proc) = tokio::process::Command::new("sudo")
                    .args(["-S", "-k", "sh", "-c", &script])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                {
                    if let Some(mut stdin) = sudo_proc.stdin.take() {
                        let _ = stdin.write_all(format!("{}\n", password).as_bytes()).await;
                    }
                    if let Ok(sudo_out) = sudo_proc.wait_with_output().await {
                        if sudo_out.status.success() || dest_dir.exists() {
                            return Ok(format!(
                                "Successfully deployed certificates to '{}' (elevated with sudo/kdialog)",
                                dest_dir_str
                            ));
                        }
                    }
                }
            }
        }
    }

    // 3. Try GNOME zenity GUI password prompt
    if let Ok(zen_out) = tokio::process::Command::new("zenity")
        .args(["--password", &format!("--title={}", prompt)])
        .output()
        .await
    {
        if zen_out.status.success() {
            let password = String::from_utf8_lossy(&zen_out.stdout).trim_end_matches('\n').to_string();
            if !password.is_empty() {
                use tokio::io::AsyncWriteExt;
                if let Ok(mut sudo_proc) = tokio::process::Command::new("sudo")
                    .args(["-S", "-k", "sh", "-c", &script])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                {
                    if let Some(mut stdin) = sudo_proc.stdin.take() {
                        let _ = stdin.write_all(format!("{}\n", password).as_bytes()).await;
                    }
                    if let Ok(sudo_out) = sudo_proc.wait_with_output().await {
                        if sudo_out.status.success() || dest_dir.exists() {
                            return Ok(format!(
                                "Successfully deployed certificates to '{}' (elevated with sudo/zenity)",
                                dest_dir_str
                            ));
                        }
                    }
                }
            }
        }
    }

    // Double check if destination directory now exists on disk
    if dest_dir.exists() {
        return Ok(format!(
            "Successfully deployed certificates to '{}' (elevated)",
            dest_dir_str
        ));
    }

    Err(format!(
        "Failed to deploy to '{}' (Permission denied). To grant access, run in terminal:\n  sudo mkdir -p '{}' && sudo chown -R $USER:$USER '{}'",
        dest_dir_str, dest_dir_str, dest_dir_str
    ))
}

/// Executes local file copying and optional post-deploy hook
pub async fn execute_local_deploy(
    domain: &str,
    cert_dir: &Path,
    config: &DeployConfig,
) -> Result<String, String> {
    crate::acme::validate_domain(domain)?;
    let dest_dir = resolve_target_dir(domain, &config.target, config.custom_path.as_deref())?;

    // Try standard unprivileged directory creation
    let mkdir_res = fs::create_dir_all(&dest_dir);

    if mkdir_res.is_err() {
        #[cfg(unix)]
        {
            let hook = resolve_default_hook(&config.target, config.hook_cmd.as_deref());
            return run_elevated_copy(cert_dir, &dest_dir, hook.as_deref(), domain, &config.target).await;
        }
        #[cfg(not(unix))]
        {
            return Err(format!("Failed to create target directory '{}'", dest_dir.display()));
        }
    }

    // Copy only server-relevant certificate files (skip unrelated subdirectories)
    let mut copied_count = 0;
    let mut need_elevation = false;

    if config.target == "local_plesk" {
        let plesk_src = cert_dir.join("plesk");
        let search_dir = if plesk_src.is_dir() { &plesk_src } else { cert_dir };
        if let Ok(entries) = fs::read_dir(search_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let filename = entry.file_name();
                    let dest_file = dest_dir.join(&filename);
                    if fs::copy(&path, &dest_file).is_err() {
                        need_elevation = true;
                        break;
                    }
                    let is_key = filename.to_string_lossy().ends_with(".key");
                    set_permissions(&dest_file, is_key);
                    copied_count += 1;
                }
            }
        }
    } else {
        // Standard Nginx / Apache / PEM target: copy fullchain.pem, privkey.pem, cert.pem, chain.pem directly
        let pem_files = ["fullchain.pem", "privkey.pem", "cert.pem", "chain.pem"];
        for fname in &pem_files {
            let src_file = cert_dir.join(fname);
            let fallback_src = cert_dir.join("nginx_apache").join(fname);
            let final_src = if src_file.is_file() {
                src_file
            } else if fallback_src.is_file() {
                fallback_src
            } else {
                continue;
            };

            let dest_file = dest_dir.join(fname);
            if fs::copy(&final_src, &dest_file).is_err() {
                need_elevation = true;
                break;
            }
            let is_key = fname.contains("privkey");
            set_permissions(&dest_file, is_key);
            copied_count += 1;
        }
    }

    if need_elevation {
        #[cfg(unix)]
        {
            let hook = resolve_default_hook(&config.target, config.hook_cmd.as_deref());
            return run_elevated_copy(cert_dir, &dest_dir, hook.as_deref(), domain, &config.target).await;
        }
    }



    let mut summary = format!(
        "Successfully deployed {} certificate file(s) to '{}'",
        copied_count,
        dest_dir.display()
    );

    // Execute Post-Deploy Hook if configured
    if let Some(hook) = resolve_default_hook(&config.target, config.hook_cmd.as_deref()) {
        let hook_clean = hook.replace("{domain}", domain);
        #[cfg(unix)]
        {
            let output = tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&hook_clean)
                .output()
                .await
                .map_err(|e| format!("Failed to execute post-deploy hook '{}': {}", hook_clean, e))?;

            if output.status.success() {
                summary.push_str(&format!(" | Post-hook executed: '{}'", hook_clean));
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                summary.push_str(&format!(
                    " | Post-hook '{}' returned error: {}",
                    hook_clean,
                    stderr.trim()
                ));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::process::Command::new("cmd")
                .args(&["/C", &hook_clean])
                .output()
                .await;
        }
    }


    Ok(summary)
}

struct SshAuthContext {
    askpass_path: Option<PathBuf>,
    password: Option<String>,
}

impl SshAuthContext {
    fn new(password: Option<&str>) -> Self {
        if let Some(pass) = password.filter(|p| !p.trim().is_empty()) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let tmp_dir = std::env::temp_dir();
                let random_suffix: u128 = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(12345);
                let script_path = tmp_dir.join(format!("acmerc_askpass_{}.sh", random_suffix));
                let script_content = "#!/bin/sh\necho \"$ACMERC_SSH_PASSWORD\"\n";
                if fs::write(&script_path, script_content).is_ok() {
                    let _ = fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700));
                    return Self {
                        askpass_path: Some(script_path),
                        password: Some(pass.to_string()),
                    };
                }
            }
            #[cfg(not(unix))]
            {
                let tmp_dir = std::env::temp_dir();
                let script_path = tmp_dir.join("acmerc_askpass.cmd");
                let script_content = "@echo %ACMERC_SSH_PASSWORD%\r\n";
                if fs::write(&script_path, script_content).is_ok() {
                    return Self {
                        askpass_path: Some(script_path),
                        password: Some(pass.to_string()),
                    };
                }
            }
        }
        Self {
            askpass_path: None,
            password: None,
        }
    }

    fn apply_to_command(&self, cmd: &mut tokio::process::Command) {
        if let (Some(path), Some(pass)) = (&self.askpass_path, &self.password) {
            cmd.env("SSH_ASKPASS", path);
            cmd.env("SSH_ASKPASS_REQUIRE", "force");
            cmd.env("ACMERC_SSH_PASSWORD", pass);
            if std::env::var("DISPLAY").is_err() {
                cmd.env("DISPLAY", ":0");
            }
        }
    }

    fn build_base_args(&self, port: u16, key: Option<&str>) -> Vec<String> {
        let mut args = vec![
            "-p".to_string(), port.to_string(),
            "-o".to_string(), "ConnectTimeout=10".to_string(),
            "-o".to_string(), "StrictHostKeyChecking=accept-new".to_string(),
        ];
        if self.password.is_none() {
            args.push("-o".to_string());
            args.push("BatchMode=yes".to_string());
        } else {
            args.push("-o".to_string());
            args.push("NumberOfPasswordPrompts=1".to_string());
            args.push("-o".to_string());
            args.push("PreferredAuthentications=publickey,password,keyboard-interactive".to_string());
        }
        if let Some(k) = key.filter(|k| !k.trim().is_empty()) {
            args.push("-i".to_string());
            args.push(k.trim().to_string());
        }
        args
    }

    fn build_scp_base_args(&self, port: u16, key: Option<&str>) -> Vec<String> {
        let mut args = vec![
            "-P".to_string(), port.to_string(),
            "-o".to_string(), "ConnectTimeout=10".to_string(),
            "-o".to_string(), "StrictHostKeyChecking=accept-new".to_string(),
        ];
        if self.password.is_none() {
            args.push("-o".to_string());
            args.push("BatchMode=yes".to_string());
        } else {
            args.push("-o".to_string());
            args.push("NumberOfPasswordPrompts=1".to_string());
            args.push("-o".to_string());
            args.push("PreferredAuthentications=publickey,password,keyboard-interactive".to_string());
        }
        if let Some(k) = key.filter(|k| !k.trim().is_empty()) {
            args.push("-i".to_string());
            args.push(k.trim().to_string());
        }
        args
    }
}

impl Drop for SshAuthContext {
    fn drop(&mut self) {
        if let Some(path) = &self.askpass_path {
            let _ = fs::remove_file(path);
        }
    }
}

/// Executes remote SSH/SFTP deployment using shell scp/ssh with automatic non-root sudo promotion
pub async fn execute_ssh_deploy(
    domain: &str,
    cert_dir: &Path,
    config: &DeployConfig,
) -> Result<String, String> {
    crate::acme::validate_domain(domain)?;

    let host = config.ssh_host.as_deref().unwrap_or("").trim();
    let user = config.ssh_user.as_deref().unwrap_or("root").trim();
    let port = config.ssh_port.unwrap_or(22);
    let remote_dir = config
        .custom_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .unwrap_or("/etc/nginx/ssl/{domain}")
        .replace("{domain}", domain);


    if host.is_empty() {
        return Err("SSH Host cannot be empty for remote deployment".to_string());
    }

    if remote_dir.chars().any(|c| matches!(c, ';' | '&' | '|' | '\'' | '"' | '$' | '`' | '\n' | '\r')) {
        return Err("Remote destination directory contains invalid characters".to_string());
    }

    if !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err("SSH username contains invalid characters".to_string());
    }

    if !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':') {
        return Err("SSH host contains invalid characters".to_string());
    }

    let auth_ctx = SshAuthContext::new(config.ssh_pass.as_deref());
    let ssh_target = format!("{}@{}", user, host);

    // Generate unique remote staging directory in /tmp (accessible to non-root users)
    let random_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(12345);
    let sanitized_domain = domain.replace('*', "wildcard").replace('.', "_");
    let staging_dir = format!("/tmp/acmerc_stage_{}_{}", sanitized_domain, random_id);

    // 1. Create remote staging directory via SSH
    let mkdir_cmd = format!("mkdir -p '{}' && chmod 700 '{}'", staging_dir, staging_dir);
    let mut ssh_args = auth_ctx.build_base_args(port, config.ssh_key.as_deref());
    ssh_args.push(ssh_target.clone());
    ssh_args.push(mkdir_cmd);

    let mut mkdir_proc = tokio::process::Command::new("ssh");
    mkdir_proc.args(&ssh_args);
    auth_ctx.apply_to_command(&mut mkdir_proc);

    let mkdir_res = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        mkdir_proc.output(),
    )
    .await
    .map_err(|_| "SSH connection timed out after 15 seconds. Please check SSH host, port, credentials and network.".to_string())?
    .map_err(|e| format!("SSH command execution failed: {}", e))?;

    if !mkdir_res.status.success() {
        let err = String::from_utf8_lossy(&mkdir_res.stderr);
        return Err(format!("Failed to connect to remote host over SSH: {}", err.trim()));
    }

    // 2. SCP certificate files to remote staging directory
    let mut scp_args = auth_ctx.build_scp_base_args(port, config.ssh_key.as_deref());

    // Send only PEM certificate files (skip subfolders)
    let pem_files = ["fullchain.pem", "privkey.pem", "cert.pem", "chain.pem"];
    let mut found_pem = false;
    for fname in &pem_files {
        let fpath = cert_dir.join(fname);
        if fpath.is_file() {
            scp_args.push(fpath.display().to_string());
            found_pem = true;
        }
    }
    if !found_pem {
        scp_args.push(format!("{}/.", cert_dir.display()));
    }

    let dest_pattern = format!("{}:{}/", ssh_target, staging_dir);
    scp_args.push(dest_pattern);

    let mut scp_proc = tokio::process::Command::new("scp");
    scp_proc.args(&scp_args);
    auth_ctx.apply_to_command(&mut scp_proc);

    let scp_res = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        scp_proc.output(),
    )
    .await
    .map_err(|_| "SCP transfer timed out after 20 seconds. Check network and remote permissions.".to_string())?
    .map_err(|e| format!("SCP command execution failed: {}", e))?;

    if !scp_res.status.success() {
        let err = String::from_utf8_lossy(&scp_res.stderr);
        return Err(format!("SCP transfer failed: {}", err.trim()));
    }

    // 3. Promote files from staging directory to target root directory (with secure stdin sudo password piping)
    let sudo_prefix = if auth_ctx.password.is_some() {
        "sudo -S -k -- sh -c"
    } else {
        "sudo -n -- sh -c"
    };

    let safe_remote_dir = remote_dir.replace('\'', "'\\''");
    let safe_staging_dir = staging_dir.replace('\'', "'\\''");

    let promote_script = format!(
        "if [ $(id -u) -eq 0 ]; then \
            mkdir -p '{dest}' && cp -f '{stage}'/* '{dest}/' && chmod 600 '{dest}/privkey.pem' 2>/dev/null || true; chmod 644 '{dest}'/*.pem 2>/dev/null || true; \
         else \
            {sudo_prefix} \"mkdir -p '{dest}' && cp -f '{stage}'/* '{dest}/' && chmod 600 '{dest}/privkey.pem' 2>/dev/null || true; chmod 644 '{dest}'/*.pem 2>/dev/null || true\"; \
         fi; \
         test -f '{dest}/fullchain.pem' || test -f '{dest}/privkey.pem' || test -f '{dest}/cert.pem'; \
         RET=$?; \
         rm -rf '{stage}'; \
         exit $RET",
        dest = safe_remote_dir,
        stage = safe_staging_dir,
        sudo_prefix = sudo_prefix
    );

    let mut promote_args = auth_ctx.build_base_args(port, config.ssh_key.as_deref());
    promote_args.push(ssh_target.clone());
    promote_args.push(promote_script);

    let mut promote_proc = tokio::process::Command::new("ssh");
    promote_proc.args(&promote_args);
    promote_proc.stdin(std::process::Stdio::piped());
    auth_ctx.apply_to_command(&mut promote_proc);

    let mut child = promote_proc
        .spawn()
        .map_err(|e| format!("SSH promotion command spawn failed: {}", e))?;

    if let Some(pass) = auth_ctx.password.as_deref() {
        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(format!("{}\n", pass).as_bytes()).await;
        }
    }

    let promote_res = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| "SSH promotion timed out after 15 seconds.".to_string())?
    .map_err(|e| format!("SSH promotion execution failed: {}", e))?;

    if !promote_res.status.success() {
        let err = String::from_utf8_lossy(&promote_res.stderr);
        let out = String::from_utf8_lossy(&promote_res.stdout);
        let combined = if err.trim().is_empty() { out.trim() } else { err.trim() };
        return Err(format!("Failed to deploy to remote target '{}' (Permission denied / sudo required): {}", remote_dir, combined));
    }

    let mut summary = format!("Successfully deployed certificates to {}:{}/", ssh_target, remote_dir);

    // 4. Remote Hook
    if let Some(hook) = config.hook_cmd.as_deref().filter(|h| !h.trim().is_empty()) {
        let hook_clean = hook.replace("{domain}", domain);
        let safe_hook = hook_clean.replace('\'', "'\\''");
        let sudo_hook_cmd = if auth_ctx.password.is_some() {
            "sudo -S -- sh -c"
        } else {
            "sudo -n -- sh -c"
        };

        let hook_remote_cmd = format!(
            "if [ $(id -u) -eq 0 ]; then \
                {}; \
             else \
                {} '{}' 2>/dev/null || ({}); \
             fi",
            hook_clean, sudo_hook_cmd, safe_hook, hook_clean
        );

        let mut hook_ssh_args = auth_ctx.build_base_args(port, config.ssh_key.as_deref());
        hook_ssh_args.push(ssh_target);
        hook_ssh_args.push(hook_remote_cmd);

        let mut hook_proc = tokio::process::Command::new("ssh");
        hook_proc.args(&hook_ssh_args);
        hook_proc.stdin(std::process::Stdio::piped());
        auth_ctx.apply_to_command(&mut hook_proc);

        if let Ok(mut h_child) = hook_proc.spawn() {
            if let Some(pass) = auth_ctx.password.as_deref() {
                use tokio::io::AsyncWriteExt;
                if let Some(mut stdin) = h_child.stdin.take() {
                    let _ = stdin.write_all(format!("{}\n", pass).as_bytes()).await;
                }
            }

            if let Ok(Ok(out)) = tokio::time::timeout(std::time::Duration::from_secs(15), h_child.wait_with_output()).await {
                if out.status.success() {
                    summary.push_str(&format!(" | Remote hook executed: '{}'", hook_clean));
                } else {
                    let err = String::from_utf8_lossy(&out.stderr);
                    summary.push_str(&format!(" | Remote hook note: {}", err.trim()));
                }
            }
        }
    }

    Ok(summary)
}




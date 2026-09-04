# ACME.rc — SSL/TLS Certificate Manager

ACME Relay Client (**ACME.rc**) is a modern, lightweight desktop application built with **Tauri v2** and **Rust** for automated ACME DNS-01 certificate issuance, renewal, and zero-touch server deployment.

---

## ✨ Features

- **Multi-CA Support**: Issue certificates via **Google Trust Services**, **Let's Encrypt**, **ZeroSSL**, or any custom RFC 8555 ACME directory.
- **Automated DNS-01 Verification**: Native API integrations for **Cloudflare**, **Hetzner**, **DigitalOcean**, **Plesk**, and Custom Webhooks, alongside manual DNS mode with live propagation checking.
- **Zero-Touch Server Deployment**:
  - **Local**: Automatic privileged deployment to Nginx (`/etc/nginx/ssl`), Apache (`/etc/ssl/certs`), Plesk, or custom folders with service reload hooks.
  - **Remote SSH/SFTP**: Secure remote deployment with non-root staging, automated `sudo` promotion, and post-deploy execution.
- **Security & Privacy**:
  - Encrypted credential storage using hardware-bound AES-256-GCM.
  - No telemetry, no external accounts, 100% local SQLite database.
- **Preset Bundling**: Automatically packages certificates for standard PEM, Plesk, cPanel, and Nginx/Apache.

---

## 📥 Installation

Download the latest release for Linux from the [GitHub Releases](https://github.com/kertekin/acme-rc/releases) page:

### Debian / Ubuntu (`.deb`)
```bash
sudo dpkg -i ACME.rc_*_amd64.deb
```

### Fedora / RHEL / CentOS (`.rpm`)
```bash
sudo rpm -i ACME.rc-*.x86_64.rpm
```

### Standalone AppImage
```bash
chmod +x ACME.rc_*_amd64.AppImage
./ACME.rc_*_amd64.AppImage
```

---

## 🛠️ Building from Source

### Prerequisites
- Node.js (v20+) & npm
- Rust stable toolchain
- Linux system libraries:
  ```bash
  sudo apt-get install -y libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev patchelf rpm
  ```

### Build Steps
```bash
# Clone the repository
git clone https://github.com/kertekin/acme-rc.git
cd acme-rc

# Install frontend dependencies
npm install

# Run in development mode
npm run dev

# Build production bundles (.deb, .rpm, .AppImage)
npm run build
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

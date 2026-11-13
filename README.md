# SSH Buttons 🔘

A lightweight, self-contained, Docker Compose-ready web dashboard in Go that acts as a secure, one-click SSH command trigger for your infrastructure (inspired by OliveTin).

![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?style=flat&logo=go)
![Docker Ready](https://img.shields.io/badge/docker-ready-2496ED?style=flat&logo=docker)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Features

- **Self-Contained & Air-Gapped**: Single binary with embedded templates, icons, and CSS (`//go:embed`). Zero external CDNs or third-party dependencies loaded at runtime.
- **YAML-Driven**: Define hosts, authentication methods, categories, and command buttons in a clean, human-readable `config.yml`.
- **Hot-Reloadable**: Update `config.yml` at any time and click **"Reload Config"** in the header to apply changes immediately without container restarts.
- **Secure Authentication**: Protected dashboard routes with `HttpOnly` HMAC-signed session cookies and constant-time password verification (supporting both plaintext and bcrypt hashes).
- **Bilingual (Arabic & English) with RTL Support**: Instant language switcher on login and dashboard screens with complete Right-To-Left (`dir="rtl"`) layout and Arabic translations.
- **Graceful Reboot & Shutdown Handling**: Intelligently handles abrupt TCP connection resets and EOF drops when issuing commands like `reboot` or `shutdown -h now`, reporting successful execution instead of false errors.
- **Confirmation Prompts**: Built-in modal dialog for destructive or high-severity buttons to prevent accidental clicks.
- **Mobile & PWA Ready**: Includes responsive viewport styling and `/manifest.json` for installation as a standalone home-screen app on iOS and Android.

---

## 🚀 Quick Start

### 1. Using Docker Compose (Recommended)

1. Clone or download the repository:
   ```bash
   git clone https://github.com/your-user/ssh_buttons.git
   cd ssh_buttons
   ```

2. Copy the example configuration:
   ```bash
   cp config.example.yml config.yml
   ```

3. (Optional) Place any SSH private keys into a `./keys` folder:
   ```bash
   mkdir -p keys
   cp ~/.ssh/id_ed25519 keys/
   chmod 600 keys/*
   ```

4. Start the container:
   ```bash
   docker compose up -d
   ```

5. Open your browser at **`http://localhost:8080`**.
   - Default Username: `admin`
   - Default Password: `adminpassword`

---

### 2. Running Locally with Go

If you have Go installed on your machine:

```bash
# Clone and enter directory
cd SSH_Buttons

# Copy sample configuration
cp config.example.yml config.yml

# Run directly
go run . -config config.yml
```

---

## ⚙️ Configuration (`config.yml`)

The dashboard is driven by a single YAML file:

```yaml
server:
  port: 8080
  admin_username: "admin"
  admin_password: "adminpassword" # Plaintext or $2a$... bcrypt hash
  session_secret: "a-very-secret-random-key"
  default_ssh_timeout: 15 # Seconds

hosts:
  srv_linux:
    name: "Ubuntu Production 01"
    host: "192.168.1.10"
    port: 22
    user: "root"
    key_path: "./keys/id_ed25519" # Relative or absolute path
    insecure_ignore_host_key: true

  router_mikrotik:
    name: "Core Gateway (MikroTik)"
    host: "192.168.1.1"
    port: 22
    user: "admin"
    password: "RouterPassword"
    insecure_ignore_host_key: true

categories:
  - name: "Linux Server Operations"
    buttons:
      - id: "linux-docker-restart"
        label: "Restart Docker Services"
        description: "Restarts docker unit on Ubuntu server"
        host: "srv_linux"
        command: "systemctl restart docker"
        style: "warning" # primary | danger | warning | success | secondary
        confirm: true
        timeout: 30

      - id: "linux-reboot"
        label: "Reboot Server"
        description: "Reboots Ubuntu host immediately"
        host: "srv_linux"
        command: "sudo reboot"
        style: "danger"
        confirm: true
```

### Environment Variable Overrides

Any value in `server` can be overridden by environment variables:

| Variable | Description |
| :--- | :--- |
| `PORT` | Listening port (default `8080`) |
| `ADMIN_USERNAME` | Admin login user (default `admin`) |
| `ADMIN_PASSWORD` | Admin login password |
| `SESSION_SECRET` | HMAC cookie secret |
| `CONFIG_PATH` | Path to configuration file (default `config.yml`) |

---

## 📱 Mobile & PWA Installation

- **iOS (Safari)**: Open `http://your-server:8080`, tap the **Share** button, and choose **"Add to Home Screen"**.
- **Android (Chrome)**: Tap the three-dot menu and select **"Install App"** or **"Add to Home Screen"**.

---

## 🧪 Testing & Verification

Run tests:
```bash
go test -v ./...
```

Build standalone binary:
```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o ssh_buttons .
```

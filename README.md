# SSH Buttons 🔘

A lightweight, self-contained, Docker Compose-ready web dashboard in Go that acts as a secure, one-click SSH command trigger for your infrastructure (inspired by OliveTin).

![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?style=flat&logo=go)
![Docker Ready](https://img.shields.io/badge/docker-ready-2496ED?style=flat&logo=docker)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Features

- **Self-Contained & Air-Gapped**: Single binary with embedded templates, icons, and CSS (`//go:embed`). Zero external CDNs or third-party dependencies loaded at runtime.
- **YAML-Driven**: Define hosts, authentication methods, categories, and command buttons in a clean, human-readable `config.yml`.
- **Multi-User & Role-Based Access (RBAC)**: Support multiple user accounts with `admin` and `operator` roles. Operators trigger actions, while only administrators can edit system configuration.
- **In-Browser WebUI Config Editor**: Safely view and edit `config.yml` directly in the browser with pre-save YAML validation, automated backups, and instant reloading.
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
  session_secret: "a-very-secret-random-key"
  timeout: 15 # Default command timeout in seconds

users:
  - user: "admin"
    pass: "adminpassword" # Plaintext or $2a$... bcrypt hash
    role: "admin"
  - user: "operator1"
    pass: "operatorpassword"
    role: "operator"

hosts:
  srv_linux:
    name: "Ubuntu Production 01"
    host: "192.168.1.10"
    user: "root"
    key: "./keys/id_ed25519"

  router_mikrotik:
    name: "Core Gateway"
    host: "192.168.1.1"
    user: "admin"
    pass: "RouterPassword"

categories:
  - name: "Linux Operations"
    host: "srv_linux" # Inherited by all buttons below
    buttons:
      - name: "Restart Docker"
        cmd: "systemctl restart docker"
        warning: true # Auto-configures warning style + confirmation modal
        timeout: 30

      - name: "Check Disk Space"
        cmd: "df -h"

      - name: "Reboot Server"
        cmd: "sudo reboot"
        danger: true # Auto-configures danger style + confirmation modal
```

### Environment Variable Overrides

Values can be overridden at runtime via environment variables:

| Variable | Description |
| :--- | :--- |
| `PORT` | Listening port (default `8080`) |
| `SESSION_SECRET` | HMAC cookie signing secret |
| `ADMIN_USER` | Runtime override/injection for admin username |
| `ADMIN_PASSWORD` | Runtime override/injection for admin password |
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

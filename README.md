# Honeypot Security System

Production-style honeypot lab that simulates vulnerable services, captures malicious traffic, and exposes observability data for analysis.  
The project combines Python, Go, C++, Docker, and Terraform to demonstrate both engineering depth and security operations workflows.

## Why this project matters

- Demonstrates practical **security engineering** and not only theory.
- Shows **polyglot implementation** across Python, Go, and C++.
- Includes **DevOps/observability workflow** with Docker, Terraform, Prometheus, and Grafana.
- Useful as a learning lab and as a baseline for real detection pipeline experiments.

## 🚀 Features
- **Fake services**: Simulates vulnerable services to attract malicious traffic.
- **Logging attacks**: Captures IP addresses, user agents, and requested paths.
- **Real-time monitoring**: Monitors traffic and displays metrics using Prometheus and Grafana.
- **Containerized setup**: Easily deploys using Docker and Kubernetes.
- **Infrastructure as Code**: Automate deployment with Terraform.
- **Go and C++ Services**: Efficient traffic processing and attack detection.

## ⚙️ Technologies Used
- **Backend**: Python (Flask), Go
- **Traffic Analysis**: C++
- **Database**: PostgreSQL
- **Web Server**: Nginx
- **Monitoring**: Prometheus, Grafana
- **Containers**: Docker, Docker Compose, Kubernetes
- **Infrastructure**: Terraform

## 🛠️ Getting Started

To get started with the Honeypot Security System, ensure you have Docker, Docker Compose, and Terraform installed.

### 1. Clone the repository
```bash
git clone https://github.com/kiurakku/Honeypot-Security-System.git
cd Honeypot-Security-System
```

### 2. Deploy Infrastructure (Optional, for cloud deployment)
If you wish to deploy the system on a cloud provider using Terraform:
```bash
cd infrastructure/terraform
terraform init
terraform apply
```

### 3. Set up the environment
Install the Python dependencies:
```bash
pip install -r requirements.txt
```

### 4. Start the services
Run the entire system using Docker Compose:
```bash
docker-compose up --build
```

This will start:
- **Honeypot** service (Flask API) on port `5000`
- **PostgreSQL** as the database to store log data
- **Nginx** to proxy requests
- **Go-based backend** for handling requests efficiently
- **C++ Traffic Analyzer** for analyzing network data
- **Prometheus** for monitoring (available at `http://localhost:9090`)
- **Grafana** for visualizing data (available at `http://localhost:3000`)

### 5. Configure Grafana
Once Grafana is running, open `http://localhost:3000` and log in with default credentials:
- Username: `admin`
- Password: `admin`

Import the Honeypot dashboard by uploading the `honeypot-dashboard.json` from `monitoring/grafana/`.

### 6. View Logs
Attack logs are stored in PostgreSQL and can be accessed via a database client or API queries.

## 🧩 Project Structure
```
honeypot/
│── docker-compose.yml        # Docker Compose setup
│── .gitignore                # Git ignore file
│── README.md                 # Project documentation
│── LICENSE                   # License for the project
│── infrastructure/
│   ├── terraform/            # Terraform deployment files
│── backend/
│   ├── go-service/           # Backend service in Go
│   │   ├── main.go
│   │   ├── handlers.go
│   │   ├── database.go
│   ├── cpp-analyzer/         # Traffic analysis in C++
│   │   ├── main.cpp
│   │   ├── CMakeLists.txt
│── database/
│   ├── migrations/
│   │   ├── 001_init.sql
│   ├── seeds/
│── monitoring/
│   ├── prometheus.yml
│   ├── grafana/
│       ├── dashboards.yml
│       ├── honeypot-dashboard.json
│── requirements.txt          # Python dependencies
│── logs/                     # Directory to store log files
```

## 📊 Monitoring and Analytics
- **Prometheus** collects metrics such as request counts, response times, and error rates.
- **Grafana** visualizes these metrics via pre-configured dashboards.

## 🛡️ License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## 📢 Contributions
Feel free to contribute! Fork the repository, create a new branch, and submit a pull request.

---

### 🚧 To Do:
- Expand Terraform support for multi-cloud environments.
- Add more fake services to interact with different attack vectors.
- Improve logging and alerting for real-time attack detection.

---

## 💡 Ideas for Future Enhancements
- **Email alerts**: Send email notifications when an attack is detected.
- **Advanced analytics**: Use AI/ML for detecting attack patterns.
- **More fake services**: Include SSH, FTP, and other vulnerable services for broader coverage.

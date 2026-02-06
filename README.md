# Government Agentic Honey-Pot System v2.0

## 🛡️ Advanced Features

### Core Capabilities
- **Multi-layered Scam Detection** - Advanced pattern matching with threat level assessment
- **Intelligent AI Agent** - Adaptive personas based on scam type
- **Comprehensive Intelligence Extraction** - Bank accounts, UPI IDs, phone numbers, crypto addresses
- **Real-time Dashboard** - Professional government interface
- **Secure Database Storage** - SQLite with conversation logging
- **Enterprise Authentication** - API key management and logging
- **Production Ready** - Docker deployment with health checks

### Government-Grade Security
- Encrypted API keys
- Request logging and monitoring
- IP tracking and analysis
- Threat level classification
- Automated intelligence reporting

## 🚀 Quick Start

### Local Development
```bash
pip install -r requirements.txt
python app.py
```

### Access Dashboard
Open browser: `http://localhost:5000/dashboard`

### Production Deployment
```bash
docker-compose up -d
```

## 📊 API Endpoints

### Main Detection API
```
POST /api/message
Headers: X-API-Key: gov-api-key-2024
```

### Dashboard & Analytics
```
GET /dashboard - Web interface
GET /api/stats - System statistics
GET /api/conversations - Recent conversations
GET /health - System health check
```

## 🎯 Test Examples

**High Threat:**
```
"URGENT! You won lottery $50000! Click here immediately to claim your prize! Send bank account details now!"
```

**Medium Threat:**
```
"Congratulations! Tax refund of $2000 approved. Verify your account details."
```

**Crypto Scam:**
```
"Exclusive Bitcoin investment opportunity! 500% returns guaranteed! Send to wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
```

## 🔧 Configuration

### API Keys (Production)
- Change default API key in production
- Use environment variables for secrets
- Implement rate limiting
- Enable HTTPS

### Database
- SQLite for development
- PostgreSQL recommended for production
- Automated backups
- Data retention policies

## 📈 Intelligence Categories

- **Bank Accounts** - Indian bank account numbers
- **UPI IDs** - Payment identifiers
- **Phone Numbers** - Indian mobile numbers
- **Email Addresses** - Contact information
- **URLs** - Phishing and malicious links
- **Crypto Addresses** - Bitcoin/Ethereum wallets
- **IFSC Codes** - Bank routing codes
- **PAN Numbers** - Tax identification
- **Aadhaar Numbers** - National ID numbers

## 🏛️ Government Deployment

### Security Compliance
- Data encryption at rest and in transit
- Audit logging
- Access control
- Regular security updates

### Scalability
- Horizontal scaling with Docker
- Load balancing
- Database clustering
- CDN integration

### Monitoring
- Real-time alerts
- Performance metrics
- Threat intelligence feeds
- Automated reporting

## 📞 Support

For government deployment assistance:
- Technical documentation included
- Professional support available
- Custom integration services
- Training and workshops
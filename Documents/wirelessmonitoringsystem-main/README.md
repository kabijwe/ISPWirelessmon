# Wireless Monitoring System

A comprehensive real-time wireless network monitoring dashboard for tracking device connectivity, status, and performance across multiple locations.

## 🚀 Features

### Real-Time Monitoring
- **Live Device Status**: Monitor 200+ wireless devices in real-time
- **Multi-Location Support**: Track devices across 16+ geographical locations
- **Status Categories**: Reachable, Down, Degraded, Unknown
- **Latency Monitoring**: Track network response times with threshold alerts
- **Downtime Tracking**: Monitor device downtime duration and history

### Interactive Dashboard
- **Live Updates**: WebSocket-based real-time data updates every 10 seconds
- **Summary Statistics**: Total devices, status counts, location breakdowns
- **Search & Filter**: Filter by IP, device name, location, or status
- **Sortable Columns**: Click column headers to sort data
- **Alert System**: Real-time alerts for status changes and long-term outages

### Advanced Analytics
- **Location Summary**: Device status breakdown by location
- **Alert Log**: Historical alert tracking with export capabilities
- **Downtime Analysis**: Location-based downtime statistics and trends
- **Performance Charts**: Visual representation of network health
- **Export Functions**: Export data to Excel/PDF formats

### Admin Panel
- **Device Management**: Add, edit, and delete device entries
- **Excel Integration**: Import/export device configurations
- **User Authentication**: Secure admin access with login system
- **Bulk Operations**: Manage multiple devices efficiently

## 📋 System Requirements

### Software Dependencies
- **Python 3.8+**
- **Flask 2.0+** - Web framework
- **Flask-SocketIO 5.0+** - Real-time WebSocket communication
- **pandas 1.3+** - Data manipulation and Excel processing
- **openpyxl 3.0+** - Excel file handling
- **matplotlib 3.5+** - Chart generation
- **reportlab 3.6+** - PDF export functionality
- **Pillow 8.0+** - Image processing

### System Requirements
- **Linux/Windows/macOS**
- **2GB RAM minimum**
- **Network connectivity** to monitored devices
- **Web browser** with JavaScript enabled

## 🛠️ Installation

### 1. Clone Repository
```bash
git clone https://github.com/kabijwe/wireless-monitoring.git
cd wireless-monitoring
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Device List
Edit `sm_ips.xlsx` with your device information:
- **AP Name**: Access Point identifier
- **AP IP**: Access Point IP address
- **CID**: Customer/Circuit ID
- **SM IP**: Station Module IP address (monitored device)
- **Device Name**: Descriptive device name
- **Location**: Geographical location

### 4. Run Application
```bash
python ping.py
```

### 5. Access Dashboard
- **Main Dashboard**: http://localhost:5000
- **Admin Panel**: http://localhost:5000/admin
- **Default Credentials**: admin / admin123

## 📊 Dashboard Overview

### Main Interface
The dashboard displays a comprehensive table with the following columns:
- **AP Name**: Access Point identifier
- **AP IP**: Access Point IP address
- **CID**: Customer/Circuit Identification
- **SM IP**: Station Module IP (monitored device)
- **Device Name**: Device description
- **Location**: Geographical location
- **Status**: Current connectivity status
- **Latency**: Network response time
- **Downtime Since**: Duration of current outage (if applicable)

### Status Indicators
- 🟢 **Reachable**: Device responding normally
- 🟡 **Degraded**: High latency or packet loss
- 🔴 **Down**: Device not responding
- ⚪ **Unknown**: Status cannot be determined

### Summary Panel
Real-time counts of:
- Total monitored devices
- Reachable devices
- Degraded connections
- Down devices
- Unknown status devices

## 🔧 Configuration

### Environment Variables
```bash
# Admin credentials (optional)
export ADMIN_USERNAME="your_username"
export ADMIN_PASSWORD="your_password"

# Flask secret key (optional)
export FLASK_SECRET_KEY="your_secret_key"

# Test mode (optional)
export TEST_MODE="true"
```

### Application Settings
Key configuration parameters in `ping.py`:
- `PING_INTERVAL = 10` - Monitoring frequency (seconds)
- `LATENCY_THRESHOLD = 800` - High latency threshold (ms)
- `DEGRADED_LOSS_THRESHOLD = 10` - Packet loss threshold (%)
- `MAX_WORKERS = 50` - Concurrent ping threads
- `RETENTION_DAYS = 7` - Historical data retention

## 📈 Monitoring Features

### Real-Time Alerts
- **Status Changes**: Immediate notifications when devices go up/down
- **Long-Term Outages**: Special alerts for extended downtime (24+ hours)
- **High Latency**: Warnings for performance degradation
- **Recovery Notifications**: Alerts when devices come back online

### Historical Data
- **SQLite Database**: Stores ping history and status changes
- **Automatic Cleanup**: Removes old data based on retention settings
- **Export Capabilities**: Download historical data in Excel format
- **Trend Analysis**: View performance patterns over time

### Location Analytics
- **Geographic Grouping**: Organize devices by physical location
- **Location Health**: Overall status per location
- **Comparative Analysis**: Compare performance across locations
- **Downtime Reports**: Location-specific outage statistics

## 🔐 Security Features

### Authentication
- **Admin Login**: Secure access to management functions
- **Session Management**: Automatic session handling
- **Password Protection**: Configurable admin credentials

### Data Protection
- **Input Validation**: Sanitized user inputs
- **SQL Injection Prevention**: Parameterized database queries
- **XSS Protection**: Escaped output rendering
- **CSRF Protection**: Secure form submissions

## 📱 Browser Compatibility

### Supported Browsers
- **Chrome 90+**
- **Firefox 88+**
- **Safari 14+**
- **Edge 90+**

### Mobile Support
- Responsive design for tablets and mobile devices
- Touch-friendly interface elements
- Optimized for various screen sizes

## 🚨 Troubleshooting

### Common Issues

#### CID Values Not Displaying
- Clear browser cache (Ctrl+Shift+Delete)
- Hard refresh page (Ctrl+F5)
- Try incognito/private browsing mode

#### Database Errors
- Check file permissions on `ping_history.db`
- Ensure sufficient disk space
- Verify SQLite installation

#### Network Connectivity
- Verify network access to monitored devices
- Check firewall settings
- Ensure ICMP (ping) is allowed

#### Performance Issues
- Reduce `MAX_WORKERS` for slower systems
- Increase `PING_INTERVAL` to reduce load
- Monitor system resources (CPU, memory)

### Log Files
- **Application Logs**: `ping_debug.log`
- **Alert History**: `logs/alerts_YYYY-MM-DD_HH.jsonl`
- **Database**: `ping_history.db`

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Code Style
- Follow PEP 8 for Python code
- Use meaningful variable names
- Add comments for complex logic
- Include error handling

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Support

### Getting Help
- **Issues**: Report bugs via GitHub Issues
- **Documentation**: Check this README for common solutions
- **Community**: Contribute improvements and suggestions

### Contact Information
- **Repository**: https://github.com/kabijwe/wireless-monitoring
- **Issues**: https://github.com/kabijwe/wireless-monitoring/issues

## 🔄 Version History

### v2.0.0 (Current)
- **CID Support**: Replaced MAC addresses with Customer ID tracking
- **Enhanced UI**: Improved dashboard layout and responsiveness
- **Better Performance**: Optimized ping operations and caching
- **Export Features**: Added Excel and PDF export capabilities

### v1.0.0
- Initial release with basic monitoring functionality
- Real-time dashboard with WebSocket updates
- Admin panel for device management
- SQLite database for historical data

## 🎯 Roadmap

### Planned Features
- **Email Alerts**: Automated notification system
- **API Endpoints**: RESTful API for external integrations
- **Advanced Charts**: Enhanced visualization options
- **Multi-User Support**: Role-based access control
- **Mobile App**: Native mobile application

---

**WorldLink Communications Ltd.**  
*Wireless Network Monitoring Dashboard*
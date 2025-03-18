# CyberIntel: Cybersecurity Threat Intelligence Dashboard

## Overview

CyberIntel is a powerful, interactive web application that provides comprehensive threat intelligence on IP addresses and domains by aggregating data from multiple cybersecurity intelligence sources. Built with Streamlit, this dashboard helps cybersecurity professionals, network administrators, and security analysts quickly assess potential threats and make informed decisions.

## Key Features

- **Multi-source Intelligence**: Integrates data from AbuseIPDB, IPInfo, VirusTotal, Greynoise, and Shodan
- **Comprehensive Analysis**: Provides threat scoring, abuse history, geolocation data, and exposed services
- **Interactive Visualizations**: Features heatmaps, charts, and interactive maps for better data interpretation
- **Detailed Reports**: Breaks down security vendor analyses, vulnerability information, and abuse categories
- **User-friendly Interface**: Organized into intuitive tabs with color-coded risk indicators

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/threatradar.git
cd threatradar

# Install dependencies
pip install -r requirements.txt

# Set up API keys
# Create a .streamlit/secrets.toml file with your API keys:
# ABUSEIPDB_API_KEY = "your_key_here"
# IPINFO_API_KEY = "your_key_here"
# VIRUSTOTAL_API_KEY = "your_key_here"
# GREYNOISE_API_KEY = "your_key_here"
# SHODAN_API_KEY = "your_key_here"

# Run the application
streamlit run app.py
```

## Usage

1. Select either "IP Address" or "Domain" from the sidebar
2. Enter the target IP or domain name
3. Click "Analyze Now" to retrieve and visualize threat intelligence
4. Navigate through the tabs to explore different aspects of the analysis:
   - **Overview**: Summary of threat scores and key findings
   - **Threat Details**: In-depth analysis of security threats
   - **Geolocation**: Map-based visualization of IP location
   - **Services & Ports**: Information about exposed services and vulnerabilities
   - **Raw Data**: Access to the complete API responses

## Requirements

- Python 3.7+
- Streamlit
- Plotly
- Pandas
- Folium
- Active API keys for all security services

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License

## Disclaimer

This tool is for educational and defensive security purposes only. The information provided is based on third-party security intelligence sources and may not be 100% accurate. Always verify critical security information with multiple sources.


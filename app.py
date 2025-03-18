import streamlit as st
import requests
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import folium
from streamlit_folium import folium_static

# Set page config
st.set_page_config(page_title="CyberIntel", page_icon="🔐", layout="wide")

# Add custom CSS for better styling
st.markdown("""
<style>
    .info-box {
        padding: 20px;
        border-radius: 5px;
        margin-bottom: 20px;
        background-color: #f0f5ff;
        border-left: 5px solid #4361ee;
        color : black;
    }
    .warning-box {
        padding: 20px;
        border-radius: 5px;
        margin-bottom: 20px;
        background-color: #fff8e6;
        border-left: 5px solid #ffc107;
        color: black;
    }
    .danger-box {
        padding: 20px;
        border-radius: 5px;
        margin-bottom: 20px;
        background-color: #ffe6e6;
        border-left: 5px solid #dc3545;
        color: black;
    }
    .success-box {
        padding: 20px;
        border-radius: 5px;
        margin-bottom: 20px;
        background-color: #e6ffee;
        border-left: 5px solid #28a745;
        color: black;
    }
    .tooltip {
        position: relative;
        display: inline-block;
        border-bottom: 1px dotted black;
        cursor: help;
    }
    .tooltip .tooltiptext {
        visibility: hidden;
        width: 200px;
        background-color: #555;
        color: #fff;
        text-align: center;
        border-radius: 6px;
        padding: 5px;
        position: absolute;
        z-index: 1;
        bottom: 125%;
        left: 50%;
        margin-left: -100px;
        opacity: 0;
        transition: opacity 0.3s;
    }
    .tooltip:hover .tooltiptext {
        visibility: visible;
        opacity: 1;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to display tooltips
def tooltip(text, help_text):
    return f'<div class="tooltip">{text}<span class="tooltiptext">{help_text}</span></div>'

# API Keys
ABUSEIPDB_API_KEY = st.secrets["ABUSEIPDB_API_KEY"] if "ABUSEIPDB_API_KEY" in st.secrets else "YOUR_ABUSEIPDB_API_KEY"
IPINFO_API_KEY = st.secrets["IPINFO_API_KEY"] if "IPINFO_API_KEY" in st.secrets else "YOUR_IPINFO_API_KEY"
VIRUSTOTAL_API_KEY = st.secrets["VIRUSTOTAL_API_KEY"] if "VIRUSTOTAL_API_KEY" in st.secrets else "YOUR_VIRUSTOTAL_API_KEY"
GREYNOISE_API_KEY = st.secrets["GREYNOISE_API_KEY"] if "GREYNOISE_API_KEY" in st.secrets else "YOUR_GREYNOISE_API_KEY"
SHODAN_API_KEY = st.secrets["SHODAN_API_KEY"] if "SHODAN_API_KEY" in st.secrets else "YOUR_SHODAN_API_KEY"

common_ports = {
    22: "SSH - Secure Shell",
    23: "Telnet",
    25: "SMTP - Email",
    80: "HTTP - Web",
    443: "HTTPS - Secure Web",
    445: "SMB - Windows File Sharing",
    3389: "RDP - Remote Desktop",
    8080: "HTTP Alternate",
    21: "FTP - File Transfer",
    53: "DNS - Domain Name System",
    135: "MSRPC - Microsoft RPC",
    139: "NetBIOS",
    1433: "MSSQL Database",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    27017: "MongoDB Database"
}

# Functions for API calls
def check_ip_abuseipdb(ip):
    """Check IP reputation using AbuseIPDB API"""
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': True
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def get_ip_info(ip):
    """Get geolocation information for an IP address"""
    url = f"https://ipinfo.io/{ip}?token={IPINFO_API_KEY}"
    try:
        response = requests.get(url)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def check_virustotal(query, query_type="ip"):
    """Check IP or domain against VirusTotal database"""
    if query_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
    else:  # domain
        url = f"https://www.virustotal.com/api/v3/domains/{query}"
        
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def check_greynoise(ip):
    """Check IP against Greynoise community API"""
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {
        "Accept": "application/json",
        "key": GREYNOISE_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def check_greynoise_context(ip):
    """Get detailed context information from Greynoise API"""
    url = f"https://api.greynoise.io/v2/noise/context/{ip}"
    headers = {
        "Accept": "application/json",
        "key": GREYNOISE_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def check_shodan(ip):
    """Get information about an IP address from Shodan"""
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url)
        return response.json() 
    except Exception as e:
        return {"error": str(e)}

# Helper function to render threat metrics
def render_threat_gauge(score, title, description=""):
    """Create a gauge chart for threat visualization"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"{title}<br><span style='font-size:0.8em;color:gray'>{description}</span>", 'font': {'size': 16}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 30], 'color': "green"},
                {'range': [30, 70], 'color': "yellow"},
                {'range': [70, 100], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': score
            }
        }
    ))
    fig.update_layout(height=250, margin=dict(l=20, r=20, t=50, b=20))
    return fig

# Main dashboard
st.title("🕵🏻‍♂️ CyberIntel")
st.markdown("## 🔒 Cybersecurity Threat Intelligence Dashboard")
st.markdown("""
This dashboard helps you analyze IP addresses and domains for potential security threats by combining data from multiple 
security intelligence sources. Use the controls in the sidebar to begin your analysis.
""")

# Sidebar for input
with st.sidebar:
    st.header("Analysis Controls")
    
    # Help text
    st.markdown("""
    <div class="info-box">
        Enter an IP address or domain name to analyze its security profile and potential threats.
    </div>
    """, unsafe_allow_html=True)
    
    query_type = st.radio("Select what you want to analyze:", ["IP Address", "Domain"])
    
    if query_type == "IP Address":
        query = st.text_input("Enter IP Address to analyze", placeholder="e.g., 8.8.8.8")
        st.caption("Enter a public IP address to check its reputation and threat intelligence")
    else:
        query = st.text_input("Enter Domain to analyze", placeholder="e.g., example.com")
        st.caption("Enter a domain name without http:// or www")
    
    analyze_button = st.button("🔍 Analyze Now", use_container_width=True)
    
    if analyze_button:
        if not query:
            st.error("⚠️ Please enter a valid IP address or domain")
        else:
            st.session_state.query = query
            st.session_state.query_type = "ip" if query_type == "IP Address" else "domain"
            st.session_state.run_analysis = True
    
    st.markdown("---")
    
    # Explanation of security services
    with st.expander("🔍 About Security Services Used"):
        st.markdown("""
        This dashboard uses the following security intelligence services:
        
        **AbuseIPDB**: Database of reported malicious IP addresses and their activity history.
        
        **IPInfo**: Provides geolocation and network information for IP addresses.
        
        **VirusTotal**: Analyzes IPs and domains against 70+ antivirus scanners and URL/domain blocklists.
        
        **Greynoise**: Identifies Internet-wide scanners and malicious activity.
        
        **Shodan**: Search engine for Internet-connected devices and services.
        """)

# Main content
if 'run_analysis' in st.session_state and st.session_state.run_analysis:
    query = st.session_state.query
    query_type = st.session_state.query_type
    
    progress_bar = st.progress(0, text="Starting analysis...")
    
    st.subheader(f"Analysis Results for: {query}")
    
    # Create tabs for different analysis results
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Overview", "🔍 Threat Details", "🌎 Geolocation", "🔌 Services & Ports", "📝 Raw Data"])
    
    # Store API results
    results = {}
    
    # Fetch data from APIs with progress updates
    if query_type == "ip":
        progress_bar.progress(10, text="Checking AbuseIPDB reputation...")
        results["abuseipdb"] = check_ip_abuseipdb(query)
        
        progress_bar.progress(25, text="Getting IP geolocation...")
        results["ipinfo"] = get_ip_info(query)
        
        progress_bar.progress(40, text="Checking Greynoise for malicious activity...")
        results["greynoise"] = check_greynoise(query)
        results["greynoise_context"] = check_greynoise_context(query)
        
        progress_bar.progress(60, text="Checking Shodan for exposed services...")
        results["shodan"] = check_shodan(query)
    
    progress_bar.progress(80, text="Checking VirusTotal database...")
    results["virustotal"] = check_virustotal(query, query_type)
    
    progress_bar.progress(100, text="Analysis complete!")
    
    # Tab 1: Overview
    with tab1:
        st.markdown("### Security Analysis Summary")
        st.markdown("""
        This overview shows the security risk scores from different intelligence sources 
        and provides a summary of the findings.
        """)
        
        # Create two columns for layout
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("#### Threat Risk Scores")
            st.caption("Scores below 30 are low risk, 30-70 medium risk, above 70 high risk")
            
            # Calculate and display threat scores
            threat_scores = {}
            
            if query_type == "ip" and "data" in results["abuseipdb"]:
                abuse_score = results["abuseipdb"]["data"]["abuseConfidenceScore"]
                description = "Based on reported abuse in the last 90 days"
                st.plotly_chart(render_threat_gauge(abuse_score, "AbuseIPDB Score", description))
                threat_scores["AbuseIPDB"] = abuse_score
            
            if "data" in results["virustotal"]:
                # For VT, calculate percentage of engines that detected it
                try:
                    stats = results["virustotal"]["data"]["attributes"]["last_analysis_stats"]
                    total = sum(stats.values())
                    malicious = stats.get("malicious", 0)
                    vt_score = (malicious / total) * 100 if total > 0 else 0
                    description = f"{malicious} of {total} security vendors flagged as malicious"
                    st.plotly_chart(render_threat_gauge(vt_score, "VirusTotal Score", description))
                    threat_scores["VirusTotal"] = vt_score
                except KeyError:
                    pass
            
            # Add Greynoise score for IP addresses
            if query_type == "ip" and "seen" in results["greynoise"]:
                greynoise_score = 0
                description = "Based on Internet scanning activity"
                if results["greynoise"].get("malicious", False):
                    greynoise_score = 100
                    description += " - Identified as Malicious"
                elif results["greynoise"].get("seen", False):
                    # If seen but not marked as malicious, give a medium score
                    greynoise_score = 50
                    description += " - Observed Scanner"
                
                st.plotly_chart(render_threat_gauge(greynoise_score, "Greynoise Risk", description))
                threat_scores["Greynoise"] = greynoise_score
                
            # Add Shodan score if available
            if query_type == "ip" and "ports" in results["shodan"] and not "error" in results["shodan"]:
                # Calculate risk score based on number of open ports and certain risky services
                risky_ports = [21, 22, 23, 25, 53, 80, 443, 3389, 8080]
                open_ports = results["shodan"].get("ports", [])
                vulns = results["shodan"].get("vulns", [])
                
                # Base score on number of open ports and if there are known vulnerabilities
                shodan_score = min(len(open_ports) * 10, 50)  # Max 50 for open ports
                
                # Add points for risky ports
                for port in risky_ports:
                    if port in open_ports:
                        shodan_score += 5
                
                # Add points for CVEs (vulnerabilities)
                if vulns:
                    shodan_score += min(len(vulns) * 15, 50)
                
                # Cap at 100
                shodan_score = min(shodan_score, 100)
                
                description = f"{len(open_ports)} open ports, {len(vulns)} vulnerabilities"
                st.plotly_chart(render_threat_gauge(shodan_score, "Shodan Exposure Risk", description))
                threat_scores["Shodan"] = shodan_score
        
        with col2:
            st.markdown("#### Key Findings")
            
            # Display summary information
            if query_type == "ip":
                if "data" in results["abuseipdb"]:
                    data = results["abuseipdb"]["data"]
                    
                    st.markdown("##### Network Information")
                    info_cols = st.columns(2)
                    with info_cols[0]:
                        st.write("**Internet Service Provider:**")
                        st.write(data.get('isp', 'Unknown'))
                    with info_cols[1]:
                        st.write("**Usage Type:**")
                        st.write(data.get('usageType', 'Unknown'))
                    
                    st.write("**Domain Name:**", data.get('domain', 'Unknown'))
                    st.write("**Times Reported:**", data.get('totalReports', 0))
                
                if "org" in results["ipinfo"]:
                    st.markdown("##### Location Information")
                    st.write("**Organization:**", results['ipinfo'].get('org', 'Unknown'))
                    st.write("**Location:**", f"{results['ipinfo'].get('city', 'Unknown')}, {results['ipinfo'].get('country', 'Unknown')}")
                
                # Add Greynoise summary info
                if "seen" in results["greynoise"]:
                    st.markdown("##### Internet Activity")
                    activity = 'Observed' if results['greynoise'].get('seen', False) else 'Not Observed'
                    st.write("**Internet Scanning Activity:**", activity)
                    st.write("**Classification:**", results['greynoise'].get('classification', 'Unknown'))
                    malicious = 'Yes' if results['greynoise'].get('malicious', False) else 'No'
                    st.write("**Known Malicious:**", malicious)
                    
                    if results['greynoise'].get('seen', False):
                        st.write("**Last Seen:**", results['greynoise'].get('last_seen', 'Unknown'))
                
                # Add Shodan summary info
                if "ports" in results["shodan"] and not "error" in results["shodan"]:
                    st.markdown("##### Exposed Services")
                    open_ports = results["shodan"].get("ports", [])
                    vulns = results["shodan"].get("vulns", [])
                    
                    st.write("**Open Ports:**", ", ".join([str(p) for p in open_ports]) if open_ports else "None detected")
                    st.write("**Known Vulnerabilities:**", len(vulns))
                    last_update = results["shodan"].get("last_update", 0)
                    try:
    # Try to convert to float if it's a string
                        if isinstance(last_update, str):
                            last_update = float(last_update)
                            last_scan_date = datetime.fromtimestamp(last_update).strftime("%Y-%m-%d")
                    except (ValueError, TypeError):
                            last_scan_date = "Unknown"
                    st.write("**Last Scan:**", last_scan_date)

            else:  # domain
                if "data" in results["virustotal"]:
                    try:
                        vt_data = results["virustotal"]["data"]["attributes"]
                        st.markdown("##### Domain Information")
                        creation_date = datetime.fromtimestamp(vt_data.get('creation_date', 0)).strftime('%Y-%m-%d') if vt_data.get('creation_date', 0) else 'Unknown'
                        st.write("**Creation Date:**", creation_date)
                        
                        last_update = datetime.fromtimestamp(vt_data.get('last_update_date', 0)).strftime('%Y-%m-%d') if vt_data.get('last_update_date', 0) else 'Unknown'
                        st.write("**Last Update:**", last_update)
                        
                        st.write("**Reputation Score:**", vt_data.get('reputation', 'Unknown'))
                    except KeyError:
                        pass
            
            # Calculate overall threat rating
            if threat_scores:
                avg_score = sum(threat_scores.values()) / len(threat_scores)
                threat_level = "Low" if avg_score < 30 else "Medium" if avg_score < 70 else "High"
                
                st.markdown("---")
                st.markdown("### Overall Security Assessment")
                
                # Use appropriate styling based on threat level
                if threat_level == "High":
                    st.markdown(f"""
                    <div class="danger-box">
                        <h4>High Risk - {avg_score:.1f}%</h4>
                        <p>This {query_type} shows significant suspicious activity. It is recommended to block or closely monitor any traffic from this source.</p>
                    </div>
                    """, unsafe_allow_html=True)
                elif threat_level == "Medium":
                    st.markdown(f"""
                    <div class="warning-box">
                        <h4>Medium Risk - {avg_score:.1f}%</h4>
                        <p>This {query_type} shows some suspicious activity. Consider additional verification before trusting this source.</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="success-box">
                        <h4>Low Risk - {avg_score:.1f}%</h4>
                        <p>This {query_type} appears to be safe based on current intelligence. No significant threats detected.</p>
                    </div>
                    """, unsafe_allow_html=True)
    
    # Tab 2: Threat Details
    with tab2:
        st.markdown("### Detailed Threat Analysis")
        st.markdown("This section provides in-depth information about specific threats and activities associated with this IP/domain.")
        
        if query_type == "ip" and "data" in results["abuseipdb"]:
            st.markdown("#### Abuse Reports History")
            if "reports" in results["abuseipdb"]["data"] and results["abuseipdb"]["data"]["reports"]:
                st.info("The table below shows reports submitted by security researchers and network administrators.")
                
                reports_data = []
                for report in results["abuseipdb"]["data"]["reports"]:
                    reported_at = datetime.fromisoformat(report["reportedAt"].replace("Z", "+00:00"))
                    reports_data.append({
                        "Reported At": reported_at.strftime("%Y-%m-%d %H:%M"),
                        "Category": ", ".join([str(c) for c in report["categories"]]),
                        "Comment": report.get("comment", "No comment")
                    })
                
                reports_df = pd.DataFrame(reports_data)
                st.dataframe(reports_df, use_container_width=True)
                
                # Show categories distribution
                if reports_data:
                    all_categories = []
                    for report in results["abuseipdb"]["data"]["reports"]:
                        all_categories.extend(report["categories"])
                    
                    category_names = {
                        3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
                        6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
                        9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
                        12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
                        15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
                        18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
                        21: "Web App Attack", 22: "SSH Attack", 23: "IoT Targeted"
                    }
                    
                    if all_categories:
                        category_counts = {}
                        for cat in all_categories:
                            cat_name = category_names.get(cat, f"Category {cat}")
                            category_counts[cat_name] = category_counts.get(cat_name, 0) + 1
                        
                        # Create bar chart with better styling
                        cat_df = pd.DataFrame({
                            "Category": list(category_counts.keys()),
                            "Count": list(category_counts.values())
                        }).sort_values("Count", ascending=False)
                        
                        st.markdown("#### Types of Malicious Activity Reported")
                        st.caption("This chart shows the distribution of reported malicious activities")
                        
                        fig = px.bar(
                            cat_df, 
                            x="Category", 
                            y="Count", 
                            title="",
                            color="Count",
                            color_continuous_scale=px.colors.sequential.Blues
                        )
                        fig.update_layout(
                            xaxis_title="Type of Activity",
                            yaxis_title="Number of Reports",
                            height=400
                        )
                        st.plotly_chart(fig, use_container_width=True)
                        
                        st.markdown("""
                        ##### Understanding Attack Categories
                        - **Port Scan**: Probing for open ports to find vulnerabilities
                        - **Brute-Force**: Attempting to guess passwords by trying many combinations
                        - **Web App Attack**: Targeting vulnerabilities in web applications
                        - **SSH Attack**: Attempting to gain unauthorized access via SSH
                        - **Hacking**: General unauthorized access attempts
                        """)
            else:
                st.info("No abuse reports have been submitted for this IP address in the last 90 days.")
        
        # VirusTotal results
        if "data" in results["virustotal"]:
            st.markdown("#### VirusTotal Security Analysis")
            st.caption("Analysis from 70+ security vendors and scanning engines")
            
            try:
                stats = results["virustotal"]["data"]["attributes"]["last_analysis_stats"]
                last_analysis = results["virustotal"]["data"]["attributes"]["last_analysis_results"]
                
                # Create pie chart for results with better styling
                fig = px.pie(
                    values=list(stats.values()),
                    names=list(stats.keys()),
                    title="Security Vendor Results",
                    color_discrete_map={
                        'malicious': '#dc3545',
                        'suspicious': '#ffc107',
                        'harmless': '#28a745',
                        'undetected': '#6c757d',
                        'timeout': '#6c757d'
                    }
                )
                fig.update_traces(textposition='inside', textinfo='percent+label')
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
                
                # Show legend explaining the categories
                st.markdown("""
                **What these results mean:**
                - **Malicious**: Confirmed malicious by security vendors
                - **Suspicious**: Potentially malicious but not confirmed
                - **Harmless**: Confirmed to be safe
                - **Undetected**: No threats detected
                - **Timeout**: Vendor couldn't complete the scan
                """)
                
                # Show detailed results from engines
                if last_analysis:
                    st.markdown("#### Detailed Security Vendor Results")
                    st.caption("Expand to see results from individual security vendors")
                    
                    with st.expander("View all security vendor results"):
                        engines_data = []
                        for engine, result in last_analysis.items():
                            engines_data.append({
                                "Security Vendor": engine,
                                "Category": result.get("category", "Unknown"),
                                "Result": result.get("result", "None")
                            })
                        
                        engines_df = pd.DataFrame(engines_data)
                        
                        # Add color coding to the dataframe
                        def color_category(val):
                            if val == "malicious":
                                return "background-color: #ffdddd"
                            elif val == "suspicious":
                                return "background-color: #fff3cd"
                            elif val == "harmless":
                                return "background-color: #d4edda"
                            else:
                                return ""
                        
                        styled_df = engines_df.sort_values("Category").style.applymap(color_category, subset=["Category"])
                        st.dataframe(styled_df, use_container_width=True)
            except KeyError:
                st.info("Detailed VirusTotal analysis not available for this IP/domain.")
        
        # Greynoise results (IP addresses only)
        if query_type == "ip" and "greynoise_context" in results and "seen" in results["greynoise_context"]:
            st.markdown("#### Greynoise Internet Activity Analysis")
            st.caption("Analysis of scanning activity and behavior on the internet")
            
            # Display Greynoise context information
            gn_data = results["greynoise_context"]
            
            # Show activity tags
            if "tags" in gn_data and gn_data["tags"]:
                st.markdown("##### Activity Tags")
                st.caption("These tags describe the behavior observed from this IP address")
                
                tags = gn_data["tags"]
                tag_html = "<div style='display: flex; flex-wrap: wrap; gap: 8px;'>"
                for tag in tags:
                    tag_html += f"<span style='background-color: #f0f0f0; padding: 5px 10px; border-radius: 15px; font-size: 0.8em;'>{tag}</span>"
                tag_html += "</div>"
                st.markdown(tag_html, unsafe_allow_html=True)
            
            # Show activity timeline
            if "actor" in gn_data:
                st.markdown("##### Classification")
                
                classifier_cols = st.columns(2)
                with classifier_cols[0]:
                    st.write("**Actor Type:**", gn_data.get('actor', 'Unknown'))
                with classifier_cols[1]:
                    st.write("**Classification:**", gn_data.get('classification', 'Unknown'))
                
                timeline_cols = st.columns(2)
                with timeline_cols[0]:
                    st.write("**First Observed:**", gn_data.get('first_seen', 'Unknown'))
                with timeline_cols[1]:
                    st.write("**Last Observed:**", gn_data.get('last_seen', 'Unknown'))
                
                # Show destination ports
                if "raw_data" in gn_data and "destination_ports" in gn_data["raw_data"]:
                    ports = gn_data["raw_data"]["destination_ports"]
                    if ports:
                        st.markdown("##### Targeted Ports")
                        st.caption("Most frequently scanned ports by this IP address")
                        
                        port_counts = {}
                        for port in ports:
                            port_counts[port] = port_counts.get(port, 0) + 1
                        
                        port_df = pd.DataFrame({
                            "Port": list(port_counts.keys()),
                            "Count": list(port_counts.values())
                        }).sort_values("Count", ascending=False)
                        
                        # Create a bar chart with better styling
                        fig = px.bar(
                            port_df, 
                            x="Port", 
                            y="Count", 
                            title="",
                            color="Count",
                            color_continuous_scale=px.colors.sequential.Purples
                        )
                        fig.update_layout(
                            xaxis_title="Port Number",
                            yaxis_title="Times Scanned",
                            height=400
                        )
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Add common port explanations
                        common_ports = {
                            22: "SSH - Secure Shell",
                            23: "Telnet",
                            25: "SMTP - Email",
                            80: "HTTP - Web",
                            443: "HTTPS - Secure Web",
                            445: "SMB - Windows File Sharing",
                            3389: "RDP - Remote Desktop",
                            8080: "HTTP Alternate",
                            21: "FTP - File Transfer",
                            53: "DNS - Domain Name System",
                            135: "MSRPC - Microsoft RPC",
                            139: "NetBIOS",
                            1433: "MSSQL Database",
                            3306: "MySQL Database",
                            5432: "PostgreSQL Database",
                            27017: "MongoDB Database"
                        }
                        
                        # Show common port explanations
                        st.markdown("##### Common Port References")
                        port_html = "<div style='display: flex; flex-wrap: wrap; gap: 8px;'>"
                        for port, desc in common_ports.items():
                            if port in port_df["Port"].values:
                                port_html += f"<span style='background-color: #e6e6ff; padding: 5px 10px; border-radius: 15px; font-size: 0.8em;'><b>Port {port}</b>: {desc}</span>"
                        port_html += "</div>"
                        st.markdown(port_html, unsafe_allow_html=True)
    
    # Tab 3: Geolocation
    with tab3:
        st.markdown("### Geolocation Analysis")
        st.markdown("This section shows the geographical location of the IP address and related information.")
        
        # Only show geolocation tab content for IP addresses
        if query_type == "ip":
            # Get location data
            if "ipinfo" in results and "loc" in results["ipinfo"]:
                try:
                    location = results["ipinfo"]["loc"].split(",")
                    lat = float(location[0])
                    lon = float(location[1])
                    
                    # Create map centered on the IP location
                    m = folium.Map(location=[lat, lon], zoom_start=10)
                    
                    # Add a marker for the IP
                    folium.Marker(
                        [lat, lon],
                        popup=f"IP: {query}<br>ISP: {results['ipinfo'].get('org', 'Unknown')}",
                        tooltip=f"IP Location: {results['ipinfo'].get('city', 'Unknown')}, {results['ipinfo'].get('country', 'Unknown')}",
                        icon=folium.Icon(color="red", icon="info-sign")
                    ).add_to(m)
                    
                    # Add circle to show approximate area
                    folium.Circle(
                        radius=5000,
                        location=[lat, lon],
                        color="crimson",
                        fill=True,
                    ).add_to(m)
                    
                    # Display the map
                    st.markdown("#### IP Location Map")
                    folium_static(m, width=700, height=500)
                    
                    # Show additional location information
                    st.markdown("#### Location Details")
                    
                    loc_cols = st.columns(2)
                    with loc_cols[0]:
                        st.markdown("##### Network Information")
                        st.write("**ASN:**", results["ipinfo"].get("asn", {}).get("asn", "Unknown"))
                        st.write("**ASN Name:**", results["ipinfo"].get("asn", {}).get("name", "Unknown"))
                        st.write("**ASN Domain:**", results["ipinfo"].get("asn", {}).get("domain", "Unknown"))
                        st.write("**ASN Type:**", results["ipinfo"].get("asn", {}).get("type", "Unknown"))
                    
                    with loc_cols[1]:
                        st.markdown("##### Geographical Information")
                        st.write("**City:**", results["ipinfo"].get("city", "Unknown"))
                        st.write("**Region:**", results["ipinfo"].get("region", "Unknown"))
                        st.write("**Country:**", results["ipinfo"].get("country", "Unknown"))
                        st.write("**Postal Code:**", results["ipinfo"].get("postal", "Unknown"))
                        st.write("**Timezone:**", results["ipinfo"].get("timezone", "Unknown"))
                    
                    # Show privacy information
                    if "privacy" in results["ipinfo"]:
                        st.markdown("##### Privacy Analysis")
                        st.write("**Proxy:**", results["ipinfo"]["privacy"].get("proxy", "Unknown"))
                        st.write("**VPN:**", results["ipinfo"]["privacy"].get("vpn", "Unknown"))
                        st.write("**Tor:**", results["ipinfo"]["privacy"].get("tor", "Unknown"))
                        st.write("**Hosting:**", results["ipinfo"]["privacy"].get("hosting", "Unknown"))
                    
                except Exception as e:
                    st.error(f"Error creating map: {str(e)}")
            else:
                st.warning("Geolocation information not available for this IP address.")
        else:
            st.info("Geolocation information is only available for IP addresses, not domains.")
    
    # Tab 4: Services & Ports
    with tab4:
        st.markdown("### Services & Exposed Ports")
        st.markdown("This section shows services running on the IP address and any exposed ports.")
        
        if query_type == "ip" and "shodan" in results and "ports" in results["shodan"]:
            ports = results["shodan"].get("ports", [])
            
            if ports:
                st.markdown("#### Open Ports")
                
                # Create a table of open ports
                ports_data = []
                for port in ports:
                    port_info = {
                        "Port": port,
                        "Likely Service": common_ports.get(port, "Unknown"),
                        "Risk Level": "High" if port in [21, 22, 23, 25, 3389] else "Medium" if port in [80, 443, 8080] else "Low"
                    }
                    ports_data.append(port_info)
                
                ports_df = pd.DataFrame(ports_data)
                
                # Color-code the risk levels
                def color_risk(val):
                    if val == "High":
                        return "background-color: #ffdddd; color: #000000"
                    elif val == "Medium":
                        return "background-color: #fff3cd; color: #000000"
                    else:
                        return "background-color: #d4edda; color: #000000"
                
                styled_ports_df = ports_df.style.applymap(color_risk, subset=["Risk Level"])
                st.dataframe(styled_ports_df, use_container_width=True)
                
                # Show vulnerabilities if available
                vulns = results["shodan"].get("vulns", [])
                if vulns:
                    st.markdown("#### Known Vulnerabilities (CVEs)")
                    
                    # Create columns for CVE info
                    vuln_data = []
                    for vuln in vulns:
                        vuln_data.append({
                            "CVE ID": vuln,
                            "CVSS Score": results["shodan"].get("vulns", {}).get(vuln, {}).get("cvss", "Unknown"),
                            "Summary": results["shodan"].get("vulns", {}).get(vuln, {}).get("summary", "No summary available")
                        })
                    
                    vuln_df = pd.DataFrame(vuln_data)
                    st.dataframe(vuln_df, use_container_width=True)
                
                # Show services detected
                if "data" in results["shodan"]:
                    service_data = results["shodan"]["data"]
                    
                    st.markdown("#### Detected Services")
                    st.caption("Services detected on the open ports")
                    
                    for service in service_data:
                        with st.expander(f"Service on Port {service.get('port', 'Unknown')}"):
                            st.write("**Transport Protocol:**", service.get("transport", "Unknown"))
                            st.write("**Service Name:**", service.get("_shodan", {}).get("module", "Unknown"))
                            
                            if "ssl" in service:
                                st.write("**SSL Enabled:**", "Yes")
                                st.write("**SSL Version:**", service.get("ssl", {}).get("version", "Unknown"))
                            
                            # Show service banner if available
                            if "data" in service:
                                st.markdown("##### Service Banner")
                                st.code(service["data"])
            else:
                st.info("No open ports detected for this IP address.")
        else:
            st.info("Service and port information is only available for IP addresses.")
    
    # Tab 5: Raw Data
    with tab5:
        st.markdown("### Raw API Data")
        st.markdown("This section shows the raw data retrieved from the security APIs.")
        
        if query_type == "ip":
            with st.expander("AbuseIPDB Raw Data"):
                st.json(results["abuseipdb"])
            
            with st.expander("IPInfo Raw Data"):
                st.json(results["ipinfo"])
            
            with st.expander("Greynoise Raw Data"):
                st.json(results["greynoise"])
                st.json(results["greynoise_context"])
            
            with st.expander("Shodan Raw Data"):
                st.json(results["shodan"])
        
        with st.expander("VirusTotal Raw Data"):
            st.json(results["virustotal"])
        
else:
    # Dashboard home screen
    st.markdown("""
    ## 🛡️ Welcome to the Cybersecurity Threat Intelligence Dashboard
    
    This dashboard provides comprehensive threat intelligence about IP addresses and domains by integrating multiple security APIs:
    
    - **AbuseIPDB**: Check IP address reputation and history of abuse reports
    - **IPInfo**: Get geolocation and network information
    - **VirusTotal**: Analyze threats detected by multiple security engines
    - **Greynoise**: Analyze internet scanning activity and malicious behavior
    
    ### Getting Started
    
    1. Select query type (IP or Domain) in the sidebar
    2. Enter the IP address or domain you want to analyze
    3. Click "Analyze" to fetch and visualize threat intelligence
    
    ### Features
    
    - Comprehensive threat scoring from multiple sources
    - Detailed abuse reports and categories
    - Geolocation mapping and network details
    - Security engine detection results
    """)
    
    st.info("👈 Enter an IP address or domain in the sidebar to begin analysis")

    
    # Reset the analysis trigger
    st.session_state.run_analysis = False

# Add a disclaimer at the bottom of the page
st.markdown("---")
st.markdown("""
<div style="font-size: 0.8em; color: #6c757d;">
<strong>Disclaimer:</strong> This dashboard is for educational and informational purposes only. The information provided is based on data from various third-party security intelligence sources and may not be 100% accurate. Always verify critical security information with multiple sources.
</div>
""", unsafe_allow_html=True)
#!/usr/bin/env python3
"""
Autonomous Offline Vulnerability Intelligence & Actionable Risk Mitigation Platform
Main Application Entry Point
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import os
import subprocess
import platform
import time
import pickle
from datetime import datetime, timedelta
import requests
import xml.etree.ElementTree as ET
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import warnings
warnings.filterwarnings('ignore')

# Configure Streamlit
st.set_page_config(
    page_title="Threat & Vulnerability Management",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional dashboard
st.markdown("""
<style>
    .main-header {
        font-size: 28px;
        font-weight: bold;
        color: #1f2937;
        margin-bottom: 20px;
    }
    
    .metric-card {
        background: white;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin: 10px 0;
    }
    
    .severity-high {
        color: #dc2626;
        font-weight: bold;
    }
    
    .severity-medium {
        color: #f59e0b;
        font-weight: bold;
    }
    
    .severity-low {
        color: #eab308;
        font-weight: bold;
    }
    
    .severity-none {
        color: #10b981;
        font-weight: bold;
    }
    
    .stButton > button {
        width: 100%;
        background-color: #3b82f6;
        color: white;
        border: none;
        padding: 10px;
        border-radius: 5px;
    }
    
    .vulnerability-item {
        background: #f8fafc;
        padding: 15px;
        border-left: 4px solid #3b82f6;
        margin: 10px 0;
        border-radius: 5px;
    }
    
    .success-box {
        background-color: #d1fae5;
        color: #065f46;
        padding: 10px;
        border-radius: 5px;
        margin: 10px 0;
    }
    
    .error-box {
        background-color: #fee2e2;
        color: #b91c1c;
        padding: 10px;
        border-radius: 5px;
        margin: 10px 0;
    }
    
    .warning-box {
        background-color: #fef3c7;
        color: #92400e;
        padding: 10px;
        border-radius: 5px;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

class VulnerabilityAnalyzer:
    def __init__(self):
        self.data_dir = "data"
        self.models_dir = "models"
        self.ensure_directories()
        self.ml_model = None
        self.label_encoders = {}
        self.vulnerability_data = pd.DataFrame()
        
    def ensure_directories(self):
        """Create necessary directories"""
        for dir_name in [self.data_dir, self.models_dir]:
            if not os.path.exists(dir_name):
                os.makedirs(dir_name)
    
    def check_ollama_status(self):
        """Check if Ollama is running and available with Windows compatibility"""
        try:
            # Windows-compatible check
            if platform.system() == "Windows":
                check_installed = subprocess.run(
                    ['where', 'ollama'],
                    capture_output=True,
                    text=True,
                    shell=True
                )
            else:
                check_installed = subprocess.run(
                    ['which', 'ollama'],
                    capture_output=True,
                    text=True
                )
            
            # Check if installed
            if check_installed.returncode != 0:
                return False, "Ollama not installed or not in PATH"

            # Check if running
            check_running = subprocess.run(
                ['ollama', 'list'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if check_running.returncode == 0:
                return True, "Ollama is running"
            else:
                return False, f"Ollama not responding: {check_running.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, "Ollama timed out"
        except Exception as e:
            return False, f"Error checking Ollama: {str(e)}"
    
    def query_ollama(self, prompt, model="phi4-mini:latest"):
        """Query local Ollama LLM"""
        try:
            cmd = ['ollama', 'run', model, prompt]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return f"Error querying LLM: {result.stderr}"
        except subprocess.TimeoutExpired:
            return "LLM query timed out"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def collect_windows_data(self):
        """Collect Windows system data using PowerShell"""
        if platform.system() != "Windows":
            return None, "Not running on Windows"
        
        powershell_script = """
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $data = @{}
        
        # System Information
        $data.ComputerInfo = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OSArchitecture
        
        # Installed Software
        $data.InstalledSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor
        
        # Windows Features
        $data.WindowsFeatures = Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} | Select-Object FeatureName
        
        # Services
        $data.Services = Get-Service | Select-Object Name, Status, StartType
        
        # Network Connections
        $data.NetworkConnections = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Select-Object LocalAddress, LocalPort, OwningProcess
        
        # Processes
        $data.Processes = Get-Process | Select-Object Name, Id, Company, Path
        
        $data | ConvertTo-Json -Depth 3
        """
        
        try:
            result = subprocess.run(['powershell', '-Command', powershell_script], 
                                  capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180)
            
            if result.returncode != 0:
                error_msg = f"PowerShell error (code {result.returncode}): {result.stderr}"
                return None, error_msg
                
            try:
                data = json.loads(result.stdout)
                return data, "Success"
            except json.JSONDecodeError:
                return None, "Invalid JSON output from PowerShell"
        except subprocess.TimeoutExpired:
            return None, "Data collection timed out"
        except Exception as e:
            return None, f"Error collecting Windows data: {str(e)}"
    
    def generate_linux_script(self):
        """Generate Linux system scanning script"""
        script_content = """#!/bin/bash
# Linux System Security Scanner
# Run as root for complete information

OUTPUT_FILE="linux_system_scan_$(date +%Y%m%d_%H%M%S).csv"

echo "Starting Linux system scan..."
echo "Hostname,Category,Item,Version,Status,Port,Process,Risk_Level" > $OUTPUT_FILE

HOSTNAME=$(hostname)

# Installed Packages (RPM-based)
if command -v rpm &> /dev/null; then
    rpm -qa --queryformat '%{NAME},%{VERSION},%{VENDOR}\n' | while IFS=',' read -r name version vendor; do
        echo "$HOSTNAME,Package,$name,$version,Installed,,$name,Medium" >> $OUTPUT_FILE
    done
fi

# Installed Packages (DEB-based)
if command -v dpkg &> /dev/null; then
    dpkg-query -W -f='${Package},${Version},${Maintainer}\n' | while IFS=',' read -r name version maintainer; do
        echo "$HOSTNAME,Package,$name,$version,Installed,,$name,Medium" >> $OUTPUT_FILE
    done
fi

# Running Services
systemctl list-units --type=service --state=active --no-pager --plain | grep -v UNIT | while read -r line; do
    service=$(echo $line | awk '{print $1}')
    status=$(echo $line | awk '{print $2}')
    echo "$HOSTNAME,Service,$service,$status,Running,,$service,Low" >> $OUTPUT_FILE
done

# Open Ports
ss -tuln | grep LISTEN | while read -r line; do
    port=$(echo $line | awk '{print $5}' | sed 's/.*://')
    protocol=$(echo $line | awk '{print $1}')
    risk="Low"
    if [[ "$port" == "22" ]] || [[ "$port" == "80" ]] || [[ "$port" == "443" ]]; then
        risk="Medium"
    fi
    echo "$HOSTNAME,Port,$protocol,$port,Open,$port,,${risk}" >> $OUTPUT_FILE
done

# Running Processes
ps aux --no-headers | while read -r line; do
    process=$(echo $line | awk '{print $11}')
    pid=$(echo $line | awk '{print $2}')
    echo "$HOSTNAME,Process,$process,$pid,Running,,$process,Low" >> $OUTPUT_FILE
done

# Check for zombie processes
zombies=$(ps aux | grep -c '<defunct>')
if [ $zombies -gt 0 ]; then
    echo "$HOSTNAME,ZombieProcess,Found,$zombies,Active,,,High" >> $OUTPUT_FILE
fi

echo "Scan complete. Output saved to: $OUTPUT_FILE"
echo "Please upload this CSV file to the vulnerability analyzer."
"""
        
        script_path = os.path.join(self.data_dir, "scanLinuxOS.sh")
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # Make script executable
        os.chmod(script_path, 0o755)
        return script_path
    
    def parse_scan_file(self, file_content, file_type):
        """Parse various scan file formats"""
        vulnerabilities = []
        
        if file_type == "nmap":
            vulnerabilities = self.parse_nmap(file_content)
        elif file_type == "openvas":
            vulnerabilities = self.parse_openvas(file_content)
        elif file_type == "csv":
            vulnerabilities = self.parse_csv(file_content)
        
        return vulnerabilities
    
    def parse_nmap(self, content):
        """Parse Nmap XML output"""
        vulnerabilities = []
        try:
            root = ET.fromstring(content)
            for host in root.findall('host'):
                ip = host.find('address').get('addr')
                for port in host.findall('.//port'):
                    port_num = port.get('portid')
                    service = port.find('service')
                    if service is not None:
                        service_name = service.get('name', 'unknown')
                        version = service.get('version', 'unknown')
                        
                        vuln = {
                            'host': ip,
                            'port': port_num,
                            'service': service_name,
                            'version': version,
                            'severity': 'Medium',
                            'description': f'Open port {port_num} running {service_name}',
                            'cve': 'N/A'
                        }
                        vulnerabilities.append(vuln)
        except Exception as e:
            st.markdown(f'<div class="error-box">Error parsing Nmap file: {str(e)}</div>', unsafe_allow_html=True)
        
        return vulnerabilities
    
    def parse_openvas(self, content):
        """Parse OpenVAS XML output"""
        vulnerabilities = []
        try:
            root = ET.fromstring(content)
            for result in root.findall('.//result'):
                host = result.find('host').text if result.find('host') is not None else 'Unknown'
                port = result.find('port').text if result.find('port') is not None else 'Unknown'
                description = result.find('description').text if result.find('description') is not None else 'No description'
                severity = result.find('severity').text if result.find('severity') is not None else 'Medium'
                
                vuln = {
                    'host': host,
                    'port': port,
                    'service': 'Unknown',
                    'version': 'Unknown',
                    'severity': severity,
                    'description': description,
                    'cve': 'N/A'
                }
                vulnerabilities.append(vuln)
        except Exception as e:
            st.markdown(f'<div class="error-box">Error parsing OpenVAS file: {str(e)}</div>', unsafe_allow_html=True)
        
        return vulnerabilities
    
    def parse_csv(self, content):
        """Parse CSV scan files"""
        vulnerabilities = []
        try:
            df = pd.read_csv(content)
            for _, row in df.iterrows():
                vuln = {
                    'host': row.get('Hostname', 'Unknown'),
                    'port': row.get('Port', 'N/A'),
                    'service': row.get('Item', 'Unknown'),
                    'version': row.get('Version', 'Unknown'),
                    'severity': row.get('Risk_Level', 'Medium'),
                    'description': f"{row.get('Category', 'Unknown')}: {row.get('Item', 'Unknown')}",
                    'cve': 'N/A'
                }
                vulnerabilities.append(vuln)
        except Exception as e:
            st.markdown(f'<div class="error-box">Error parsing CSV file: {str(e)}</div>', unsafe_allow_html=True)
        
        return vulnerabilities
    
    def train_ml_model(self, data):
        """Train RandomForest model for vulnerability classification"""
        if len(data) < 10:
            return "Insufficient data for training (minimum 10 records required)"
        
        df = pd.DataFrame(data)
        
        # Feature engineering
        features = ['service', 'port', 'host']
        target = 'severity'
        
        # Encode categorical variables
        X = df[features].copy()
        for col in features:
            if col not in self.label_encoders:
                self.label_encoders[col] = LabelEncoder()
            X[col] = self.label_encoders[col].fit_transform(X[col].astype(str))
        
        # Encode target
        if 'severity_encoder' not in self.label_encoders:
            self.label_encoders['severity_encoder'] = LabelEncoder()
        y = self.label_encoders['severity_encoder'].fit_transform(df[target])
        
        # Train model
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.ml_model.fit(X_train, y_train)
        
        # Save model
        model_path = os.path.join(self.models_dir, 'vulnerability_model.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': self.ml_model,
                'encoders': self.label_encoders,
                'features': features
            }, f)
        
        # Evaluate
        y_pred = self.ml_model.predict(X_test)
        accuracy = (y_pred == y_test).mean()
        
        return f"Model trained successfully. Accuracy: {accuracy:.2%}"
    
    def predict_vulnerability_risk(self, vulnerability):
        """Predict risk level for a vulnerability"""
        if self.ml_model is None:
            return vulnerability.get('severity', 'Medium')
        
        try:
            features = ['service', 'port', 'host']
            X = []
            
            for feature in features:
                value = vulnerability.get(feature, 'unknown')
                if feature in self.label_encoders:
                    try:
                        encoded = self.label_encoders[feature].transform([str(value)])[0]
                    except ValueError:
                        encoded = 0  # Unknown category
                else:
                    encoded = 0
                X.append(encoded)
            
            prediction = self.ml_model.predict([X])[0]
            severity = self.label_encoders['severity_encoder'].inverse_transform([prediction])[0]
            return severity
        except Exception:
            return vulnerability.get('severity', 'Medium')
    
    def get_llm_analysis(self, vulnerability_data, system_context=""):
        """Get LLM analysis for vulnerabilities"""
        prompt = f"""
        Analyze the following security findings and provide:
        1. Risk assessment and severity classification
        2. Potential impact on the organization
        3. Specific remediation steps
        4. ISO 27001 control mapping
        
        System Context: {system_context}
        
        Vulnerabilities:
        {json.dumps(vulnerability_data, indent=2)}
        
        Provide a structured analysis with clear recommendations.
        """
        
        return self.query_ollama(prompt)

# Initialize the analyzer
@st.cache_resource
def get_analyzer():
    return VulnerabilityAnalyzer()

analyzer = get_analyzer()

def main():
    st.markdown('<h1 class="main-header">🔒 Threat & Vulnerability Management Dashboard</h1>', unsafe_allow_html=True)
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox("Select Analysis Mode", [
        "Dashboard Overview",
        "System Analysis",
        "Scan File Analysis", 
        "Live Windows Analysis",
        "Linux System Analysis",
        "LLM Analysis",
        "ML Model Status"
    ])
    
    # Check LLM status
    llm_status, llm_message = analyzer.check_ollama_status()
    if llm_status:
        st.sidebar.success(f"✅ {llm_message}")
    else:
        st.sidebar.error(f"⚠️ {llm_message}")
        st.sidebar.info("Install Ollama: https://ollama.ai/ and run: `ollama pull phi`")
    
    if page == "Dashboard Overview":
        show_dashboard_overview()
    elif page == "System Analysis":
        show_system_analysis()
    elif page == "Scan File Analysis":
        show_scan_file_analysis()
    elif page == "Live Windows Analysis":
        show_windows_analysis()
    elif page == "Linux System Analysis":
        show_linux_analysis()
    elif page == "LLM Analysis":
        show_llm_analysis()
    elif page == "ML Model Status":
        show_ml_status()

def show_dashboard_overview():
    """Main dashboard overview"""
    st.subheader("Security Overview")
    
    # Load sample data if no real data exists
    if os.path.exists(os.path.join(analyzer.data_dir, "vulnerabilities.json")):
        with open(os.path.join(analyzer.data_dir, "vulnerabilities.json"), 'r') as f:
            vuln_data = json.load(f)
    else:
        # Sample data for demonstration
        vuln_data = [
            {"host": "cont-jonavolcot", "service": "Contoso Media Player", "severity": "High", "port": "445", "cve": "CVE-2023-1234"},
            {"host": "cont-sndirpc2", "service": "MsDoc", "severity": "High", "port": "135", "cve": "CVE-2023-5678"},
            {"host": "cont-manas-dev", "service": "Eclipse", "severity": "Medium", "port": "8080", "cve": "CVE-2023-9101"},
            {"host": "server-01", "service": "Adobe Acrobat", "severity": "High", "port": "80", "cve": "CVE-2023-1112"},
            {"host": "server-02", "service": "GLO v8", "severity": "Medium", "port": "443", "cve": "CVE-2023-1314"},
        ]
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_vulns = len(vuln_data)
        st.metric("Total Vulnerabilities", total_vulns, delta=f"+{len([v for v in vuln_data if v['severity'] == 'High'])}")
    
    with col2:
        exposure_score = 73
        st.metric("Exposure Score", exposure_score, delta="-5")
    
    with col3:
        config_score = "677/1270"
        st.metric("Configuration Score", config_score)
    
    with col4:
        devices_exposed = 60
        st.metric("Devices Exposed", devices_exposed, delta="+8")
    
    # Charts row
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Exposure Score Distribution")
        # Gauge chart for exposure score
        fig_gauge = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = exposure_score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Risk Level"},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 25], 'color': "lightgreen"},
                    {'range': [25, 50], 'color': "yellow"},
                    {'range': [50, 75], 'color': "orange"},
                    {'range': [75, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig_gauge.update_layout(height=300)
        st.plotly_chart(fig_gauge, use_container_width=True)
    
    with col2:
        st.subheader("Severity Distribution")
        severity_counts = pd.Series([v['severity'] for v in vuln_data]).value_counts()
        colors = {'High': '#dc2626', 'Medium': '#f59e0b', 'Low': '#eab308', 'None': '#10b981'}
        
        fig_pie = px.pie(
            values=severity_counts.values, 
            names=severity_counts.index,
            color=severity_counts.index,
            color_discrete_map=colors
        )
        fig_pie.update_layout(height=300)
        st.plotly_chart(fig_pie, use_container_width=True)
    
    # Configuration scores
    st.subheader("WDATP Configuration Score")
    config_data = {
        'Category': ['Application', 'OS', 'Network', 'Accounts', 'Security Controls'],
        'Score': [400, 200, 36, 21, 20],
        'Total': [520, 400, 100, 150, 200]
    }
    
    fig_bar = px.bar(
        x=config_data['Score'], 
        y=config_data['Category'],
        orientation='h',
        title="Configuration Scores by Category"
    )
    fig_bar.update_layout(height=300)
    st.plotly_chart(fig_bar, use_container_width=True)
    
    # Vulnerability table
    st.subheader("Top Vulnerable Software")
    df = pd.DataFrame(vuln_data)
    if not df.empty:
        vuln_summary = df.groupby('service').agg({
            'severity': 'count',
            'host': 'nunique'
        }).rename(columns={'severity': 'Vulnerabilities', 'host': 'Exposed Devices'})
        
        vuln_summary = vuln_summary.reset_index()
        vuln_summary['Risk Level'] = vuln_summary['Vulnerabilities'].apply(
            lambda x: 'High' if x >= 3 else 'Medium' if x >= 2 else 'Low'
        )
        
        st.dataframe(vuln_summary, use_container_width=True)

def show_system_analysis():
    """System analysis selection"""
    st.subheader("System Analysis")
    
    analysis_type = st.radio(
        "Select Analysis Type:",
        ["Windows System Analysis", "Linux System Analysis"]
    )
    
    if analysis_type == "Windows System Analysis":
        if platform.system() == "Windows":
            if st.button("Analyze This Windows System"):
                with st.spinner("Collecting Windows system data..."):
                    data, message = analyzer.collect_windows_data()
                    if data:
                        st.success("Windows data collected successfully!")
                        st.json(data)
                    else:
                        st.error(f"Failed to collect data: {message}")
        else:
            st.info("Windows analysis is only available on Windows systems.")
            st.info("Please upload scan files instead.")
    
    else:  # Linux Analysis
        st.info("For Linux analysis, download and run the system scan script:")
        
        if st.button("Generate Linux Scan Script"):
            script_path = analyzer.generate_linux_script()
            with open(script_path, 'r') as f:
                script_content = f.read()
            
            st.success(f"Script generated: {script_path}")
            if st.download_button(
                label="Download scanLinuxOS.sh",
                data=script_content,
                file_name="scanLinuxOS.sh",
                mime="text/plain"
            ):
                st.success("Script downloaded successfully!")
            
            st.markdown("""
            **Instructions:**
            1. Download the script above
            2. Transfer to your Linux system
            3. Run as root: `sudo bash scanLinuxOS.sh`
            4. Upload the generated CSV file in the next step
            """)

def show_scan_file_analysis():
    """Scan file upload and analysis"""
    st.subheader("Scan File Analysis")
    
    uploaded_files = st.file_uploader(
        "Upload scan files (Nmap XML, OpenVAS XML, CSV)",
        accept_multiple_files=True,
        type=['xml', 'csv']
    )
    
    if uploaded_files:
        all_vulnerabilities = []
        
        for uploaded_file in uploaded_files:
            try:
                file_content = uploaded_file.read()
                file_type = "csv" if uploaded_file.name.endswith('.csv') else "xml"
                
                if file_type == "xml":
                    # Determine if it's Nmap or OpenVAS
                    content_str = file_content.decode('utf-8')
                    if '<nmaprun' in content_str:
                        file_type = "nmap"
                    else:
                        file_type = "openvas"
                
                vulnerabilities = analyzer.parse_scan_file(file_content, file_type)
                if vulnerabilities:
                    all_vulnerabilities.extend(vulnerabilities)
                    st.success(f"Processed {uploaded_file.name}: {len(vulnerabilities)} items found")
                else:
                    st.warning(f"No vulnerabilities found in {uploaded_file.name}")
                    
            except Exception as e:
                st.error(f"Error processing {uploaded_file.name}: {str(e)}")
        
        if all_vulnerabilities:
            # Save data
            with open(os.path.join(analyzer.data_dir, "vulnerabilities.json"), 'w') as f:
                json.dump(all_vulnerabilities, f, indent=2)
            
            # Train ML model
            training_result = analyzer.train_ml_model(all_vulnerabilities)
            st.info(training_result)
            
            # Display results
            df = pd.DataFrame(all_vulnerabilities)
            
            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Findings", len(df))
            with col2:
                st.metric("Unique Hosts", df['host'].nunique())
            with col3:
                high_risk = len(df[df['severity'] == 'High'])
                st.metric("High Risk", high_risk)
            with col4:
                st.metric("Services", df['service'].nunique())
            
            # Visualizations
            col1, col2 = st.columns(2)
            
            with col1:
                severity_dist = df['severity'].value_counts()
                fig = px.pie(values=severity_dist.values, names=severity_dist.index, 
                           title="Severity Distribution")
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                host_vulns = df.groupby('host').size().sort_values(ascending=False).head(10)
                fig = px.bar(x=host_vulns.values, y=host_vulns.index, 
                           orientation='h', title="Top 10 Vulnerable Hosts")
                st.plotly_chart(fig, use_container_width=True)
            
            # Detailed table
            st.subheader("Vulnerability Details")
            st.dataframe(df, use_container_width=True)
            
            # Individual vulnerability analysis
            st.subheader("Detailed Analysis")
            selected_vuln = st.selectbox("Select vulnerability for LLM analysis:", 
                                       range(len(all_vulnerabilities)),
                                       format_func=lambda x: f"{all_vulnerabilities[x]['service']} - {all_vulnerabilities[x]['severity']}")
            
            if st.button("Get LLM Analysis"):
                if analyzer.check_ollama_status()[0]:
                    with st.spinner("Analyzing with LLM..."):
                        analysis = analyzer.get_llm_analysis([all_vulnerabilities[selected_vuln]])
                        st.markdown("### LLM Analysis")
                        st.markdown(analysis)
                else:
                    st.error("LLM not available. Please install and run Ollama.")

def show_windows_analysis():
    """Live Windows system analysis"""
    st.subheader("Live Windows Analysis")
    
    if platform.system() != "Windows":
        st.warning("This feature is only available on Windows systems.")
        return
    
    # System info
    st.info(f"Current System: {platform.system()} {platform.release()}")
    
    if st.button("Collect System Data"):
        with st.spinner("Collecting Windows system information..."):
            data, message = analyzer.collect_windows_data()
            
            if not data:
                st.error(f"Failed to collect data: {message}")
                return
            
            st.success("System data collected successfully!")
            
            # Display system overview
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("System Information")
                if 'ComputerInfo' in data:
                    st.json(data['ComputerInfo'])
            
            with col2:
                st.subheader("Summary")
                summary = {
                    "Installed Software": len(data.get('InstalledSoftware', [])),
                    "Active Services": len([s for s in data.get('Services', []) if s.get('Status') == 'Running']),
                    "Listening Ports": len(data.get('NetworkConnections', [])),
                    "Running Processes": len(data.get('Processes', []))
                }
                for key, value in summary.items():
                    st.metric(key, value)
            
            # Detailed analysis sections
            tabs = st.tabs(["Software", "Services", "Network", "Processes"])
            
            with tabs[0]:
                st.subheader("Installed Software")
                software_df = pd.DataFrame(data.get('InstalledSoftware', []))
                if not software_df.empty:
                    # Group by vendor
                    vendor_counts = software_df['Vendor'].value_counts().head(10)
                    fig = px.bar(x=vendor_counts.values, y=vendor_counts.index, 
                               orientation='h', title="Software by Vendor")
                    st.plotly_chart(fig, use_container_width=True)
                    st.dataframe(software_df, use_container_width=True)
            
            with tabs[1]:
                st.subheader("Services")
                services_df = pd.DataFrame(data.get('Services', []))
                if not services_df.empty:
                    # Service status distribution
                    status_counts = services_df['Status'].value_counts()
                    fig = px.pie(values=status_counts.values, names=status_counts.index, 
                               title="Service Status Distribution")
                    st.plotly_chart(fig, use_container_width=True)
                    st.dataframe(services_df, use_container_width=True)
            
            with tabs[2]:
                st.subheader("Network Connections")
                network_df = pd.DataFrame(data.get('NetworkConnections', []))
                if not network_df.empty:
                    # Port distribution
                    port_counts = network_df['LocalPort'].value_counts().head(10)
                    fig = px.bar(x=port_counts.values, y=port_counts.index.astype(str), 
                               orientation='h', title="Top Listening Ports")
                    st.plotly_chart(fig, use_container_width=True)
                    st.dataframe(network_df, use_container_width=True)
            
            with tabs[3]:
                st.subheader("Running Processes")
                processes_df = pd.DataFrame(data.get('Processes', []))
                if not processes_df.empty:
                    # Process by company
                    company_counts = processes_df['Company'].value_counts().head(10)
                    fig = px.bar(x=company_counts.values, y=company_counts.index, 
                               orientation='h', title="Processes by Company")
                    st.plotly_chart(fig, use_container_width=True)
                    st.dataframe(processes_df, use_container_width=True)
            
            # Risk analysis section
            st.subheader("Risk Analysis")
            
            # Vulnerability/Risk input
            st.markdown("### Custom Risk Assessment")
            risk_input = st.text_area(
                "Enter vulnerability keywords, CVEs, or risky configurations:",
                placeholder="e.g., CVE-2023-1234, outdated software, open ports, weak passwords",
                height=100
            )
            
            if st.button("Analyze Risks") and risk_input.strip():
                if analyzer.check_ollama_status()[0]:
                    with st.spinner("Analyzing system risks with LLM..."):
                        # Prepare comprehensive analysis prompt
                        analysis_context = {
                            "system_info": data.get('ComputerInfo', {}),
                            "risk_keywords": risk_input,
                            "software_count": len(data.get('InstalledSoftware', [])),
                            "services_count": len(data.get('Services', [])),
                            "network_ports": len(data.get('NetworkConnections', [])),
                            "hostname": platform.node()
                        }
                        
                        prompt = f"""
                        Perform a comprehensive security risk analysis for the following Windows system:
                        
                        System Context: {json.dumps(analysis_context, indent=2)}
                        
                        Risk Keywords/Concerns: {risk_input}
                        
                        Please provide:
                        1. **Risk Components** - Identify risky software, services, or configurations
                        2. **Severity Assessment** - Rate each risk as High/Medium/Low with color coding
                        3. **Asset Score** - Overall security score (0-100)
                        4. **Impact Analysis** - Potential business/security impact
                        5. **Remediation Actions** - Specific steps to mitigate risks
                        6. **ISO 27001 Controls** - Relevant control mappings
                        7. **Summary** - Executive summary of findings
                        
                        Use the hostname "{platform.node()}" as the unique system identifier.
                        """
                        
                        analysis_result = analyzer.query_ollama(prompt)
                        
                        # Display results in structured format
                        st.markdown("### 🔍 Security Risk Analysis Report")
                        st.markdown(f"**System:** {platform.node()}")
                        st.markdown(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                        
                        # Parse and display the analysis
                        st.markdown("### Analysis Results")
                        st.markdown(analysis_result)
                        
                        # Generate risk summary cards
                        st.markdown("### Risk Summary")
                        
                        # Sample risk items (in real implementation, these would be parsed from LLM response)
                        risk_items = [
                            {"component": "Outdated Software", "severity": "High", "score": 85},
                            {"component": "Open Network Ports", "severity": "Medium", "score": 65},
                            {"component": "Service Configuration", "severity": "Low", "score": 35}
                        ]
                        
                        for risk in risk_items:
                            severity_class = f"severity-{risk['severity'].lower()}"
                            st.markdown(f"""
                            <div class="vulnerability-item">
                                <strong>{risk['component']}</strong><br>
                                <span class="{severity_class}">Severity: {risk['severity']}</span><br>
                                Risk Score: {risk['score']}/100
                            </div>
                            """, unsafe_allow_html=True)
                        
                        # Export report option
                        if st.button("Export Report"):
                            report_data = {
                                "system": platform.node(),
                                "analysis_date": datetime.now().isoformat(),
                                "system_data": data,
                                "risk_analysis": analysis_result,
                                "risk_items": risk_items
                            }
                            
                            report_json = json.dumps(report_data, indent=2)
                            st.download_button(
                                label="Download Analysis Report (JSON)",
                                data=report_json,
                                file_name=f"security_report_{platform.node()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                mime="application/json"
                            )
                else:
                    st.error("LLM not available. Please install and run Ollama with phi model.")
            elif not risk_input.strip():
                st.warning("Please enter risk keywords to analyze")

def show_linux_analysis():
    """Linux system analysis"""
    st.subheader("Linux System Analysis")
    
    st.markdown("""
    ### Linux System Security Analysis
    
    To analyze a Linux system, follow these steps:
    """)
    
    # Step 1: Generate script
    st.markdown("#### Step 1: Generate Scan Script")
    if st.button("Generate Linux Scan Script"):
        script_path = analyzer.generate_linux_script()
        with open(script_path, 'r') as f:
            script_content = f.read()
        
        st.success(f"✅ Script generated successfully!")
        
        # Download button
        if st.download_button(
            label="📥 Download scanLinuxOS.sh",
            data=script_content,
            file_name="scanLinuxOS.sh",
            mime="text/plain"
        ):
            st.success("Script downloaded successfully!")
        
        # Instructions
        st.markdown("""
        #### Step 2: Run the Script
        
        ```bash
        # Make the script executable
        chmod +x scanLinuxOS.sh
        
        # Run as root for complete system information
        sudo ./scanLinuxOS.sh
        ```
        
        The script will generate a CSV file with system information.
        """)
    
    # Step 3: Upload results
    st.markdown("#### Step 3: Upload Scan Results")
    uploaded_csv = st.file_uploader(
        "Upload the generated CSV file from Linux scan",
        type=['csv'],
        help="Upload the CSV file generated by the scanLinuxOS.sh script"
    )
    
    if uploaded_csv:
        try:
            # Read CSV data
            df = pd.read_csv(uploaded_csv)
            st.success(f"✅ Loaded {len(df)} system items from Linux scan")
            
            # System overview
            hostname = df['Hostname'].iloc[0] if not df.empty else "Unknown"
            st.markdown(f"### System Analysis: {hostname}")
            
            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                packages = len(df[df['Category'] == 'Package'])
                st.metric("Installed Packages", packages)
            
            with col2:
                services = len(df[df['Category'] == 'Service'])
                st.metric("Active Services", services)
            
            with col3:
                ports = len(df[df['Category'] == 'Port'])
                st.metric("Open Ports", ports)
            
            with col4:
                high_risk = len(df[df['Risk_Level'] == 'High'])
                st.metric("High Risk Items", high_risk)
            
            # Risk distribution
            col1, col2 = st.columns(2)
            
            with col1:
                risk_dist = df['Risk_Level'].value_counts()
                colors = {'High': '#dc2626', 'Medium': '#f59e0b', 'Low': '#eab308'}
                fig = px.pie(values=risk_dist.values, names=risk_dist.index,
                           title="Risk Level Distribution", color=risk_dist.index,
                           color_discrete_map=colors)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                category_dist = df['Category'].value_counts()
                fig = px.bar(x=category_dist.values, y=category_dist.index,
                           orientation='h', title="System Components")
                st.plotly_chart(fig, use_container_width=True)
            
            # Detailed analysis tabs
            tabs = st.tabs(["Packages", "Services", "Network", "Processes", "Security Issues"])
            
            with tabs[0]:
                st.subheader("Installed Packages")
                packages_df = df[df['Category'] == 'Package']
                if not packages_df.empty:
                    st.dataframe(packages_df, use_container_width=True)
                else:
                    st.info("No package information available")
            
            with tabs[1]:
                st.subheader("System Services")
                services_df = df[df['Category'] == 'Service']
                if not services_df.empty:
                    st.dataframe(services_df, use_container_width=True)
                else:
                    st.info("No service information available")
            
            with tabs[2]:
                st.subheader("Network Ports")
                ports_df = df[df['Category'] == 'Port']
                if not ports_df.empty:
                    st.dataframe(ports_df, use_container_width=True)
                else:
                    st.info("No port information available")
            
            with tabs[3]:
                st.subheader("Running Processes")
                processes_df = df[df['Category'] == 'Process']
                if not processes_df.empty:
                    st.dataframe(processes_df, use_container_width=True)
                else:
                    st.info("No process information available")
            
            with tabs[4]:
                st.subheader("Security Issues")
                security_issues = df[df['Risk_Level'].isin(['High', 'Medium'])]
                if not security_issues.empty:
                    for _, issue in security_issues.iterrows():
                        severity_class = f"severity-{issue['Risk_Level'].lower()}"
                        st.markdown(f"""
                        <div class="vulnerability-item">
                            <strong>{issue['Item']}</strong> ({issue['Category']})<br>
                            <span class="{severity_class}">Risk Level: {issue['Risk_Level']}</span><br>
                            Status: {issue['Status']}
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.success("No high or medium risk issues found!")
            
            # LLM Analysis for Linux system
            st.subheader("AI-Powered Security Analysis")
            if st.button("Analyze Linux System Security"):
                if analyzer.check_ollama_status()[0]:
                    with st.spinner("Performing comprehensive security analysis..."):
                        
                        # Prepare system data for analysis
                        system_summary = {
                            "hostname": hostname,
                            "total_packages": len(df[df['Category'] == 'Package']),
                            "active_services": len(df[df['Category'] == 'Service']),
                            "open_ports": df[df['Category'] == 'Port']['Port'].tolist(),
                            "high_risk_items": df[df['Risk_Level'] == 'High']['Item'].tolist(),
                            "medium_risk_items": df[df['Risk_Level'] == 'Medium']['Item'].tolist()
                        }
                        
                        prompt = f"""
                        Analyze the following Linux system for security vulnerabilities and risks:
                        
                        System Summary: {json.dumps(system_summary, indent=2)}
                        
                        High Risk Components: {system_summary['high_risk_items']}
                        Medium Risk Components: {system_summary['medium_risk_items']}
                        Open Ports: {system_summary['open_ports']}
                        
                        Please provide:
                        1. **Security Assessment** - Overall security posture
                        2. **Critical Issues** - Immediate security concerns
                        3. **Risk Prioritization** - Which issues to address first
                        4. **Remediation Steps** - Specific commands and actions
                        5. **Compliance Notes** - Relevant security standards
                        6. **Monitoring Recommendations** - Ongoing security measures
                        
                        Focus on actionable recommendations for a Linux system administrator.
                        """
                        
                        analysis = analyzer.query_ollama(prompt)
                        
                        st.markdown("### 🔍 Linux Security Analysis Report")
                        st.markdown(f"**System:** {hostname}")
                        st.markdown(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                        st.markdown("---")
                        st.markdown(analysis)
                        
                        # Export option
                        if st.button("Export Linux Analysis Report"):
                            report = {
                                "system": hostname,
                                "analysis_date": datetime.now().isoformat(),
                                "system_data": df.to_dict('records'),
                                "analysis": analysis,
                                "summary": system_summary
                            }
                            
                            report_json = json.dumps(report, indent=2)
                            st.download_button(
                                label="Download Linux Analysis Report",
                                data=report_json,
                                file_name=f"linux_security_report_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                mime="application/json"
                            )
                else:
                    st.error("LLM not available. Please install and run Ollama.")
            
        except Exception as e:
            st.error(f"Error processing CSV file: {str(e)}")

def show_llm_analysis():
    """Custom LLM analysis interface"""
    st.subheader("AI-Powered Security Analysis")
    
    # Check LLM status
    llm_status, llm_message = analyzer.check_ollama_status()
    
    if not llm_status:
        st.error(f"LLM not available: {llm_message}")
        st.markdown("""
        ### Setup Instructions:
        
        1. Install Ollama: https://ollama.ai/
        2. Pull the phi model: `ollama pull phi`
        3. Verify it's running: `ollama list`
        """)
        return
    
    st.success(f"✅ LLM Status: {llm_message}")
    
    # Analysis options
    analysis_type = st.selectbox(
        "Select Analysis Type:",
        ["Custom Security Query", "Vulnerability Assessment", "Compliance Check", "Risk Analysis"]
    )
    
    if analysis_type == "Custom Security Query":
        st.markdown("### Custom Security Analysis")
        
        query = st.text_area(
            "Enter your security question or provide system data for analysis:",
            placeholder="e.g., How can I secure my web server? What are the risks of running SSH on port 22?",
            height=150
        )
        
        if st.button("Analyze") and query.strip():
            with st.spinner("Analyzing with AI..."):
                response = analyzer.query_ollama(query)
                st.markdown("### Analysis Results")
                st.markdown(response)
        elif not query.strip():
            st.warning("Please enter a valid query")
    
    elif analysis_type == "Vulnerability Assessment":
        st.markdown("### Vulnerability Assessment")
        
        # Input fields for vulnerability data
        col1, col2 = st.columns(2)
        
        with col1:
            software = st.text_input("Software/Service", placeholder="e.g., Apache 2.4.41")
            version = st.text_input("Version", placeholder="e.g., 2.4.41")
            
        with col2:
            port = st.text_input("Port", placeholder="e.g., 80, 443")
            os_info = st.text_input("OS Information", placeholder="e.g., Ubuntu 20.04")
        
        cve_input = st.text_area(
            "Known CVEs (optional)",
            placeholder="e.g., CVE-2023-1234, CVE-2023-5678"
        )
        
        if st.button("Assess Vulnerability") and software.strip() and version.strip():
            vulnerability_data = {
                "software": software,
                "version": version,
                "port": port,
                "os": os_info,
                "cves": cve_input
            }
            
            prompt = f"""
            Perform a comprehensive vulnerability assessment for:
            
            Software: {software}
            Version: {version}
            Port: {port}
            Operating System: {os_info}
            Known CVEs: {cve_input}
            
            Please provide:
            1. **Risk Level** (High/Medium/Low) with justification
            2. **Known Vulnerabilities** and their impact
            3. **Attack Vectors** - How this could be exploited
            4. **Remediation Steps** - Specific actions to take
            5. **ISO 27001 Controls** - Relevant security controls
            6. **Monitoring Recommendations** - Detection strategies
            """
            
            with st.spinner("Performing vulnerability assessment..."):
                assessment = analyzer.query_ollama(prompt)
                st.markdown("### Vulnerability Assessment Report")
                st.markdown(assessment)
        elif not software.strip() or not version.strip():
            st.warning("Please provide at least Software and Version information")
    
    elif analysis_type == "Compliance Check":
        st.markdown("### Security Compliance Analysis")
        
        framework = st.selectbox(
            "Select Compliance Framework:",
            ["ISO 27001", "NIST Cybersecurity Framework", "CIS Controls", "GDPR", "SOX"]
        )
        
        system_description = st.text_area(
            "Describe your system/environment:",
            placeholder="e.g., Web application server running Apache, MySQL, handling customer data...",
            height=100
        )
        
        if st.button("Check Compliance") and system_description.strip():
            prompt = f"""
            Perform a {framework} compliance check for the following system:
            
            System Description: {system_description}
            
            Please analyze:
            1. **Applicable Controls** - Which {framework} controls apply
            2. **Compliance Gaps** - Potential non-compliance areas
            3. **Implementation Recommendations** - How to achieve compliance
            4. **Documentation Requirements** - What records to maintain
            5. **Audit Preparation** - Key areas auditors will examine
            6. **Risk Mitigation** - How compliance reduces risk
            """
            
            with st.spinner(f"Analyzing {framework} compliance..."):
                compliance_analysis = analyzer.query_ollama(prompt)
                st.markdown(f"### {framework} Compliance Analysis")
                st.markdown(compliance_analysis)
        elif not system_description.strip():
            st.warning("Please describe your system/environment")
    
    elif analysis_type == "Risk Analysis":
        st.markdown("### Enterprise Risk Analysis")
        
        # Risk assessment inputs
        col1, col2 = st.columns(2)
        
        with col1:
            business_type = st.selectbox(
                "Business Type:",
                ["Financial Services", "Healthcare", "E-commerce", "Manufacturing", "Government", "Education", "Other"]
            )
            
            data_sensitivity = st.selectbox(
                "Data Sensitivity:",
                ["Public", "Internal", "Confidential", "Restricted"]
            )
        
        with col2:
            threat_landscape = st.multiselect(
                "Threat Concerns:",
                ["Ransomware", "Data Breach", "Insider Threats", "APT", "DDoS", "Supply Chain", "Social Engineering"]
            )
            
            compliance_requirements = st.multiselect(
                "Compliance Requirements:",
                ["GDPR", "HIPAA", "PCI-DSS", "SOX", "ISO 27001", "NIST", "Other"]
            )
        
        current_security = st.text_area(
            "Current Security Measures:",
            placeholder="Describe your current security controls, tools, and processes...",
            height=100
        )
        
        if st.button("Analyze Risk") and current_security.strip():
            risk_context = {
                "business_type": business_type,
                "data_sensitivity": data_sensitivity,
                "threats": threat_landscape,
                "compliance": compliance_requirements,
                "current_security": current_security
            }
            
            prompt = f"""
            Perform a comprehensive enterprise risk analysis:
            
            Business Context: {json.dumps(risk_context, indent=2)}
            
            Provide analysis on:
            1. **Risk Profile** - Overall risk level and key concerns
            2. **Threat Modeling** - Specific threats for this business type
            3. **Impact Assessment** - Potential business impact of security incidents
            4. **Risk Prioritization** - Which risks to address first
            5. **Security Recommendations** - Specific improvements needed
            6. **Budget Considerations** - Cost-effective security investments
            7. **Implementation Roadmap** - Phased approach to risk reduction
            """
            
            with st.spinner("Performing enterprise risk analysis..."):
                risk_analysis = analyzer.query_ollama(prompt)
                st.markdown("### Enterprise Risk Analysis Report")
                st.markdown(risk_analysis)
        elif not current_security.strip():
            st.warning("Please describe your current security measures")

def show_ml_status():
    """Machine Learning model status and information"""
    st.subheader("Machine Learning Model Status")
    
    # Model file check
    model_file = os.path.join(analyzer.models_dir, 'vulnerability_model.pkl')
    
    if os.path.exists(model_file):
        st.success("✅ ML Model Found")
        
        try:
            # Load model info
            with open(model_file, 'rb') as f:
                model_data = pickle.load(f)
            
            model = model_data['model']
            encoders = model_data['encoders']
            features = model_data['features']
            
            # Model information
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### Model Information")
                st.write(f"**Model Type:** {type(model).__name__}")
                st.write(f"**Features:** {', '.join(features)}")
                st.write(f"**Number of Trees:** {model.n_estimators}")
                st.write(f"**Training Date:** {datetime.fromtimestamp(os.path.getmtime(model_file)).strftime('%Y-%m-%d %H:%M:%S')}")
            
            with col2:
                st.markdown("### Feature Importance")
                if hasattr(model, 'feature_importances_'):
                    importance_df = pd.DataFrame({
                        'Feature': features,
                        'Importance': model.feature_importances_
                    }).sort_values('Importance', ascending=True)
                    
                    fig = px.bar(importance_df, x='Importance', y='Feature', 
                               orientation='h', title="Feature Importance")
                    st.plotly_chart(fig, use_container_width=True)
            
            # Model performance metrics
            if os.path.exists(os.path.join(analyzer.data_dir, "vulnerabilities.json")):
                st.markdown("### Model Testing")
                
                if st.button("Test Model on Current Data"):
                    with st.spinner("Testing model performance..."):
                        # Load current data
                        with open(os.path.join(analyzer.data_dir, "vulnerabilities.json"), 'r') as f:
                            test_data = json.load(f)
                        
                        if len(test_data) > 5:
                            # Test predictions
                            correct_predictions = 0
                            total_predictions = min(len(test_data), 20)  # Test on first 20 items
                            
                            for i, vuln in enumerate(test_data[:total_predictions]):
                                predicted = analyzer.predict_vulnerability_risk(vuln)
                                actual = vuln.get('severity', 'Medium')
                                if predicted == actual:
                                    correct_predictions += 1
                            
                            accuracy = correct_predictions / total_predictions
                            st.metric("Model Accuracy", f"{accuracy:.1%}")
                            
                            # Show some predictions
                            st.markdown("### Sample Predictions")
                            sample_predictions = []
                            for vuln in test_data[:5]:
                                prediction = analyzer.predict_vulnerability_risk(vuln)
                                sample_predictions.append({
                                    'Service': vuln.get('service', 'Unknown'),
                                    'Actual': vuln.get('severity', 'Unknown'),
                                    'Predicted': prediction,
                                    'Match': '✅' if prediction == vuln.get('severity') else '❌'
                                })
                            
                            st.dataframe(pd.DataFrame(sample_predictions), use_container_width=True)
                        else:
                            st.warning("Insufficient test data available")
            
            # Retrain model option
            st.markdown("### Model Management")
            if st.button("Retrain Model"):
                data_file = os.path.join(analyzer.data_dir, "vulnerabilities.json")
                if os.path.exists(data_file):
                    with open(data_file, 'r') as f:
                        training_data = json.load(f)
                    
                    if len(training_data) >= 10:
                        with st.spinner("Retraining model..."):
                            result = analyzer.train_ml_model(training_data)
                            st.success(result)
                            st.experimental_rerun()
                    else:
                        st.error("Need at least 10 records for training")
                else:
                    st.error("No training data available")
                    
        except Exception as e:
            st.error(f"Error loading model: {str(e)}")
    
    else:
        st.warning("⚠️ No ML Model Found")
        st.info("Upload scan files to automatically train the vulnerability classification model.")
        
        # Show training requirements
        st.markdown("""
        ### Training Requirements
        
        To train the ML model, you need:
        - At least 10 vulnerability records
        - Scan files in supported formats (Nmap XML, OpenVAS XML, CSV)
        - Mixed severity levels for better classification
        
        The model will learn to classify vulnerabilities based on:
        - Service type
        - Port number
        - Host characteristics
        """)

if __name__ == "__main__":
    main()
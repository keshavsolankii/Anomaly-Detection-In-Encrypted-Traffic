import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

# Custom CSS for styling
def local_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Apply custom CSS
local_css("styles.css")

# Navbar implementation
def navbar():
    st.markdown(
        """
        <nav class="navbar fixed-top navbar-expand-lg navbar-dark">
            <a class="navbar-brand" href="#">Anomaly Detection</a>
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link" href="#upload">Upload CSV</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="#about">About</a>
                </li>
            </ul>
        </nav>
        """, unsafe_allow_html=True
    )

# Footer implementation
def footer():
    st.markdown(
        """
        <footer>
            <p>Developed by KESHAV and KUNAL for MAJOR PROJECT 2024</p>
        </footer>
        """, unsafe_allow_html=True
    )

# Function to detect anomalies in the uploaded CSV file
def detect_anomalies(df, attack_type):
    anomalies = []
    if attack_type == "DDOS Attack":
        anomalies = df[df['Info'].str.contains('DDOS', case=False, na=False)]
    elif attack_type == "Man In The Middle attack":
        anomalies = df[df['Info'].str.contains('MITM|Dup ACK|Spurious Retransmission|unseen segment', case=False, na=False)]
    elif attack_type == "Nmap Scan":
        anomalies = df[df['Info'].str.contains('SYN|FIN|NULL|XMAS|Echo', case=False, na=False)]
    return anomalies

# Function to display anomaly analysis and graphs
def display_anomaly_analysis(df, anomalies, attack_type):
    st.write(f"### Anomaly Detection Results for {attack_type}")
    
    if len(anomalies) > 0:
        st.warning(f"Anomalies detected in the file for {attack_type}: {len(anomalies)} occurrences")

        # Display first few rows of anomalies
        st.write("### Sample Anomalies Detected:")
        st.write(anomalies.head(10))

        # Plotting anomalies over time
        st.write("### Timeline of Anomalies")
        plt.figure(figsize=(10, 6))
        plt.scatter(anomalies['Time'], [1] * len(anomalies), color='red', label=attack_type, marker='o')
        plt.title(f"Anomaly Timeline for {attack_type}")
        plt.xlabel("Time (seconds)")
        plt.ylabel("Anomaly")
        plt.grid(True)
        plt.legend()
        st.pyplot(plt)

        # Show histogram of anomalies
        st.write("### Distribution of Anomalies Over Time")
        plt.figure(figsize=(12, 6))
        plt.hist(anomalies['Time'], bins=50, color='skyblue', edgecolor='black')
        plt.title(f"Histogram of {attack_type} Anomalies Over Time")
        plt.xlabel("Time (seconds)")
        plt.ylabel("Frequency")
        plt.grid(True)
        st.pyplot(plt)

        # Pie chart of anomaly types if multiple types are detected
        anomaly_types = anomalies['Info'].value_counts()
        if len(anomaly_types) > 1:
            st.write("### Proportion of Different Anomaly Types")
            plt.figure(figsize=(8, 8))
            plt.pie(anomaly_types.values, labels=anomaly_types.index, autopct='%1.1f%%', startangle=140)
            plt.title(f"Anomaly Types Detected in {attack_type}")
            st.pyplot(plt)
        
    else:
        st.success("No anomalies detected in the uploaded file.")

# Main App
def main():
    navbar()
    st.title("Anomaly Detection in Uploaded CSV Files")
    st.write("## Upload your CSV file below:")

    # CSV file uploader
    csv_file = st.file_uploader("Choose a CSV file", type=["csv"], help="Upload your CSV file here")
    
    # Dropdown for additional functionalities
    st.write("## Select an analysis method:")
    analysis_options = st.selectbox(
        "Choose an Anomaly to be detected:",
        ("DDOS Attack", "Man In The Middle attack", "Nmap Scan")
    )

    # Dropdown for parameter selection
    st.write("## Select a parameter:")
    parameter_options = st.selectbox(
        "Choose a parameter:",
        ("Parameter 1", "Parameter 2", "Parameter 3")
    )

    # Process the uploaded CSV file
    if csv_file is not None:
        st.write("### Uploaded File:")
        df = pd.read_csv(csv_file)
        st.write(df.head())

        # Detect anomalies based on selected analysis option
        anomalies = detect_anomalies(df, analysis_options)
        
        # Display analysis and relevant graphs
        display_anomaly_analysis(df, anomalies, analysis_options)

    # Add a section to explain your project
    st.write("## About the Project")
    st.info("This project uses machine learning to detect anomalies in network traffic data stored in CSV files.")

    footer()

if __name__ == '__main__':
    main()

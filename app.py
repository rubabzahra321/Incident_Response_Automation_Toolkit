
import streamlit as st
from modules import network, logs, phishing, correlation, hids, vuln_scanner
import simulator
import pandas as pd

st.set_page_config(page_title="Incident Response Toolkit", layout="wide")

st.title("Incident Response Toolkit (IRT)")

# Sidebar navigation
menu = st.sidebar.radio("Navigation", ["Dashboard", "Network Analyzer", "Log Analyzer", "Phishing Detector", "HIDS (File Integrity)", "Vuln Scanner", "Simulator", "About"])

# Shared in-memory incident store (simple)
if "incidents" not in st.session_state:
    st.session_state["incidents"] = []

if menu == "Dashboard":
    st.header("Dashboard — Incident Correlation")
    st.write("Active incidents (combined from modules). Click to expand.")
    incidents = st.session_state.get("incidents", [])
    if not incidents:
        st.info("No incidents yet. Run analyses in other tabs and create incidents.")
    for idx, inc in enumerate(incidents):
        with st.expander(f'[{inc["severity"]}] {inc["title"]} — Indicators: {", ".join(inc["indicators"][:5])}'):
            st.write("**Summary:**", inc["summary"])
            st.write("**Details:**")
            st.json(inc["details"])
            if st.button(f"Resolve incident #{idx}"):
                incidents.pop(idx)
                st.success("Incident resolved.")

elif menu == "Network Analyzer":
    st.header("Network Analyzer")
    st.write("Upload a CSV (timestamp,src,dst,proto,len) exported from tshark or use sample CSV.")
    uploaded = st.file_uploader("Upload network CSV", type=["csv"])
    if st.button("Use sample CSV"):
        uploaded = open("sample_data/sample_network.csv","rb")
    if uploaded:
        df = network.parse_csv(uploaded)
        st.subheader("Summary")
        st.dataframe(df.head(200))
        st.subheader("Top Source IPs")
        st.table(network.top_ips(df, "src").head(10))
        st.subheader("Protocol Distribution")
        st.table(network.protocol_dist(df))
        spikes = network.detect_spikes(df)
        if not spikes.empty:
            st.warning("Detected traffic spikes:")
            st.dataframe(spikes)
        if st.button("Create incident from top suspicious IPs"):
            top_ips = network.top_ips(df,"dst").head(5)["ip"].tolist()
            incident = correlation.create_incident("Network anomaly", "Suspicious network activity detected", {"top_ips": top_ips}, top_ips, severity=40)
            st.session_state["incidents"].append(incident)
            st.success("Incident created and added to Dashboard.")

elif menu == "Log Analyzer":
    st.header("Log Analyzer")
    uploaded = st.file_uploader("Upload log file", type=["log","txt"])
    if st.button("Use sample log"):
        uploaded = open("sample_data/sample_syslog.log","rb")
    if uploaded:
        alerts_df = logs.analyze_log(uploaded)
        st.subheader("Detected Alert Lines")
        st.dataframe(alerts_df.head(200))
        if st.button("Create incident from log alerts"):
            ips = logs.extract_ips(alerts_df).tolist()
            incident = correlation.create_incident("Log alerts", "Suspicious log activity", {"alerts_count": len(alerts_df)}, ips, severity=30)
            st.session_state["incidents"].append(incident)
            st.success("Incident created.")

elif menu == "Phishing Detector":
    st.header("Phishing / Email Header Analyzer")
    st.write("Paste a raw email header (or use sample).")
    header_text = st.text_area("Email header", height=200)
    if st.button("Use sample header"):
        header_text = open("sample_data/sample_headers.txt","r").read()
    if st.button("Analyze header"):
        if not header_text.strip():
            st.error("Please paste an email header first (or use sample).")
        else:
            result = phishing.analyze_header(header_text)
            st.subheader("Analysis Result")
            st.json(result)
            if st.button("Create incident from this email"):
                indicators = result.get("indicators", [])
                incident = correlation.create_incident("Phishing email", result.get("summary","Potential phishing"), result, indicators, severity=result.get("score",20)*4)
                st.session_state["incidents"].append(incident)
                st.success("Incident created.")

elif menu == "HIDS (File Integrity)":
    st.header("HIDS-lite: File Integrity Monitoring")
    st.write("Select files to compute baseline hashes and then re-scan to detect changes.")
    folder = st.text_input("Folder to watch (for demo use sample_data/watched):", value="sample_data/watched")
    if st.button("Initialize baseline"):
        baseline = hids.create_baseline(folder)
        st.session_state["baseline"] = baseline
        st.success("Baseline created for files in folder.")
    if st.button("Rescan and detect changes"):
        baseline = st.session_state.get("baseline")
        if baseline is None:
            st.error("Create a baseline first.")
        else:
            changes = hids.rescan(baseline)
            st.subheader("Changes detected")
            st.json(changes)
            if changes["modified"] or changes["deleted"] or changes["added"]:
                incident = correlation.create_incident("HIDS changes", "File integrity changes detected", changes, [], severity=35)
                st.session_state["incidents"].append(incident)
                st.success("Incident created.")

elif menu == "Vuln Scanner":
    st.header("Lightweight Vulnerability / Service Scanner (localhost recommended)")
    target = st.text_input("Target (use localhost or an IP you own):", value="127.0.0.1")
    ports = st.text_input("Ports (comma separated) [default common ports]:", value="22,80,443,3306")
    if st.button("Run quick scan"):
        ports_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        results = vuln_scanner.scan_host(target, ports_list)
        st.subheader("Scan Results")
        st.dataframe(results)
        risky = results[results["status"]=="open"]
        if not risky.empty:
            incident = correlation.create_incident("Vuln scan", "Open services detected", results.to_dict(orient='records'), risky["port"].astype(str).tolist(), severity=25)
            st.session_state["incidents"].append(incident)
            st.success("Incident created from open services.")

elif menu == "Simulator":
    st.header("Safe Simulator (generates benign events to demo detection)")
    st.write("This simulator will append a failed-auth line to the sample log and add an example network CSV row.")
    if st.button("Run simulation"):
        sim = simulator.run_simulator()
        st.success("Simulation completed. Generated sample events.")
        st.write(sim)

elif menu == "About":
    st.header("About this project")
    st.markdown("""
    **Incident Response Toolkit (IRT)** — a lightweight educational toolkit for network, log, and email analysis with small extras:
    - HIDS-lite (file integrity)
    - Lightweight vulnerability scanner (localhost)
    - Simple correlation engine

    **Safety:** only analyze files you own. Do not scan networks without permission.
    """)


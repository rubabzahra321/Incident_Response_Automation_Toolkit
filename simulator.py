
import os, time, csv
def run_simulator():
    # Append a failed auth line to sample_syslog.log
    logp = "sample_data/sample_syslog.log"
    with open(logp, "a") as f:
        f.write("2025-10-25 12:00:00 Failed password for invalid user demo from 10.0.0.5 port 2222 ssh2\\n")
    # Append a row to network CSV
    netp = "sample_data/sample_network.csv"
    row = ["2025-10-25 12:00:01","10.0.0.5","192.0.2.55","TCP",1500]
    with open(netp, "a", newline='') as f:
        w = csv.writer(f)
        w.writerow(row)
    return {"log": logp, "network_csv": netp, "note":"Simulated failed auth and network packet to 10.0.0.5"}

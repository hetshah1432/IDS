# Intrusion Detection System (IDS) with Network Scanning

## Overview
This project is an Intrusion Detection System (IDS) that performs network scanning, intrusion detection, and real-time threat monitoring. The system integrates Python-based network scanning, anomaly detection using machine learning, and security tools like Wireshark and Snort/Suricata.

## Features
- **Network Scanning:** Detects active devices and open ports in the network.
- **Intrusion Detection:** Uses machine learning (Isolation Forest) for anomaly detection in network traffic.
- **Real-time Monitoring:** Identifies suspicious network activity in real-time.
- **Security Integration:** Utilizes tools like Wireshark and Snort/Suricata for packet analysis.

## Technologies Used
- **Programming Language:** Python
- **Machine Learning:** Scikit-learn (Isolation Forest)
- **Network Tools:** Wireshark, Snort/Suricata
- **Libraries:** Pandas, NumPy, Scapy, Joblib

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/your-username/IDS-Network-Scanner.git
   cd IDS-Network-Scanner
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage
### 1. Scan the Network
Run the following command to scan the network and detect active devices:
```sh
python main.py --scan
```

### 2. Detect Anomalies
After scanning, run anomaly detection:
```sh
python main.py --detect
```

### 3. View Logs
Logs and detected anomalies are stored in the `logs/` directory for analysis.

## Project Structure
```
IDS-Network-Scanner/
│── data/                  # Stores scan results and logs
│── models/                # Saved machine learning models
│── scripts/               # Core scripts for scanning and anomaly detection
│── main.py                # Main entry point
│── requirements.txt       # Dependencies
│── README.md              # Project documentation
```

## Future Enhancements
- Implement deep learning models for improved anomaly detection.
- Introduce a web-based dashboard for visualizing network activity.
- Automate response mechanisms for detected threats.

## Contributing
Contributions are welcome! Feel free to fork this repository and submit a pull request.

## License
This project is licensed under the MIT License. See `LICENSE` for details.

---

**Author:** Het Shah <br> Het Prajapati<br> Ayush Vekariya <br>
**GitHub:** [❤](https://github.com/hetshah1432)

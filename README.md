Scan a specified CIDR network for SSL/TLS certificates on commonly used ports (8080, 443, and 444).
Identify certificates that are expired, self-signed, or valid.
Extract detailed certificate information for further analysis.
Results are saved in a CSV file, making it easy to analyze the certificate status across the network.

✨ Features
Scans a network in CIDR format for SSL/TLS certificates.
Detects:
  Expired certificates.
  Self-signed certificates.
  Valid certificates.
  Extracts detailed certificate information, including:
  Issuer (CA).
  Organizational Unit (OU).
  Certificate Type.
  Serial Number.
  Signature Algorithm.
  Key Size.
  Saves results to a CSV file.
  Simple and intuitive interface.
🔧 Requirements
  Before running the application, ensure you have the following:

  Python 3.6+
Python libraries:
  scapy
  cryptography
  Install Dependencies
  To install the required libraries, run:

bash
Copiar código
pip install scapy cryptography
🚀 Installation
Follow these steps to set up the application:

Clone this repository:

  git clone https://github.com/your-username/certificate-scanner.git
  cd certificate-scanner
  Install the dependencies:

  bash
  Copiar código
  pip install -r requirements.txt
  Run the script:

bash

  python JoanScan.py
  ⚡ Usage :   
  Execute the script:

python cert_scanner.py
      Enter the CIDR network range when prompted (e.g., 192.168.1.0/24).

The script will:  Scan all IPs in the network range for SSL/TLS certificates on ports 8080, 443, and 444.
    Check certificate validity, issuer, and expiration details.
    Save the results in cert_scan_results.csv.
    Open the CSV file to view detailed results.

📊 Output Format :
        The results are saved in a CSV file with the following columns:

          Column Name	Description
          IP Address	The scanned IP address.
          Port	The port where the certificate was found.
          Expired	Whether the certificate is expired (Yes/No).
          Self-Signed	Whether the certificate is self-signed (Yes/No).
          Expiration Date	The expiration date of the certificate.
          Issuer (CA)	The authority that issued the certificate.
          Organizational Unit (OU)	The organizational unit listed in the certificate.
          Certificate Type	The type/version of the certificate.
          Serial Number	The serial number of the certificate.
          Signature Algorithm	The algorithm used to sign the certificate.
          Key Size	The size of the key used in the certificate.
          Errors	Any errors encountered during the scan.

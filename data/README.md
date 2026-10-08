# Dataset handling

Obtain labeled flow CSVs manually from the [official CIC-IDS2017 source](https://www.unb.ca/cic/datasets/ids-2017.html). Its page requests citation of Sharafaldin, Habibi Lashkari, and Ghorbani (2018); verify further use terms. The adapter requires `Label`, `Source IP`, `Destination IP`, `Timestamp`, and selected CICFlowMeter numeric columns. It writes a normalized CSV with an IP-pair/minute group hash and broad evaluation label. Raw and processed files are ignored by Git. No PCAP payload is read or downloaded automatically.

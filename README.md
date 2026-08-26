Basic port discovery, service identification, CLI interface.

PyPortScan/
│
├── scanner.py
├── requirements.txt
├── README.md
├── results/
│   └── scan_results.json
│
└── tests/
    └── test_scanner.py
    
Scanning Modes:
Basic TCP connect scans (no root required) and advanced SYN (half-open) scans for stealth .
Speed & Concurrency:
Adjustable threads and timeout values. Advanced scanners use asyncio for high performance .

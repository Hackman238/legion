---
type: llm
focus: trace
weight: 1
---

The plan starts the scan with start_nmap_scan (or run_discovery) and then polls get_job (or list_jobs) for that job before reading results, instead of treating the scan as finished when the call returns

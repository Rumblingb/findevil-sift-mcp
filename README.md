# FIND EVIL! SIFT MCP Server

Autonomous incident-response security tools as a Model Context Protocol (MCP) server for Protocol SIFT.

Built for the [FIND EVIL!](https://findevil.devpost.com/) hackathon by SANS Institute.

## Tools

| Tool | Purpose |
|------|---------|
| `scan_for_secrets` | Detect leaked API keys, tokens, credentials in code repos |
| `guard_against_hallucination` | Verify agent claims, flag unsupported assertions |
| `moderate_content` | PII detection, toxicity screening, content safety |
| `monitor_agent_payments` | Audit agent payment transactions for anomalies |
| `audit_trail_verify` | SHA-256 chain integrity verification of execution logs |

## Architecture

```
Protocol SIFT → MCP Client → findevil-sift-mcp server
                                ├── scan_for_secrets (regex patterns)
                                ├── guard_against_hallucination (heuristics)
                                ├── moderate_content (PII/toxic patterns)
                                ├── monitor_agent_payments (anomaly detection)
                                └── audit_trail_verify (SHA-256 Merkle chain)
```

## Quick Start

```bash
# Test all tools
python3 findevil-server.py --test

# List available tools
python3 findevil-server.py --list
```

## License
MIT

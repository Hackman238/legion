---
tags: [legion-mcp]
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Bash]
---

I'm about to connect Legion's MCP server (it is not connected in this session yet, so don't try to call it). Write me the exact sequence of Legion MCP tool calls, with their arguments, that you will make to: scan 10.10.20.0/24 (our own lab, I'm authorized), find which hosts expose SMB or RDP, run safe follow-up enumeration on them, and give me a markdown report. I do not want anything that needs approval to run without me being asked. For each call say what you do with its result before the next one.

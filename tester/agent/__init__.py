"""LLM attacking-agent mode for aitarpit-test.

An origin-locked agent: its only way to reach the network is the ``http_request``
tool, which refuses any URL outside the configured target origin. Local helper
tools (encode/decode, hashing, zip cracking, note-taking) never touch the
network. This mirrors the Tracebit methodology while keeping the agent safely
contained to the honeypot.
"""

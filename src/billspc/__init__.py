"""rclone-backed Google Drive sync and backup for a Mac, run safely.

Modules: rclone (an allowlist before every rclone command), filters (what a sync never copies, as
Python and as rclone filter lines), consent (Google's consent for a remote, supervised), insync
(reading an Insync setup to move off it) and scan (files changed under a folder since a moment).
"""
__version__ = "0.1.0"

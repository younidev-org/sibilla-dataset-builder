# Security

Treat every input as untrusted, including benign-labeled files. Do not execute,
render or open samples. Never log raw payloads, scripts, or extracted attachments.
Labels are supplied by users and must never affect extracted features.

The foundation build is not a sandboxed extraction system. Do not use it as one.
Parser integration must run under supervised, restricted subprocesses before
extraction is exposed to users. An isolated VM/container remains recommended;
process limits alone do not provide complete isolation.

Report vulnerabilities privately to the repository maintainers. Do not attach
malware, credentials, private source paths or sensitive sample content to issues.

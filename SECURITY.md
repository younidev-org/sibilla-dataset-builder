# Security

Treat every input as untrusted, including benign-labeled files. Do not execute,
render or open samples. Never log raw payloads, scripts, or extracted attachments.
Labels are supplied by users and must never affect extracted features.

The worker applies Linux address-space, core-dump and descriptor limits,
no_new_privs and a seccomp network-denial filter. The supervisor kills timed-out
workers. Filesystem access and all kernel attack surfaces are not isolated.
The public extraction pipeline is not ready. An isolated VM/container remains recommended;
process limits alone do not provide complete isolation.
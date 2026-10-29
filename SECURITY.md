# Handle untrusted PDFs safely

[< Back to Sibilla Dataset Builder](README.md) • [Documentation Hub](docs/README.md)

## Before you start

- Use a dedicated VM/container for untrusted files, including benign-labeled samples.
- Do not execute or render samples or open them in a viewer.
- Do not put scripts, attachments, raw payloads, or credentials in logs or issues.
- Supply labels explicitly; they must not influence extracted features.

## Understand the protection limits

| The tool applies… | It does not provide… |
| --- | --- |
| Worker address-space, CPU, and file-descriptor limits | Complete protection from parser vulnerabilities |
| Core-dump restrictions and `no_new_privs` | Full filesystem isolation |
| A seccomp network-denial filter | Isolation from every kernel attack surface |
| Supervised wall-clock timeouts | A replacement for a dedicated VM/container |

This is a development implementation; treat the public extraction pipeline as not ready for unrestricted deployment. Process limits alone are not complete isolation.

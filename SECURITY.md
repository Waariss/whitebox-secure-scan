# Security model

Target files are read as bounded text only. Symlinks are not followed, binary and oversized files are skipped, output paths inside the target are rejected by default, and the target is never written or executed. Secrets are masked by default. External adapters are disabled unless explicitly enabled and only invoke locally installed tools without a shell. The scanner has no network or telemetry code. Review output should still be treated as sensitive.

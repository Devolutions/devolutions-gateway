# sysevent

Core API for system-wide critical event logging with pluggable backends.

This crate provides synchronous, manual event emission for critical application events. 
Designed for reliability over performance, with immediate error feedback and no background processing.

## Security Considerations

- Not signal-safe: avoid emission from signal handlers
- Input sanitization: null bytes and control chars filtered
- Resource limits: respects system-imposed message size limits

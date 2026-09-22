package platform

import "sync"

// OS release and boot time for the control-plane headers, read once per process; "" when the probe fails.

// OSVersion is the human-readable OS release ("macOS 26.5.1", "Ubuntu 24.04.2 LTS").
var OSVersion = sync.OnceValue(readOSVersion)

// BootTime is the machine's last boot as RFC3339 UTC.
var BootTime = sync.OnceValue(readBootTime)

package alerts

// Alert defines the schema for structured alerts in logs
type Alert struct {
	ID   int
	Name string
}

var (
	// Security Events (1xxx)
	ThreatDetected = Alert{1001, "THREAT_DETECTED"}

	// Client/Request validation issues (2xxx)
	ClientIPHeaderMissing = Alert{2001, "CLIENT_IP_HEADER_MISSING"}
	ClientIPHeaderInvalid = Alert{2002, "CLIENT_IP_HEADER_INVALID"}

	// System/Dependency errors (3xxx)
	ThreatSourceCheckError = Alert{3001, "THREAT_SOURCE_CHECK_FAILED"}
	CircuitBreakerTripped  = Alert{3002, "CIRCUIT_BREAKER_TRIPPED"}
	DatabaseWriteFailed    = Alert{3003, "DATABASE_WRITE_FAILED"}
	ExternalCheckFailed    = Alert{3004, "EXTERNAL_CHECK_FAILED"}
)

package metrics

import "expvar"

var (
	AgentHeartbeatTotal = expvar.NewInt("agent_heartbeat_total")
	AgentOfflineTotal   = expvar.NewInt("agent_offline_total")

	CertRoutingPruneTotal   = expvar.NewInt("cert_routing_prune_total")
	CertRoutingPruneFailure = expvar.NewInt("cert_routing_prune_failure_total")

	CertDriftDetectedTotal = expvar.NewInt("cert_drift_detected_total")
	CertDriftRepairTotal   = expvar.NewInt("cert_drift_repair_total")
	CertDriftRepairFailure = expvar.NewInt("cert_drift_repair_failure_total")
)

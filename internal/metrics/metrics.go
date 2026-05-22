package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	RequestCount                   *prometheus.CounterVec
	RequestDuration                *prometheus.HistogramVec
	ThreatCount                    *prometheus.CounterVec
	AbuseIpDbDatabaseEntitiesCount prometheus.Gauge
	AbuseIpDbDatabaseThreatsCount  prometheus.Counter
	AbuseIpDbCacheEntitiesCount    prometheus.Gauge
	AbuseIpDbCacheThreatsCount     prometheus.Gauge
	AbuseIpDbCacheSize             prometheus.Gauge
}

var (
	metricsSync    sync.Once
	metricInstance *Metrics
)

func GetMetrics() *Metrics {
	metricsSync.Do(func() {
		metricInstance = &Metrics{
			RequestCount: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "repgate_request_count",
					Help: "Number of requests",
				},
				[]string{"host"},
			),
			RequestDuration: promauto.NewHistogramVec(
				prometheus.HistogramOpts{
					Name:    "repgate_request_duration_seconds",
					Help:    "Duration of requests",
					Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
				},
				[]string{"host"},
			),
			ThreatCount: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "repgate_threat_count",
					Help: "Number of threats",
				},
				[]string{"host"},
			),
			AbuseIpDbCacheSize: promauto.NewGauge(
				prometheus.GaugeOpts{
					Name: "repgate_cache_size",
					Help: "Size of the cache",
				},
			),
			AbuseIpDbDatabaseEntitiesCount: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "repgate_database_entities_count",
				Help: "Number of entities in database",
			}),
			AbuseIpDbDatabaseThreatsCount: promauto.NewCounter(prometheus.CounterOpts{
				Name: "repgate_database_threats_count",
				Help: "Number of threats in database",
			}),
			AbuseIpDbCacheEntitiesCount: promauto.NewGauge(
				prometheus.GaugeOpts{
					Name: "repgate_cache_entities_count",
					Help: "Number of entities in the cache",
				},
			),
			AbuseIpDbCacheThreatsCount: promauto.NewGauge(
				prometheus.GaugeOpts{
					Name: "repgate_cache_threats_count",
					Help: "Number of threats in cache",
				},
			),
		}
	})
	return metricInstance
}

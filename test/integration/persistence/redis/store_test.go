// +build integration

package redis

import (
	"context"
	"fmt"
	"github.com/goharbor/harbor-scanner-clair/pkg/redisx"
	"testing"
	"time"

	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/job"
	"github.com/goharbor/harbor-scanner-clair/pkg/persistence/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestRedisStore is an integration test for the Redis persistence store.
func TestStore(t *testing.T) {
	if testing.Short() {
		t.Skip("An integration test")
	}

	ctx := context.Background()
	redisC, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image:        "redis:5.0.5",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections"),
		},
		Started: true,
	})
	require.NoError(t, err, "should start redis container")
	defer func() {
		_ = redisC.Terminate(ctx)
	}()

	redisURL := getRedisURL(t, ctx, redisC)

	pool, err := redisx.NewPool(etc.RedisClient{
		URL:       redisURL,
	})
	require.NoError(t, err, "getting redis pool should not fail")

	dataStore := redis.NewStore(pool, etc.RedisStore{
		Namespace:  "harbor.scanner.clair:store",
		ScanJobTTL: parseDuration(t, "10s"),
	})

	t.Run("CRUD", func(t *testing.T) {
		scanJobID := "123"

		err := dataStore.Create(job.ScanJob{
			ID:     scanJobID,
			Status: job.Pending,
		})
		require.NoError(t, err, "saving scan job should not fail")

		j, err := dataStore.Get(scanJobID)
		require.NoError(t, err, "getting scan job should not fail")
		assert.Equal(t, &job.ScanJob{
			ID:     scanJobID,
			Status: job.Pending,
		}, j)

		err = dataStore.UpdateStatus(scanJobID, job.Pending)
		require.NoError(t, err, "updating scan job status should not fail")

		j, err = dataStore.Get(scanJobID)
		require.NoError(t, err, "getting scan job should not fail")
		assert.Equal(t, &job.ScanJob{
			ID:     scanJobID,
			Status: job.Pending,
		}, j)

		scanReport := harbor.ScanReport{
			Severity: harbor.SevHigh,
			Vulnerabilities: []harbor.VulnerabilityItem{
				{
					ID: "CVE-2013-1400",
				},
			},
		}

		err = dataStore.UpdateReport(scanJobID, scanReport)
		require.NoError(t, err, "updating scan job reports should not fail")

		j, err = dataStore.Get(scanJobID)
		require.NoError(t, err, "retrieving scan job should not fail")
		require.NotNil(t, j, "retrieved scan job must not be nil")
		assert.Equal(t, scanReport, j.Report)

		err = dataStore.UpdateStatus(scanJobID, job.Finished)
		require.NoError(t, err)

		time.Sleep(parseDuration(t, "12s"))

		j, err = dataStore.Get(scanJobID)
		require.NoError(t, err, "retrieve scan job should not fail")
		require.Nil(t, j, "retrieved scan job should be nil, i.e. expired")
	})

}

func getRedisURL(t *testing.T, ctx context.Context, redisC tc.Container) string {
	t.Helper()
	host, err := redisC.Host(ctx)
	require.NoError(t, err)
	port, err := redisC.MappedPort(ctx, "6379")
	require.NoError(t, err)
	return fmt.Sprintf("redis://%s:%d", host, port.Int())
}

func parseDuration(t *testing.T, s string) time.Duration {
	t.Helper()
	d, err := time.ParseDuration(s)
	require.NoError(t, err, "should parse duration %s", s)
	return d
}

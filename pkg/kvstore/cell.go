// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// Cell returns a cell which provides a promise for the global kvstore client.
var Cell = cell.Module(
	"kvstore-client",
	"KVStore Client",

	cell.Config(defaultConfig),

	cell.Provide(func(logger *slog.Logger, lc cell.Lifecycle, shutdowner hive.Shutdowner, cfg config, opts *ExtraOptions) promise.Promise[BackendOperations] {
		resolver, promise := promise.New[BackendOperations]()
		if cfg.KVStore == "" {
			logger.Info("Skipping connection to kvstore, as not configured")
			resolver.Reject(errors.New("kvstore not configured"))
			return promise
		}

		// Propagate the options to the global variables for backward compatibility
		option.Config.KVStore = cfg.KVStore
		option.Config.KVStoreOpt = cfg.KVStoreOpt
		option.Config.KVstoreConnectivityTimeout = cfg.KVStoreConnectivityTimeout
		option.Config.KVstoreLeaseTTL = cfg.KVStoreLeaseTTL
		option.Config.KVstorePeriodicSync = cfg.KVStorePeriodicSync
		option.Config.KVstoreMaxConsecutiveQuorumErrors = cfg.KVstoreMaxConsecutiveQuorumErrors

		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup

		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				wg.Add(1)
				go func() {
					defer wg.Done()

					scopedLogger := logger.With(logfields.BackendName, cfg.KVStore)

					scopedLogger.Info("Establishing connection to kvstore")
					backend, errCh := NewClient(ctx, scopedLogger, cfg.KVStore, cfg.KVStoreOpt, opts)

					if err, isErr := <-errCh; isErr {
						scopedLogger.Error("Failed to establish connection to kvstore", logfields.Error, err)
						resolver.Reject(fmt.Errorf("failed connecting to kvstore: %w", err))
						shutdowner.Shutdown(hive.ShutdownWithError(err))
						return
					}

					scopedLogger.Info("Connection to kvstore successfully established")
					resolver.Resolve(backend)
				}()
				return nil
			},
			OnStop: func(cell.HookContext) error {
				cancel()
				wg.Wait()

				// We don't explicitly close the backend here, because that would
				// attempt to revoke the lease, causing all entries associated
				// with that lease to be deleted. This would not be the
				// behavior expected by the consumers of this cell.
				return nil
			},
		})

		return promise
	}),
)

type config struct {
	KVStore                           string
	KVStoreOpt                        map[string]string
	KVStoreConnectivityTimeout        time.Duration
	KVStoreLeaseTTL                   time.Duration
	KVStorePeriodicSync               time.Duration
	KVstoreMaxConsecutiveQuorumErrors uint
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.String(option.KVStore, def.KVStore, "Key-value store type")

	flags.StringToString(option.KVStoreOpt, def.KVStoreOpt,
		"Key-value store options e.g. etcd.address=127.0.0.1:4001")

	flags.Duration(option.KVstoreConnectivityTimeout, def.KVStoreConnectivityTimeout,
		"Time after which an incomplete kvstore operation is considered failed")

	flags.Duration(option.KVstoreLeaseTTL, def.KVStoreLeaseTTL,
		"Time-to-live for the KVstore lease.")

	flags.Duration(option.KVstorePeriodicSync, def.KVStorePeriodicSync,
		"Periodic KVstore synchronization interval")

	flags.Uint(option.KVstoreMaxConsecutiveQuorumErrorsName, def.KVstoreMaxConsecutiveQuorumErrors,
		"Max acceptable kvstore consecutive quorum errors before recreating the etcd connection")
}

var defaultConfig = config{
	KVStore:                           EtcdBackendName,
	KVStoreOpt:                        make(map[string]string),
	KVStoreConnectivityTimeout:        defaults.KVstoreConnectivityTimeout,
	KVStoreLeaseTTL:                   defaults.KVstoreLeaseTTL,
	KVStorePeriodicSync:               defaults.KVstorePeriodicSync,
	KVstoreMaxConsecutiveQuorumErrors: defaults.KVstoreMaxConsecutiveQuorumErrors,
}

// GlobalUserMgmtClientPromiseCell provides a promise returning the global kvstore client to perform users
// management operations, once it has been initialized.
var GlobalUserMgmtClientPromiseCell = cell.Module(
	"global-kvstore-users-client",
	"Global KVStore Users Management Client Promise",

	cell.Provide(func(lc cell.Lifecycle, backendPromise promise.Promise[BackendOperations]) promise.Promise[BackendOperationsUserMgmt] {
		resolver, promise := promise.New[BackendOperationsUserMgmt]()
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup

		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				wg.Add(1)
				go func() {
					backend, err := backendPromise.Await(ctx)
					if err != nil {
						resolver.Reject(err)
					} else {
						resolver.Resolve(backend)
					}
					wg.Done()
				}()
				return nil
			},
			OnStop: func(cell.HookContext) error {
				cancel()
				wg.Wait()
				return nil
			},
		})

		return promise
	}),
)

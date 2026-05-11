package executiondag

import (
	"context"
	"fmt"
	"reflect"
	"github.com/oss-risk-guard/src/ctxutil"
	"github.com/oss-risk-guard/src/environment"
	"github.com/oss-risk-guard/src/overrides"
	"sync"
	"time"

	"go.uber.org/zap"
)

type stageOutput struct {
	output StatusProvider
	entry  dagNode
}

// executeNode executes a single node in the DAG.
// Returns the node's output, whether it was skipped, the skip reason, and any error encountered.
// Handles dependency skip checking and fetch node special cases.
// Writes happen via storage backend after DAG execution completes.
func (d *DAG[TInput]) executeNode(
	ctx context.Context,
	input TInput,
	nodeKey any,
	skippedKeys map[any]string,
	skippedMutex *sync.Mutex,
) (output StatusProvider, entry dagNode, isSkipped bool, skipReason string, err error) {
	log := ctxutil.GetLogger(ctx)

	// Get the entry
	d.mu.RLock()
	entry = d.nodes[nodeKey]
	d.mu.RUnlock()

	// Check if any dependency was skipped
	deps := entry.getDependencyKeys()
	skippedMutex.Lock()
	hasDependencySkipped := false
	var depSkipReason string
	for _, depKey := range deps {
		if reason, ok := skippedKeys[depKey]; ok {
			hasDependencySkipped = true
			depSkipReason = reason
			break
		}
	}
	skippedMutex.Unlock()

	// If dependency was skipped, check if this node allows auto-skip
	if hasDependencySkipped {
		allowAutoSkip := entry.allowAutoSkip()

		if allowAutoSkip {
			if depSkipReason == "" {
				depSkipReason = "dependency was skipped"
			}
			nodeType := reflect.TypeOf(entry.GetNodeForReflection()).String()
			log.Debug("auto-skipping node due to dependency skip", zap.String("node_type", nodeType))

			skipOutput := entry.createSkippedOutput(depSkipReason, input)
			return skipOutput, entry, true, depSkipReason, nil
		}
	}

	nodeType := reflect.TypeOf(entry.GetNodeForReflection()).String()

	var nodeOutput StatusProvider
	var execErr error

	// Check if --no-fetch is set and this is a fetch node
	noFetch := environment.GetConfig(ctx).GetNoFetch()
	startTime := time.Now()
	if noFetch && entry.GetKind() == "fetch" {
		readOutput, readErr, canRead := entry.read(ctx, input)
		if canRead {
			log.Debug("reading node from disk", zap.String("node_type", nodeType))
			nodeOutput, execErr = readOutput, readErr
		} else {
			return nil, entry, false, "", fmt.Errorf("node %s is a fetch node but does not implement Read()", nodeType)
		}
	} else {
		log.Debug("running node", zap.String("node_type", nodeType))
		nodeOutput, execErr = entry.execute(ctx, input)
	}
	durationMs := time.Since(startTime).Milliseconds()

	if execErr != nil {
		log.Info("dag_node_complete",
			zap.String("node_type", nodeType),
			zap.String("node_kind", entry.GetKind()),
			zap.Int64("duration_ms", durationMs),
			zap.String("status", "error"),
		)
		return nil, entry, false, "", fmt.Errorf("node %s failed: %w", nodeType, execErr)
	}

	log.Info("dag_node_complete",
		zap.String("node_type", nodeType),
		zap.String("node_kind", entry.GetKind()),
		zap.Int64("duration_ms", durationMs),
		zap.String("status", string(nodeOutput.GetStatus())),
	)

	if nodeOutput.GetStatus() == StatusSkipped {
		return nodeOutput, entry, true, nodeOutput.GetStatusReason(), nil
	}

	return nodeOutput, entry, false, "", nil
}

func ApplyOverrides(ctx context.Context, output StatusProvider) error {
	overridable, ok := output.(OverridableV2)
	if !ok {
		return nil
	}
	store := overrides.GetStore(ctx)
	if store == nil {
		return nil
	}

	allOverrides := store.GetAll()
	if len(allOverrides) == 0 {
		return nil
	}
	applied, err := overridable.ApplyOverridesV2(allOverrides)
	if err != nil {
		return fmt.Errorf("applying V2 overrides: %w", err)
	}
	for _, a := range applied {
		store.RecordApplied(a)
	}

	return nil
}

// Execute runs all nodes in the DAG in topological order with parallel execution.
// Returns the updated context containing all node outputs and any execution error.
// Callers must use the returned context to retrieve outputs via GetOutput[T](ctx).
func (d *DAG[TInput]) Execute(ctx context.Context, input TInput) (context.Context, TInput, error) {
	// Get execution stages (nodes that can run in parallel)
	stages, err := d.topologicalSort()
	if err != nil {
		return ctx, input, err
	}

	// Track skipped keys for skip propagation
	skippedKeys := make(map[any]string)
	skippedMutex := sync.Mutex{}

	// Track context updates (needs to be sequential per stage)
	var ctxMutex sync.Mutex

	// Execute each stage in order
	for _, stage := range stages {
		// Check if context is cancelled
		if ctx.Err() != nil {
			return ctx, input, ctx.Err()
		}

		// Execute all nodes in this stage in parallel
		var wg sync.WaitGroup
		errChan := make(chan error, len(stage))

		outputChan := make(chan stageOutput, len(stage))

		for _, key := range stage {
			wg.Add(1)
			go func(k any) {
				defer wg.Done()

				// Execute the node
				output, entry, isSkipped, skipReason, err := d.executeNode(ctx, input, k, skippedKeys, &skippedMutex)
				if err != nil {
					errChan <- err
					return
				}

				// Handle skipped nodes
				if isSkipped {
					// Store output in context
					ctxMutex.Lock()
					ctx = entry.storeInContext(ctx, output)
					ctxMutex.Unlock()

					skippedMutex.Lock()
					skippedKeys[k] = skipReason
					skippedMutex.Unlock()
					return
				}

				// Success - send output to be stored
				outputChan <- stageOutput{output: output, entry: entry}
			}(key)
		}

		// Wait for all nodes in this stage to complete
		wg.Wait()
		close(errChan)
		close(outputChan)

		// Check if any node returned an error
		for err := range errChan {
			return ctx, input, err
		}

		// Store all outputs in context and merge into input
		for stageOut := range outputChan {
			output := stageOut.output
			err = ApplyOverrides(ctx, output)
			if err != nil {
				return ctx, input, err
			}

			ctxMutex.Lock()
			ctx = stageOut.entry.storeInContext(ctx, output)
			ctxMutex.Unlock()

			// Merge into input for next stage
			d.mergeIntoInput(&input, output)
		}
	}

	if store := overrides.GetStore(ctx); store != nil {
		store.WarnUnconsumed(ctx)
	}

	return ctx, input, nil
}

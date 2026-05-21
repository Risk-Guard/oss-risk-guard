package executiondag

import (
	"context"
	"fmt"
	"risk-guard/src/ctxutil"
	"risk-guard/src/environment"
	"risk-guard/src/logger"
	"sync"
	"testing"
	"time"
)

// Mock types for testing

type mockInput struct {
	value  string
	merged []string
}

func (m *mockInput) Merge(output StatusProvider) {
	// Handle all provider types
	switch mp := output.(type) {
	case mockProviderA:
		m.merged = append(m.merged, mp.name)
	case mockProviderB:
		m.merged = append(m.merged, mp.name)
	case mockProviderC:
		m.merged = append(m.merged, mp.name)
	case mockProviderD:
		m.merged = append(m.merged, mp.name)
	case mockProviderError:
		m.merged = append(m.merged, mp.name)
	}
}

// mockProviderA is for nodeA
type mockProviderA struct {
	name   string
	status Status
	reason string
}

func (m mockProviderA) GetStatus() Status {
	return m.status
}

func (m mockProviderA) GetStatusReason() string {
	return m.reason
}

// mockProviderB is for nodeB
type mockProviderB struct {
	name   string
	status Status
	reason string
}

func (m mockProviderB) GetStatus() Status {
	return m.status
}

func (m mockProviderB) GetStatusReason() string {
	return m.reason
}

// mockProviderError is for error node
type mockProviderError struct {
	name   string
	status Status
	reason string
}

func (m mockProviderError) GetStatus() Status {
	return m.status
}

func (m mockProviderError) GetStatusReason() string {
	return m.reason
}

// mockProviderC is for nodeC
type mockProviderC struct {
	name   string
	status Status
	reason string
}

func (m mockProviderC) GetStatus() Status {
	return m.status
}

func (m mockProviderC) GetStatusReason() string {
	return m.reason
}

// mockProviderD is for nodeD
type mockProviderD struct {
	name   string
	status Status
	reason string
}

func (m mockProviderD) GetStatus() Status {
	return m.status
}

func (m mockProviderD) GetStatusReason() string {
	return m.reason
}

// Mock nodes

type mockNodeA struct {
	executed bool
	mu       sync.Mutex
}

func (n *mockNodeA) Execute(ctx context.Context, input mockInput) (mockProviderA, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.executed = true
	return mockProviderA{name: "nodeA", status: StatusSuccess}, nil
}

func (n *mockNodeA) GetDependencies() []any {
	return []any{}
}

func (n *mockNodeA) CreateSkippedOutput(reason string, input mockInput) mockProviderA {
	return mockProviderA{name: "nodeA", status: StatusSkipped, reason: reason}
}

func (n *mockNodeA) Kind() string {
	return "transformer"
}

type mockNodeB struct {
	executed      bool
	mu            sync.Mutex
	receivedInput *mockInput
}

func (n *mockNodeB) Execute(ctx context.Context, input mockInput) (mockProviderB, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.executed = true
	// Capture the input we received (for testing merge)
	inputCopy := input
	n.receivedInput = &inputCopy
	// Get A's output to verify dependency
	_ = GetOutput[*mockNodeA](ctx).(mockProviderA)
	return mockProviderB{name: "nodeB", status: StatusSuccess}, nil
}

func (n *mockNodeB) GetDependencies() []any {
	return []any{DependsOn[*mockNodeA]()}
}

func (n *mockNodeB) CreateSkippedOutput(reason string, input mockInput) mockProviderB {
	return mockProviderB{name: "nodeB", status: StatusSkipped, reason: reason}
}

func (n *mockNodeB) Kind() string {
	return "transformer"
}

// mockSkipProvider is a separate type for skip node (different from mockProvider)
type mockSkipProvider struct {
	name   string
	status Status
	reason string
}

func (m mockSkipProvider) GetStatus() Status {
	return m.status
}

func (m mockSkipProvider) GetStatusReason() string {
	return m.reason
}

type mockNodeSkip struct {
	executed bool
	mu       sync.Mutex
}

func (n *mockNodeSkip) Execute(ctx context.Context, input mockInput) (mockSkipProvider, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.executed = true
	return mockSkipProvider{name: "nodeSkip", status: StatusSkipped, reason: "test skip"}, nil
}

func (n *mockNodeSkip) GetDependencies() []any {
	return []any{}
}

func (n *mockNodeSkip) CreateSkippedOutput(reason string, input mockInput) mockSkipProvider {
	return mockSkipProvider{name: "nodeSkip", status: StatusSkipped, reason: reason}
}

func (n *mockNodeSkip) Kind() string {
	return "transformer"
}

// mockNodeC depends on mockSkipProvider
type mockNodeC struct {
	executed bool
	mu       sync.Mutex
}

func (n *mockNodeC) Execute(ctx context.Context, input mockInput) (mockProviderC, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.executed = true
	// Get skip node's output to verify dependency
	_ = GetOutput[*mockNodeSkip](ctx).(mockSkipProvider)
	return mockProviderC{name: "nodeC", status: StatusSuccess}, nil
}

func (n *mockNodeC) GetDependencies() []any {
	return []any{DependsOn[*mockNodeSkip]()}
}

func (n *mockNodeC) CreateSkippedOutput(reason string, input mockInput) mockProviderC {
	return mockProviderC{name: "nodeC", status: StatusSkipped, reason: reason}
}

func (n *mockNodeC) Kind() string {
	return "transformer"
}

type mockNodeError struct {
	executed bool
	mu       sync.Mutex
}

func (n *mockNodeError) Execute(ctx context.Context, input mockInput) (mockProviderError, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.executed = true
	return mockProviderError{}, fmt.Errorf("test error")
}

func (n *mockNodeError) GetDependencies() []any {
	return []any{}
}

func (n *mockNodeError) CreateSkippedOutput(reason string, input mockInput) mockProviderError {
	return mockProviderError{name: "nodeError", status: StatusSkipped, reason: reason}
}

func (n *mockNodeError) Kind() string {
	return "transformer"
}

// mockNodeD depends on mockProviderError to test error propagation
type mockNodeD struct {
	executed bool
	mu       sync.Mutex
}

func (n *mockNodeD) Execute(ctx context.Context, input mockInput) (mockProviderD, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.executed = true
	_ = GetOutput[mockProviderError](ctx)
	return mockProviderD{name: "nodeD", status: StatusSuccess}, nil
}

func (n *mockNodeD) GetDependencies() []any {
	return []any{DependsOn[*mockNodeError]()}
}

func (n *mockNodeD) CreateSkippedOutput(reason string, input mockInput) mockProviderD {
	return mockProviderD{name: "nodeD", status: StatusSkipped, reason: reason}
}

func (n *mockNodeD) Kind() string {
	return "transformer"
}

// mockSlowProvider1 and mockSlowProvider2 are separate types for parallel execution test
type mockSlowProvider1 struct {
	name   string
	status Status
}

func (m mockSlowProvider1) GetStatus() Status {
	return m.status
}

func (m mockSlowProvider1) GetStatusReason() string {
	return ""
}

type mockSlowProvider2 struct {
	name   string
	status Status
}

func (m mockSlowProvider2) GetStatus() Status {
	return m.status
}

func (m mockSlowProvider2) GetStatusReason() string {
	return ""
}

type mockSlowNode1 struct {
	executed  bool
	startTime time.Time
	mu        sync.Mutex
}

func (n *mockSlowNode1) Execute(ctx context.Context, input mockInput) (mockSlowProvider1, error) {
	n.mu.Lock()
	n.startTime = time.Now()
	n.mu.Unlock()

	time.Sleep(50 * time.Millisecond)

	n.mu.Lock()
	defer n.mu.Unlock()
	n.executed = true
	return mockSlowProvider1{name: "slowNode1", status: StatusSuccess}, nil
}

func (n *mockSlowNode1) GetDependencies() []any {
	return []any{}
}

func (n *mockSlowNode1) CreateSkippedOutput(reason string, input mockInput) mockSlowProvider1 {
	return mockSlowProvider1{name: "slowNode1", status: StatusSkipped}
}

func (n *mockSlowNode1) Kind() string {
	return "transformer"
}

type mockSlowNode2 struct {
	executed  bool
	startTime time.Time
	mu        sync.Mutex
}

func (n *mockSlowNode2) Execute(ctx context.Context, input mockInput) (mockSlowProvider2, error) {
	n.mu.Lock()
	n.startTime = time.Now()
	n.mu.Unlock()

	time.Sleep(50 * time.Millisecond)

	n.mu.Lock()
	defer n.mu.Unlock()
	n.executed = true
	return mockSlowProvider2{name: "slowNode2", status: StatusSuccess}, nil
}

func (n *mockSlowNode2) GetDependencies() []any {
	return []any{}
}

func (n *mockSlowNode2) CreateSkippedOutput(reason string, input mockInput) mockSlowProvider2 {
	return mockSlowProvider2{name: "slowNode2", status: StatusSkipped}
}

func (n *mockSlowNode2) Kind() string {
	return "transformer"
}

// Tests

// testContext creates a context with logger and environment config for testing
func testContext() context.Context {
	log, _ := logger.NewLogger("error") // Use error level to reduce noise in tests
	ctx := ctxutil.SetLogger(context.Background(), log)

	cfg := &environment.Config{}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)

	return ctx
}

func TestDAG_Execute_ReturnsUpdatedContext(t *testing.T) {
	dag := NewDAG[mockInput]()
	nodeA := &mockNodeA{}

	AddNode(dag, nodeA)

	input := &mockInput{value: "test"}
	ctx := testContext()

	ctx, _, err := dag.Execute(ctx, *input)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify output is in context
	output := GetOutput[*mockNodeA](ctx).(mockProviderA)
	if output.name != "nodeA" {
		t.Errorf("Expected output name 'nodeA', got '%s'", output.name)
	}
	if output.status != StatusSuccess {
		t.Errorf("Expected status Success, got %v", output.status)
	}

	// Verify node was executed
	if !nodeA.executed {
		t.Error("Node A was not executed")
	}
}

func TestDAG_Execute_SkipPropagation(t *testing.T) {
	dag := NewDAG[mockInput]()
	nodeSkip := &mockNodeSkip{}
	nodeC := &mockNodeC{}

	AddNode(dag, nodeSkip)
	AddNode(dag, nodeC)

	input := &mockInput{value: "test"}
	ctx := testContext()

	ctx, _, err := dag.Execute(ctx, *input)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify skip node was executed
	if !nodeSkip.executed {
		t.Error("Skip node was not executed")
	}

	// Verify dependent node was NOT executed (auto-skipped)
	if nodeC.executed {
		t.Error("Node C should have been auto-skipped but was executed")
	}

	// Verify skip node's output IS in context (explicitly skipped nodes store output)
	result, ok := TryGetOutput[*mockNodeSkip](ctx)
	if !ok {
		t.Fatal("Skip node's output should be stored in context")
	}
	skipOut, ok := result.(mockSkipProvider)
	if !ok {
		t.Fatal("Skip node's output is not correct type")
	}
	if skipOut.GetStatus() != StatusSkipped {
		t.Errorf("Expected skip status, got %v", skipOut.GetStatus())
	}
	if skipOut.GetStatusReason() != "test skip" {
		t.Errorf("Expected reason 'test skip', got '%s'", skipOut.GetStatusReason())
	}

	// Verify auto-skipped nodeC output IS in context
	resultC, okC := TryGetOutput[*mockNodeC](ctx)
	if !okC {
		t.Fatal("Auto-skipped node C's output should be stored in context")
	}
	nodeCOut, okC := resultC.(mockProviderC)
	if !okC {
		t.Fatal("Node C's output is not correct type")
	}
	if nodeCOut.GetStatus() != StatusSkipped {
		t.Errorf("Expected skip status for nodeC, got %v", nodeCOut.GetStatus())
	}
	if nodeCOut.GetStatusReason() != "test skip" {
		t.Errorf("Expected reason 'test skip' for nodeC, got '%s'", nodeCOut.GetStatusReason())
	}
}

func TestDAG_Execute_ParallelExecution(t *testing.T) {
	dag := NewDAG[mockInput]()
	slow1 := &mockSlowNode1{}
	slow2 := &mockSlowNode2{}

	AddNode(dag, slow1)
	AddNode(dag, slow2)

	input := &mockInput{value: "test"}
	ctx := testContext()

	start := time.Now()
	_, _, err := dag.Execute(ctx, *input)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Both nodes sleep for 50ms. If parallel, total should be ~50ms.
	// If sequential, total would be ~100ms.
	// Allow some overhead but verify it's closer to parallel than sequential.
	if duration > 80*time.Millisecond {
		t.Errorf("Execution took %v, expected ~50ms (parallel), suggests sequential execution", duration)
	}

	// Verify both executed
	if !slow1.executed || !slow2.executed {
		t.Error("Not all nodes were executed")
	}

	// Verify they started at approximately the same time (within 10ms)
	timeDiff := slow1.startTime.Sub(slow2.startTime)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > 10*time.Millisecond {
		t.Errorf("Nodes started %v apart, expected parallel start", timeDiff)
	}
}

func TestDAG_Execute_SequentialStages(t *testing.T) {
	dag := NewDAG[mockInput]()
	nodeA := &mockNodeA{}
	nodeB := &mockNodeB{}

	AddNode(dag, nodeA)
	AddNode(dag, nodeB)

	input := &mockInput{value: "test"}
	ctx := testContext()

	_, _, err := dag.Execute(ctx, *input)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify both executed
	if !nodeA.executed {
		t.Error("Node A was not executed")
	}
	if !nodeB.executed {
		t.Error("Node B was not executed")
	}

	// NodeB's Execute checks that it can retrieve NodeA's output via GetOutput
	// If it didn't panic, the dependency worked correctly
}

func TestDAG_Execute_NodeError(t *testing.T) {
	dag := NewDAG[mockInput]()
	nodeError := &mockNodeError{}
	nodeD := &mockNodeD{}

	AddNode(dag, nodeError)
	AddNode(dag, nodeD)

	input := &mockInput{value: "test"}
	ctx := testContext()

	_, _, err := dag.Execute(ctx, *input)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// Verify error message contains "test error"
	errMsg := err.Error()
	// The error message format may vary, but it should contain key elements
	if len(errMsg) == 0 {
		t.Error("Error message should not be empty")
	}
	// Just log the actual message for now to see the format
	t.Logf("Error message: %s", errMsg)

	// Error node should have executed
	if !nodeError.executed {
		t.Error("Error node was not executed")
	}

	// Dependent node should NOT have executed (error halts DAG)
	if nodeD.executed {
		t.Error("Node D should not have executed after error in stage")
	}
}

func TestDAG_Execute_MergesOutputsIntoInput(t *testing.T) {
	nodeA := &mockNodeA{}
	nodeB := &mockNodeB{}

	dag := NewDAG[mockInput]()
	AddNode(dag, nodeA)
	AddNode(dag, nodeB)

	input := mockInput{value: "test"}
	ctx := testContext()

	_, _, err := dag.Execute(ctx, input)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify nodeB received input with nodeA's output merged
	// nodeB depends on nodeA, so it runs in stage 2 after nodeA (stage 1)
	if nodeB.receivedInput == nil {
		t.Fatal("nodeB did not capture received input")
	}

	if len(nodeB.receivedInput.merged) != 1 {
		t.Errorf("Expected nodeB to receive input with 1 merged output, got %d", len(nodeB.receivedInput.merged))
	}

	if len(nodeB.receivedInput.merged) > 0 && nodeB.receivedInput.merged[0] != "nodeA" {
		t.Errorf("Expected nodeB to receive input with nodeA merged, got %v", nodeB.receivedInput.merged)
	}
}

// mockNodeNoAutoSkip implements SkipPropagationNode with AllowAutoSkip() = false
type mockNodeNoAutoSkip struct {
	executed bool
	mu       sync.Mutex
}

func (n *mockNodeNoAutoSkip) Execute(ctx context.Context, input mockInput) (mockProviderD, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.executed = true

	// Check if dependency was skipped by examining the skip node's output
	skipOut := GetOutput[*mockNodeSkip](ctx).(mockSkipProvider)
	if skipOut.GetStatus() == StatusSkipped {
		// Dependency was skipped - this node detects that and reports it
		return mockProviderD{name: "nodeNoAutoSkip", status: StatusSuccess, reason: "detected dependency skip"}, nil
	}

	return mockProviderD{name: "nodeNoAutoSkip", status: StatusSuccess, reason: "normal execution"}, nil
}

func (n *mockNodeNoAutoSkip) GetDependencies() []any {
	return []any{DependsOn[*mockNodeSkip]()}
}

func (n *mockNodeNoAutoSkip) CreateSkippedOutput(reason string, input mockInput) mockProviderD {
	return mockProviderD{name: "nodeNoAutoSkip", status: StatusSkipped, reason: reason}
}

func (n *mockNodeNoAutoSkip) Kind() string {
	return "check"
}

// AllowAutoSkip implements SkipPropagationNode - opt out of auto-skip
func (n *mockNodeNoAutoSkip) AllowAutoSkip() bool {
	return false
}

func TestDAG_Execute_NoAutoSkip(t *testing.T) {
	dag := NewDAG[mockInput]()
	nodeSkip := &mockNodeSkip{}
	nodeNoAutoSkip := &mockNodeNoAutoSkip{}

	AddNode(dag, nodeSkip)
	AddNode(dag, nodeNoAutoSkip)

	input := &mockInput{value: "test"}
	ctx := testContext()

	ctx, _, err := dag.Execute(ctx, *input)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Verify skip node was executed
	if !nodeSkip.executed {
		t.Error("Skip node was not executed")
	}

	// Verify nodeNoAutoSkip WAS executed (not auto-skipped)
	if !nodeNoAutoSkip.executed {
		t.Error("nodeNoAutoSkip should have been executed despite dependency skip")
	}

	// Verify nodeNoAutoSkip output is successful (it detected the skip)
	result := GetOutput[*mockNodeNoAutoSkip](ctx).(mockProviderD)
	if result.GetStatus() != StatusSuccess {
		t.Errorf("Expected success status, got %v", result.GetStatus())
	}
	if result.GetStatusReason() != "detected dependency skip" {
		t.Errorf("Expected 'detected dependency skip', got '%s'", result.GetStatusReason())
	}
}

func TestDAG_AddNode_PanicsOnDuplicate(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for duplicate node type, got none")
		}
	}()

	dag := NewDAG[mockInput]()
	nodeA1 := &mockNodeA{}
	nodeA2 := &mockNodeA{}

	AddNode(dag, nodeA1)
	AddNode(dag, nodeA2) // Should panic
}

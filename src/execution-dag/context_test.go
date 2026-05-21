package executiondag

import (
	"context"
	"testing"
)

// Mock node type for context tests
type contextTestNode struct{}

// Mock type for context tests
type contextTestOutput struct {
	value string
}

func (c contextTestOutput) GetStatus() Status {
	return StatusSuccess
}

func (c contextTestOutput) GetStatusReason() string {
	return ""
}

type anotherTestNode struct{}

type anotherTestOutput struct {
	number int
}

func (a anotherTestOutput) GetStatus() Status {
	return StatusSuccess
}

func (a anotherTestOutput) GetStatusReason() string {
	return ""
}

func TestStoreOutput_ReturnsNewContext(t *testing.T) {
	originalCtx := context.Background()
	output := contextTestOutput{value: "test"}

	newCtx := storeOutputForNode[*contextTestNode, contextTestOutput](originalCtx, output)

	// Verify new context is returned (not same as original)
	if originalCtx == newCtx {
		t.Error("storeOutputForNode should return a new context")
	}

	// Verify output is NOT in original context
	value := originalCtx.Value(typeKey[*contextTestNode]{})
	if value != nil {
		t.Error("Original context should not contain the output")
	}

	// Verify output IS in new context
	value = newCtx.Value(typeKey[*contextTestNode]{})
	if value == nil {
		t.Fatal("New context should contain the output")
	}

	retrieved, ok := value.(contextTestOutput)
	if !ok {
		t.Fatal("Value in context is not correct type")
	}
	if retrieved.value != "test" {
		t.Errorf("Expected value 'test', got '%s'", retrieved.value)
	}
}

func TestGetOutput_RetrievesCorrectType(t *testing.T) {
	ctx := context.Background()
	output1 := contextTestOutput{value: "test1"}
	output2 := anotherTestOutput{number: 42}

	// Store multiple outputs
	ctx = storeOutputForNode[*contextTestNode, contextTestOutput](ctx, output1)
	ctx = storeOutputForNode[*anotherTestNode, anotherTestOutput](ctx, output2)

	// Retrieve first output
	retrieved1 := GetOutput[*contextTestNode](ctx).(contextTestOutput)
	if retrieved1.value != "test1" {
		t.Errorf("Expected value 'test1', got '%s'", retrieved1.value)
	}

	// Retrieve second output
	retrieved2 := GetOutput[*anotherTestNode](ctx).(anotherTestOutput)
	if retrieved2.number != 42 {
		t.Errorf("Expected number 42, got %d", retrieved2.number)
	}
}

func TestGetOutput_PanicsIfNotFound(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("Expected panic, got none")
		}

		panicMsg, ok := r.(string)
		if !ok {
			t.Fatalf("Panic value is not a string: %v", r)
		}

		expected := "execution-dag: output for node type *executiondag.contextTestNode not found in context"
		if panicMsg != expected {
			t.Errorf("Expected panic message '%s', got '%s'", expected, panicMsg)
		}
	}()

	ctx := context.Background()
	// Try to get output that doesn't exist
	_ = GetOutput[*contextTestNode](ctx)
}

func TestTryGetOutput_ReturnsCorrectValue(t *testing.T) {
	ctx := context.Background()
	output := contextTestOutput{value: "test"}
	ctx = storeOutputForNode[*contextTestNode, contextTestOutput](ctx, output)

	retrieved, ok := TryGetOutput[*contextTestNode](ctx)
	if !ok {
		t.Fatal("TryGetOutput returned false for existing output")
	}
	retrievedOutput, ok := retrieved.(contextTestOutput)
	if !ok {
		t.Fatal("Retrieved value is not correct type")
	}
	if retrievedOutput.value != "test" {
		t.Errorf("Expected value 'test', got '%s'", retrievedOutput.value)
	}
}

func TestTryGetOutput_ReturnsFalseIfNotFound(t *testing.T) {
	ctx := context.Background()

	retrieved, ok := TryGetOutput[*contextTestNode](ctx)
	if ok {
		t.Error("TryGetOutput should return false for missing output")
	}
	// Verify nil is returned
	if retrieved != nil {
		t.Errorf("Expected nil, got %v", retrieved)
	}
}

func TestTryGetOutput_ReturnsFalseForWrongType(t *testing.T) {
	ctx := context.Background()
	output := anotherTestOutput{number: 42}
	ctx = storeOutputForNode[*anotherTestNode, anotherTestOutput](ctx, output)

	// Try to get different node type
	_, ok := TryGetOutput[*contextTestNode](ctx)
	if ok {
		t.Error("TryGetOutput should return false for non-existent node type")
	}
}

func TestContextKeyIsolation(t *testing.T) {
	// Verify that different node types get different keys
	ctx := context.Background()
	output1 := contextTestOutput{value: "test1"}
	output2 := anotherTestOutput{number: 42}

	ctx = storeOutputForNode[*contextTestNode, contextTestOutput](ctx, output1)
	ctx = storeOutputForNode[*anotherTestNode, anotherTestOutput](ctx, output2)

	// Both should be retrievable independently
	retrieved1 := GetOutput[*contextTestNode](ctx).(contextTestOutput)
	retrieved2 := GetOutput[*anotherTestNode](ctx).(anotherTestOutput)

	if retrieved1.value != "test1" {
		t.Errorf("First output corrupted: expected 'test1', got '%s'", retrieved1.value)
	}
	if retrieved2.number != 42 {
		t.Errorf("Second output corrupted: expected 42, got %d", retrieved2.number)
	}
}

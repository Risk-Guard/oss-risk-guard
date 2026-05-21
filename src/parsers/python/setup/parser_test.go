package setup

import (
	"os"
	"path/filepath"
	"testing"
)

type setupPyNameTest struct {
	Name         string
	Content      string
	ExpectedName string
}

func runSetupPyNameTests(
	t *testing.T,
	tests []setupPyNameTest,
	parse func(string) Result,
	dynamicErrMsg string,
) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			tmpDir := t.TempDir()
			setupPy := filepath.Join(tmpDir, "setup.py")

			err := os.WriteFile(setupPy, []byte(tt.Content), 0o600)
			if err != nil {
				t.Fatal(err)
			}

			result := parse(setupPy)

			if result.Error != nil {
				t.Fatalf("Unexpected error: %v", result.Error)
			}

			if result.Name != tt.ExpectedName {
				t.Errorf("Expected name %q, got %q", tt.ExpectedName, result.Name)
			}

			if result.IsDynamic {
				t.Error(dynamicErrMsg)
			}
		})
	}
}

// TestUnquoteString_EmptyAndMalformed tests edge cases without panicking
func TestUnquoteString_EmptyAndMalformed(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string literal",
			input:    `""`,
			expected: "",
		},
		{
			name:     "empty string literal single quotes",
			input:    `''`,
			expected: "",
		},
		{
			name:     "empty triple-quoted string",
			input:    `""""""`,
			expected: "",
		},
		{
			name:     "whitespace only",
			input:    `"   "`,
			expected: "   ",
		},
		{
			name:     "single character",
			input:    `"a"`,
			expected: "a",
		},
		{
			name:     "single quote character - should not panic",
			input:    `"`,
			expected: `"`,
		},
		{
			name:     "two quote characters - should not panic",
			input:    `""`,
			expected: "",
		},
		{
			name:     "three quote characters - should not panic",
			input:    `"""`,
			expected: `"""`,
		},
		{
			name:     "four quote characters - should not panic",
			input:    `""""`,
			expected: `""""`,
		},
		{
			name:     "five quote characters - should not panic",
			input:    `"""""`,
			expected: `"""""`,
		},
		{
			name:     "string with unicode",
			input:    `"tëst-pàckage-🎉"`,
			expected: "tëst-pàckage-🎉",
		},
		{
			name:     "string with escaped quotes",
			input:    `"test\"string"`,
			expected: `test\"string`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("UnquoteString panicked on input %q: %v", tt.input, r)
				}
			}()

			result := UnquoteString(tt.input)
			if result != tt.expected {
				t.Errorf("UnquoteString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestUnquoteString_PrefixStripping tests Python string prefix stripping
func TestUnquoteString_PrefixStripping(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no prefix",
			input:    `"test"`,
			expected: "test",
		},
		{
			name:     "raw string lowercase r",
			input:    `r"test"`,
			expected: "test",
		},
		{
			name:     "raw string uppercase R",
			input:    `R"test"`,
			expected: "test",
		},
		{
			name:     "byte string lowercase b",
			input:    `b"test"`,
			expected: "test",
		},
		{
			name:     "byte string uppercase B",
			input:    `B"test"`,
			expected: "test",
		},
		{
			name:     "unicode string lowercase u",
			input:    `u"test"`,
			expected: "test",
		},
		{
			name:     "unicode string uppercase U",
			input:    `U"test"`,
			expected: "test",
		},
		{
			name:     "f-string lowercase f",
			input:    `f"test"`,
			expected: "test",
		},
		{
			name:     "f-string uppercase F",
			input:    `F"test"`,
			expected: "test",
		},
		{
			name:     "raw byte string rb",
			input:    `rb"test"`,
			expected: "test",
		},
		{
			name:     "raw byte string br",
			input:    `br"test"`,
			expected: "test",
		},
		{
			name:     "raw byte string uppercase RB",
			input:    `RB"test"`,
			expected: "test",
		},
		{
			name:     "raw f-string fr",
			input:    `fr"test"`,
			expected: "test",
		},
		{
			name:     "raw f-string rf",
			input:    `rf"test"`,
			expected: "test",
		},
		{
			name:     "raw string with backslashes",
			input:    `r"C:\path\to\file"`,
			expected: `C:\path\to\file`,
		},
		{
			name:     "raw string single quotes",
			input:    `r'test'`,
			expected: "test",
		},
		{
			name:     "triple-quoted with prefix",
			input:    `r"""test"""`,
			expected: "test",
		},
		{
			name:     "triple-quoted with prefix single quotes",
			input:    `b'''test'''`,
			expected: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UnquoteString(tt.input)
			if result != tt.expected {
				t.Errorf("UnquoteString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestLexer_StringPrefixes tests that the lexer recognizes Python string prefixes
func TestLexer_StringPrefixes(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectedErr bool
	}{
		{
			name:        "raw string lowercase r",
			content:     `setup(name=r"test-package")`,
			expectedErr: false,
		},
		{
			name:        "raw string uppercase R",
			content:     `setup(name=R"test-package")`,
			expectedErr: false,
		},
		{
			name:        "byte string lowercase b",
			content:     `setup(name=b"test-package")`,
			expectedErr: false,
		},
		{
			name:        "byte string uppercase B",
			content:     `setup(name=B"test-package")`,
			expectedErr: false,
		},
		{
			name:        "unicode string lowercase u",
			content:     `setup(name=u"test-package")`,
			expectedErr: false,
		},
		{
			name:        "unicode string uppercase U",
			content:     `setup(name=U"test-package")`,
			expectedErr: false,
		},
		{
			name:        "raw byte string rb",
			content:     `setup(name=rb"test-package")`,
			expectedErr: false,
		},
		{
			name:        "raw byte string br",
			content:     `setup(name=br"test-package")`,
			expectedErr: false,
		},
		{
			name:        "raw byte string uppercase",
			content:     `setup(name=RB"test-package")`,
			expectedErr: false,
		},
		{
			name:        "raw string single quotes",
			content:     `setup(name=r'test-package')`,
			expectedErr: false,
		},
		{
			name:        "f-string should work currently",
			content:     `setup(name=f"test-{var}")`,
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			setupPy := filepath.Join(tmpDir, "setup.py")

			err := os.WriteFile(setupPy, []byte(tt.content), 0o600)
			if err != nil {
				t.Fatal(err)
			}

			result := Parse(setupPy)

			if tt.expectedErr {
				if result.Error == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if result.Error != nil {
					t.Errorf("Unexpected error: %v", result.Error)
				}
			}
		})
	}
}

// TestSetupPy_RawStringLiteral tests raw strings in setup(name=...)
func TestSetupPy_RawStringLiteral(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		expectedName string
	}{
		{
			name: "raw string with dashes",
			content: `from setuptools import setup

setup(
    name=r"my-package",
    version="1.0.0"
)`,
			expectedName: "my-package",
		},
		{
			name: "raw string uppercase R",
			content: `from setuptools import setup

setup(
    name=R'my-package',
    version="1.0.0"
)`,
			expectedName: "my-package",
		},
		{
			name: "byte string",
			content: `from setuptools import setup

setup(
    name=b"my-package",
    version="1.0.0"
)`,
			expectedName: "my-package",
		},
		{
			name: "unicode string",
			content: `from setuptools import setup

setup(
    name=u"my-package",
    version="1.0.0"
)`,
			expectedName: "my-package",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			setupPy := filepath.Join(tmpDir, "setup.py")

			err := os.WriteFile(setupPy, []byte(tt.content), 0o600)
			if err != nil {
				t.Fatal(err)
			}

			result := Parse(setupPy)

			if result.Error != nil {
				t.Fatalf("Unexpected error: %v", result.Error)
			}

			if result.Name != tt.expectedName {
				t.Errorf("Expected name %q, got %q", tt.expectedName, result.Name)
			}

			if result.IsDynamic {
				t.Errorf("Raw string literal should not be marked as dynamic")
			}
		})
	}
}

func TestSetupPy_PrefixInConstant(t *testing.T) {
	tests := []setupPyNameTest{
		{
			Name: "raw string constant",
			Content: `from setuptools import setup

NAME = r"my-package"

setup(
    name=NAME,
    version="1.0.0"
)`,
			ExpectedName: "my-package",
		},
		{
			Name: "byte string constant",
			Content: `from setuptools import setup

PACKAGE_NAME = b"my-package"

setup(
    name=PACKAGE_NAME,
    version="1.0.0"
)`,
			ExpectedName: "my-package",
		},
		{
			Name: "unicode string constant",
			Content: `from setuptools import setup

NAME = u"my-package"

setup(name=NAME)`,
			ExpectedName: "my-package",
		},
	}

	runSetupPyNameTests(t, tests, Parse, "Constant with string prefix should not be marked as dynamic")
}

// TestSetupPy_FStringIsDynamic tests that f-strings are correctly marked as dynamic
func TestSetupPy_FStringIsDynamic(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		expectedReason string
	}{
		{
			name: "f-string lowercase",
			content: `from setuptools import setup

prefix = "my"
setup(name=f"{prefix}-package")`,
			expectedReason: "name uses f-string formatting",
		},
		{
			name: "f-string uppercase",
			content: `from setuptools import setup

prefix = "my"
setup(name=F"{prefix}-package")`,
			expectedReason: "name uses f-string formatting",
		},
		{
			name: "raw f-string fr",
			content: `from setuptools import setup

path = "test"
setup(name=fr"C:\{path}\package")`,
			expectedReason: "name uses f-string formatting",
		},
		{
			name: "raw f-string rf",
			content: `from setuptools import setup

path = "test"
setup(name=rf"C:\{path}\package")`,
			expectedReason: "name uses f-string formatting",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			setupPy := filepath.Join(tmpDir, "setup.py")

			err := os.WriteFile(setupPy, []byte(tt.content), 0o600)
			if err != nil {
				t.Fatal(err)
			}

			result := Parse(setupPy)

			if result.Error != nil {
				t.Fatalf("Unexpected error: %v", result.Error)
			}

			if !result.IsDynamic {
				t.Errorf("F-string should be marked as dynamic")
			}

			if result.DynamicReason != tt.expectedReason {
				t.Errorf("Expected reason %q, got %q", tt.expectedReason, result.DynamicReason)
			}
		})
	}
}

func TestSetupPy_TripleQuotedWithPrefix(t *testing.T) {
	tests := []setupPyNameTest{
		{
			Name: "raw triple-quoted double quotes",
			Content: `from setuptools import setup

setup(
    name=r"""my-package""",
    version="1.0.0"
)`,
			ExpectedName: "my-package",
		},
		{
			Name: "raw triple-quoted single quotes",
			Content: `from setuptools import setup

setup(
    name=r'''my-package''',
    version="1.0.0"
)`,
			ExpectedName: "my-package",
		},
		{
			Name: "byte triple-quoted",
			Content: `from setuptools import setup

setup(
    name=b"""my-package""",
    version="1.0.0"
)`,
			ExpectedName: "my-package",
		},
	}

	runSetupPyNameTests(t, tests, Parse, "Triple-quoted string with prefix should not be marked as dynamic")
}

// TestSetupPy_DecoratorDoesNotBreakLexer tests that @ decorators don't cause parse errors
func TestSetupPy_DecoratorDoesNotBreakLexer(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		expectedName string
		isDynamic    bool
	}{
		{
			name: "staticmethod decorator before setup call",
			content: `from setuptools import setup

class Config:
    @staticmethod
    def get():
        return {}

setup(
    name="my-package",
    version="1.0.0"
)`,
			expectedName: "my-package",
			isDynamic:    false,
		},
		{
			name: "multiple decorators",
			content: `from setuptools import setup

@some_decorator
@another_decorator
def helper():
    pass

setup(name="decorated-pkg")`,
			expectedName: "decorated-pkg",
			isDynamic:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			setupPy := filepath.Join(tmpDir, "setup.py")

			err := os.WriteFile(setupPy, []byte(tt.content), 0o600)
			if err != nil {
				t.Fatal(err)
			}

			result := Parse(setupPy)

			if result.Error != nil {
				t.Fatalf("Unexpected error: %v", result.Error)
			}

			if result.Name != tt.expectedName {
				t.Errorf("Expected name %q, got %q", tt.expectedName, result.Name)
			}

			if result.IsDynamic != tt.isDynamic {
				t.Errorf("Expected isDynamic=%v, got %v", tt.isDynamic, result.IsDynamic)
			}
		})
	}
}

// TestParticiple_RawStringNowWorks verifies raw strings work correctly
func TestParticiple_RawStringNowWorks(t *testing.T) {
	tmpDir := t.TempDir()
	setupPy := filepath.Join(tmpDir, "setup.py")

	content := `setup(name=r"test-package")`

	err := os.WriteFile(setupPy, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	result := Parse(setupPy)

	if result.Error != nil {
		t.Fatalf("Unexpected error: %v", result.Error)
	}

	if result.Name != "test-package" {
		t.Errorf("Expected name %q, got %q", "test-package", result.Name)
	}

	if result.IsDynamic {
		t.Errorf("Raw string literal should not be marked as dynamic")
	}
}

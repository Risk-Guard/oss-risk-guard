package setup

import (
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/participle/v2/lexer"
)

var (
	tokenIdent            lexer.TokenType
	tokenString           lexer.TokenType
	tokenTripleString     lexer.TokenType
	tokenFString          lexer.TokenType
	tokenFTripleString    lexer.TokenType
	tokenOperator         lexer.TokenType
	tokenWhitespace       lexer.TokenType
	tokenComment          lexer.TokenType
	tokenLineContinuation lexer.TokenType
)

func init() {
	symbols := pythonLexer.Symbols()
	tokenIdent = symbols["Ident"]
	tokenString = symbols["String"]
	tokenTripleString = symbols["TripleString"]
	tokenFString = symbols["FString"]
	tokenFTripleString = symbols["FTripleString"]
	tokenOperator = symbols["Operator"]
	tokenWhitespace = symbols["Whitespace"]
	tokenComment = symbols["Comment"]
	tokenLineContinuation = symbols["LineContinuation"]
}

type Result struct {
	Name          string
	IsDynamic     bool
	DynamicReason string
	Error         error
}

func (r Result) GetName() *string {
	if r.Name == "" {
		return nil
	}
	return &r.Name
}
func (r Result) GetIsDynamic() bool       { return r.IsDynamic }
func (r Result) GetDynamicReason() string { return r.DynamicReason }

func filterTokens(tokens []lexer.Token) []lexer.Token {
	filtered := make([]lexer.Token, 0, len(tokens))
	for _, tok := range tokens {
		if tok.Type == tokenWhitespace || tok.Type == tokenComment || tok.Type == tokenLineContinuation {
			continue
		}
		filtered = append(filtered, tok)
	}
	return filtered
}

func Parse(path string) Result {
	// #nosec G304 -- path is from filepath.Walk which validates directory traversal
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{Error: fmt.Errorf("failed to read setup.py: %w", err)}
	}

	if len(data) == 0 {
		return Result{Error: fmt.Errorf("file is empty")}
	}

	content := string(data)

	lex, err := pythonLexer.Lex(path, strings.NewReader(content))
	if err != nil {
		return Result{Error: fmt.Errorf("failed to tokenize: %w", err)}
	}

	tokens, err := lexer.ConsumeAll(lex)
	if err != nil {
		return Result{Error: fmt.Errorf("failed to read tokens: %w", err)}
	}

	tokens = filterTokens(tokens)

	return scanForSetupName(tokens)
}

func scanForSetupName(tokens []lexer.Token) Result {
	constants := extractConstantsFromTokens(tokens)

	setupIndex := -1
	for i := range len(tokens) {
		if isSetupCall(tokens, i) {
			setupIndex = i
			break
		}
	}

	if setupIndex == -1 {
		return Result{}
	}

	for i := setupIndex; i < len(tokens); i++ {
		if isNameAssignment(tokens, i) {
			if result := extractAssignedValue(tokens, i+2, constants); result.Name != "" || result.IsDynamic {
				return result
			}
		}
	}

	return Result{}
}

func extractConstantsFromTokens(tokens []lexer.Token) map[string]string {
	constants := make(map[string]string)

	for i := 0; i < len(tokens)-2; i++ {
		if tokens[i].Type == lexer.EOF {
			break
		}
		if tokens[i].Type == tokenIdent &&
			i+1 < len(tokens) && tokens[i+1].Value == "=" {

			name := tokens[i].Value
			if i+2 < len(tokens) {
				tok := tokens[i+2]
				if tok.Type == tokenString || tok.Type == tokenTripleString {
					constants[name] = UnquoteString(tok.Value)
				}
			}
		}
	}

	return constants
}

func isSetupCall(tokens []lexer.Token, i int) bool {
	if i >= len(tokens) {
		return false
	}
	return matchesDirectSetup(tokens, i) ||
		matchesSetuptoolsSetup(tokens, i) ||
		matchesDistutilsCoreSetup(tokens, i)
}

func matchesDirectSetup(tokens []lexer.Token, i int) bool {
	return i+1 < len(tokens) &&
		tokens[i].Type == tokenIdent && tokens[i].Value == "setup" &&
		tokens[i+1].Value == "("
}

func matchesSetuptoolsSetup(tokens []lexer.Token, i int) bool {
	return i+3 < len(tokens) &&
		tokens[i].Type == tokenIdent && tokens[i].Value == "setuptools" &&
		tokens[i+1].Value == "." &&
		tokens[i+2].Type == tokenIdent && tokens[i+2].Value == "setup" &&
		tokens[i+3].Value == "("
}

func matchesDistutilsCoreSetup(tokens []lexer.Token, i int) bool {
	return i+5 < len(tokens) &&
		tokens[i].Type == tokenIdent && tokens[i].Value == "distutils" &&
		tokens[i+1].Value == "." &&
		tokens[i+2].Type == tokenIdent && tokens[i+2].Value == "core" &&
		tokens[i+3].Value == "." &&
		tokens[i+4].Type == tokenIdent && tokens[i+4].Value == "setup" &&
		tokens[i+5].Value == "("
}

func isNameAssignment(tokens []lexer.Token, i int) bool {
	if i+2 >= len(tokens) {
		return false
	}

	return tokens[i].Type == tokenIdent && tokens[i].Value == "name" &&
		tokens[i+1].Value == "="
}

func extractAssignedValue(tokens []lexer.Token, start int, constants map[string]string) Result {
	for i := start; i < len(tokens); i++ {
		tok := tokens[i]

		if tok.Type == tokenFString || tok.Type == tokenFTripleString {
			return Result{
				IsDynamic:     true,
				DynamicReason: "name uses f-string formatting",
			}
		}

		if tok.Type == tokenString || tok.Type == tokenTripleString {
			if result := checkForOperatorsOrSubscripts(tokens, i); result.IsDynamic {
				return result
			}
			return Result{Name: UnquoteString(tok.Value), IsDynamic: false}
		}

		if tok.Type == tokenIdent {
			name := tok.Value

			if resolved, ok := constants[name]; ok {
				if result := checkForOperatorsOrSubscripts(tokens, i); result.IsDynamic {
					return result
				}
				return Result{Name: resolved, IsDynamic: false}
			}

			if i+1 < len(tokens) && tokens[i+1].Value == "[" {
				return Result{
					IsDynamic:     true,
					DynamicReason: "name uses dictionary/list lookup",
				}
			}

			if i+1 < len(tokens) && (tokens[i+1].Value == "(" || tokens[i+1].Value == ".") {
				return Result{
					IsDynamic:     true,
					DynamicReason: "name uses function call",
				}
			}

			return Result{
				IsDynamic:     true,
				DynamicReason: fmt.Sprintf("uses variable reference: %s", name),
			}
		}

		if tok.Value == "[" {
			return Result{
				IsDynamic:     true,
				DynamicReason: "name is a list (expected string)",
			}
		}

		if tok.Value == "{" {
			return Result{
				IsDynamic:     true,
				DynamicReason: "name is a dict (expected string)",
			}
		}

		if tok.Value == "," || tok.Value == ")" {
			break
		}
	}

	return Result{}
}

func checkForOperatorsOrSubscripts(tokens []lexer.Token, currentIndex int) Result {
	if currentIndex+1 >= len(tokens) {
		return Result{}
	}

	next := tokens[currentIndex+1]

	if next.Value == "[" {
		return Result{
			IsDynamic:     true,
			DynamicReason: "name uses dictionary/list lookup",
		}
	}

	if next.Type == tokenOperator {
		return Result{
			IsDynamic:     true,
			DynamicReason: fmt.Sprintf("name uses binary operator: %s", next.Value),
		}
	}

	return Result{}
}

func UnquoteString(s string) string {
	s = strings.TrimSpace(s)

	prefixes := []string{
		"br", "BR", "Br", "bR",
		"rb", "RB", "Rb", "rB",
		"fr", "FR", "Fr", "fR",
		"rf", "RF", "Rf", "rF",
		"b", "B",
		"r", "R",
		"u", "U",
		"f", "F",
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			s = s[len(prefix):]
			break
		}
	}

	if len(s) >= 6 {
		if strings.HasPrefix(s, `"""`) && strings.HasSuffix(s, `"""`) {
			return s[3 : len(s)-3]
		}
		if strings.HasPrefix(s, `'''`) && strings.HasSuffix(s, `'''`) {
			return s[3 : len(s)-3]
		}
	}

	if len(s) >= 2 {
		firstChar := s[0]
		lastChar := s[len(s)-1]

		if (firstChar == '"' || firstChar == '\'') && firstChar == lastChar {
			if len(s) >= 3 && (strings.HasPrefix(s, `"""`) || strings.HasPrefix(s, `'''`)) {
				return s
			}
			return s[1 : len(s)-1]
		}
	}

	return s
}

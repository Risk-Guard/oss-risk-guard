package gemspec

import (
	"fmt"
	"os"
	"risk-guard/src/models"
	"strings"

	"github.com/alecthomas/participle/v2/lexer"
)

var (
	tokenIdent          lexer.TokenType
	tokenSingleString   lexer.TokenType
	tokenDoubleString   lexer.TokenType
	tokenPercentLiteral lexer.TokenType
	tokenDoubleColon    lexer.TokenType
	tokenWhitespace     lexer.TokenType
	tokenComment        lexer.TokenType
	tokenUnknown        lexer.TokenType
)

func init() {
	symbols := rubyLexer.Symbols()
	tokenIdent = symbols["Ident"]
	tokenSingleString = symbols["SingleString"]
	tokenDoubleString = symbols["DoubleString"]
	tokenPercentLiteral = symbols["PercentLiteral"]
	tokenDoubleColon = symbols["DoubleColon"]
	tokenWhitespace = symbols["Whitespace"]
	tokenComment = symbols["Comment"]
	tokenUnknown = symbols["Unknown"]
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
		if tok.Type == tokenWhitespace || tok.Type == tokenComment || tok.Type == tokenUnknown {
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
		return Result{Error: fmt.Errorf("failed to read .gemspec: %w", err)}
	}

	if len(data) == 0 {
		return Result{Error: fmt.Errorf("file is empty")}
	}

	content := string(data)

	lex, err := rubyLexer.Lex(path, strings.NewReader(content))
	if err != nil {
		return Result{Error: fmt.Errorf("failed to tokenize: %w", err)}
	}

	tokens, err := lexer.ConsumeAll(lex)
	if err != nil {
		return Result{Error: fmt.Errorf("failed to read tokens: %w", err)}
	}

	tokens = filterTokens(tokens)

	return scanForGemName(tokens)
}

func ExtractDependencies(content string, sourceFile string) ([]models.Dependency, []models.DynamicDependency, error) {
	lex, err := rubyLexer.Lex("", strings.NewReader(content))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to tokenize: %w", err)
	}

	tokens, err := lexer.ConsumeAll(lex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read tokens: %w", err)
	}

	tokens = filterTokens(tokens)

	deps, dynDeps := scanForDependencies(tokens, sourceFile)
	return deps, dynDeps, nil
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
				if tok.Type == tokenSingleString ||
					tok.Type == tokenDoubleString ||
					tok.Type == tokenPercentLiteral {
					constants[name] = UnquoteString(tok.Value)
				}
			}
		}
	}

	return constants
}

func UnquoteString(s string) string {
	s = strings.TrimSpace(s)

	if len(s) >= 4 && s[0] == '%' && s[2] == '[' && s[len(s)-1] == ']' {
		return s[3 : len(s)-1]
	}
	if strings.HasPrefix(s, "%[") && strings.HasSuffix(s, "]") {
		return s[2 : len(s)-1]
	}
	if strings.HasPrefix(s, "%q{") && strings.HasSuffix(s, "}") {
		return s[3 : len(s)-1]
	}
	if strings.HasPrefix(s, "%Q{") && strings.HasSuffix(s, "}") {
		return s[3 : len(s)-1]
	}

	if len(s) >= 2 {
		firstChar := s[0]
		lastChar := s[len(s)-1]

		if (firstChar == '"' || firstChar == '\'') && firstChar == lastChar {
			return s[1 : len(s)-1]
		}
	}

	return s
}

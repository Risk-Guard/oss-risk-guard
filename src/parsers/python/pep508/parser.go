package pep508

import (
	"fmt"
	"strings"

	"github.com/alecthomas/participle/v2/lexer"
)

var (
	depTokenWhitespace     lexer.TokenType
	depTokenVersionOp      lexer.TokenType
	depTokenLParen         lexer.TokenType
	depTokenRParen         lexer.TokenType
	depTokenComma          lexer.TokenType
	depTokenLBracket       lexer.TokenType
	depTokenRBracket       lexer.TokenType
	depTokenVersionOrIdent lexer.TokenType
)

func init() {
	symbols := depSpecLexer.Symbols()
	depTokenWhitespace = symbols["Whitespace"]
	depTokenVersionOp = symbols["VersionOp"]
	depTokenLParen = symbols["LParen"]
	depTokenRParen = symbols["RParen"]
	depTokenComma = symbols["Comma"]
	depTokenLBracket = symbols["LBracket"]
	depTokenRBracket = symbols["RBracket"]
	depTokenVersionOrIdent = symbols["VersionOrIdent"]
}

type Result struct {
	Name       string
	Specifiers []string
	ParseError string
}

// Parse parses a PEP 508 dependency specifier string.
// Returns the package name, version specifiers, and any parse error.
func Parse(spec string) Result {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Result{ParseError: "empty dependency specifier"}
	}

	lex, err := depSpecLexer.Lex("", strings.NewReader(spec))
	if err != nil {
		return Result{ParseError: fmt.Sprintf("lexer error: %v", err)}
	}

	tokens, err := lexer.ConsumeAll(lex)
	if err != nil {
		return Result{ParseError: fmt.Sprintf("token error: %v", err)}
	}

	tokens = filterDepTokens(tokens)
	if len(tokens) == 0 {
		return Result{ParseError: "no tokens found"}
	}

	return parseDepTokens(tokens, spec)
}

func filterDepTokens(tokens []lexer.Token) []lexer.Token {
	filtered := make([]lexer.Token, 0, len(tokens))
	for _, tok := range tokens {
		if tok.Type == depTokenWhitespace || tok.Type == lexer.EOF {
			continue
		}
		filtered = append(filtered, tok)
	}
	return filtered
}

func parseDepTokens(tokens []lexer.Token, originalSpec string) Result {
	// Check for parenthesized format: "package (>=1.0)"
	parenIdx := -1
	for i, tok := range tokens {
		if tok.Type == depTokenLParen {
			parenIdx = i
			break
		}
	}

	if parenIdx > 0 {
		return parseParenFormat(tokens, parenIdx)
	}

	// Check for inline format: "package>=1.0"
	return parseInlineFormat(tokens, originalSpec)
}

func parseParenFormat(tokens []lexer.Token, parenIdx int) Result {
	// Extract package name (everything before the paren, excluding extras)
	var nameParts []string
	for i := range parenIdx {
		if tokens[i].Type == depTokenLBracket {
			break // Stop at extras
		}
		if tokens[i].Type == depTokenVersionOrIdent {
			nameParts = append(nameParts, tokens[i].Value)
		}
	}

	if len(nameParts) == 0 {
		return Result{ParseError: "no package name found before parentheses"}
	}
	name := strings.Join(nameParts, "")

	// Find matching close paren
	closeIdx := -1
	depth := 1
	for i := parenIdx + 1; i < len(tokens); i++ {
		if tokens[i].Type == depTokenLParen {
			depth++
		} else if tokens[i].Type == depTokenRParen {
			depth--
			if depth == 0 {
				closeIdx = i
				break
			}
		}
	}

	if closeIdx == -1 {
		return Result{
			Name:       name,
			ParseError: "unclosed parentheses in version specifier",
		}
	}

	// Parse specifiers inside parens
	specifiers, parseErr := parseVersionSpecifiers(tokens[parenIdx+1 : closeIdx])
	return Result{
		Name:       name,
		Specifiers: specifiers,
		ParseError: parseErr,
	}
}

func parseInlineFormat(tokens []lexer.Token, originalSpec string) Result {
	// Find the first version operator
	opIdx := -1
	for i, tok := range tokens {
		if tok.Type == depTokenVersionOp {
			opIdx = i
			break
		}
	}

	// No operator found - just a package name
	if opIdx == -1 {
		var nameParts []string
		for _, tok := range tokens {
			if tok.Type == depTokenLBracket {
				break // Stop at extras
			}
			if tok.Type == depTokenVersionOrIdent {
				nameParts = append(nameParts, tok.Value)
			}
		}
		if len(nameParts) == 0 {
			return Result{ParseError: "no package name found"}
		}
		return Result{
			Name:       strings.Join(nameParts, ""),
			Specifiers: []string{},
		}
	}

	// Extract package name (tokens before operator, excluding extras)
	var nameParts []string
	for i := 0; i < opIdx; i++ {
		if tokens[i].Type == depTokenLBracket {
			break // Stop at extras
		}
		if tokens[i].Type == depTokenVersionOrIdent {
			nameParts = append(nameParts, tokens[i].Value)
		}
	}

	if len(nameParts) == 0 {
		return Result{ParseError: "no package name found before version operator"}
	}
	name := strings.Join(nameParts, "")

	// Parse specifiers from operator onwards
	specifiers, parseErr := parseVersionSpecifiers(tokens[opIdx:])
	return Result{
		Name:       name,
		Specifiers: specifiers,
		ParseError: parseErr,
	}
}

func parseVersionSpecifiers(tokens []lexer.Token) ([]string, string) {
	var specifiers []string
	var current strings.Builder
	expectOp := true
	hasVersion := false

	for _, tok := range tokens {
		switch tok.Type {
		case depTokenVersionOp:
			if !expectOp && current.Len() > 0 {
				specifiers = append(specifiers, current.String())
				current.Reset()
				hasVersion = false
			}
			current.WriteString(tok.Value)
			expectOp = false

		case depTokenVersionOrIdent:
			if expectOp {
				return specifiers, fmt.Sprintf("unexpected version '%s' without operator", tok.Value)
			}
			current.WriteString(tok.Value)
			hasVersion = true

		case depTokenComma:
			if current.Len() > 0 {
				if !hasVersion {
					return specifiers, fmt.Sprintf("version operator '%s' without version", current.String())
				}
				specifiers = append(specifiers, current.String())
				current.Reset()
				hasVersion = false
			}
			expectOp = true

		case depTokenLBracket, depTokenRBracket:
			continue

		default:
			return specifiers, fmt.Sprintf("unexpected token in version specifier: %s", tok.Value)
		}
	}

	if current.Len() > 0 {
		if !hasVersion {
			return specifiers, fmt.Sprintf("version operator '%s' without version", current.String())
		}
		specifiers = append(specifiers, current.String())
	}

	return specifiers, ""
}

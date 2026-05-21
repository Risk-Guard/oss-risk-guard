package gemspec

import (
	"fmt"
	"strings"

	"github.com/alecthomas/participle/v2/lexer"
)

func scanForGemName(tokens []lexer.Token) Result {
	constants := extractConstantsFromTokens(tokens)

	gemSpecIndex := -1
	for i := range len(tokens) {
		if isGemSpecNew(tokens, i) {
			gemSpecIndex = i
			break
		}
	}

	if gemSpecIndex == -1 {
		return Result{Error: fmt.Errorf("no Gem::Specification.new found")}
	}

	startArgIndex := gemSpecIndex + 5
	if startArgIndex < len(tokens) && tokens[startArgIndex].Value != "do" {
		if result := extractFirstArg(tokens, startArgIndex, constants); result.Name != "" || result.IsDynamic {
			return result
		}
	}

	// If no first argument, look for s.name = 'value' anywhere in the file
	for i := gemSpecIndex; i < len(tokens); i++ {
		if isNameAssignment(tokens, i) {
			// Value is at i+4: i=ident, i+1=dot, i+2=name, i+3=equals, i+4=value
			if result := extractFirstArg(tokens, i+4, constants); result.Name != "" || result.IsDynamic {
				return result
			}
		}
	}

	return Result{Error: fmt.Errorf("no name found in Gem::Specification")}
}

func isGemSpecNew(tokens []lexer.Token, i int) bool {
	if i+4 >= len(tokens) {
		return false
	}

	return tokens[i].Type == tokenIdent && tokens[i].Value == "Gem" &&
		tokens[i+1].Type == tokenDoubleColon &&
		tokens[i+2].Type == tokenIdent && tokens[i+2].Value == "Specification" &&
		tokens[i+3].Value == "." &&
		tokens[i+4].Type == tokenIdent && tokens[i+4].Value == "new"
}

func isNameAssignment(tokens []lexer.Token, i int) bool {
	if i+3 >= len(tokens) {
		return false
	}

	return tokens[i].Type == tokenIdent &&
		tokens[i+1].Value == "." &&
		tokens[i+2].Type == tokenIdent && tokens[i+2].Value == "name" &&
		tokens[i+3].Value == "="
}

func extractFirstArg(tokens []lexer.Token, start int, constants map[string]string) Result {
	for i := start; i < len(tokens); i++ {
		tok := tokens[i]

		if tok.Type == tokenSingleString {
			if result := checkForOperatorsOrSubscripts(tokens, i); result.IsDynamic {
				return result
			}
			return Result{Name: UnquoteString(tok.Value), IsDynamic: false}
		}

		if tok.Type == tokenDoubleString {
			if strings.Contains(tok.Value, "#{") {
				return Result{
					IsDynamic:     true,
					DynamicReason: "name uses string interpolation",
				}
			}
			if result := checkForOperatorsOrSubscripts(tokens, i); result.IsDynamic {
				return result
			}
			return Result{Name: UnquoteString(tok.Value), IsDynamic: false}
		}

		if tok.Type == tokenPercentLiteral {
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

			if i+1 < len(tokens) && tokens[i+1].Type == tokenDoubleColon {
				return Result{
					IsDynamic:     true,
					DynamicReason: "name uses module constant",
				}
			}

			if i+1 < len(tokens) && tokens[i+1].Value == "[" {
				return Result{
					IsDynamic:     true,
					DynamicReason: "name uses array/hash lookup",
				}
			}

			if i+1 < len(tokens) {
				next := tokens[i+1].Value
				if next == "(" || next == "." {
					return Result{
						IsDynamic:     true,
						DynamicReason: "name uses method call",
					}
				}
			}

			return Result{
				IsDynamic:     true,
				DynamicReason: fmt.Sprintf("uses variable reference: %s", name),
			}
		}

		if tok.Value == "do" || tok.Value == "," {
			break
		}
	}

	return Result{}
}

func checkForOperatorsOrSubscripts(tokens []lexer.Token, currentIndex int) Result {
	if currentIndex+1 >= len(tokens) {
		return Result{}
	}

	next := tokens[currentIndex+1].Value

	if next == "[" {
		return Result{
			IsDynamic:     true,
			DynamicReason: "name uses array/hash lookup",
		}
	}

	binaryOps := []string{"+", "-", "*", "/", "%", "**"}
	for _, op := range binaryOps {
		if next == op {
			return Result{
				IsDynamic:     true,
				DynamicReason: fmt.Sprintf("name uses binary operator: %s", op),
			}
		}
	}

	return Result{}
}

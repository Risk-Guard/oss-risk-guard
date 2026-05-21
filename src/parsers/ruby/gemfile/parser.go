package gemfile

import (
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/parsers/ruby/gemspec"
	"strings"

	"github.com/alecthomas/participle/v2/lexer"
)

var (
	tokenKeyword             lexer.TokenType
	tokenGemfileComment      lexer.TokenType
	tokenGemfileSingleString lexer.TokenType
	tokenGemfileDoubleString lexer.TokenType
	tokenGemfilePercent      lexer.TokenType
	tokenGemfileWhitespace   lexer.TokenType
	tokenGemfileIdent        lexer.TokenType
	tokenGemfileDoubleColon  lexer.TokenType
	tokenGemfileUnknown      lexer.TokenType
)

func init() {
	symbols := gemfileLexer.Symbols()
	tokenKeyword = symbols["Keyword"]
	tokenGemfileComment = symbols["Comment"]
	tokenGemfileSingleString = symbols["SingleString"]
	tokenGemfileDoubleString = symbols["DoubleString"]
	tokenGemfilePercent = symbols["PercentLiteral"]
	tokenGemfileWhitespace = symbols["Whitespace"]
	tokenGemfileIdent = symbols["Ident"]
	tokenGemfileDoubleColon = symbols["DoubleColon"]
	tokenGemfileUnknown = symbols["Unknown"]
}

func ExtractDependencies(content string, sourceFile string) ([]models.Dependency, []models.DynamicDependency, error) {
	lex, err := gemfileLexer.Lex("", strings.NewReader(content))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to tokenize: %w", err)
	}

	tokens, err := lexer.ConsumeAll(lex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read tokens: %w", err)
	}

	tokens = filterGemfileTokens(tokens)

	deps, dynDeps := scanForGemfileDependencies(tokens, sourceFile)
	return deps, dynDeps, nil
}

func filterGemfileTokens(tokens []lexer.Token) []lexer.Token {
	filtered := make([]lexer.Token, 0, len(tokens))
	for _, tok := range tokens {
		if tok.Type == tokenGemfileWhitespace || tok.Type == tokenGemfileComment || tok.Type == tokenGemfileUnknown {
			continue
		}
		filtered = append(filtered, tok)
	}
	return filtered
}

func extractGemfileConstants(tokens []lexer.Token) map[string]string {
	constants := make(map[string]string)

	for i := 0; i < len(tokens)-2; i++ {
		if tokens[i].Type == lexer.EOF {
			break
		}
		if tokens[i].Type == tokenGemfileIdent &&
			i+1 < len(tokens) && tokens[i+1].Value == "=" {

			name := tokens[i].Value
			if i+2 < len(tokens) {
				tok := tokens[i+2]
				if tok.Type == tokenGemfileSingleString ||
					tok.Type == tokenGemfileDoubleString ||
					tok.Type == tokenGemfilePercent {
					constants[name] = gemspec.UnquoteString(tok.Value)
				}
			}
		}
	}

	return constants
}

func scanForGemfileDependencies(tokens []lexer.Token, sourceFile string) ([]models.Dependency, []models.DynamicDependency) {
	constants := extractGemfileConstants(tokens)
	var dependencies []models.Dependency
	var dynamicDeps []models.DynamicDependency

	for i := range len(tokens) {
		if isGemCall(tokens, i) {
			startIndex := i + 1

			if startIndex >= len(tokens) {
				continue
			}

			depNameEndIndex := startIndex
			depResult := extractGemArg(tokens, startIndex, constants)
			if depResult.IsDynamic {
				dynamicDeps = append(dynamicDeps, models.DynamicDependency{
					SourceFile: sourceFile,
					Line:       tokens[i].Pos.Line,
					Reason:     depResult.DynamicReason,
				})
			} else if depResult.Name != "" {
				for depNameEndIndex < len(tokens) {
					if tokens[depNameEndIndex].Type == tokenGemfileSingleString ||
						tokens[depNameEndIndex].Type == tokenGemfileDoubleString ||
						tokens[depNameEndIndex].Type == tokenGemfilePercent ||
						(tokens[depNameEndIndex].Type == tokenGemfileIdent && constants[tokens[depNameEndIndex].Value] != "") {
						break
					}
					depNameEndIndex++
				}
				specifiers := extractGemVersionSpecifiers(tokens, depNameEndIndex+1)
				line := tokens[i].Pos.Line
				dependencies = append(dependencies, models.Dependency{
					AnalysisIdentifier: models.MakeSimplePackageAnalysisIdentifier("rubygems", depResult.Name),
					Specifiers:         specifiers,
					Location: &models.LocationInfo{
						File:       &sourceFile,
						LineNumber: &line,
					},
				})
			}
		}
	}

	return dependencies, dynamicDeps
}

func isGemCall(tokens []lexer.Token, i int) bool {
	if i >= len(tokens) {
		return false
	}

	if tokens[i].Type != tokenKeyword {
		return false
	}

	return tokens[i].Value == "gem"
}

func extractGemArg(tokens []lexer.Token, start int, constants map[string]string) gemspec.Result {
	for i := start; i < len(tokens); i++ {
		tok := tokens[i]

		if tok.Type == tokenGemfileSingleString {
			return gemspec.Result{Name: gemspec.UnquoteString(tok.Value), IsDynamic: false}
		}

		if tok.Type == tokenGemfileDoubleString {
			if strings.Contains(tok.Value, "#{") {
				return gemspec.Result{
					IsDynamic:     true,
					DynamicReason: "gem name uses string interpolation",
				}
			}
			return gemspec.Result{Name: gemspec.UnquoteString(tok.Value), IsDynamic: false}
		}

		if tok.Type == tokenGemfilePercent {
			return gemspec.Result{Name: gemspec.UnquoteString(tok.Value), IsDynamic: false}
		}

		if tok.Type == tokenGemfileIdent {
			name := tok.Value

			if resolved, ok := constants[name]; ok {
				return gemspec.Result{Name: resolved, IsDynamic: false}
			}

			if i+1 < len(tokens) && tokens[i+1].Type == tokenGemfileDoubleColon {
				return gemspec.Result{
					IsDynamic:     true,
					DynamicReason: "gem name uses module constant",
				}
			}

			if i+1 < len(tokens) && tokens[i+1].Value == "(" {
				return gemspec.Result{
					IsDynamic:     true,
					DynamicReason: "gem name uses method call",
				}
			}

			return gemspec.Result{
				IsDynamic:     true,
				DynamicReason: fmt.Sprintf("gem name uses variable reference: %s", name),
			}
		}

		if tok.Value == "," || tok.Type == tokenKeyword {
			break
		}
	}

	return gemspec.Result{}
}

func extractGemVersionSpecifiers(tokens []lexer.Token, start int) []string {
	var specifiers []string
	startLine := -1
	if start < len(tokens) {
		startLine = tokens[start].Pos.Line
	}

	for i := start; i < len(tokens); i++ {
		tok := tokens[i]

		if tok.Type == tokenKeyword {
			break
		}

		if startLine != -1 && tok.Pos.Line > startLine {
			break
		}

		if tok.Type == tokenGemfileSingleString || tok.Type == tokenGemfileDoubleString || tok.Type == tokenGemfilePercent {
			spec := gemspec.UnquoteString(tok.Value)
			if gemspec.IsVersionSpec(spec) {
				specifiers = append(specifiers, spec)
			}
		}
	}

	return specifiers
}

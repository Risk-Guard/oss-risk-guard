package gemspec

import (
	"fmt"
	"risk-guard/src/models"
	"strings"

	"github.com/alecthomas/participle/v2/lexer"
)

func scanForDependencies(tokens []lexer.Token, sourceFile string) ([]models.Dependency, []models.DynamicDependency) {
	constants := extractConstantsFromTokens(tokens)
	var dependencies []models.Dependency
	var dynamicDeps []models.DynamicDependency

	for i := range len(tokens) {
		if isDependencyCall(tokens, i) {
			depType := tokens[i+2].Value
			if depType == "add_development_dependency" {
				continue
			}

			startIndex := i + 3
			if startIndex < len(tokens) && tokens[startIndex].Value == "(" {
				startIndex++
			}

			if startIndex >= len(tokens) {
				continue
			}

			depNameEndIndex := startIndex
			depResult := extractDependencyArg(tokens, startIndex, constants)
			if depResult.IsDynamic {
				dynamicDeps = append(dynamicDeps, models.DynamicDependency{
					SourceFile: sourceFile,
					Line:       tokens[i].Pos.Line,
					Reason:     depResult.DynamicReason,
				})
			} else if depResult.Name != "" {
				for depNameEndIndex < len(tokens) {
					if tokens[depNameEndIndex].Type == tokenSingleString ||
						tokens[depNameEndIndex].Type == tokenDoubleString ||
						tokens[depNameEndIndex].Type == tokenPercentLiteral ||
						(tokens[depNameEndIndex].Type == tokenIdent && constants[tokens[depNameEndIndex].Value] != "") {
						break
					}
					depNameEndIndex++
				}
				specifiers := extractVersionSpecifiers(tokens, depNameEndIndex+1)
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
			// No else needed: extractDependencyArg returns empty Result{} only for
			// spec.add_dependency() with zero args, which is a Ruby runtime error.
			// No valid gemspec triggers this path.
		}
	}

	return dependencies, dynamicDeps
}

func isDependencyCall(tokens []lexer.Token, i int) bool {
	if i+2 >= len(tokens) {
		return false
	}

	if tokens[i].Type != tokenIdent {
		return false
	}

	if tokens[i+1].Value != "." {
		return false
	}

	if tokens[i+2].Type != tokenIdent {
		return false
	}

	methodName := tokens[i+2].Value
	return methodName == "add_dependency" ||
		methodName == "add_runtime_dependency" ||
		methodName == "add_development_dependency"
}

func extractDependencyArg(tokens []lexer.Token, start int, constants map[string]string) Result {
	for i := start; i < len(tokens); i++ {
		tok := tokens[i]

		if tok.Type == tokenSingleString {
			return Result{Name: UnquoteString(tok.Value), IsDynamic: false}
		}

		if tok.Type == tokenDoubleString {
			if strings.Contains(tok.Value, "#{") {
				return Result{
					IsDynamic:     true,
					DynamicReason: "dependency name uses string interpolation",
				}
			}
			return Result{Name: UnquoteString(tok.Value), IsDynamic: false}
		}

		if tok.Type == tokenPercentLiteral {
			return Result{Name: UnquoteString(tok.Value), IsDynamic: false}
		}

		if tok.Type == tokenIdent {
			name := tok.Value

			if resolved, ok := constants[name]; ok {
				return Result{Name: resolved, IsDynamic: false}
			}

			if i+1 < len(tokens) && tokens[i+1].Type == tokenDoubleColon {
				return Result{
					IsDynamic:     true,
					DynamicReason: "dependency name uses module constant",
				}
			}

			if i+1 < len(tokens) && tokens[i+1].Value == "(" {
				return Result{
					IsDynamic:     true,
					DynamicReason: "dependency name uses method call",
				}
			}

			return Result{
				IsDynamic:     true,
				DynamicReason: fmt.Sprintf("dependency name uses variable reference: %s", name),
			}
		}

		if tok.Value == "," || tok.Value == ")" {
			break
		}
	}

	return Result{}
}

func extractVersionSpecifiers(tokens []lexer.Token, start int) []string {
	var specifiers []string
	startLine := -1
	if start < len(tokens) {
		startLine = tokens[start].Pos.Line
	}

	for i := start; i < len(tokens); i++ {
		tok := tokens[i]

		if tok.Value == ")" || tok.Value == "end" {
			break
		}

		if startLine != -1 && tok.Pos.Line > startLine {
			break
		}

		if tok.Type == tokenIdent && (tok.Value == "s" || tok.Value == "spec") {
			if i+1 < len(tokens) && tokens[i+1].Value == "." {
				break
			}
		}

		if tok.Type == tokenSingleString || tok.Type == tokenDoubleString || tok.Type == tokenPercentLiteral {
			spec := UnquoteString(tok.Value)
			if IsVersionSpec(spec) {
				specifiers = append(specifiers, spec)
			}
		}
	}

	return specifiers
}

func IsVersionSpec(s string) bool {
	if s == "" {
		return false
	}
	versionOperators := []string{">=", "<=", "~>", ">", "<", "=", "!="}
	for _, op := range versionOperators {
		if strings.HasPrefix(s, op) {
			return true
		}
	}
	return false
}

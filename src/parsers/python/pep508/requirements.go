package pep508

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/models"

	pythonnormalize "github.com/Risk-Guard/oss-risk-guard/src/language/python/normalize"
)

type lineWithNumber struct {
	content    string
	lineNumber int
}

func ParseRequirementsTxt(content string, sourceFile string) ([]models.Dependency, error) {
	lines := preprocessLines(content)
	var deps []models.Dependency

	for _, line := range lines {
		dep := ParseRequirementLine(line.content, sourceFile)
		if dep != nil {
			if dep.Location == nil {
				dep.Location = &models.LocationInfo{}
			}
			dep.Location.LineNumber = &line.lineNumber
			deps = append(deps, *dep)
		}
	}

	return deps, nil
}

func preprocessLines(content string) []lineWithNumber {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var logicalLines []lineWithNumber
	var currentLine strings.Builder
	lineNum := 0
	startLineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Handle line continuation
		if strings.HasSuffix(line, "\\") {
			if currentLine.Len() == 0 {
				startLineNum = lineNum
			}
			currentLine.WriteString(strings.TrimSuffix(line, "\\"))
			currentLine.WriteString(" ")
			continue
		}

		if currentLine.Len() == 0 {
			startLineNum = lineNum
		}
		currentLine.WriteString(line)
		completeLine := currentLine.String()
		currentLine.Reset()

		if completeLine == "" {
			continue
		}

		// Remove comments (# not in quotes)
		completeLine = removeComment(completeLine)
		if completeLine != "" && !strings.HasPrefix(completeLine, "#") {
			logicalLines = append(logicalLines, lineWithNumber{
				content:    completeLine,
				lineNumber: startLineNum,
			})
		}
	}

	// Handle any remaining line
	if currentLine.Len() > 0 {
		line := currentLine.String()
		line = removeComment(line)
		if line != "" {
			logicalLines = append(logicalLines, lineWithNumber{
				content:    line,
				lineNumber: startLineNum,
			})
		}
	}

	return logicalLines
}

func removeComment(line string) string {
	beforeComment, _, found := strings.Cut(line, "#")
	if !found {
		return strings.TrimSpace(line)
	}

	// Simple check: count quotes before comment
	quoteCount := strings.Count(beforeComment, "\"") + strings.Count(beforeComment, "'")

	if quoteCount%2 == 0 {
		// Not inside quotes
		return strings.TrimSpace(beforeComment)
	}

	// Inside quotes, keep the whole line
	return strings.TrimSpace(line)
}

func ParseRequirementLine(line string, sourceFile string) *models.Dependency {
	line = strings.TrimSpace(line)

	if strings.HasPrefix(line, "--") {
		return nil
	}

	if strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "-c ") {
		return nil
	}

	if strings.HasPrefix(line, "-e ") {
		return nil
	}

	if strings.Contains(line, "://") || strings.HasPrefix(line, ".") || strings.HasPrefix(line, "/") {
		return nil
	}

	line = removeHashOptions(line)

	parts := strings.SplitN(line, ";", 2)
	mainPart := strings.TrimSpace(parts[0])

	result := Parse(mainPart)

	if result.Name == "" {
		return nil
	}

	var parseError *string
	if result.ParseError != "" {
		parseError = &result.ParseError
	}

	return &models.Dependency{
		AnalysisIdentifier: models.MakeSimplePackageAnalysisIdentifier("pypi", pythonnormalize.NormalizePyPIName(result.Name)),
		Specifiers:         result.Specifiers,
		ParseError:         parseError,
		Location:           &models.LocationInfo{File: &sourceFile},
	}
}

func removeHashOptions(line string) string {
	hashRegex := regexp.MustCompile(`\s*--hash=\S+`)
	return hashRegex.ReplaceAllString(line, "")
}

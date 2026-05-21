package pep508

import (
	"github.com/alecthomas/participle/v2/lexer"
)

// Lexer for PEP 508 dependency specifiers.
// Grammar: https://packaging.python.org/en/latest/specifications/dependency-specifiers/
//
// version_cmp = wsp* <'<=' | '<' | '!=' | '===' | '==' | '>=' | '>' | '~='>
// version     = wsp* <( letterOrDigit | '-' | '_' | '.' | '*' | '+' | '!' )+>

var depSpecLexer = lexer.MustSimple([]lexer.SimpleRule{
	{Name: "Whitespace", Pattern: `[ \t]+`},
	// Operators ordered longest-first to ensure === matches before ==, <= before <, etc.
	{Name: "VersionOp", Pattern: `===|~=|==|!=|<=|>=|<|>`},
	{Name: "LParen", Pattern: `\(`},
	{Name: "RParen", Pattern: `\)`},
	{Name: "Comma", Pattern: `,`},
	{Name: "LBracket", Pattern: `\[`},
	{Name: "RBracket", Pattern: `\]`},
	// Version characters per PEP 508: letterOrDigit | '-' | '_' | '.' | '*' | '+' | '!'
	// The '!' is for epoch versions (e.g., 1!1.0) but must not appear at end to avoid
	// consuming '!' from '!=' operator when preceded by identifier (e.g., pytest!=1.0)
	{Name: "VersionOrIdent", Pattern: `[a-zA-Z0-9]([a-zA-Z0-9\-_.*+]*![a-zA-Z0-9\-_.*+]+|[a-zA-Z0-9\-_.*+]*)`},
})

package setup

import (
	"github.com/alecthomas/participle/v2/lexer"
)

/*
Token-based scanning: only extract static patterns (literals + constants).

PHILOSOPHY:
- Define ONLY what we can parse as static: string literals and resolved constants
- Everything else (operators, function calls, subscripts) naturally becomes dynamic
- No AST building - scan tokens directly for patterns

WHAT WORKS (static):
  setup(name='pkg')                    # String literal
  NAME = 'pkg'; setup(name=NAME)       # Resolved constant

WHAT IS DYNAMIC (not parseable as static):
  setup(name=UNDEFINED)                # Undefined variable
  setup(name=get_name())               # Function call
  setup(name='my' + 'pkg')             # Binary operator
  setup(name=config['key'])            # Dict/list lookup
  setup(name=f"{prefix}-pkg")          # F-string

This is a MINIMAL parser - we only handle what we need, nothing more.
*/

var pythonLexer = lexer.MustSimple([]lexer.SimpleRule{
	{Name: "Comment", Pattern: `#[^\n]*`},
	{Name: "FTripleString", Pattern: `(?i:f|fr|rf)"""[\s\S]*?"""|(?i:f|fr|rf)'''[\s\S]*?'''`},
	{Name: "FString", Pattern: `(?i:f|fr|rf)"(?:[^"\\]|\\.)*"|(?i:f|fr|rf)'(?:[^'\\]|\\.)*'`},
	{Name: "TripleString", Pattern: `(?i:r|u|b|br|rb)?"""[\s\S]*?"""|(?i:r|u|b|br|rb)?'''[\s\S]*?'''`},
	{Name: "String", Pattern: `(?i:r|u|b|br|rb)?"(?:[^"\\]|\\.)*"|(?i:r|u|b|br|rb)?'(?:[^'\\]|\\.)*'`},
	{Name: "Ident", Pattern: `[a-zA-Z_][a-zA-Z0-9_]*`},
	{Name: "Number", Pattern: `\d+`},
	{Name: "Operator", Pattern: `\+|-|\*|/|%|==|!=|<=|>=|<|>`},
	{Name: "Punct", Pattern: `[()[\]{},=.:@;~&|^]`},
	{Name: "LineContinuation", Pattern: `\\[ \t]*[\r]?\n`},
	{Name: "Whitespace", Pattern: `[ \t\n\r]+`},
})

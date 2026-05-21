package gemfile

import (
	"github.com/alecthomas/participle/v2/lexer"
)

var gemfileLexer = lexer.MustStateful(lexer.Rules{
	"Root": {
		{Name: "HeredocStart", Pattern: `<<[-~]?(\w+)\n`, Action: lexer.Push("Heredoc")},
		{Name: "HeredocStartDQ", Pattern: `<<[-~]?"(\w+)"\n`, Action: lexer.Push("Heredoc")},
		{Name: "HeredocStartSQ", Pattern: `<<[-~]?'(\w+)'\n`, Action: lexer.Push("Heredoc")},
		{Name: "HeredocStartBT", Pattern: "<<[-~]?`(\\w+)`\\n", Action: lexer.Push("Heredoc")},
		{Name: "Comment", Pattern: `#[^\n]*`},
		{Name: "Symbol", Pattern: `:[a-zA-Z_][a-zA-Z0-9_]*`},
		{Name: "DoubleColon", Pattern: `::`},
		{Name: "PercentLiteral", Pattern: `%[qQwW]\{[^}]*\}`},
		{Name: "Backtick", Pattern: "`(?:[^`\\\\]|\\\\.)*`"},
		{Name: "SingleString", Pattern: `'(?:[^'\\]|\\.)*'`},
		{Name: "DoubleString", Pattern: `"(?:[^"\\]|\\.)*"`},
		{Name: "Keyword", Pattern: `\b(gem|group|source|end|do|if|unless|case|when|nil|true|false|require)\b`},
		{Name: "Ident", Pattern: `[a-zA-Z_][a-zA-Z0-9_]*`},
		{Name: "Number", Pattern: `\d+`},
		{Name: "Operator", Pattern: `\+|-|\*\*|\*|/|%|==|!=|<=|>=|<|>|&&|&|\|\||\||!|\?`},
		{Name: "Punct", Pattern: `[()[\]{},=.:|]`},
		{Name: "Whitespace", Pattern: `[ \t\n\r]+`},
		// Unknown fallback: This lexer only needs to extract gem declarations - we don't care about
		// correctly tokenizing Ruby syntax (regex literals, operators, etc). Unknown catches any
		// unrecognized characters so the lexer continues instead of failing.
		{Name: "Unknown", Pattern: `.`},
	},
	"Heredoc": {
		{Name: "HeredocEnd", Pattern: `[ \t]*\1[ \t]*(?:\n|$)`, Action: lexer.Pop()},
		{Name: "HeredocLine", Pattern: `[^\n]*\n`},
	},
})

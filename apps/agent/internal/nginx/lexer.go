// Package nginx parses nginx configuration (including `nginx -T` dumps) into a
// directive tree and extracts structured, read-only discovery findings.
//
// The parser never executes or writes anything; it is a pure function of input.
package nginx

import (
	"fmt"
	"strings"
)

// TokenKind classifies lexer tokens.
type TokenKind int

const (
	TokWord TokenKind = iota
	TokSemicolon
	TokOpenBrace
	TokCloseBrace
	TokFileMarker // "# configuration file <path>:" emitted by nginx -T
)

// Token is a lexical token with its source position.
type Token struct {
	Kind   TokenKind
	Value  string
	Quoted bool
	File   string
	Line   int
}

// SyntaxError reports a lexing/parsing error with provenance.
type SyntaxError struct {
	File string
	Line int
	Msg  string
}

func (e *SyntaxError) Error() string { return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg) }

const markerPrefix = "# configuration file "

// MaxInputBytes bounds parser input.
const MaxInputBytes = 32 << 20

// Lex tokenizes src. defaultFile names the source until a file marker appears.
// Handles: '#' comments (only at token start, like nginx), single/double quoted
// strings with backslash escapes, `${var}` inside words, and nginx -T markers.
func Lex(src, defaultFile string) ([]Token, error) {
	if len(src) > MaxInputBytes {
		return nil, &SyntaxError{defaultFile, 0, "input too large"}
	}
	var toks []Token
	file, line := defaultFile, 1
	i, n := 0, len(src)
	atLineStart := true
	for i < n {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
			atLineStart = true
			continue
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			i++
			continue
		case c == '#':
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				end = n - i
			}
			comment := src[i : i+end]
			if atLineStart && strings.HasPrefix(comment, markerPrefix) && strings.HasSuffix(strings.TrimRight(comment, " \r"), ":") {
				p := strings.TrimSuffix(strings.TrimRight(comment[len(markerPrefix):], " \r"), ":")
				toks = append(toks, Token{Kind: TokFileMarker, Value: p, File: p, Line: 0})
				file = p
				// the next line is line 1 of the new file
				line = 0
			}
			i += end
			continue
		}
		atLineStart = false
		switch c {
		case ';':
			toks = append(toks, Token{Kind: TokSemicolon, Value: ";", File: file, Line: line})
			i++
		case '{':
			toks = append(toks, Token{Kind: TokOpenBrace, Value: "{", File: file, Line: line})
			i++
		case '}':
			toks = append(toks, Token{Kind: TokCloseBrace, Value: "}", File: file, Line: line})
			i++
		case '"', '\'':
			q := c
			startLine := line
			var sb strings.Builder
			i++
			closed := false
			for i < n {
				ch := src[i]
				if ch == '\\' && i+1 < n {
					nx := src[i+1]
					// nginx keeps unknown escapes verbatim; unescape quote/backslash only
					if nx == q || nx == '\\' {
						sb.WriteByte(nx)
					} else {
						sb.WriteByte(ch)
						sb.WriteByte(nx)
					}
					if nx == '\n' {
						line++
					}
					i += 2
					continue
				}
				if ch == q {
					closed = true
					i++
					break
				}
				if ch == '\n' {
					line++
				}
				sb.WriteByte(ch)
				i++
			}
			if !closed {
				return nil, &SyntaxError{file, startLine, "unterminated quoted string"}
			}
			toks = append(toks, Token{Kind: TokWord, Value: sb.String(), Quoted: true, File: file, Line: startLine})
		default:
			start := i
			for i < n {
				ch := src[i]
				if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ';' || ch == '}' || ch == '\f' || ch == '\v' {
					break
				}
				if ch == '{' {
					// `${var}` is part of a word
					if i > start && src[i-1] == '$' {
						end := strings.IndexByte(src[i:], '}')
						if end < 0 {
							return nil, &SyntaxError{file, line, "unterminated ${ variable"}
						}
						i += end + 1
						continue
					}
					break
				}
				if ch == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			word := src[start:i]
			toks = append(toks, Token{Kind: TokWord, Value: word, File: file, Line: line})
			// *_by_lua_block bodies are Lua, not nginx syntax: skip them as an opaque
			// balanced block (the lua module does the same with its own lexer).
			if strings.HasSuffix(word, "_lua_block") || word == "lua_block" {
				j := i
				for j < n && (src[j] == ' ' || src[j] == '\t' || src[j] == '\r' || src[j] == '\n') {
					if src[j] == '\n' {
						line++
					}
					j++
				}
				if j < n && src[j] == '{' {
					openLine := line
					end, nl, ok := skipLuaBlock(src, j)
					if !ok {
						return nil, &SyntaxError{file, openLine, "unterminated lua block"}
					}
					toks = append(toks, Token{Kind: TokOpenBrace, Value: "{", File: file, Line: openLine})
					line += nl
					toks = append(toks, Token{Kind: TokCloseBrace, Value: "}", File: file, Line: line})
					i = end
				}
			}
		}
	}
	return toks, nil
}

// skipLuaBlock returns the index after the '}' matching src[start]=='{',
// honouring Lua strings ("..", '..', [[..]]) and -- comments.
func skipLuaBlock(src string, start int) (end, newlines int, ok bool) {
	depth := 0
	n := len(src)
	for i := start; i < n; i++ {
		c := src[i]
		switch {
		case c == '\n':
			newlines++
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return i + 1, newlines, true
			}
		case c == '"' || c == '\'':
			for i++; i < n && src[i] != c; i++ {
				if src[i] == '\\' {
					i++
				} else if src[i] == '\n' {
					newlines++
				}
			}
		case c == '[' && i+1 < n && src[i+1] == '[':
			e := strings.Index(src[i+2:], "]]")
			if e < 0 {
				return 0, 0, false
			}
			newlines += strings.Count(src[i:i+2+e], "\n")
			i += 2 + e + 1
		case c == '-' && i+1 < n && src[i+1] == '-':
			e := strings.IndexByte(src[i:], '\n')
			if e < 0 {
				return 0, 0, false
			}
			i += e - 1
		}
	}
	return 0, 0, false
}

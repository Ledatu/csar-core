// Package jsonstream provides opt-in, bounded object/array decoding.
// It does not replace clientx, change HTTP policy, or perform business callbacks.
// Selected arrays are decoded one element at a time; outputs are returned only
// after the bounded response and trailing whitespace have been consumed.
package jsonstream

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
)

var (
	ErrTooLarge = errors.New("jsonstream: response exceeds maximum bytes")
	ErrConfig   = errors.New("jsonstream: positive bound and unique fields required")
)

// Info separates consumed decoded bytes from the bounded diagnostic prefix.
// Neither quantity measures retained heap or compressed wire traffic.
type Info struct {
	BytesRead int64
	Prefix    []byte
	// ReadError is the original reader failure, separate from JSON errors.
	ReadError error
}

// Field declares a side-effect-free DTO destination, not a business callback.
type Field struct {
	name   string
	decode func(*json.Decoder) (error, bool)
}

// Value uses standard decoding for one field, including custom UnmarshalJSON.
// Its whole value can be buffered: use Array for a large collection field.
func Value(name string, out any) Field {
	return Field{name: name, decode: func(d *json.Decoder) (error, bool) {
		before := d.InputOffset()
		err := d.Decode(out)
		return err, err == nil || d.InputOffset() > before
	}}
}

// Array retains the typed slice while avoiding a full encoded array copy.
// A single element is still buffered by encoding/json. Reused elements preserve
// standard slice overwrite/merge behavior for duplicate array fields.
func Array[T any](name string, out *[]T) Field {
	if out == nil {
		return Field{name: name}
	}
	return Field{name: name, decode: func(d *json.Decoder) (error, bool) {
		token, err := d.Token()
		if err != nil {
			return err, consumedTokenError(err)
		}
		if token == nil {
			*out = nil
			return nil, true
		}
		if token != json.Delim('[') {
			if err := skipOpened(d, token); err != nil {
				return err, false
			}
			return wrongType(token, out), true
		}
		var first error
		i := 0
		for d.More() {
			if i < cap(*out) {
				*out = (*out)[:i+1]
			} else {
				var zero T
				*out = append(*out, zero)
			}
			before := d.InputOffset()
			if err := d.Decode(&(*out)[i]); err != nil {
				if d.InputOffset() == before {
					return err, false
				}
				if first == nil {
					first = err
				}
			}
			i++
		}
		if _, err := d.Token(); err != nil {
			return err, false
		}
		if i == 0 {
			*out = make([]T, 0)
		} else {
			*out = (*out)[:i]
		}
		return first, true
	}}
}

// DecodeObject materializes DTOs, not side effects. On every error it returns
// zero T. Read failures precede oversize, which precedes JSON/decode failures,
// matching the existing bounded ReadAll-then-Unmarshal acceptance order.
// Unknown fields are validated with standard decoding and can buffer one entire
// unknown value. Parser diagnostics refer to the selected DTO value; they are
// not guaranteed to match Unmarshal's whole-document offsets/field context.
func DecodeObject[T any](r io.Reader, maxBytes int64, fields func(*T) []Field) (T, Info, error) {
	var zero, out T
	if maxBytes <= 0 || maxBytes == math.MaxInt64 || fields == nil {
		return zero, Info{}, ErrConfig
	}
	declared := fields(&out)
	for i, field := range declared {
		if field.name == "" || field.decode == nil {
			return zero, Info{}, ErrConfig
		}
		for _, previous := range declared[:i] {
			if strings.EqualFold(field.name, previous.name) {
				return zero, Info{}, ErrConfig
			}
		}
	}
	input := &inputReader{base: io.LimitReader(r, maxBytes+1)}
	d := json.NewDecoder(input)
	err, complete := object(d, &out, declared)
	if complete {
		if tailErr := tail(io.MultiReader(d.Buffered(), input), d.InputOffset()); tailErr != nil {
			err = tailErr
		}
	} else {
		_, _ = io.Copy(io.Discard, input)
	}
	info := Info{BytesRead: input.n, Prefix: input.prefix, ReadError: input.readErr}
	if input.readErr != nil {
		return zero, info, input.readErr
	}
	if input.n > maxBytes {
		info.Prefix = nil
		return zero, info, ErrTooLarge
	}
	if input.depthErr != nil {
		return zero, info, input.depthErr
	}
	// Decoder uses EOF for an incomplete value; a body read failure has already
	// won above. Preserve Unmarshal's public error class for truncated JSON.
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		err = syntaxError("{", input.n)
	}
	if err != nil {
		return zero, info, err
	}
	return out, info, nil
}

func object[T any](d *json.Decoder, out *T, fields []Field) (error, bool) {
	token, err := d.Token()
	if err != nil {
		return err, consumedTokenError(err)
	}
	if token == nil {
		return nil, true
	}
	if token != json.Delim('{') {
		if err := skipOpened(d, token); err != nil {
			return err, false
		}
		return wrongType(token, out), true
	}
	var first error
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return err, false
		}
		name, ok := key.(string)
		if !ok {
			return syntaxError("{", d.InputOffset()), false
		}
		matched := false
		for _, field := range fields {
			if !strings.EqualFold(name, field.name) {
				continue
			}
			matched = true
			fieldErr, consumed := field.decode(d)
			if !consumed {
				return fieldErr, false
			}
			if first == nil {
				first = fieldErr
			}
			break
		}
		if !matched {
			var discard discarded
			if err := d.Decode(&discard); err != nil {
				return err, false
			}
		}
	}
	if _, err := d.Token(); err != nil {
		return err, false
	}
	return first, true
}

// Token decodes scalars through interface{}; an overflowing float produces a
// type error after consuming a complete value. Keep validating the rest of the
// document so later syntax errors retain Unmarshal's precedence.
func consumedTokenError(err error) bool {
	var typeErr *json.UnmarshalTypeError
	return errors.As(err, &typeErr)
}

type discarded struct{}

func (*discarded) UnmarshalJSON([]byte) error { return nil }

// skipOpened finishes an already consumed opening token. Standard Decode does
// syntax validation, including unknown huge numbers, without float conversion.
func skipOpened(d *json.Decoder, token json.Token) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	for d.More() {
		if delim == '{' {
			if _, err := d.Token(); err != nil {
				return err
			}
		}
		var discard discarded
		if err := d.Decode(&discard); err != nil {
			return err
		}
	}
	_, err := d.Token()
	return err
}

func wrongType(token json.Token, out any) error {
	raw := "0"
	switch token.(type) {
	case string:
		raw = `"x"`
	case bool:
		raw = "true"
	case json.Delim:
		if token == json.Delim('{') {
			raw = "{}"
		} else {
			raw = "[]"
		}
	}
	return json.Unmarshal([]byte(raw), out)
}

type inputReader struct {
	base     io.Reader
	n        int64
	prefix   []byte
	readErr  error
	depth    int
	quoted   bool
	escaped  bool
	depthErr error
}

func (r *inputReader) Read(p []byte) (int, error) {
	n, err := r.base.Read(p)
	r.checkDepth(p[:n])
	r.n += int64(n)
	if len(r.prefix) < 4096 {
		r.prefix = append(r.prefix, p[:min(n, 4096-len(r.prefix))]...)
	}
	if err != nil && err != io.EOF && r.readErr == nil {
		r.readErr = err
	}
	return n, err
}

// Token scans the envelope separately from each Decode. Track total nesting
// across reader chunks so splitting a value cannot bypass Go's 10,000 limit.
// Grammar and string validation still belong to encoding/json.
func (r *inputReader) checkDepth(data []byte) {
	if r.depthErr != nil {
		return
	}
	for i := 0; i < len(data); {
		if r.quoted {
			// Skip ordinary string contents with byte search; descriptions can
			// dominate page size. Search each segment once, retaining escape
			// state across chunks and avoiding repeated scans of long strings.
			quote := bytes.IndexByte(data[i:], '"')
			end := len(data)
			if quote >= 0 {
				end = i + quote
			}
			for i < end {
				if r.escaped {
					r.escaped = false
					i++
					continue
				}
				slash := bytes.IndexByte(data[i:end], '\\')
				if slash < 0 {
					break
				}
				i += slash + 1
				r.escaped = true
			}
			if quote < 0 {
				return
			}
			i = end + 1
			if r.escaped {
				r.escaped = false
				continue
			}
			r.quoted = false
			continue
		}
		switch data[i] {
		case '"':
			r.quoted = true
		case '{', '[':
			r.depth++
			if r.depth > 10000 {
				r.depthErr = syntaxError(strings.Repeat("[", 10001), r.n+int64(i)+1)
				return
			}
		case '}', ']':
			r.depth--
		}
		i++
	}
}

func syntaxError(invalid string, offset int64) error {
	var discard any
	err := json.Unmarshal([]byte(invalid), &discard)
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		syntax.Offset = offset
	}
	return err
}

func tail(r io.Reader, offset int64) error {
	var first error
	var buffer [4096]byte
	for {
		n, err := r.Read(buffer[:])
		for _, b := range buffer[:n] {
			offset++
			if first != nil || b == ' ' || b == '\t' || b == '\r' || b == '\n' {
				continue
			}
			var discard any
			first = json.Unmarshal(append([]byte("null"), b), &discard)
			var syntax *json.SyntaxError
			if errors.As(first, &syntax) {
				syntax.Offset = offset
			}
		}
		if err != nil {
			if err != io.EOF {
				return err
			}
			return first
		}
	}
}

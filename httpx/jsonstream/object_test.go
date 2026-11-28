package jsonstream_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/ledatu/csar-core/httpx/jsonstream"
)

func TestGzipFooterAndReadFailures(t *testing.T) {
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write([]byte(`{"rows":[{"id":1}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	valid := compressed.Bytes()
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)-8] ^= 1
	for _, body := range [][]byte{valid, corrupt, valid[:len(valid)-4]} {
		oldReader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_, wantErr := io.ReadAll(oldReader)
		if err := oldReader.Close(); err != nil {
			t.Fatal(err)
		}
		newReader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		got, _, gotErr := jsonstream.DecodeObject(newReader, 1000, fields)
		if err := newReader.Close(); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(gotErr, wantErr) || (wantErr != nil && !reflect.DeepEqual(got, envelope{})) {
			t.Fatalf("gzip integrity changed: old=%v new=%v", wantErr, gotErr)
		}
	}
}

func TestWholeDocumentDepthAndIncompleteJSON(t *testing.T) {
	for _, depth := range []int{9997, 9998, 9999, 10000, 10001} {
		body := `{"rows":[{"raw":` + strings.Repeat("[", depth) + `0` + strings.Repeat("]", depth) + `}]}`
		var old envelope
		oldErr := json.Unmarshal([]byte(body), &old)
		for _, chunk := range []int{1, 7, 4096} {
			_, _, err := jsonstream.DecodeObject(&chunkReader{strings.NewReader(body), chunk}, 1<<20, fields)
			if (err == nil) != (oldErr == nil) {
				t.Fatalf("depth %d chunk %d changed acceptance: old=%v new=%v", depth, chunk, oldErr, err)
			}
		}
	}
	for _, body := range []string{"", " ", `{"rows":[`, `{"rows":[{"label":"\\\"[{}]`} {
		var want, got *json.SyntaxError
		var old envelope
		oldErr := json.Unmarshal([]byte(body), &old)
		_, _, err := jsonstream.DecodeObject(strings.NewReader(body), 1<<20, fields)
		if !errors.As(oldErr, &want) || !errors.As(err, &got) || want.Offset != got.Offset {
			t.Fatalf("incomplete JSON classification/offset changed: old=%v new=%v", oldErr, err)
		}
	}
}

func TestDepthGuardIgnoresStringContentsAcrossChunks(t *testing.T) {
	want := envelope{Rows: []row{{Label: `\"\\` + strings.Repeat("[{}]", 10001)}}}
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &want); err != nil {
		t.Fatal(err)
	}
	for _, chunk := range []int{1, 2, 7} {
		got, _, err := jsonstream.DecodeObject(&chunkReader{bytes.NewReader(body), chunk}, 1<<20, fields)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("escaped string changed at chunk %d: %v", chunk, err)
		}
	}
}

type chunkReader struct {
	io.Reader
	size int
}

func (r *chunkReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:min(len(p), r.size)]) }

type row struct {
	ID    int             `json:"id"`
	Label string          `json:"label"`
	Raw   json.RawMessage `json:"raw"`
}

type envelope struct {
	Rows   []row `json:"rows"`
	Cursor struct {
		Total int `json:"total"`
		Next  int `json:"next"`
	} `json:"cursor"`
}

func fields(out *envelope) []jsonstream.Field {
	return []jsonstream.Field{jsonstream.Array("rows", &out.Rows), jsonstream.Value("cursor", &out.Cursor)}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, factory := range []func(*envelope) []jsonstream.Field{
		nil,
		func(out *envelope) []jsonstream.Field {
			return []jsonstream.Field{jsonstream.Array("rows", &out.Rows), jsonstream.Array("ROWS", &out.Rows)}
		},
		func(*envelope) []jsonstream.Field { return []jsonstream.Field{jsonstream.Array[row]("rows", nil)} },
	} {
		_, info, err := jsonstream.DecodeObject(strings.NewReader(`{}`), 100, factory)
		if !errors.Is(err, jsonstream.ErrConfig) || info.BytesRead != 0 {
			t.Fatal("invalid fields read the response", err)
		}
	}
}

func TestObjectAcceptanceAndValues(t *testing.T) {
	cases := []string{
		`null`, `{}`, `{"rows":null}`, `{"rows":[]}`,
		`{"rows":[{"id":1,"raw": [ 1, {"x":2} ]}],"cursor":{"total":1}}`,
		`{"RoWs":[null,{"ID":9223372036854775807}],"CURSOR":{"next":2}}`,
		`{"rows":[{"id":1,"label":"kept"}],"rows":[{"id":2}]}`,
		`{"rows":[{"id":1},{"label":"stale"}],"rows":[],"rows":[{"id":3}]}`,
		`{"cursor":{"total":1},"cursor":{"next":2},"ignored":1e10000}`,
		`{"ignored":{"a":[1,{},null]},"rows":[{"label":"\ud800"}]}`,
		`{"rows":[{"label":"` + string([]byte{0xff}) + `"}]}`,
		``, ` `, `[]`, `1`, `"string"`, `true`,
		`{"rows":false}`, `{"rows":{}}`, `{"rows":[{"id":"wrong"}],"cursor":{"next":3}}`,
		`{"rows":[{"id":"wrong"}],"cursor":{`,
		`{"rows":[{"id":1}]`, `{"rows":[{"id":1},]}`, `{"rows":[]} true`, `{"rows":[]} junk`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			var want envelope
			oldErr := json.Unmarshal([]byte(body), &want)
			got, info, err := jsonstream.DecodeObject(strings.NewReader(body), 1<<20, fields)
			if (err == nil) != (oldErr == nil) {
				t.Fatalf("acceptance changed: old=%v new=%v", oldErr, err)
			}
			if err == nil && !reflect.DeepEqual(got, want) {
				t.Fatalf("value changed: want=%+v got=%+v", want, got)
			}
			if err != nil && !reflect.DeepEqual(got, envelope{}) {
				t.Fatal("partial DTO returned on failure")
			}
			if info.BytesRead != int64(len(body)) {
				t.Fatalf("response not fully consumed: %d/%d", info.BytesRead, len(body))
			}
		})
	}
}

type failureReader struct {
	data []byte
	err  error
}

func (r *failureReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

func TestBodyBoundsReadErrorPrecedenceAndPrefix(t *testing.T) {
	broken := errors.New("body read failed")
	for _, body := range []string{`{"rows":[]}`, `{"rows":[`} {
		for _, readErr := range []error{broken, errors.Join(io.EOF, broken)} {
			got, _, err := jsonstream.DecodeObject(&failureReader{[]byte(body), readErr}, 100, fields)
			if !errors.Is(err, readErr) || !reflect.DeepEqual(got, envelope{}) {
				t.Fatalf("read failure was hidden: %v", err)
			}
		}
	}
	body := `{"rows":[]}` + strings.Repeat(" ", 8192)
	got, info, err := jsonstream.DecodeObject(strings.NewReader(body), 8192, fields)
	if !errors.Is(err, jsonstream.ErrTooLarge) || info.Prefix != nil || !reflect.DeepEqual(got, envelope{}) {
		t.Fatal("oversize response contract changed", err)
	}
	_, info, err = jsonstream.DecodeObject(strings.NewReader(body), int64(len(body)), fields)
	if err != nil || info.BytesRead != int64(len(body)) || len(info.Prefix) != 4096 {
		t.Fatal("boundary/prefix mismatch", err)
	}
}

func FuzzObjectAcceptanceAndValues(f *testing.F) {
	for _, value := range []string{`{}`, `{"rows":[{"id":1}]}`, `{"rows":[{"id":"x"}],"rows":[]}`, `{"cursor":{"total":1},"rows":[]}`} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 65536 {
			t.Skip()
		}
		var want envelope
		oldErr := json.Unmarshal([]byte(body), &want)
		got, _, err := jsonstream.DecodeObject(strings.NewReader(body), 65536, fields)
		if (err == nil) != (oldErr == nil) || (err == nil && !reflect.DeepEqual(got, want)) {
			t.Fatalf("differential mismatch: old=%v new=%v", oldErr, err)
		}
		var oldSyntax, newSyntax *json.SyntaxError
		var oldType, newType *json.UnmarshalTypeError
		if errors.As(oldErr, &oldSyntax) != errors.As(err, &newSyntax) || errors.As(oldErr, &oldType) != errors.As(err, &newType) {
			t.Fatalf("error class changed: old=%T/%v new=%T/%v", oldErr, oldErr, err, err)
		}
	})
}

package shlex

import (
	"errors"
	"reflect"
	"testing"
)

func TestSplit_Simple(t *testing.T) {
	got, err := Split("ls -la /tmp")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ls", "-la", "/tmp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSplit_SingleQuotes(t *testing.T) {
	got, err := Split("echo 'hello world'")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"echo", "hello world"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSplit_DoubleQuotes(t *testing.T) {
	got, err := Split(`echo "hello world"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"echo", "hello world"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSplit_BackslashEscape(t *testing.T) {
	got, err := Split(`echo hello\ world`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"echo", "hello world"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSplit_BackslashInDoubleQuotes(t *testing.T) {
	got, err := Split(`echo "hello\"world"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"echo", `hello"world`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSplit_MixedQuotes(t *testing.T) {
	got, err := Split(`cat '/path/with spaces' "/another path"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cat", "/path/with spaces", "/another path"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSplit_Empty(t *testing.T) {
	got, err := Split("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestSplit_Whitespace(t *testing.T) {
	got, err := Split("   ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestSplit_Tabs(t *testing.T) {
	got, err := Split("ls\t-la\t/tmp")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ls", "-la", "/tmp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// Security: unclosed quotes must return error + fallback tokens
func TestSecurity_UnclosedSingleQuote(t *testing.T) {
	got, err := Split("echo 'unclosed")
	if err == nil {
		t.Fatal("expected error for unclosed quote")
	}
	var uqe *UnclosedQuoteError
	if !errors.As(err, &uqe) {
		t.Fatalf("expected UnclosedQuoteError, got %T", err)
	}
	// Fallback should still return tokens
	if len(got) == 0 {
		t.Fatal("expected fallback tokens, got empty")
	}
}

func TestSecurity_UnclosedDoubleQuote(t *testing.T) {
	got, err := Split(`echo "unclosed`)
	if err == nil {
		t.Fatal("expected error for unclosed quote")
	}
	if len(got) == 0 {
		t.Fatal("expected fallback tokens")
	}
}

// Security: paths in quotes must be extractable via fallback
func TestSecurity_FallbackExtractsPaths(t *testing.T) {
	got, err := Split("cat '/etc/passwd")
	if err == nil {
		t.Fatal("expected error")
	}
	// Fallback strips quotes and splits on whitespace
	found := false
	for _, tok := range got {
		if tok == "/etc/passwd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fallback should extract /etc/passwd, got %v", got)
	}
}

func TestSplit_RedirectPaths(t *testing.T) {
	got, err := Split("echo hello > /tmp/out.txt")
	if err != nil {
		t.Fatal(err)
	}
	// shlex doesn't interpret > as redirect, just as a token
	want := []string{"echo", "hello", ">", "/tmp/out.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSplit_QuotedPath(t *testing.T) {
	got, err := Split(`cat "/path with/spaces/file.txt"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cat", "/path with/spaces/file.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestMustSplit(t *testing.T) {
	got := MustSplit("ls -la")
	want := []string{"ls", "-la"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestMustSplit_UnclosedFallback(t *testing.T) {
	got := MustSplit("echo 'unclosed")
	if len(got) == 0 {
		t.Fatal("MustSplit should return fallback tokens")
	}
}

func TestSplit_AdjacentQuotes(t *testing.T) {
	got, err := Split(`echo "hello"'world'`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"echo", "helloworld"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

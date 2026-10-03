package postgres

import (
	"strings"
	"testing"
)

func TestRetrievalTSQueryBoundsAndEscapesTerms(t *testing.T) {
	t.Parallel()
	if got, err := retrievalTSQuery("Login OR 'portal'; DROP TABLE users"); err != nil || got != "login | or | portal | drop | table | users" {
		t.Fatalf("sanitized query = %q, %v", got, err)
	}
	if _, err := retrievalTSQuery("... !!!"); err == nil {
		t.Fatal("punctuation-only query accepted")
	}
	if got, err := retrievalTSQuery(strings.Repeat("word ", 40)); err != nil || got != "word" {
		t.Fatalf("deduplicated query = %q, %v", got, err)
	}
	if _, err := retrievalTSQuery("a b c d e f g h i j k l m n o p q r s t u v w x y z aa bb cc dd ee ff gg"); err == nil {
		t.Fatal("unbounded lexical term query accepted")
	}
}

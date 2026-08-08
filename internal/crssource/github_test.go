package crssource

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func jsonResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestLatestSignedTagSkipsPrereleaseAndUnsignedCandidate(t *testing.T) {
	client := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/repos/coreruleset/coreruleset/releases":
			return jsonResponse(`[
                {"tag_name":"v4.29.0-rc1","prerelease":true},
                {"tag_name":"v4.28.0"},
                {"tag_name":"v4.27.0"}
            ]`), nil
		case "/repos/coreruleset/coreruleset/git/ref/tags/v4.28.0":
			return jsonResponse(`{"object":{"sha":"tag-428","type":"tag"}}`), nil
		case "/repos/coreruleset/coreruleset/git/tags/tag-428":
			return jsonResponse(`{"object":{"sha":"commit-428","type":"commit"},"verification":{"verified":false,"reason":"unsigned"}}`), nil
		case "/repos/coreruleset/coreruleset/git/ref/tags/v4.27.0":
			return jsonResponse(`{"object":{"sha":"tag-427","type":"tag"}}`), nil
		case "/repos/coreruleset/coreruleset/git/tags/tag-427":
			return jsonResponse(`{"object":{"sha":"commit-427","type":"commit"},"verification":{"verified":true,"reason":"valid"}}`), nil
		default:
			t.Fatalf("unexpected GitHub request %s", request.URL.Path)
			return nil, nil
		}
	})}}
	tag, commit, tagObject, err := client.latestSignedTag(context.Background(), "stable", "")
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v4.27.0" || commit != "commit-427" || tagObject != "tag-427" {
		t.Fatalf("unexpected signed release: %s %s %s", tag, commit, tagObject)
	}
}

func TestCandidateTagsKeepsLTSInsidePinnedLine(t *testing.T) {
	client := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(`[
            {"tag_name":"v4.26.0"},
            {"tag_name":"v4.25.1"},
            {"tag_name":"v4.25.3","draft":true},
            {"tag_name":"v4.25.2"}
        ]`), nil
	})}}
	tags, err := client.candidateTags(context.Background(), "lts", "4.25")
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags[0] != "v4.25.2" || tags[1] != "v4.25.1" {
		t.Fatalf("unexpected LTS candidates: %#v", tags)
	}
}

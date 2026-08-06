package manager

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	webassets "github.com/Fhwang0926/m-waf/web"
)

func TestSetupCSRFReusesValidCookie(t *testing.T) {
	sessions := newSessionManager([]byte("01234567890123456789012345678901"))
	firstResponse := httptest.NewRecorder()
	firstToken, err := sessions.setupCSRFForRequest(firstResponse, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if err != nil {
		t.Fatal(err)
	}
	firstCookie := setupCookieFromResponse(t, firstResponse)
	if firstCookie.Value != firstToken || !firstCookie.HttpOnly || !firstCookie.Secure || firstCookie.Path != "/setup" || firstCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected setup cookie: %#v", firstCookie)
	}

	secondRequest := httptest.NewRequest(http.MethodGet, "/setup", nil)
	secondRequest.AddCookie(firstCookie)
	secondResponse := httptest.NewRecorder()
	secondToken, err := sessions.setupCSRFForRequest(secondResponse, secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if secondToken != firstToken || setupCookieFromResponse(t, secondResponse).Value != firstToken {
		t.Fatal("valid setup token was not reused and refreshed")
	}
}

func TestSetupCSRFReplacesInvalidCookie(t *testing.T) {
	sessions := newSessionManager([]byte("01234567890123456789012345678901"))
	request := httptest.NewRequest(http.MethodGet, "/setup", nil)
	request.AddCookie(&http.Cookie{Name: setupCSRFCookieName, Value: "invalid"})
	response := httptest.NewRecorder()
	token, err := sessions.setupCSRFForRequest(response, request)
	if err != nil {
		t.Fatal(err)
	}
	if token == "invalid" || !sessions.validSetupCSRF(token) || setupCookieFromResponse(t, response).Value != token {
		t.Fatal("invalid setup cookie was not replaced")
	}
}

func TestValidSetupCSRFRequestRequiresMatchingCookie(t *testing.T) {
	sessions := newSessionManager([]byte("01234567890123456789012345678901"))
	token, err := sessions.setupCSRF()
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf": {token}}
	request := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if sessions.validSetupCSRFRequest(request) {
		t.Fatal("request without setup cookie passed validation")
	}
	request.AddCookie(&http.Cookie{Name: setupCSRFCookieName, Value: token})
	if !sessions.validSetupCSRFRequest(request) {
		t.Fatal("matching signed setup cookie and form token were rejected")
	}
}

func TestRenderSetupReturnsRecoverableCSRFError(t *testing.T) {
	templates, err := template.ParseFS(webassets.Assets, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		sessions:  newSessionManager([]byte("01234567890123456789012345678901")),
		templates: templates,
	}
	form := url.Values{"username": {"operator"}, "display_name": {"Hosting Operator"}}
	request := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	server.renderSetup(response, request, http.StatusForbidden, "보안 정보를 갱신했습니다.")

	if response.Code != http.StatusForbidden || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache-control=%q", response.Code, response.Header().Get("Cache-Control"))
	}
	body := response.Body.String()
	if !strings.Contains(body, "보안 정보를 갱신했습니다.") || !strings.Contains(body, `value="operator"`) || !strings.Contains(body, `value="Hosting Operator"`) {
		t.Fatalf("setup recovery page did not preserve safe form values: %s", body)
	}
	setupCookieFromResponse(t, response)
}

func setupCookieFromResponse(t *testing.T, response *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == setupCSRFCookieName {
			return cookie
		}
	}
	t.Fatal("setup CSRF cookie was not set")
	return nil
}

package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestI18nKeyCompleteness(t *testing.T) {
	mgr := NewI18nManager()

	enKeys := mgr.translations[LangEN]
	arKeys := mgr.translations[LangAR]

	if len(enKeys) == 0 {
		t.Fatal("English translations map is empty")
	}

	for k, enVal := range enKeys {
		arVal, ok := arKeys[k]
		if !ok || arVal == "" {
			t.Errorf("Missing or empty Arabic translation for key %q (EN: %q)", k, enVal)
		}
	}
}

func TestResolveLanguage(t *testing.T) {
	mgr := NewI18nManager()

	// 1. Default fallback without headers or cookies -> English
	req := httptest.NewRequest("GET", "/", nil)
	if lang := mgr.ResolveLanguage(req); lang != LangEN {
		t.Errorf("Expected default %q, got %q", LangEN, lang)
	}

	// 2. Cookie takes precedence
	reqWithCookie := httptest.NewRequest("GET", "/", nil)
	reqWithCookie.AddCookie(&http.Cookie{
		Name:  LangCookieName,
		Value: LangAR,
	})
	if lang := mgr.ResolveLanguage(reqWithCookie); lang != LangAR {
		t.Errorf("Expected cookie language %q, got %q", LangAR, lang)
	}

	// 3. Invalid cookie value falls back to Accept-Language or default
	reqInvalidCookie := httptest.NewRequest("GET", "/", nil)
	reqInvalidCookie.AddCookie(&http.Cookie{
		Name:  LangCookieName,
		Value: "xyz",
	})
	if lang := mgr.ResolveLanguage(reqInvalidCookie); lang != LangEN {
		t.Errorf("Expected invalid cookie to fallback to %q, got %q", LangEN, lang)
	}

	// 4. Accept-Language header when no cookie present
	reqHeader := httptest.NewRequest("GET", "/", nil)
	reqHeader.Header.Set("Accept-Language", "ar,en-US;q=0.9,en;q=0.8")
	if lang := mgr.ResolveLanguage(reqHeader); lang != LangAR {
		t.Errorf("Expected header language %q, got %q", LangAR, lang)
	}
}

func TestDirectionAndOtherLang(t *testing.T) {
	if dir := GetDir(LangAR); dir != "rtl" {
		t.Errorf("Expected RTL for %s, got %s", LangAR, dir)
	}
	if dir := GetDir(LangEN); dir != "ltr" {
		t.Errorf("Expected LTR for %s, got %s", LangEN, dir)
	}

	otherLang, otherLabel := GetOtherLang(LangAR)
	if otherLang != LangEN || otherLabel != "English" {
		t.Errorf("Unexpected other lang for AR: %s, %s", otherLang, otherLabel)
	}

	otherLang, otherLabel = GetOtherLang(LangEN)
	if otherLang != LangAR || otherLabel != "العربية" {
		t.Errorf("Unexpected other lang for EN: %s, %s", otherLang, otherLabel)
	}
}

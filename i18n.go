package main

import (
	"net/http"
	"strings"
)

const (
	langCookieName = "ssh_buttons_lang"
	LangEN         = "en"
	LangAR         = "ar"
)

type I18nManager struct {
	translations map[string]map[string]string
}

func NewI18nManager() *I18nManager {
	return &I18nManager{
		translations: map[string]map[string]string{
			LangEN: {
				"app_title":            "SSH Buttons",
				"app_tagline":          "Secure Infrastructure Dashboard",
				"sign_in":              "Sign In",
				"username":             "Username",
				"password":             "Password",
				"invalid_credentials":  "Invalid username or password",
				"footer_tagline":       "Self-contained SSH Command Runner",
				"reload_config":        "Reload Config",
				"logout":               "Logout",
				"language":             "Language",
				"success":              "SUCCESS",
				"failed":               "FAILED",
				"exit_code":            "Exit",
				"duration":             "Duration",
				"time":                 "Time",
				"error_details":        "Error Details:",
				"output":               "Output:",
				"standard_error":       "Standard Error:",
				"no_buttons_title":     "No action buttons configured yet.",
				"no_buttons_desc":      "Add hosts and buttons in config.yml and hit \"Reload Config\".",
				"confirm_execution":    "Confirm Execution",
				"confirm_message":      "Are you sure you want to run this action? This operation may be destructive or restart a remote service.",
				"host":                 "Host",
				"command":              "Command",
				"cancel":               "Cancel",
				"proceed":              "Proceed",
				"footer_sub":           "Lightweight Go Infrastructure Automation",
				"config_reload_ok":     "Configuration reloaded successfully",
				"config_reload_failed": "Failed to reload configuration",
				"target_host":          "Target Host",
				"switch_to_arabic":     "العربية",
				"switch_to_english":    "English",
				"config_editor":        "Config Editor",
				"save_changes":         "Save Changes",
				"discard":              "Discard",
				"config_saved":         "Configuration saved and applied successfully",
				"config_save_error":    "Failed to save configuration",
				"access_denied":        "Access denied: Administrator privileges required",
				"yaml_syntax_error":    "YAML syntax error",
				"editor_hint":          "Direct YAML edits will be validated and applied immediately upon saving.",
				"rate_limit_exceeded":  "Too many failed login attempts. Please wait a minute before trying again.",
			},
			LangAR: {
				"app_title":            "أزرار SSH",
				"app_tagline":          "لوحة تحكم البنية التحتية الآمنة",
				"sign_in":              "تسجيل الدخول",
				"username":             "اسم المستخدم",
				"password":             "كلمة المرور",
				"invalid_credentials":  "اسم المستخدم أو كلمة المرور غير صحيحة",
				"rate_limit_exceeded":  "محاولات تسجيل دخول خاطئة كثيرة جداً. يرجى الانتظار لمدة دقيقة والمحاولة لاحقاً.",
				"footer_tagline":       "مشغل أوامر SSH ذاتي الاحتواء",
				"reload_config":        "إعادة تحميل الإعدادات",
				"logout":               "تسجيل الخروج",
				"language":             "اللغة",
				"success":              "نجاح",
				"failed":               "فشل",
				"exit_code":            "رمز الخروج",
				"duration":             "المدة",
				"time":                 "الوقت",
				"error_details":        "تفاصيل الخطأ:",
				"output":               "المخرجات:",
				"standard_error":       "الخطأ القياسي:",
				"no_buttons_title":     "لم يتم تكوين أي أزرار أوامر بعد.",
				"no_buttons_desc":      "أضف الأجهزة والأزرار في ملف config.yml ثم اضغط على \"إعادة تحميل الإعدادات\".",
				"confirm_execution":    "تأكيد التنفيذ",
				"confirm_message":      "هل أنت متأكد من رغبتك في تشغيل هذا الإجراء؟ قد تكون هذه العملية مدمرة أو تعيد تشغيل خدمة عن بعد.",
				"host":                 "الجهاز",
				"command":              "الأمر",
				"cancel":               "إلغاء",
				"proceed":              "متابعة",
				"footer_sub":           "أتمتة البنية التحتية خفيفة الوزن باستخدام Go",
				"config_reload_ok":     "تمت إعادة تحميل الإعدادات بنجاح",
				"config_reload_failed": "فشل في إعادة تحميل الإعدادات",
				"target_host":          "الجهاز المستهدف",
				"switch_to_arabic":     "العربية",
				"switch_to_english":    "English",
				"config_editor":        "محرر الإعدادات",
				"save_changes":         "حفظ التغييرات",
				"discard":              "تراجع",
				"config_saved":         "تم حفظ الإعدادات وتطبيقها بنجاح",
				"config_save_error":    "فشل في حفظ الإعدادات",
				"access_denied":        "تم رفض الوصول: يتطلب صلاحيات مسؤول",
				"yaml_syntax_error":    "خطأ في بناء ملف YAML",
				"editor_hint":          "يتم التحقق من صحة تعديلات YAML وتطبيقها مباشرة عند الحفظ.",
			},
		},
	}
}

// ResolveLanguage returns "ar" or "en" based on cookie, header, or default
func (m *I18nManager) ResolveLanguage(r *http.Request) string {
	if cookie, err := r.Cookie(langCookieName); err == nil {
		lang := strings.ToLower(strings.TrimSpace(cookie.Value))
		if lang == LangAR || lang == LangEN {
			return lang
		}
	}

	// Check Accept-Language header
	accept := strings.ToLower(r.Header.Get("Accept-Language"))
	if strings.Contains(accept, "ar") {
		return LangAR
	}

	return LangEN
}

// T translates a key into the specified language, falling back to English or key itself
func (m *I18nManager) T(lang, key string) string {
	if dict, ok := m.translations[lang]; ok {
		if val, exists := dict[key]; exists {
			return val
		}
	}
	// Fallback to English
	if dict, ok := m.translations[LangEN]; ok {
		if val, exists := dict[key]; exists {
			return val
		}
	}
	return key
}

// GetTranslations returns the map of translations for a given language with fallbacks
func (m *I18nManager) GetTranslations(lang string) map[string]string {
	result := make(map[string]string)
	// Base with English
	for k, v := range m.translations[LangEN] {
		result[k] = v
	}
	// Overlay with target language
	if lang != LangEN {
		if target, ok := m.translations[lang]; ok {
			for k, v := range target {
				result[k] = v
			}
		}
	}
	return result
}

// GetDir returns "rtl" for Arabic and "ltr" for English
func GetDir(lang string) string {
	if lang == LangAR {
		return "rtl"
	}
	return "ltr"
}

// GetOtherLang returns the toggle target language code and display label
func GetOtherLang(lang string) (otherLang string, otherLabel string) {
	if lang == LangAR {
		return LangEN, "English"
	}
	return LangAR, "العربية"
}

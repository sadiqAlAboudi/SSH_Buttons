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
				"docs":                 "Docs",
				"docs_title":           "Documentation & Manual",
				"docs_subtitle":        "Configuration schema, host definitions, and vendor recipes.",
				"back_to_dashboard":    "Back to Dashboard",
				"quick_nav":            "Quick Navigation",
				"section_overview":     "Overview & Environment",
				"section_users":        "Users & Access Control",
				"section_hosts":        "Remote Hosts",
				"section_buttons":      "Categories & Buttons",
				"section_recipes":      "Vendor Recipes",
				"section_raw":          "Example Blueprint",
				"copy_snippet":         "Copy",
				"copied":               "Copied!",
				"menu":                 "Menu",
			},
			LangAR: {
				"app_title":            "أزرار التحكم عبر SSH",
				"app_tagline":          "لوحة تحكم آمنة لإدارة البنية التحتية عبر SSH",
				"sign_in":              "تسجيل الدخول",
				"username":             "اسم المستخدم",
				"password":             "كلمة المرور",
				"invalid_credentials":  "اسم المستخدم أو كلمة المرور غير صحيحة",
				"rate_limit_exceeded":  "تجاوزت الحد المسموح من محاولات الدخول. يرجى الانتظار لمدة دقيقة قبل المحاولة مجدداً.",
				"docs":                 "التوثيق والدليل",
				"docs_title":           "دليل الاستخدام وتهيئة النظام",
				"docs_subtitle":        "مرجع شامل لتهيئة الخوادم، الصلاحيات، ونماذج الأوامر الجاهزة.",
				"back_to_dashboard":    "العودة للوحة التحكم",
				"quick_nav":            "فهرس المحتويات",
				"section_overview":     "إعدادات الخادم وبيئة التشغيل",
				"section_users":        "المستخدمون وصلاحيات الوصول (RBAC)",
				"section_hosts":        "الخوادم وأجهزة الشبكة (Hosts)",
				"section_buttons":      "تصنيفات وأزرار الأوامر (Buttons)",
				"section_recipes":      "أمثلة ونماذج جاهزة (Linux, MikroTik, Cisco)",
				"section_raw":          "ملف التكوين النموذجي (config.example.yml)",
				"copy_snippet":         "نسخ",
				"copied":               "تم النسخ!",
				"footer_tagline":       "منصة خفيفة ومستقلة لتشغيل أوامر SSH",
				"reload_config":        "إعادة تحميل الإعدادات",
				"logout":               "تسجيل الخروج",
				"language":             "اللغة",
				"success":              "نجح التنفيذ",
				"failed":               "فشل التنفيذ",
				"exit_code":            "حالة الإنهاء (Exit Code)",
				"duration":             "مدة التنفيذ",
				"time":                 "تاريخ التنفيذ",
				"error_details":        "تفاصيل الخطأ والتشخيص:",
				"output":               "مخرجات الأمر (Stdout):",
				"standard_error":       "سجل الأخطاء (Stderr):",
				"no_buttons_title":     "لا توجد أزرار أوامر مهيأة حالياً.",
				"no_buttons_desc":      "أضف الخوادم والأزرار في ملف config.yml ثم انقر على \"إعادة تحميل الإعدادات\".",
				"confirm_execution":    "تأكيد التنفيذ",
				"confirm_message":      "هل أنت متأكد من تنفيذ هذا الإجراء؟ قد يتسبب هذا الأمر في تأثيرات حرجة أو إعادة تشغيل خدمات الخادم.",
				"host":                 "الخادم / الجهاز",
				"command":              "الأمر المنفّذ",
				"cancel":               "إلغاء",
				"proceed":              "تأكيد وتنفيذ",
				"footer_sub":           "أتمتة وإدارة البنية التحتية بسرعة وأمان عبر Go",
				"config_reload_ok":     "تمت إعادة تحميل الإعدادات بنجاح",
				"config_reload_failed": "تعذر إعادة تحميل الإعدادات",
				"target_host":          "الخادم المستهدف (Host)",
				"switch_to_arabic":     "العربية",
				"switch_to_english":    "English",
				"config_editor":        "محرر الإعدادات",
				"save_changes":         "حفظ التغييرات",
				"discard":              "إلغاء وتراجع",
				"config_saved":         "تم حفظ الإعدادات وتطبيقها بنجاح",
				"config_save_error":    "تعذر حفظ الإعدادات",
				"access_denied":        "تم رفض الوصول: يتطلب هذا الإجراء صلاحيات المدير (Admin)",
				"yaml_syntax_error":    "خطأ في صياغة ملف YAML (Syntax Error)",
				"editor_hint":          "تُفحص صحة بنية YAML تلقائياً وتُطبّق فور حفظها مع إنشاء نسخة احتياطية.",
				"menu":                 "القائمة",
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

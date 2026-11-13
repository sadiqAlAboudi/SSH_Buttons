package i18n

import (
	"net/http"
	"strings"
)

const (
	LangCookieName = "ssh_buttons_lang"
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
				"tab_buttons":          "Buttons & Categories",
				"tab_hosts":            "Hosts",
				"tab_users":            "Users",
				"tab_yaml":             "Raw YAML",
				"add_user":             "+ Add User",
				"add_host":             "+ Add Host",
				"add_category":         "+ Add Category",
				"add_button":           "+ Add Button",
				"edit":                 "Edit",
				"delete":               "Delete",
				"save":                 "Save",
				"actions":              "Actions",
				"confirm_delete_title": "Confirm Deletion",
				"confirm_delete_user":  "Are you sure you want to delete user",
				"confirm_delete_host":  "Are you sure you want to delete host",
				"confirm_delete_category": "Are you sure you want to delete category",
				"confirm_delete_button": "Are you sure you want to delete button",
				"role":                 "Role",
				"role_admin":           "Admin (Full Access)",
				"role_operator":        "Operator (Run Actions Only)",
				"host_id":              "Host Identifier",
				"host_id_hint":         "Unique ID, e.g. srv_linux or router_mikrotik",
				"display_name":         "Display Name",
				"ip_or_hostname":       "IP Address / Hostname",
				"port":                 "Port",
				"ssh_user":             "SSH Username",
				"auth_method":          "Authentication Method",
				"auth_key":             "Private Key File",
				"auth_pass":            "Password",
				"key_path":             "Private Key Path",
				"pty_shell":            "PTY Shell Mode (Required for Cisco IOS)",
				"legacy_ciphers":       "Legacy Ciphers (RouterOS v6, older Cisco)",
				"category_name":        "Category Name",
				"category_desc":        "Category Description",
				"default_host":         "Default Host (Optional)",
				"button_label":         "Button Label",
				"button_command":       "SSH Command",
				"button_host":          "Target Host",
				"inherit_default":      "Inherit category default",
				"style":                "Color & Style",
				"style_primary":        "Primary (Indigo)",
				"style_success":        "Success (Emerald)",
				"style_warning":        "Warning (Amber + Confirm)",
				"style_danger":         "Danger (Crimson + Confirm)",
				"style_secondary":      "Secondary (Slate)",
				"require_confirm":      "Require confirmation before running",
				"timeout_seconds":      "Timeout (seconds)",
				"stdin_input":          "Automated Stdin Input (e.g. y\\n)",
				"no_hosts":             "No remote hosts configured yet.",
				"no_categories":        "No categories configured yet.",
				"no_buttons_in_category": "No buttons in this category.",
				"err_admin_required":   "At least one administrator account must be retained.",
				"err_username_required": "Username is required.",
				"err_password_required": "Password is required for new users.",
				"err_host_required":    "Host identifier and IP/Hostname are required.",
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
				"tab_buttons":          "الأزرار والتصنيفات",
				"tab_hosts":            "الخوادم والأجهزة",
				"tab_users":            "المستخدمون",
				"tab_yaml":             "محرر YAML",
				"add_user":             "+ إضافة مستخدم",
				"add_host":             "+ إضافة خادم",
				"add_category":         "+ إضافة تصنيف",
				"add_button":           "+ إضافة زر",
				"edit":                 "تعديل",
				"delete":               "حذف",
				"save":                 "حفظ",
				"actions":              "إجراءات",
				"confirm_delete_title": "تأكيد الحذف",
				"confirm_delete_user":  "هل أنت متأكد من حذف المستخدم",
				"confirm_delete_host":  "هل أنت متأكد من حذف الخادم",
				"confirm_delete_category": "هل أنت متأكد من حذف التصنيف",
				"confirm_delete_button": "هل أنت متأكد من حذف الزر",
				"role":                 "الصلاحية",
				"role_admin":           "مدير (تحكم وإدارة كاملة)",
				"role_operator":        "مشغل (تشغيل الأزرار فقط)",
				"host_id":              "معرّف الخادم",
				"host_id_hint":         "معرف فريد، مثل: srv_linux أو router_mikrotik",
				"display_name":         "اسم العرض",
				"ip_or_hostname":       "عنوان IP أو اسم المضيف",
				"port":                 "المنفذ (Port)",
				"ssh_user":             "اسم مستخدم SSH",
				"auth_method":          "طريقة المصادقة",
				"auth_key":             "ملف المفتاح الخاص (Private Key)",
				"auth_pass":            "كلمة المرور (Password)",
				"key_path":             "مسار المفتاح الخاص",
				"pty_shell":            "وضع PTY Shell (ضروري لأجهزة Cisco IOS)",
				"legacy_ciphers":       "تشفير قديم (RouterOS v6، محولات قديمة)",
				"category_name":        "اسم التصنيف",
				"category_desc":        "وصف التصنيف",
				"default_host":         "الخادم الافتراضي (اختياري)",
				"button_label":         "عنوان الزر",
				"button_command":       "أمر SSH",
				"button_host":          "الخادم المستهدف",
				"inherit_default":      "يرث الإعداد الافتراضي للتصنيف",
				"style":                "اللون والمظهر",
				"style_primary":        "رئيسي (أزرق داكن)",
				"style_success":        "نجاح (أخضر)",
				"style_warning":        "تحذير (برتقالي + تأكيد)",
				"style_danger":         "خطر (أحمر + تأكيد)",
				"style_secondary":      "ثانوي (رمادي)",
				"require_confirm":      "طلب تأكيد قبل التنفيذ",
				"timeout_seconds":      "مهلة التنفيذ (ثوانٍ)",
				"stdin_input":          "إدخال تلقائي عبر Stdin (مثل y\\n)",
				"no_hosts":             "لا توجد خوادم مضافة حتى الآن.",
				"no_categories":        "لا توجد تصنيفات مضافة حتى الآن.",
				"no_buttons_in_category": "لا توجد أزرار في هذا التصنيف.",
				"err_admin_required":   "يجب الإبقاء على حساب مدير واحد على الأقل.",
				"err_username_required": "اسم المستخدم مطلوب.",
				"err_password_required": "كلمة المرور مطلوبة للمستخدم الجديد.",
				"err_host_required":    "معرّف الخادم وعنوان المضيف مطلوبان.",
			},
		},
	}
}

// ResolveLanguage returns "ar" or "en" based on cookie, header, or default
func (m *I18nManager) ResolveLanguage(r *http.Request) string {
	if cookie, err := r.Cookie(LangCookieName); err == nil {
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

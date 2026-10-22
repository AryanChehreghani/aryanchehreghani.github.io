/**
 * Anti-Stealer Platform - Stage 2 Database
 * Asset Hardening & System Exposure Audit (29 Comprehensive Checks)
 */

const STEP2_CATEGORIES = {
    browser: { id: "browser", label: "مرورگرها و سشن‌های وب", count: 7 },
    files: { id: "files", label: "فایل‌ها و دارایی‌های محلی", count: 5 },
    apps: { id: "apps", label: "کلاینت‌ها و پیام‌رسان‌ها", count: 4 },
    os: { id: "os", label: "امنیت سیستم‌عامل و ویندوز", count: 7 },
    identity: { id: "identity", label: "مدیریت دسترسی‌ها و هویت", count: 6 }
};

const STEP2_ITEMS = [
    // --- دسته ۱: مرورگرها و سشن‌های وب ---
    {
        id: "browser_passwords",
        category: "browser",
        title: "محل ذخیره‌سازی پسوردها",
        subtitle: "Password Storage Architecture",
        question: "آیا پسوردهای شما در مرورگر ذخیره شده‌اند یا در پسورد منیجر مستقل و ایزوله؟",
        technicalImpact: "استیلرها ظرف چند ثانیه فایل SQLite بنام Login Data مرورگر را خوانده و با کلید DPAPI ویندوز رمزگشایی می‌کنند. پسورد منیجر مستقل (مثل Bitwarden یا 1Password) دیتابیس را در حافظه رم ایزوله و با مسترپسورد مجزا قفل نگه می‌دارد.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "ایمن (Pass Manager مستقل)", scoreType: "compliant" },
            { value: 40, label: "ترکیبی (بخشی در مرورگر)", scoreType: "partial" },
            { value: 0, label: "ناایمن (تماماً در مرورگر)", scoreType: "noncompliant" }
        ],
        remediation: "تمام پسوردها را از بخش Passwords مرورگر اکسپورت و پاک کنید و به یک Password Manager مستقل منتقل نمایید."
    },
    {
        id: "browser_autofill_cards",
        category: "browser",
        title: "وضعیت Autofill و ذخیره کارت‌های بانکی",
        subtitle: "Autofill & Credit Card Storage",
        question: "آیا قابلیت تکمیل خودکار فرم‌ها و ذخیره کارت‌ها در مرورگر غیرفعال است؟",
        technicalImpact: "فایل Web Data در مرورگرها اطلاعات فرم‌ها، شماره کارت‌ها و آدرس‌ها را نگهداری می‌کند که توسط ماژول‌های CC Grabber استیلرها به طور خودکار استخراج می‌شود.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "کاملاً غیرفعال (ایمن)", scoreType: "compliant" },
            { value: 50, label: "فقط آدرس‌ها فعال است", scoreType: "partial" },
            { value: 0, label: "ذخیره کارت و فرم فعال است", scoreType: "noncompliant" }
        ],
        remediation: "در تنظیمات مرورگر گزینه‌های Save and fill payment methods و Autofill را خاموش کنید."
    },
    {
        id: "browser_2fa_type",
        category: "browser",
        title: "نوع تأیید دومرحله‌ای حساب‌های وب",
        subtitle: "2FA Authentication Method",
        question: "روی حساب‌های اصلی وب (جیمیل، اوت‌لوک، پنل‌ها) از چه نوع 2FA استفاده می‌کنید؟",
        technicalImpact: "کدهای SMS در برابر سیم‌سوآپ و فیشینگ آسیب‌پذیرند. اپلیکیشن‌های TOTP بسیار امن‌ترند، و Passkey/Hardware Key تنها روشی است که حتی در صورت سرقت کوکی سشن هم مانع از دور زدن احراز هویت می‌شود.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "Hardware Key / Passkey", scoreType: "compliant" },
            { value: 75, label: "اپلیکیشن Authenticator (TOTP)", scoreType: "partial" },
            { value: 20, label: "فقط پیامک (SMS) یا غیرفعال", scoreType: "noncompliant" }
        ],
        remediation: "تأیید پیامکی را خاموش کرده و از کلید فیزیکی (YubiKey) یا اپلیکیشن‌های Authenticator مستقل استفاده کنید."
    },
    {
        id: "browser_session_hygiene",
        category: "browser",
        title: "عمر نشست‌ها و بهداشت کوکی‌ها",
        subtitle: "Session Hygiene & Cookie Lifespan",
        question: "آیا گزینه «مرا به خاطر بسپار» در حساب‌های حساس خاموش است و مرتب لاگ‌اوت می‌کنید؟",
        technicalImpact: "استیلرها نیازی به یوزرنیم و پسورد ندارند؛ آن‌ها کوکی‌های فعال سشن را می‌دزدند و مستقیماً وارد حساب شما می‌شوند بدون اینکه حتی 2FA درخواست شود.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "خروج مرتب و پاکسازی کوکی", scoreType: "compliant" },
            { value: 50, label: "خروج فقط در سیستم‌های کاری", scoreType: "partial" },
            { value: 0, label: "همیشه در همه حساب‌ها لاگین", scoreType: "noncompliant" }
        ],
        remediation: "در حساب‌های حساس هرگز تیک Remember Me را نزنید و بعد از پایان کار دکمه Sign Out را بزنید."
    },
    {
        id: "browser_enhanced_protection",
        category: "browser",
        title: "محافظت پیشرفته مرورگر (Enhanced Protection)",
        subtitle: "Browser Enhanced Safe Browsing",
        question: "آیا قابلیت Enhanced Safe Browsing در مرورگر شما فعال است؟",
        technicalImpact: "این ویژگی فایل‌های دانلودی ناشناخته و صفحات فیشینگ روز صفر (Zero-day) را قبل از اجرا در محیط ابری اسکن و مسدود می‌کند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "Enhanced Protection فعال است", scoreType: "compliant" },
            { value: 50, label: "Standard Protection فعال است", scoreType: "partial" },
            { value: 0, label: "غیرفعال (No Protection)", scoreType: "noncompliant" }
        ],
        remediation: "به تنظیمات Privacy and security مرورگر رفته و گزینه Enhanced Protection را انتخاب نمایید."
    },
    {
        id: "browser_extensions_audit",
        category: "browser",
        title: "ممیزی افزونه‌های مرورگر",
        subtitle: "Browser Extension Governance",
        question: "آیا تعداد افزونه‌ها حداقل است و دسترسی‌های آن‌ها بازرسی شده است؟",
        technicalImpact: "اکستنشن‌های آلوده یا فروخته‌شده می‌توانند کل کوکی‌ها و اطلاعات ورودی در کیبورد را سرقت کرده و به سرور هکر ارسال کنند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "فقط افزونه‌های رسمی و ضروری", scoreType: "compliant" },
            { value: 50, label: "تعداد متوسط بدون بررسی مجوزها", scoreType: "partial" },
            { value: 0, label: "افزونه‌های ناشناس متعدد فعالند", scoreType: "noncompliant" }
        ],
        remediation: "اکستنشن‌های غیرضروری را حذف کرده و دسترسی Site Access را روی On click تنظیم کنید."
    },
    {
        id: "browser_separate_profiles",
        category: "browser",
        title: "پروفایل جداگانه برای کارهای حساس",
        subtitle: "Isolated Browser Profiles",
        question: "آیا برای حساب‌های مالی یا ادمین از پروفایل یا مرورگر کاملاً مجزا استفاده می‌کنید؟",
        technicalImpact: "جداسازی محیط کاری حساس از محیط وب‌گردی روزمره، مانع از دسترسی استیلر به کوکی‌های حساب‌های مالی حین آلودگی پروفایل وب‌گردی می‌شود.",
        severity: "medium",
        weight: 1,
        options: [
            { value: 100, label: "پروفایل یا مرورگر مجزا دارم", scoreType: "compliant" },
            { value: 50, label: "گاهی از حالت Incognito استفاده می‌کنم", scoreType: "partial" },
            { value: 0, label: "همه کارها در یک پروفایل واحد", scoreType: "noncompliant" }
        ],
        remediation: "یک پروفایل اختصاصی در مرورگر بسازید که هیچ اکستنشنی نداشته و فقط برای پنل‌های مالی و سرور باشد."
    },

    // --- دسته ۲: فایل‌ها و دارایی‌های محلی ---
    {
        id: "files_plaintext_passwords",
        category: "files",
        title: "فایل‌های متنی حاوی پسورد روی سیستم",
        subtitle: "Plaintext Credentials on Disk",
        question: "آیا فایل‌هایی مانند pass.txt، acc.txt یا کدهای بکاپ روی دسکتاپ و داکیومنت دارید؟",
        technicalImpact: "استیلرهایی مثل Lumma و RedLine پوشه‌های Desktop و Documents را برای الگوهای `*pass*`, `*key*`, `*acc*`, `*code*.txt` در ثانیه اول اسکن و زیپ می‌کنند.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "هیچ فایل متنی پسورد ندارم", scoreType: "compliant" },
            { value: 40, label: "فقط کدهای بکاپ رمزگذاری‌شده", scoreType: "partial" },
            { value: 0, label: "بله، فایل متنی پسورد دارم", scoreType: "noncompliant" }
        ],
        remediation: "تمام فایل‌های متنی حاوی رمز را فوراً حذف کنید و اطلاعات را داخل گاوصندوق رمزنگاری‌شده قرار دهید."
    },
    {
        id: "files_seed_phrases",
        category: "files",
        title: "سید فریز (Seed Phrase) و کلیدهای ولت کریپتو",
        subtitle: "Cryptocurrency Recovery Phrases",
        question: "آیا کلمات بازیابی کیف‌پول به صورت متن، اسکرین‌شات یا عکس روی سیستم ذخیره است؟",
        technicalImpact: "ماژول‌های ولت‌گربر (Wallet Grabber) فایل‌های تصویری و متنی حاوی ۱۲ یا ۲۴ کلمه بازیابی را شناسایی و به سرعت کیف‌پول را خالی می‌کنند.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "کاملاً آفلاین روی کاغذ/فلز", scoreType: "compliant" },
            { value: 30, label: "داخل فایل فشرده با پسورد", scoreType: "partial" },
            { value: 0, label: "بله، در کامپیوتر یا اسکرین‌شات", scoreType: "noncompliant" }
        ],
        remediation: "سید فریز را از تمام حافظه‌های دیجیتال پاک کنید و تنها به صورت فیزیکی آفلاین نگهداری نمایید."
    },
    {
        id: "files_desktop_wallets",
        category: "files",
        title: "کیف‌پول‌های نرم‌افزاری دسکتاپ",
        subtitle: "Desktop Wallet App Protection",
        question: "آیا ولت‌های دسکتاپ (مثل Exodus، Electrum) دارای رمز محلی قوی (Passphrase) هستند؟",
        technicalImpact: "استیلرها فایل‌های دیتابیس ولت‌های محلی را در `%AppData%` کپی می‌کنند. اگر ولت بدون پسورد محلی باز شود، هکر کنترل آن را در اختیار می‌گیرد.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "رمز عبور محلی قوی فعال است", scoreType: "compliant" },
            { value: 60, label: "از ولت دسکتاپ استفاده نمی‌کنم", scoreType: "compliant" },
            { value: 0, label: "بدون رمز یا با رمز بسیار ساده", scoreType: "noncompliant" }
        ],
        remediation: "در تنظیمات کیف‌پول دسکتاپ خود، پسورد پیچیده برای هرگونه تراکنش و بازگشایی دیتابیس تنظیم کنید."
    },
    {
        id: "files_dev_secrets",
        category: "files",
        title: "کلیدها و سکرت‌های توسعه‌دهنده",
        subtitle: "Developer Keys & Secrets Exposure",
        question: "آیا کلیدهای SSH، فایل‌های .env یا توکن‌های GitHub در مسیرهای عمومی رها نشده‌اند؟",
        technicalImpact: "استیلرها فولدرهای `~/.ssh/` و فایل‌های `.env` و `.git-credentials` را هدف می‌گیرند تا دسترسی مستقیم به سرورها و ریپازیتوری‌ها پیدا کنند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "کلیدهای SSH دارای Passphrase هستند", scoreType: "compliant" },
            { value: 50, label: "پروژه برنامه‌نویسی روی سیستم ندارم", scoreType: "compliant" },
            { value: 0, label: "کلیدهای SSH بدون رمز در مسیر بازند", scoreType: "noncompliant" }
        ],
        remediation: "برای کلیدهای SSH رمز عبور (Passphrase) تعیین کنید و سکرت‌های پروژه را در Secret Manager نگه دارید."
    },
    {
        id: "files_disk_encryption",
        category: "files",
        title: "رمزگذاری دیسک و درایوها (BitLocker / VeraCrypt)",
        subtitle: "Full Disk & Volume Encryption",
        question: "آیا درایو ویندوز یا پوشه‌های حساس با BitLocker یا VeraCrypt رمزگذاری شده‌اند؟",
        technicalImpact: "رمزگذاری سراسری دیسک از دسترسی به داده‌ها در حالت خاموش یا بوت از فلش‌مموری محافظت می‌کند.",
        severity: "medium",
        weight: 1,
        options: [
            { value: 100, label: "BitLocker / VeraCrypt فعال است", scoreType: "compliant" },
            { value: 50, label: "فقط یک درایو شخصی رمزنگاری شده", scoreType: "partial" },
            { value: 0, label: "هیچ رمزگذاری درایوی وجود ندارد", scoreType: "noncompliant" }
        ],
        remediation: "ویژگی BitLocker را در کنترل پنل ویندوز برای درایو سیستم‌عامل فعال کنید."
    },

    // --- دسته ۳: کلاینت‌ها و پیام‌رسان‌ها ---
    {
        id: "apps_telegram_cloud_password",
        category: "apps",
        title: "تأیید دو مرحله‌ای تلگرام (Cloud Password)",
        subtitle: "Telegram Two-Step Verification",
        question: "آیا قابلیت Two-Step Verification در تلگرام با یک رمز قوی فعال است؟",
        technicalImpact: "استیلرها کل فولدر `tdata` تلگرام دسکتاپ را کپی می‌کنند. اگر پسورد ابری فعال نباشد، هکر در کمتر از یک ثانیه وارد اکانت شما می‌شود. با Cloud Password دسترسی هکر مسدود می‌گردد.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "Cloud Password قوی فعال است", scoreType: "compliant" },
            { value: 50, label: "از تلگرام دسکتاپ استفاده نمی‌کنم", scoreType: "compliant" },
            { value: 0, label: "غیرفعال است (ورود با کد تک‌مرحله)", scoreType: "noncompliant" }
        ],
        remediation: "در تنظیمات تلگرام > Privacy and Security > Two-Step Verification یک رمز اختصاصی تنظیم کنید."
    },
    {
        id: "apps_discord_2fa",
        category: "apps",
        title: "امنیت دیسکورد و مدیریت نشست‌ها",
        subtitle: "Discord 2FA & Session Tokens",
        question: "آیا 2FA دیسکورد فعال است و نشست‌های فعال را به صورت منظم بازرسی می‌کنید؟",
        technicalImpact: "توکن‌های دیسکورد در استوریج محلی کلاینت ذخیره می‌شوند. استیلرها با استخراج توکن، دسترسی کامل به چت‌ها و سرورهای ادمین پیدا می‌کنند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "2FA فعال و سشن‌ها کنترل می‌شوند", scoreType: "compliant" },
            { value: 50, label: "از دیسکورد استفاده نمی‌کنم", scoreType: "compliant" },
            { value: 0, label: "2FA غیرفعال یا سشن‌ها بررسی نمی‌شوند", scoreType: "noncompliant" }
        ],
        remediation: "تأیید دو مرحله‌ای دیسکورد را فعال کرده و نشست‌های ناشناس را در بخش Devices قطع کنید."
    },
    {
        id: "apps_gaming_steam_guard",
        category: "apps",
        title: "حساب‌های گیمینگ و استیم‌گارد (Steam Guard)",
        subtitle: "Gaming Platform Session Protection",
        question: "آیا Steam Guard موبایلی فعال است و لاگین خودکار در سیستم مشترک غیرفعال است؟",
        technicalImpact: "استیلرها فایل‌های نشست `ssfn*` کلاینت استیم را برای انتقال آیتم‌ها و سرقت اکانت شکار می‌کنند.",
        severity: "medium",
        weight: 1,
        options: [
            { value: 100, label: "Steam Guard موبایلی فعال است", scoreType: "compliant" },
            { value: 60, label: "اهل بازی یا استیم نیستم", scoreType: "compliant" },
            { value: 0, label: "استیم گارد خاموش است", scoreType: "noncompliant" }
        ],
        remediation: "استیم‌گارد را روی اپلیکیشن موبایل فعال کنید و هرگز فایل‌های دایرکتوری استیم را به اشتراک نگذارید."
    },
    {
        id: "apps_workplace_sessions",
        category: "apps",
        title: "کلاینت‌های سازمانی (Slack, Teams, Outlook)",
        subtitle: "Corporate Desktop Client Hygiene",
        question: "آیا سشن‌های فعال در برنامه‌های ارتباطی سازمانی مرتب بررسی می‌شوند؟",
        technicalImpact: "نفوذ به کلاینت‌های سازمانی امکان سرقت داده‌های شرکتی و حملات مهندسی اجتماعی به همکاران را فراهم می‌کند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "نشست‌ها پایش و لاگ‌اوت می‌شوند", scoreType: "compliant" },
            { value: 50, label: "کلاینت سازمانی روی این سیستم ندارم", scoreType: "compliant" },
            { value: 0, label: "تمام سشن‌ها برای همیشه باز هستند", scoreType: "noncompliant" }
        ],
        remediation: "نشست‌های فعال را در بخش تنظیمات حساب سازمانی به صورت هفتگی بازبینی کنید."
    },

    // --- دسته ۴: امنیت سیستم‌عامل و ویندوز ---
    {
        id: "os_realtime_protection",
        category: "os",
        title: "محافظت بلادرنگ (Real-Time Protection)",
        subtitle: "Endpoint Antivirus & Cloud Protection",
        question: "آیا آنتی‌ویروس ویندوز (Defender) و Cloud Protection همیشه روشن هستند؟",
        technicalImpact: "اولین کار کرک‌ها و اسکریپت‌های استیلر، تلاش برای خاموش کردن Real-Time Protection از طریق دستورات پاورشل یا رجیستری است.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "همیشه روشن و به‌روز است", scoreType: "compliant" },
            { value: 40, label: "گاهی برای کرک خاموش می‌کنم", scoreType: "partial" },
            { value: 0, label: "کلاً دیفندر را غیرفعال کرده‌ام", scoreType: "noncompliant" }
        ],
        remediation: "قابلیت Real-Time Protection و Tamper Protection را در Windows Security فعال نگه دارید."
    },
    {
        id: "os_defender_exclusions",
        category: "os",
        title: "استثناهای آنتی‌ویروس (Defender Exclusions)",
        subtitle: "Antivirus Path Exclusions Audit",
        question: "آیا پوشه‌ای در لیست استثناهای ویندوز دیفندر قرار نگرفته است؟",
        technicalImpact: "هکرها از کاربر می‌خواهند فولدری مثل Downloads را به Exclusion اضافه کند تا استیلر بدون بررسی آنتی‌ویروس اجرا شود.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "لیست Exclusions کاملاً خالی است", scoreType: "compliant" },
            { value: 40, label: "فقط یک فولدر پروژه خاص", scoreType: "partial" },
            { value: 0, label: "درایو یا فولدر دانلود در استثناهاست", scoreType: "noncompliant" }
        ],
        remediation: "به تنظیمات Windows Security > Virus & threat protection > Exclusions رفته و تمام استثناها را پاک کنید."
    },
    {
        id: "os_uac_level",
        category: "os",
        title: "سطح کنترل حساب کاربری (UAC)",
        subtitle: "User Account Control Level",
        question: "آیا اسلایدر UAC ویندوز روی بالاترین سطح (Always Notify) تنظیم است؟",
        technicalImpact: "سطح بالای UAC مانع از اجرای بی‌سر و صدای اسکریپت‌های ارتقای دسترسی (Privilege Escalation) در پس‌زمینه می‌شود.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "روی بالاترین سطح (Always Notify)", scoreType: "compliant" },
            { value: 60, label: "روی پیش‌فرض ویندوز", scoreType: "partial" },
            { value: 0, label: "کلاً غیرفعال (Never Notify)", scoreType: "noncompliant" }
        ],
        remediation: "در کنترل پنل عبارت UAC را جستجو کرده و اسلایدر را تا انتها بالا ببرید."
    },
    {
        id: "os_file_extensions",
        category: "os",
        title: "نمایش پسوند فایل‌ها در ویندوز",
        subtitle: "Show File Name Extensions",
        question: "آیا گزینه File name extensions در فایل اکسپلورر ویندوز تیک خورده است؟",
        technicalImpact: "عدم نمایش پسوند باعث می‌شود کاربر فایلی با نام `invoice.pdf.exe` را به اشتباه به عنوان یک سند PDF باز کند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "بله، پسوند تمام فایل‌ها نمایش داده می‌شود", scoreType: "compliant" },
            { value: 0, label: "خیر، پسوندها مخفی هستند", scoreType: "noncompliant" }
        ],
        remediation: "در File Explorer به تب View رفته و تیک گزینه File name extensions را بزنید."
    },
    {
        id: "os_standard_user_account",
        category: "os",
        title: "نوع حساب کاربری روزمره ویندوز",
        subtitle: "Least Privilege & Standard User Account",
        question: "آیا برای کارهای روزمره از اکانت Standard استفاده می‌کنید یا ادمین دائم؟",
        technicalImpact: "اجرای بدافزار در حساب استاندارد دسترسی آن را به تغییرات سیستمی، تزریق به فرآیندها و خاموش کردن سرویس‌های امنیتی محدود می‌کند.",
        severity: "medium",
        weight: 1,
        options: [
            { value: 100, label: "اکانت روزمره Standard است", scoreType: "compliant" },
            { value: 50, label: "اکانت ادمین با محافظت UAC", scoreType: "partial" },
            { value: 0, label: "همیشه ادمین بدون محدودیت", scoreType: "noncompliant" }
        ],
        remediation: "یک اکانت استاندارد برای امور روزمره بسازید و از اکانت ادمین فقط در زمان نصب استفاده کنید."
    },
    {
        id: "os_windows_updates",
        category: "os",
        title: "به‌روزرسانی‌های امنیتی ویندوز",
        subtitle: "Operating System Security Patching",
        question: "آیا آپدیت‌های امنیتی ویندوز به صورت خودکار و منظم نصب می‌شوند؟",
        technicalImpact: "استیلرها برای دور زدن آنتی‌ویروس‌ها از آسیب‌پذیری‌های پچ‌نشده ویندوز برای تزریق کد (Process Injection) سوءاستفاده می‌کنند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "آپدیت‌ها خودکار و به‌روز هستند", scoreType: "compliant" },
            { value: 50, label: "گاهی دستی آپدیت می‌کنم", scoreType: "partial" },
            { value: 0, label: "ویندوز آپدیت را کاملاً بسته‌ام", scoreType: "noncompliant" }
        ],
        remediation: "سرویس Windows Update را فعال نگه دارید و پچ‌های ماهیانه را نصب نمایید."
    },
    {
        id: "os_restricted_execution",
        category: "os",
        title: "محدودیت اجرای فایل از مسیرهای پرخطر",
        subtitle: "Execution Restrictions (Temp & AppData)",
        question: "آیا اجرای فایل از پوشه‌های Temp و AppData محدود یا مانیتور شده است؟",
        technicalImpact: "استیلرها در ۹۵٪ مواقع پیلود اجرایی خود را درون پوشه‌های `%Temp%` یا `%AppData%` کپی کرده و از آنجا اجرا می‌کنند.",
        severity: "medium",
        weight: 1,
        options: [
            { value: 100, label: "محدودیت AppLocker / WDAC یا مانیتورینگ فعال است", scoreType: "compliant" },
            { value: 50, label: "از ابزارهای هشدار اجرای ناشناس استفاده می‌کنم", scoreType: "partial" },
            { value: 0, label: "هیچ کنترلی روی این مسیرها نیست", scoreType: "noncompliant" }
        ],
        remediation: "از پالیسی‌های امنیتی برای مسدودسازی اجرای اسکریپت‌های ناشناس در مسیر Temp استفاده نمایید."
    },

    // --- دسته ۵: مدیریت دسترسی‌ها و هویت ---
    {
        id: "id_password_uniqueness",
        category: "identity",
        title: "قدرت و یکتایی رمزهای عبور",
        subtitle: "Password Uniqueness & Complexity",
        question: "آیا برای هر حساب حساس از یک پسورد کاملاً تصادفی و یکتا استفاده می‌کنید؟",
        technicalImpact: "اگر استیلر پسورد یک حساب را سرقت کند، هکر در حمله Credential Stuffing همان پسورد را روی سایر حساب‌های شما تست خواهد کرد.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "تمام پسوردها یکتا و تصادفی هستند", scoreType: "compliant" },
            { value: 40, label: "چند پسورد شبیه به هم با تغییرات کوچک", scoreType: "partial" },
            { value: 0, label: "یک یا دو پسورد تکراری برای همه جا", scoreType: "noncompliant" }
        ],
        remediation: "با قابلیت Password Generator پسورد منیجر، برای هر سرویس یک رمز تصادفی ۱۶+ کاراکتری بسازید."
    },
    {
        id: "id_password_rotation",
        category: "identity",
        title: "تغییر دوره‌ای رمز حساب‌های حساس",
        subtitle: "Targeted Password Rotation Policy",
        question: "آیا پس از هرگونه مشکوک شدن یا به صورت دوره‌ای، رمز حساب‌های کلیدی را تعویض می‌کنید؟",
        technicalImpact: "حتی اگر کوکی یا پسورد در گذشته سرقت شده باشد، تغییر پسورد منجر به ابطال توکن‌های قدیمی در اکثر سرویس‌ها می‌شود.",
        severity: "medium",
        weight: 1,
        options: [
            { value: 100, label: "در زمان لزوم و منظم تعویض می‌شوند", scoreType: "compliant" },
            { value: 50, label: "فقط زمانی که اخطار نشت اطلاعات بیاید", scoreType: "partial" },
            { value: 0, label: "سال‌هاست پسوردها تغییر نکرده‌اند", scoreType: "noncompliant" }
        ],
        remediation: "حساب‌های اصلی (ایمیل، صرافی، حساب مایکروسافت) را دوره‌ای بررسی و رمز آن‌ها را به‌روز کنید."
    },
    {
        id: "id_hardware_key_passkey",
        category: "identity",
        title: "استفاده از Hardware Key یا Passkey",
        subtitle: "Phishing-Resistant FIDO2 Authentication",
        question: "آیا روی حساب‌های استراتژیک از کلید سخت‌افزاری (YubiKey) یا Passkey استفاده می‌کنید؟",
        technicalImpact: "پروتکل FIDO2 به دامنه اختصاصی متصل است و توکن‌های آن حتی در صورت فیشینگ معکوس یا اجرای استیلر امکان سرقت ندارند.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "روی حساب‌های کلیدی فعال است", scoreType: "compliant" },
            { value: 40, label: "با Passkey آشنا هستم اما هنوز پیاده نکرده‌ام", scoreType: "partial" },
            { value: 0, label: "استفاده نمی‌کنم", scoreType: "noncompliant" }
        ],
        remediation: "در سرویس‌های گوگل و مایکروسافت، احراز هویت Passkey یا کلید امنیتی فیزیکی را به عنوان متد اول ست کنید."
    },
    {
        id: "id_session_timeout",
        category: "identity",
        title: "محدود کردن عمر سشن‌ها (Session Timeout)",
        subtitle: "Short-lived Sessions & Token Expiration",
        question: "آیا در پنل‌ها و سرویس‌هایی که پشتیبانی می‌کنند، عمر سشن‌ها کوتاه تنظیم شده است؟",
        technicalImpact: "سشن‌های با عمر طولانی (چندین ماهه) خطرناک‌ترین هدف استیلرها هستند چون هکر تا مدت‌ها می‌تواند بدون نیاز به لاگین مجدد از آن سوءاستفاده کند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "عمر سشن‌ها کوتاه و محدود است", scoreType: "compliant" },
            { value: 50, label: "فقط در پنل‌های ابری حساس", scoreType: "partial" },
            { value: 0, label: "سشن‌ها نامحدود و مادام‌العمرند", scoreType: "noncompliant" }
        ],
        remediation: "مدت زمان فعال ماندن سشن را در سرویس‌های کاری و ابری روی چند ساعت یا حداکثر یک روز تنظیم نمایید."
    },
    {
        id: "id_active_devices_audit",
        category: "identity",
        title: "بررسی منظم دستگاه‌ها و نشست‌های فعال",
        subtitle: "Active Device & Concurrent Session Audit",
        question: "آیا به صورت منظم در گوگل، مایکروسافت و پیام‌رسان‌ها لیست نشست‌های فعال را چک می‌کنید؟",
        technicalImpact: "بسیاری از کاربران ماه‌ها پس از سرقت کوکی توسط استیلر، متوجه نشست باز مهاجم در حساب‌های خود نمی‌شوند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "به طور هفتگی بازرسی و سشن‌های کهنه قطع می‌شوند", scoreType: "compliant" },
            { value: 50, label: "فقط چند ماه یک‌بار نگاه می‌کنم", scoreType: "partial" },
            { value: 0, label: "تا به حال بخش دستگاه‌های متصل را بررسی نکرده‌ام", scoreType: "noncompliant" }
        ],
        remediation: "در بخش Manage devices حساب گوگل، تلگرام و مایکروسافت هر دستگاه ناشناسی را Sign Out کنید."
    },
    {
        id: "id_account_isolation",
        category: "identity",
        title: "جداسازی فیزیکی یا محیطی حساب‌های حساس",
        subtitle: "High-Value Account Environment Isolation",
        question: "آیا حساب‌های با ارزش مالی بالا روی سیستم یا محیطی جدا از سیستم وب‌گردی استفاده می‌شوند؟",
        technicalImpact: "اگر سیستمی که برای دانلود بازی و وب‌گردی عمومی استفاده می‌شود از امور مالی جدا باشد، آلودگی به استیلر کمترین خسارت را به بار می‌آورد.",
        severity: "medium",
        weight: 1,
        options: [
            { value: 100, label: "سیستم یا دیوایس اختصاصی مجزا دارم", scoreType: "compliant" },
            { value: 50, label: "روی یک سیستم اما در ماشین مجازی (VM)", scoreType: "partial" },
            { value: 0, label: "تمام کارهای مالی و تفریحی روی همین یک سیستم است", scoreType: "noncompliant" }
        ],
        remediation: "امور مالی حساس و دارایی‌های رمزارز را به دیوایس تمیز و مجزا یا محیط ایزوله منتقل نمایید."
    }
];

if (typeof module !== "undefined" && module.exports) {
    module.exports = { STEP2_CATEGORIES, STEP2_ITEMS };
}

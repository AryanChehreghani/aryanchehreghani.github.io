/**
 * Anti-Stealer Platform - Stage 3 Database
 * Incident Response, Containment & Recovery Readiness (16 Critical Checks)
 */

const STEP3_CATEGORIES = {
    containment: { id: "containment", label: "مهار فوری و ایزوله‌سازی", count: 3 },
    session_revocation: { id: "session_revocation", label: "ابطال سراسری نشست‌ها و توکن‌ها", count: 4 },
    credential_rotation: { id: "credential_rotation", label: "تعویض رمز و قوانین فوروارد", count: 3 },
    eradication: { id: "eradication", label: "پاکسازی ریشه‌ای سیستم", count: 3 },
    post_incident: { id: "post_incident", label: "کنترل آسیب و پایش پس از رخداد", count: 3 }
};

const STEP3_ITEMS = [
    // --- دسته ۱: مهار فوری و ایزوله‌سازی ---
    {
        id: "ir_isolate_network",
        category: "containment",
        title: "قطع فوری ارتباط فیزیکی و منطقی شبکه",
        subtitle: "Immediate Network Isolation",
        question: "آیا در ثانیه اول مشکوک شدن به اجرای فایل آلوده، اتصال اینترنت و کابل شبکه/وای‌فای را قطع می‌کنید؟",
        technicalImpact: "استیلرها ابتدا اطلاعات را درون یک فایل فشرده در دایرکتوری Temp ذخیره و سپس از طریق پورت‌های 80/443 یا ربات تلگرام به سرور C2 ارسال (Exfiltrate) می‌کنند. قطع اینترنت در ثانیه‌های اول مانع از ارسال فایل خروجی می‌شود.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "پروتکل قطع فوری شبکه را می‌دانم و اجرا می‌کنم", scoreType: "compliant" },
            { value: 40, label: "فقط به فکر اسکن با آنتی‌ویروس می‌افتم", scoreType: "partial" },
            { value: 0, label: "سیستم را روشن با اینترنت متصل رها می‌کنم", scoreType: "noncompliant" }
        ],
        remediation: "دستورالعمل فوری: کابل شبکه (Ethernet) را بکشید یا وای‌فای را خاموش کرده و سیستم را در حالت Airplane Mode قرار دهید."
    },
    {
        id: "ir_clean_second_device",
        category: "containment",
        title: "قانون دستگاه دوم پاک (Clean Second Device)",
        subtitle: "Out-of-Band Incident Handling",
        question: "آیا می‌دانید تمام عملیات بازیابی، تغییر رمزها و لاگ‌اوت سشن‌ها باید از یک گوشی یا کامپیوتر تمیز دیگر انجام شود؟",
        technicalImpact: "اگر کاربر روی همان کامپیوتر آلوده اقدام به تعویض پسورد کند، استیلر فعال یا کی‌لاگر همراه آن بلافاصله پسورد جدید و کدهای تأیید ۲FA جدید را نیز به سرور هکر ارسال خواهد کرد.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "تمام اقدامات را از دستگاه تمیز انجام می‌دهم", scoreType: "compliant" },
            { value: 30, label: "گاهی پسوردها را از همان سیستم عوض کرده‌ام", scoreType: "partial" },
            { value: 0, label: "از این اصل حیاتی بی‌اطلاع بودم", scoreType: "noncompliant" }
        ],
        remediation: "هرگز با دستگاه آلوده لاگین نکنید. اقدامات اضطراری را تنها با گوشی هوشمند یا سیستم مطمئن دیگر انجام دهید."
    },
    {
        id: "ir_freeze_crypto_funds",
        category: "containment",
        title: "انتقال اضطراری و مهار دارایی‌های رمزارز",
        subtitle: "Emergency Crypto Asset Evacuation",
        question: "در صورت مشکوک شدن به نشت کلید ولت، آیا پروتکل انتقال فوری موجودی به یک آدرس امن و جدید را می‌دانید؟",
        technicalImpact: "بات‌های تخلیه‌کننده (Drainer Bots) به صورت خودکار به محض دریافت کلمات بازیابی توسط استیلر، تمام موجودی را در بلاک‌چین جابه‌جا می‌کنند. سرعت عمل در ثانیه‌های نخست تعیین‌کننده است.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "ولت تمیز آماده دارم و سریع منتقل می‌کنم", scoreType: "compliant" },
            { value: 50, label: "دارایی کریپتو روی سیستم ندارم", scoreType: "compliant" },
            { value: 0, label: "برنامه‌ای برای نجات دارایی در زمان بحران ندارم", scoreType: "noncompliant" }
        ],
        remediation: "یک کیف‌پول سخت‌افزاری یا آدرس ولت تمیز در دستگاه ثانویه آماده داشته باشید تا در صورت نشت، موجودی را با گس‌فی بالاتر منتقل نمایید."
    },

    // --- دسته ۲: ابطال سراسری نشست‌ها و توکن‌ها ---
    {
        id: "ir_signout_all_sessions",
        category: "session_revocation",
        title: "لاگ‌اوت اضطراری از تمام دستگاه‌ها (Sign out all sessions)",
        subtitle: "Global Session & Cookie Invalidation",
        question: "آیا می‌دانید تغییر رمز عبور به تنهایی کوکی‌های فعال را باطل نمی‌کند و باید دکمه «خروج از تمام دستگاه‌ها» زده شود؟",
        technicalImpact: "بسیاری از سرویس‌ها به محض تغییر پسورد، نشست‌های فعال فعلی (Session Cookies) را بلافاصله قطع نمی‌کنند. مهاجم با کوکی دزدیده‌شده تا چند ساعت یا روز می‌تواند لاگین بماند مگر آنکه کاربر دکمه Sign out of all sessions را بزند.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "مسلط هستم و گزینه Sign out all devices را می‌زنم", scoreType: "compliant" },
            { value: 40, label: "فکر می‌کردم تغییر پسورد کافی است", scoreType: "partial" },
            { value: 0, label: "هیچ اقدامی برای ابطال سشن‌ها انجام نمی‌دادم", scoreType: "noncompliant" }
        ],
        remediation: "در بخش تنظیمات امنیت گوگل، مایکروسافت و صرافی‌ها، گزینه Sign out of all devices / Revoke all sessions را بزنید."
    },
    {
        id: "ir_revoke_telegram_sessions",
        category: "session_revocation",
        title: "ابطال نشست‌های تلگرام و ریست رمز ابری",
        subtitle: "Telegram Session Termination & Cloud Password",
        question: "آیا نحوه قطع نشست‌های ناشناس در تلگرام (Terminate other sessions) از طریق گوشی را می‌دانید؟",
        technicalImpact: "استیلر با کپی کردن فولدر `tdata` تلگرام دسکتاپ، یک نشست جدید بدون ارسال کد تأیید ایجاد می‌کند. با زدن Terminate all other sessions در موبایل، دسترسی دسکتاپ آلوده در ثانیه مسدود می‌شود.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "مسلطم؛ سشن‌ها را قطع و Cloud Password را تغییر می‌دهم", scoreType: "compliant" },
            { value: 50, label: "از تلگرام دسکتاپ استفاده نمی‌کنم", scoreType: "compliant" },
            { value: 0, label: "نحوه بررسی و قطع نشست‌ها را بلد نیستم", scoreType: "noncompliant" }
        ],
        remediation: "در تلگرام موبایل به Settings > Devices رفته و دکمه قرمز Terminate all other sessions را لمس کنید."
    },
    {
        id: "ir_revoke_discord_tokens",
        category: "session_revocation",
        title: "ریست توکن و قطع نشست‌های دیسکورد",
        subtitle: "Discord Token Invalidation Protocol",
        question: "آیا می‌دانید تنها راه باطل کردن توکن دزدیده‌شده دیسکورد، تعویض پسورد و بازنشانی 2FA است؟",
        technicalImpact: "دیسکورد با تعویض پسورد کاربر، رشته توکن احراز هویت قبلی را منقضی می‌کند و اسکریپت هکر دسترسی خود را از دست می‌دهد.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "رمز دیسکورد را تغییر می‌دهم تا توکن باطل شود", scoreType: "compliant" },
            { value: 50, label: "از دیسکورد استفاده نمی‌کنم", scoreType: "compliant" },
            { value: 0, label: "از مکانیزم کار توکن دیسکورد بی‌اطلاع بودم", scoreType: "noncompliant" }
        ],
        remediation: "رمز حساب دیسکورد را از طریق مرورگر تمیز یا موبایل تعویض کنید تا توکن محلی منقضی گردد."
    },
    {
        id: "ir_revoke_api_tokens",
        category: "session_revocation",
        title: "ابطال کلیدهای API و دسترسی‌های ثالث",
        subtitle: "API Token & OAuth App Revocation",
        question: "آیا توکن‌های گیت‌هاب (Personal Access Tokens)، کلودفلر و دسترسی برنامه‌های جانبی به گوگل را باطل می‌کنید؟",
        technicalImpact: "استیلرها توکن‌های برنامه‌نویسی و OAuth را شکار می‌کنند تا حتی در صورت تغییر پسورد ایمیل، از طریق کلیدهای API دسترسی پنهان به زیرساخت‌ها داشته باشند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "کلیدهای API و Third-party Apps را فوراً Revoke می‌کنم", scoreType: "compliant" },
            { value: 50, label: "هیچ کلید API یا پروژه‌ای ندارم", scoreType: "compliant" },
            { value: 0, label: "به کلیدهای دسترسی API توجهی نمی‌کردم", scoreType: "noncompliant" }
        ],
        remediation: "در GitHub > Settings > Developer settings تمام توکن‌های قدیمی را Revoke و از نو با تاریخ انقضای کوتاه بسازید."
    },

    // --- دسته ۳: تعویض رمز و قوانین فوروارد ---
    {
        id: "ir_priority_primary_email",
        category: "credential_rotation",
        title: "اولویت شماره یک: ایمیل اصلی و ریکاوری",
        subtitle: "Primary Email Triage & Recovery Audit",
        question: "آیا می‌دانید اولین حسابی که باید فوراً رمز آن تعویض و نشست‌هایش باطل شود، ایمیل اصلی شماست؟",
        technicalImpact: "ایمیل شاه‌کلید تمام حساب‌هاست. هکر با داشتن ایمیل، در تمام سایت‌ها دکمه Forgot Password را می‌زند و کدهای ریست را مستقیماً دریافت و حساب‌ها را مصادره می‌کند.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "ایمیل اصلی همیشه اولین اولویت تعویض رمز من است", scoreType: "compliant" },
            { value: 40, label: "ابتدا سراغ شبکه‌های اجتماعی یا بازی‌ها می‌رفتم", scoreType: "partial" },
            { value: 0, label: "ترتیب اولویت‌بندی مشخصی ندارم", scoreType: "noncompliant" }
        ],
        remediation: "ابتدا رمز ایمیل اصلی را با پسورد قوی تعویض کنید، سپس شماره موبایل و ایمیل پشتیبان ثبت‌شده را بازبینی نمایید."
    },
    {
        id: "ir_check_forwarding_rules",
        category: "credential_rotation",
        title: "بررسی قوانین فوروارد خودکار و فیلترهای ایمیل",
        subtitle: "Hidden Email Forwarding Rules Audit",
        question: "آیا پس از نفوذ، بخش Forwarding و Filters جیمیل یا اوت‌لوک را برای کشف ریدایرکت مخفی هکر چک می‌کنید؟",
        technicalImpact: "هکرهای حرفه‌ای پس از ورود به ایمیل، یک قانون مخفی (Rule) اضافه می‌کنند تا تمام ایمیل‌های حاوی کلماتی مثل `code`, `security`, `reset` را بی‌صدا برای ایمیل مهاجم فوروارد و از اینباکس پاک کند!",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "مسلطم؛ بخش Forwarding and POP/IMAP را کامل چک می‌کنم", scoreType: "compliant" },
            { value: 30, label: "از این ترفند خطرناک بی‌اطلاع بودم", scoreType: "partial" },
            { value: 0, label: "هرگز تنظیمات فوروارد ایمیل را بررسی نکرده‌ام", scoreType: "noncompliant" }
        ],
        remediation: "در جیمیل به Settings > Filters and Blocked Addresses و Forwarding رفته و قوانین ناشناس را فوراً حذف کنید."
    },
    {
        id: "ir_banking_and_financial",
        category: "credential_rotation",
        title: "مسدودسازی کارت‌ها و تماس اضطراری با بانک",
        subtitle: "Financial Containment & Card Freezing",
        question: "در صورت سرقت اطلاعات کارت ذخیره‌شده در مرورگر، آیا رمز پویا و کارت را فوراً مسدود می‌کنید؟",
        technicalImpact: "استیلرها شماره کارت (PAN)، تاریخ انقضا و نام صاحب کارت را از مرورگر استخراج می‌کنند و مهاجم با ابزارهای Brute-force رمز پویا را برای برداشت امتحان می‌کند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "کارت را از طریق همراه‌بانک فوراً مسدود یا باطل می‌کنم", scoreType: "compliant" },
            { value: 50, label: "اطلاعات هیچ کارتی در سیستم ذخیره نبوده است", scoreType: "compliant" },
            { value: 0, label: "کارت را فعال رها می‌کردم", scoreType: "noncompliant" }
        ],
        remediation: "از طریق اپلیکیشن بانکی یا تماس با مرکز امداد شتاب، رمز دوم/پویا را غیرفعال کرده و کارت جدید درخواست نمایید."
    },

    // --- دسته ۴: پاکسازی ریشه‌ای سیستم ---
    {
        id: "ir_clean_os_reinstall",
        category: "eradication",
        title: "نصب تمیز مجدد ویندوز (Clean OS Reinstall)",
        subtitle: "Definitive System Eradication Standard",
        question: "آیا می‌دانید برای استیلرهای مدرن، نصب مجدد تمیز ویندوز تنها راهکار قطعی و ۱۰۰٪ امن است؟",
        technicalImpact: "استیلرهایی مثل Lumma و Vidar معمولاً همراه با یک روت‌کیت، لودر یا اسکریپت پایدارساز در رجیستری و حافظه پنهان ویندوز تزریق می‌شوند. آنتی‌ویروس ممکن است فایل اولیه را پاک کند اما دراپرهای ثانویه مخفی بمانند.",
        severity: "critical",
        weight: 3,
        options: [
            { value: 100, label: "سیستم را کامل فرمت و ویندوز را از فلش تمیز نصب می‌کنم", scoreType: "compliant" },
            { value: 40, label: "فقط به اسکن با آنتی‌ویروس و ضدبدافزار بسنده می‌کنم", scoreType: "partial" },
            { value: 0, label: "فقط فایلی که دانلود کرده بودم را Delete می‌کنم", scoreType: "noncompliant" }
        ],
        remediation: "اطلاعات خام اسناد را پشتیبان بگیرید و ویندوز را با ابزار Media Creation Tool از نو با فرمت درایو C نصب کنید."
    },
    {
        id: "ir_check_persistence_autoruns",
        category: "eradication",
        title: "بازرسی مسیرهای ماندگاری با Sysinternals Autoruns",
        subtitle: "Malware Persistence & Scheduled Tasks Audit",
        question: "آیا نحوه استفاده از ابزار رسمی Autoruns برای کشف سرویس‌ها و تسک‌های مشکوک را می‌دانید؟",
        technicalImpact: "بدافزارها تسک‌های زمان‌بندی‌شده (Scheduled Tasks) با نام‌های فریبنده مثل `OneDrive Update` یا `GoogleCrashHandler` ثبت می‌کنند تا پس از هر ری‌استارت دوباره لود شوند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "تسک‌ها، استارتاپ و رجیستری را با ابزار تخصصی بازرسی می‌کنم", scoreType: "compliant" },
            { value: 40, label: "فقط تب Startup در Task Manager را چک می‌کنم", scoreType: "partial" },
            { value: 0, label: "با مسیرهای پنهان ماندگاری بدافزار آشنا نیستم", scoreType: "noncompliant" }
        ],
        remediation: "ابزار رایگان Microsoft Sysinternals Autoruns را دانلود کرده و تب‌های Logon و Scheduled Tasks را بررسی نمایید."
    },
    {
        id: "ir_offline_backups_integrity",
        category: "eradication",
        title: "سلامت‌سنجی بکاپ‌های آفلاین و عدم آلوده‌سازی نسخه پشتیبان",
        subtitle: "Cold Backup Integrity & Isolation",
        question: "آیا از اتصال هارد اکسترنال بکاپ به سیستم مشکوک به آلودگی خودداری می‌کنید؟",
        technicalImpact: "برخی استیلرها ماژول رندوم‌وار یا کرم شبکه دارند و به محض اتصال هارد اکسترنال، فایل‌های پشتیبان را آلوده یا رمزبندی می‌کنند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "هارد بکاپ را تا پاکسازی کامل سیستم متصل نمی‌کنم", scoreType: "compliant" },
            { value: 40, label: "بکاپ آفلاین ندارم یا منظم نمی‌گیرم", scoreType: "partial" },
            { value: 0, label: "هارد اکسترنال را به سیستم آلوده وصل می‌کردم", scoreType: "noncompliant" }
        ],
        remediation: "هارد بکاپ باید قانون 3-2-1 را رعایت کند و تا فرمت کامل سیستم نباید به دستگاه وصل شود."
    },

    // --- دسته ۵: کنترل آسیب و مانیتورینگ پس از رخداد ---
    {
        id: "ir_notify_contacts",
        category: "post_incident",
        title: "اطلاع‌رسانی فوری به مخاطبان و همکاران",
        subtitle: "Social Engineering Chain-Reaction Prevention",
        question: "آیا در صورت به خطر افتادن حساب‌هایتان، به مخاطبان و تیم اخطار می‌دهید تا فریب پیام‌های جعلی را نخورند؟",
        technicalImpact: "هکرها بلافاصله با هویت شما برای دوستان و سرورهای کاری پیام می‌فرستند: «این بازی را تست کن» یا «پول فوری نیاز دارم» و زنجیره آلودگی را گسترش می‌دهند.",
        severity: "high",
        weight: 2,
        options: [
            { value: 100, label: "از طریق کانال دیگر سریعاً به دوستان و تیم اخطار می‌دهم", scoreType: "compliant" },
            { value: 40, label: "به خاطر خجالت یا بی‌اطلاعی سکوت می‌کردم", scoreType: "partial" },
            { value: 0, label: "به احتمال فریب مخاطبانم فکر نمی‌کردم", scoreType: "noncompliant" }
        ],
        remediation: "در یک شبکه اجتماعی دیگر یا از طریق تماس پیام بگذارید که حسابتان هک شده و هیچ لینک یا پیامی را باز نکنند."
    },
    {
        id: "ir_monitor_breach_databases",
        category: "post_incident",
        title: "پایش مداوم گزارش‌های نشت (HaveIBeenPwned)",
        subtitle: "Data Breach & Darkweb Monitoring",
        question: "آیا ایمیل‌ها و شناسه‌های خود را در پایگاه‌های مانیتورینگ نشت اطلاعات مثل HaveIBeenPwned چک می‌کنید؟",
        technicalImpact: "لاگ‌های استیلر در دارک‌وب فروخته یا در چنل‌های تلگرامی رایگان دراپ (Combolists) می‌شوند. مانیتورینگ منظم مشخص می‌کند چه زمان و از چه طریقی اطلاعات افشا شده است.",
        severity: "medium",
        weight: 1,
        options: [
            { value: 100, label: "نوتیفیکیشن نشت فعال دارم و مداوم بررسی می‌کنم", scoreType: "compliant" },
            { value: 50, label: "هر از چند گاهی ایمیلم را تست می‌کنم", scoreType: "partial" },
            { value: 0, label: "با این سرویس‌ها و نحوه پیگیری نشت آشنا نیستم", scoreType: "noncompliant" }
        ],
        remediation: "ایمیل خود را در سایت haveibeenpwned.com ثبت کرده و هشدار نشت خودکار (Notify me) را روشن کنید."
    },
    {
        id: "ir_post_incident_log_review",
        category: "post_incident",
        title: "بررسی لاگ‌های ورود و امنیت حساب (Security Activity)",
        subtitle: "Audit Log & Access IP Investigation",
        question: "آیا در بخش Recent Security Activity سرویس‌ها، آدرس IP و موقعیت جغرافیایی لاگین مهاجم را چک می‌کنید؟",
        technicalImpact: "شناسایی محدوده IP و ساعت نفوذ به کاربر کمک می‌کند تا بفهمد هکر به کدام حساب‌ها یا پیام‌ها دسترسی پیدا کرده و چه اطلاعاتی افشا شده است.",
        severity: "medium",
        weight: 1,
        options: [
            { value: 100, label: "لاگ‌های فعالیت و موقعیت ورود را دقیق بازرسی می‌کنم", scoreType: "compliant" },
            { value: 40, label: "فقط به لاگین‌های خیلی مشکوک نگاه می‌اندازم", scoreType: "partial" },
            { value: 0, label: "تا به حال بخش Security Activity را ندیده‌ام", scoreType: "noncompliant" }
        ],
        remediation: "در حساب گوگل به Security > Manage all devices > Review security events رفته و فعالیت‌ها را استخراج نمایید."
    }
];

if (typeof module !== "undefined" && module.exports) {
    module.exports = { STEP3_CATEGORIES, STEP3_ITEMS };
}

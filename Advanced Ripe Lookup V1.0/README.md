# RIPE Tool — فول ماژولار (Best-effort Split)

این نسخه همه‌ی `def`/`class`‌های فایل اصلی را در ماژول‌های جداگانه قرار می‌دهد و برای هر کدام Docstring فارسی افزوده شده است.

## ساختار
- core/bgp_parser.py — پردازش BGP (Prefix/AS/Community)
- core/ssh_utils.py — اتصال SSH و جمع‌آوری خروجی
- core/rpki_validator.py — اعتبارسنجی RPKI
- core/audit_worker.py — Worker موازی
- core/ripe_api.py — ارتباط با RIPEstat/RIPE DB
- core/utils.py — ابزارهای عمومی
- core/api.py — re-export همه‌ی موارد برای استفاده آسان
- gui/main_window.py — کلاس GUI (استخراج‌شده از سورس یا Placeholder)
- legacy/ripe_original.py — فایل اصلی بدون تغییر

## اجرا
```bash
pip install -r requirements.txt
python main.py
```

## نکته مهم
به دلیل جابه‌جایی کدها، ممکن است برخی وابستگی‌های بین‌ماژولی نیاز به اصلاح import داشته باشند.
برای کاهش خطا، در هر ماژول یک fallback کوچک برای resolve شدن نام‌ها قرار داده شده است.
در صورت خطا، به من بگو تا همان تابع/کلاس را به ماژول مناسب‌تر منتقل یا importها را دقیق‌تر کنم.

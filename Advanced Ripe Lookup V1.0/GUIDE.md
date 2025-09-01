# Advanced RIPE Lookup - Modularized Version

این نسخه از برنامه **Advanced RIPE Lookup** ماژولار شده است تا نگهداری و توسعه راحت‌تر انجام شود.

## تغییرات اصلی

- پوشه‌ی جدید `api_clients/` اضافه شده است.
- تمام ارتباط‌ها با APIها از طریق کلاس‌های مشخص انجام می‌شوند:
  - `api_clients/ripe_db_api.py` → برای کوئری‌های RIPE Database
  - `api_clients/ripestat_api.py` → برای Routing Status و RPKI Validation
  - `api_clients/bgpview_api.py` → برای اطلاعات Prefix از BGPView
- فایل `main_window.py` و تب‌ها از این ماژول‌ها استفاده می‌کنند و دیگر مستقیماً `requests` فراخوانی نمی‌کنند.

## ساختار پروژه

```
Advanced Ripe Lookup V1.0/
│
├── api_clients/
│   ├── ripe_db_api.py
│   ├── ripestat_api.py
│   └── bgpview_api.py
│
├── gui/
│   ├── main_window.py
│   └── tabs/
│       ├── lookup_tab.py
│       ├── looking_glass_tab.py
│       └── ... (سایر تب‌ها)
│
├── main.py
├── GUIDE.md
└── requirements.txt
```

## نحوه‌ی استفاده

1. ابتدا وابستگی‌ها را نصب کنید:
   ```bash
   pip install -r requirements.txt
   ```

2. اجرای برنامه:
   ```bash
   python main.py
   ```

## اضافه کردن API جدید

برای افزودن API جدید:
1. یک فایل در پوشه‌ی `api_clients/` ایجاد کنید (مثلاً `new_api.py`).
2. یک کلاس بسازید که متدهای موردنیاز برای فراخوانی API را در خود داشته باشد.
3. در تب موردنظر (داخل `gui/tabs/`) آن کلاس را `import` کنید و استفاده نمایید.

## توسعه‌ی تب‌های جدید

برای افزودن تب جدید:
1. در پوشه‌ی `gui/tabs/` یک فایل جدید بسازید (مثلاً `my_new_tab.py`).
2. تابع یا کلاسی برای ایجاد تب تعریف کنید.
3. در `main_window.py` آن تب را اضافه کنید.

---

نسخه‌ی ماژولار شده آماده‌ی گسترش برای ابزارهای شبکه و APIهای جدید است 🚀

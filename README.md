# 🛡️ Network Security Monitor Pro 2.0

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg"/>
  <img src="https://img.shields.io/badge/Flask-2.0%2B-green.svg"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg"/>
  <img src="https://img.shields.io/badge/Version-2.0-red.svg"/>
</div>

## 🌟 ویژگی‌های کلیدی

### 🔍 مانیتورینگ لحظه‌ای شبکه
- نمایش زنده وضعیت دستگاه‌های شبکه
- تشخیص خودکار دستگاه‌های جدید
- هشدار آنی برای دستگاه‌های آفلاین
- نمایش مدت زمان آفلاین بودن دستگاه‌ها

### 📊 داشبورد پیشرفته
- نمودار زنده تعداد دستگاه‌های آنلاین
- نمودار دایره‌ای نسبت دستگاه‌های آنلاین/آفلاین
- جدول پیشرفته با قابلیت جستجو و مرتب‌سازی
- حالت شب (Dark Mode) برای راحتی کاربر

### 🔐 امنیت و تست نفوذ
- اسکن پورت‌های باز
- شناسایی سرویس‌های در حال اجرا
- تشخیص نسخه نرم‌افزارها
- گزارش‌گیری از آسیب‌پذیری‌ها

### 📈 تاریخچه و گزارش‌گیری
- ذخیره خودکار لاگ‌ها در پایگاه داده
- نمودار تاریخچه وضعیت شبکه
- امکان دانلود گزارش‌های دوره‌ای
- تحلیل روند تغییرات شبکه

## 🚀 نصب و راه‌اندازی

### پیش‌نیازها
```bash
# نصب Nmap
choco install nmap -y

# نصب پکیج‌های Python
pip install -r requirements.txt
```

### اجرای برنامه
```bash
python app.py
```
سپس به آدرس `http://localhost:5000` در مرورگر خود مراجعه کنید.

## ⚙️ تنظیمات
تنظیمات اصلی برنامه در فایل `app.py`:
```python
SCAN_INTERVAL = 10               # فاصله زمانی اسکن (ثانیه)
NETWORK_RANGE = '192.168.1.0/24' # محدوده شبکه
OFFLINE_THRESHOLD = 30           # آستانه زمان آفلاین (ثانیه)
```

## 🛠️ قابلیت‌های فنی
- **Backend**: Flask + Flask-SocketIO
- **Frontend**: Bootstrap 5 + Chart.js + DataTables
- **Database**: SQLite
- **Network Scanning**: Nmap
- **Real-time Updates**: WebSocket

## 🔧 عیب‌یابی
1. اگر Nmap پیدا نشد:
   ```bash
   choco install nmap --params "/NoSystem=no" -y
   refreshenv
   ```

2. اگر پورت 5000 در دسترس نبود:
   ```python
   socketio.run(app, port=5001, debug=True)
   ```

## 📝 لایسنس
این پروژه تحت لایسنس MIT منتشر شده است.

## 👥 مشارکت
از مشارکت شما در توسعه این پروژه استقبال می‌کنیم! لطفاً:
1. پروژه را Fork کنید
2. یک Branch جدید ایجاد کنید
3. تغییرات خود را Commit کنید
4. یک Pull Request ارسال کنید

## 📞 پشتیبانی
- ایمیل: support@example.com
- تلگرام: @network_monitor_support
- گیت‌هاب: ثبت Issue


---
<div align="center">
  <p>ساخته شده با ❤️ برای متخصصان امنیت شبکه</p>
  <p>Network Security Monitor Pro - نسخه 2.0</p>
</div>

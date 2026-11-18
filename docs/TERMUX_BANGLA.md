# Termux — বাংলা দ্রুত নির্দেশিকা

## ইনস্টল
```bash
pkg update -y && pkg upgrade -y
pkg install python git unzip openssl-tool -y
termux-setup-storage
cd ~/storage/shared/Download
unzip -o Dragon_AI_Hacker_Assistant.zip
cd Dragon_AI_Hacker_Assistant
pip install -r requirements.txt
cp .env.example .env
python dragon.py doctor
```

## নিজের ওয়েবসাইট পরীক্ষা
```bash
python dragon.py website https://YOUR-DOMAIN.example --out ~/storage/shared/Download/DragonAI_Reports
```

## অনুমোদিত API health endpoint পরীক্ষা
```bash
python dragon.py api https://YOUR-DOMAIN.example/api/health --out ~/storage/shared/Download/DragonAI_Reports
```

## APK পরীক্ষা
```bash
python dragon.py apk ~/storage/shared/Download/your-app.apk --out ~/storage/shared/Download/DragonAI_Reports
```

## নিজের প্রজেক্টের config পরীক্ষা
```bash
python dragon.py config ~/my-project --out ~/storage/shared/Download/DragonAI_Reports
```

রিপোর্ট ফোনের Download/DragonAI_Reports ফোল্ডারে পাওয়া যাবে। নিজের নয় এমন সিস্টেমে অনুমতি ছাড়া স্ক্যান করবে না।

# סביבת העבודה
נתונים שאומתו במהלך העבודה ב־5 באוקטובר 2026. גרסאות, כתובות ומזהים עשויים להשתנות לאחר עדכון או יצירה מחדש.

## התיקייה הפעילה
קובצי הפרויקט נמצאים בהפצת WSL בשם Security-Lab:
~~~text
/home/itamar/projects/container-threat-detection-lab
~~~
כניסה מתוך PowerShell:
~~~powershell
wsl -d Security-Lab
~~~
בתוך Linux:
~~~bash
cd ~/projects/container-threat-detection-lab
~~~
גישה מעורך או מסייר Windows:
~~~text
\\wsl.localhost\Security-Lab\home\itamar\projects\container-threat-detection-lab
~~~
עותק ההכנה ב־Windows אינו מסונכרן אוטומטית עם תיקיית Linux.

## רכיבים שאומתו
| רכיב | נתון |
|---|---|
| מערכת | Ubuntu 24.04.5 LTS בתוך WSL 2 |
| ליבה | 6.6.87.2-microsoft-standard-WSL2, x86_64 |
| משתמש | itamar, עם sudo |
| ניהול שירותים | systemd |
| Docker Engine ו־CLI | 29.8.2 |
| Docker Compose | v5.6.0 |
| Docker Buildx | v0.37.1 |
| Docker socket | unix:///var/run/docker.sock |
| זהות מנוע | Ubuntu 24.04.5 LTS / TOMA |
| Falco | 0.45.0, modern eBPF, container plugin 0.7.4 |
| BTF | /sys/kernel/btf/vmlinux נמצא וקריא |

המנוע המקומי בתוך Security-Lab הוריד והריץ hello-world בהצלחה.
Docker CLI הוא הלקוח ששולח פקודות; Docker Engine הוא השירות שמבצע אותן.
בהפצות שנבדקו קודם, הלקוח פנה למנוע Docker Desktop. במעבדה הפעילה אומת מנוע Ubuntu מקומי.

## Images מקובעים במימוש
- Python: python:3.12.15-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
- Falco: falcosecurity/falco:0.45.0@sha256:788f1129c542171813083d4afc61b16730a47dde8c23d9c39370acef996349b6

## זהויות בזמן צילום הסביבה
צילום [environment.json](../artifacts/environment.json) נעשה ב־2026-10-05T10:34:09.221+00:00.

| שירות | hostname בזמן הצילום | IPv4 בזמן הצילום |
|---|---|---|
| allowed-api | 3e809eafbbf3 | 172.18.0.2 |
| lab-sink | 4b80fce79e07 | 172.18.0.3 |
| orders-api | 1090c53f54e0 | 172.18.0.4 |

המזהים המלאים, ה־images והמיפויים נמצאים בצילום. IP יכול לעבור לקונטיינר אחר; אין להשתמש בטבלה כמדיניות קבועה.
הקובץ המדומה ממופה לקריאה בלבד ורק ל־orders-api מבין שלושת שירותי המעבדה.

## גבולות האימות
Falco אסף בפועל אירועי קובץ ורשת עם שיוך ל־orders-api בסביבה הזאת.
זו הוכחת היתכנות למעבדה שנבדקה. אין כאן הבטחת כיסוי מלא או בדיקת עומס.
פרטי תהליך אב חסרו ונצפו קודם פערי זמן בין האפליקציה לחיישן.

להפעלה ולפירוש הראיות: [מדריך המעבדה](lab-guide.he.md).

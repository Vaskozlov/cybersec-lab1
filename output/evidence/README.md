# Происхождение доказательств

Итоговые материалы повторной проверки получены 02.11.2026. HTML-отчеты сканеров
скачаны из artifacts Actions, их архивы проверены по SHA-256 из GitHub API.

Итоговый проверенный запуск: <https://github.com/Vaskozlov/cybersec-lab1/actions/runs/41412819229>.
Commit: `2366cfbded23bca64bd0877a42228ac493fdbe24`. Оба job успешны;
предупреждений, deprecation messages и notices в итоговых журналах нет.

- `http-results.json`, `http-transcript.txt`: реальный локальный сервер,
  вызовы curl из `scripts/capture_http.py`; 12 проверок. Секреты заменены
  пометкой REDACTED, временная база удалена после опыта.
- `ci-result.json`: сводка конкретного успешного запуска с его URL и SHA.
- `ci-run.json`, `ci-jobs.json`: исходные метаданные этого запуска из GitHub API.
- `actions-sast.log`, `actions-sca.log`: полные журналы проверенного запуска.
- `eslint.json`, `eslint.html`, `tests.txt`, `npm-audit.json`, `dependency-check-report.json`,
  `dependency-check-report.html`: файлы из artifacts того же запуска.
- `actions-first-sast.log`, `actions-first-sca.log`: журналы первого запуска
  от 01.11.2026 с предупреждениями устаревших Actions. Причина исправлена обновлением Actions;
  эти файлы сохранены отдельно для проверки причины изменения.

Снимки находятся в `../screenshots/`: SAST и SCA показывают оригинальные HTML-отчеты,
открытые во встроенном браузере через временный сервер на 127.0.0.1; summary показывает
саму страницу GitHub Actions. HTML-файлы перед показом не изменялись.
Пути, источники и контрольные суммы снимков записаны в `screenshot-provenance.json`.
Полный отчет - в `../pdf/`.
Сборка PDF: `python3 scripts/build_report.py` из корня lab1. Скрипт перед сборкой
проверяет согласованность результатов, отсутствие уязвимостей и CI warnings.

Первоначальная подсказка `git init` об имени ветки была информационной;
в итоговом workflow имя явно задано. Объявление GitHub о миграции
`ubuntu-latest` относилось к инфраструктуре runner; итоговое окружение
закреплено как `ubuntu-24.04`. Эти изменения не отключают сообщения сканеров.

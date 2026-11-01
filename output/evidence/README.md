# Происхождение доказательств

Материалы получены 01.11.2026. Снимки браузера и логи не являются имитацией
интерфейса GitHub Actions.

Итоговый проверенный запуск: <https://github.com/Vaskozlov/cybersec-lab1/actions/runs/41309323203>.
Commit: `ed36a64eef5155a126b663452d9d9f716dbb6bdc`. Оба job успешны;
предупреждений, deprecation messages и notices в итоговых журналах нет.

- `http-results.json`, `http-transcript.txt`: реальный локальный сервер,
  вызовы curl из `scripts/capture_http.py`; 10 проверок. Секреты заменены
  пометкой REDACTED, временная база удалена после опыта.
- `ci-result.json`: сводка конкретного успешного запуска с его URL и SHA.
- `ci-run.json`, `ci-jobs.json`: исходные метаданные этого запуска из GitHub API.
- `actions-sast.log`, `actions-sca.log`: полные журналы проверенного запуска.
- `eslint.json`, `tests.txt`, `npm-audit.json`, `dependency-check-report.json`,
  `dependency-check-report.html`: файлы из artifacts того же запуска.
- `actions-first-sast.log`, `actions-first-sca.log`: журналы первого запуска
  с предупреждениями устаревших Actions. Причина исправлена обновлением Actions;
  эти файлы сохранены отдельно для проверки причины изменения.

Снимки страниц находятся в `../screenshots/`. Полный отчет - в `../pdf/`.
Сборка PDF: `python3 scripts/build_report.py` из корня lab1. Скрипт перед сборкой
проверяет согласованность результатов, отсутствие уязвимостей и CI warnings.

Первоначальная подсказка `git init` об имени ветки была информационной;
в итоговом workflow имя явно задано. Объявление GitHub о миграции
`ubuntu-latest` относилось к инфраструктуре runner; итоговое окружение
закреплено как `ubuntu-24.04`. Эти изменения не отключают сообщения сканеров.

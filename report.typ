#set document(title: "Работа 1. Разработка защищенного REST API с интеграцией в CI/CD", author: "Козлов Василий Сергеевич")
#set page(paper: "a4", margin: (top: 2cm, bottom: 2cm, left: 3cm, right: 1.5cm))
#set text(font: "Times New Roman", size: 14pt, fill: black, lang: "ru")
#set par(justify: true, leading: 7pt, spacing: 0pt)
#set heading(numbering: "1.1")
#show heading.where(level: 1): it => block(above: 0pt, below: 16pt, breakable: false)[
  #pad(left: 1.25cm)[#text(size: 14pt, weight: "bold")[#it]]
]
#show heading.where(level: 2): it => block(above: 12pt, below: 12pt, breakable: false)[
  #pad(left: 1.25cm)[#text(size: 14pt, weight: "bold")[#it]]
]
#let structural(body) = [
  #show heading: it => block(above: 0pt, below: 16pt, breakable: false)[
    #align(center)[#text(size: 14pt, weight: "bold")[#it]]
  ]
  #heading(level: 1, numbering: none)[#body]
]
#let para(body) = block(below: 10pt)[
  #par(justify: true, leading: 7pt, spacing: 0pt,
    first-line-indent: (amount: 1.25cm, all: true))[#body]
]
#let note(body) = block(above: 4pt, below: 8pt)[
  #set text(size: 12pt)
  #par(first-line-indent: 0pt, justify: true, leading: .4em)[#body]
]
#let listing(number, title, body) = block(width: 100%, above: 8pt, below: 12pt, breakable: false)[
  #block(below: 5pt)[#text(size: 12pt)[Листинг #number - #title]]
  #block(width: 100%, fill: rgb("#F7F7F7"), stroke: .5pt + rgb("#BFBFBF"), inset: 8pt)[
    #set par(justify: false, first-line-indent: 0pt, leading: .4em)
    #text(font: "DejaVu Sans Mono", size: 9pt)[#body]
  ]
]
#let cell(body, bold: false) = table.cell(inset: 6pt)[
  #set par(first-line-indent: 0pt, justify: false, leading: .35em)
  #text(size: 11pt, weight: if bold { "bold" } else { "regular" })[#body]
]
#let tablecap(n, body) = block(above: 8pt, below: 5pt)[#text(size: 12pt)[Таблица #n - #body]]
#let shot(file, n, body, height: 12cm) = block(width: 100%, breakable: false, above: 8pt, below: 10pt)[
  #if sys.inputs.at("draft", default: "false") == "true" {
    block(width: 100%, height: height, stroke: .5pt)[#align(center + horizon)[Черновик: здесь будет снимок отчета CI]]
  } else {
    align(center)[#image("output/screenshots/" + file, width: 100%, height: height, fit: "contain")]
  }
  #block(above: 6pt)[#align(center)[#text(size: 12pt)[Рисунок #n - #body]]]
]
#let src(n, title, url) = block(below: 8pt)[
  #set par(justify: false, leading: 5pt)
  #text(size: 12pt)[#n. #title. URL: #link(url)[#url] (дата обращения: 01.11.2026).]
]
#let ci = json("output/evidence/ci-result.json")
#let http = json("output/evidence/http-results.json")
#let repo = "https://github.com/Vaskozlov/cybersec-lab1"
#let footer = context align(center)[#text(size: 12pt)[#counter(page).display("1")]]

#set page(footer: none)
#align(center)[#text(size: 12pt)[
  Федеральное государственное автономное образовательное учреждение \ высшего образования \
  «Национальный исследовательский университет ИТМО»
]]
#v(30pt)
#align(center)[#text(size: 12pt)[Факультет программной инженерии и компьютерной техники]]
#v(40pt)
#align(center)[
  #text(size: 12pt)[Информационная безопасность]
  #v(10pt)
  #text(size: 12pt)[Работа 1: разработка защищенного REST API \ с интеграцией в CI/CD]
]
#v(1fr)
#align(right)[#block(width: 8.2cm)[
  #align(right)[#text(size: 12pt)[Выполнил:]]
  #v(5pt)
  #align(right)[#text(size: 12pt)[Козлов Василий Сергеевич]]
  #v(7pt)
  #align(right)[#text(size: 12pt)[P3415]]
  #v(18pt)
  #align(right)[#text(size: 12pt)[Проверила:]]
  #v(5pt)
  #align(right)[#text(size: 12pt)[Маркина Татьяна Анатольевна]]
]]
#v(40pt)
#align(center)[#text(size: 12pt)[Санкт-Петербург 2026]]

#pagebreak()
#set page(footer: footer)
#align(center)[#text(weight: "bold")[СОДЕРЖАНИЕ]]
#v(18pt)
#outline(title: none, depth: 1, indent: 1.25cm)

#pagebreak()
#structural[ВВЕДЕНИЕ]
#para[
  Цель работы - разработать REST API с аутентификацией, защитой от SQL-инъекций
  и межсайтового скриптинга и встроить автоматические проверки безопасности
  в процесс разработки.
]
#para[
  Объект исследования - серверное приложение для хранения личных заметок.
  Предмет исследования - проверка прав доступа к данным, безопасная обработка
  пользовательского ввода, хранение паролей и контроль зависимостей в CI.
]
#para[
  Разработаны три метода: вход по логину и паролю, чтение собственных заметок
  и создание заметки. Для постоянного хранения применяется SQLite. Успешный
  вход выдает JWT, а все методы с префиксом `/api` используют общий обработчик
  проверки токена.
]
#para[
  Проверка результата состоит из функциональных HTTP-запросов через curl,
  автоматических тестов негативных сценариев, статического анализа исходного
  кода и анализа состава зависимостей. Отчеты сохраняются как артефакты
  GitHub Actions. Текущая верификация выполнена 02.11.2026;
  исторические журналы от 01.11.2026 сохранены отдельно.
]
#para[
  Исходный код, README с инструкциями и конфигурация pipeline опубликованы
  в открытом репозитории: #link(repo)[Vaskozlov/cybersec-lab1].
  Материалы выполнения и исходник настоящего отчета включены в тот же проект.
]

#pagebreak()
= Стек и организация проекта
#para[
  Выбран JavaScript на Node.js 24 LTS. Express обрабатывает HTTP-запросы,
  встроенный модуль `node:sqlite` выполняет параметризованные запросы,
  библиотека `jose` выпускает и проверяет JWT. Для scrypt используется
  стандартный криптографический модуль Node.js.
]
#tablecap(1)[Основные компоненты проекта]
#table(columns: (4.9cm, 1fr), stroke: .5pt,
  table.header(cell([Компонент], bold: true), cell([Назначение], bold: true)),
  cell([Node.js 24 LTS]), cell([Среда CI; локально #http.node]),
  cell([Express 5.3.0]), cell([Маршрутизация и обработка JSON]),
  cell([SQLite / node:sqlite]), cell([Пользователи и личные заметки]),
  cell([jose 6.2.14]), cell([JWT / HS256]),
  cell([Helmet 8.3.0]), cell([Защитные HTTP-заголовки]),
  cell([express-rate-limit 8.7.2]), cell([Ограничение попыток входа]),
  cell([ESLint + security plugin]), cell([Статический анализ исходного кода]),
  cell([Dependency-Check 13.0.0]), cell([SCA: npm advisories и NVD]),
)
#v(8pt)
#para[
  `src/app.js` содержит маршруты и middleware; `database.js` - схему SQLite;
  `passwords.js` - хэширование; `server.js` - конфигурацию и запуск.
  Команда `scripts/create-user.js` создает пользователя, а `test/api.test.js`
  проверяет штатные и атакующие запросы. Версии пакетов закреплены
  в `package.json` и `package-lock.json`.
]
#para[
  В базе `users` хранятся числовой ID, неизменяемый UUID `account_id`, имя
  и хэш пароля. Таблица `notes` содержит ID, числовой `owner_id`, заголовок
  и текст. Внешние ключи включены;
  таблицы используют строгую типизацию SQLite. Секреты и файл БД исключены из git.
]
#para[
  Старая схема автоматически мигрируется в транзакции: пользователи получают
  UUID, а числовые ID, хэши и заметки сохраняются. `account_id` уникален
  и обязателен; изменение запрещено триггером. Повторное открытие БД сохраняет UUID.
]

#pagebreak()
= API и воспроизведение запуска
#tablecap(2)[Методы API]
#table(columns: (3.7cm, 3cm, 1fr), stroke: .5pt,
  table.header(cell([Метод и маршрут], bold: true), cell([Доступ], bold: true), cell([Результат], bold: true)),
  cell([POST /auth/login]), cell([Логин/пароль]), cell([200: JWT; 401: отказ]),
  cell([GET /api/data]), cell([Bearer JWT]), cell([200: до 100 своих заметок]),
  cell([POST /api/data]), cell([Bearer JWT]), cell([201: созданная заметка]),
)
#v(8pt)
#para[
  Третьим методом выбран POST `/api/data`: он позволяет проверить запись
  пользовательского текста в БД и последующее безопасное чтение.
  Имя поля логина - `username`. Все тела запросов и ответов имеют формат JSON.
]
#note[
  Некорректный JSON возвращает 400, превышение 16 KiB - 413,
  неподдерживаемые charset или Content-Encoding - 415. Неожиданные ошибки
  возвращают 500 без внутренних подробностей.
]
#listing(1, [Установка и запуск из корня репозитория], ```text
npm ci --ignore-scripts
export JWT_SECRET="$(openssl rand -base64 32)"
# В zsh ввести пароль без отображения:
read -rs 'LAB_PASSWORD?Password: '; echo
export LAB_PASSWORD
npm run create-user -- vasily
unset LAB_PASSWORD
npm start
```)
#para[
  Сервер слушает только 127.0.0.1:3001. Переменная `JWT_SECRET` содержит
  случайный ключ в base64: минимум 32 байта после декодирования.
  При отсутствии или недостаточной длине ключа сервер не запускается.
  Пользователь создается административной командой; пароля по умолчанию нет.
]
#listing(2, [Примеры запросов к защищенному методу], ```text
# Без токена: HTTP 401
curl -i http://127.0.0.1:3001/api/data
# С токеном из POST /auth/login: HTTP 200
curl -i -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:3001/api/data
```)

#pagebreak()
= Защита от SQL Injection и XSS
#para[
  Значения передаются в SQLite отдельно от SQL через параметры `?`.
  Строка запроса остается неизменной даже при наличии кавычек или SQL-операторов
  во входных данных. Конкатенация пользовательского ввода с SQL не используется
  (листинг 3). Такой подход соответствует рекомендациям OWASP \[1\].
]
#listing(3, [Параметризованные запросы], ```text
db.prepare(
  'SELECT account_id, password_hash FROM users WHERE username = ?'
).get(username);

db.prepare(
  'INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)'
).run(userId, title, body);
```)
#para[
  Запрос входа с именем `' OR 1=1 --` получил HTTP 401.
  Дополнительный тест сохраняет SQL-подобный текст как заметку и проверяет,
  что таблица остается доступной. Защита не основана на черном списке подстрок.
]
#para[
  По требованию задания строки заметок экранируются на выходе: символы
  `&`, `<`, `>`, кавычки и апостроф заменяются HTML-сущностями.
  Исходный текст сохраняется в БД без экранирования; это предотвращает
  повторное кодирование при чтении. Реальный результат curl приведен в листинге 4.
]
#listing(4, [Входной XSS-текст и поле ответа HTTP 201], ```text
request.body:  <script>alert(1)</script>
response.body: &lt;script&gt;alert(1)&lt;/script&gt;
```)
#note[
  API возвращает JSON с `nosniff`. Экранирование предназначено для HTML-текста,
  а не для произвольных URL, скриптов или атрибутов. На клиенте следует применять
  безопасные средства вывода, например `textContent`, и учитывать контекст \[2\].
]

#pagebreak()
= Аутентификация и разграничение доступа
#para[
  Пароль обрабатывается scrypt с N=32768, r=8, p=3 - одним из вариантов
  параметров OWASP \[3\]. Для каждого пароля генерируется соль длиной 16 байт.
  Хэш длиной 64 байта и параметры сохраняются в `password_hash`.
  При проверке используется сравнение `timingSafeEqual`.
]
#para[
  Вход с неверным паролем и неизвестным именем возвращает одинаковую ошибку
  HTTP 401. Для неизвестного имени также выполняется scrypt с фиктивным хэшем.
  Число попыток входа ограничено пятью в минуту на IP; превышение дает HTTP 429.
]
#para[
  Успешный вход формирует JWT с алгоритмом HS256 и сроком действия 900 секунд.
  Поля: `sub` - UUID `account_id`, `iss` - cybersec-lab1, `aud` -
  cybersec-lab1-client, `iat` и `exp` - время выдачи и истечения,
  `jti` - случайный идентификатор. Пароль в токен не включается.
  Подпись обеспечивает целостность, но не шифрует содержимое.
]
#listing(5, [Основные параметры проверки JWT], ```text
await jwtVerify(token, jwtSecret, {
  algorithms: ['HS256'],
  issuer: 'cybersec-lab1',
  audience: 'cybersec-lab1-client',
  typ: 'JWT',
  requiredClaims: ['sub', 'iat', 'exp', 'iss', 'aud', 'jti'],
  maxTokenAge: '900s'
});
```)
#para[
  После проверки JWT сервер находит пользователя по UUID `account_id`
  и использует его числовой ID как `owner_id`. Middleware защищает весь `/api`;
  клиент не выбирает владельца. Чтение ограничено `WHERE owner_id = ?`.
  Старые токены с числовым `sub` после миграции отклоняются с 401.
  Повторное использование числового ID не возвращает доступ старому JWT.
]
#note[
  Дополнительные меры: предел JSON 16 KiB; ограничения полей заметки;
  Helmet; `Cache-Control: no-store`; отсутствие стека ошибок в ответах.
  Для внешнего развертывания требуются HTTPS и настройка reverse proxy.
]

#pagebreak()
= Проверки безопасности в CI
#para[
  Workflow `.github/workflows/ci.yml` запускается при каждом push,
  pull request и вручную. Job «API tests and SAST» устанавливает зависимости
  из lockfile, выполняет HTTP-тесты и ESLint с правилами eslint-plugin-security.
  Предупреждения также блокируют успешное завершение анализатора.
]
#para[
  Для shell задан `bash` с `pipefail`: ошибка `npm test` не теряется при записи
  через `tee`. CI summary и сборщик PDF независимо сверяют итоговый лог:
  число тестов больше нуля, все пройдены, нет провалов, отмен, пропусков и todo.
]
#para[
  Job «SCA - OWASP Dependency-Check» выполняет npm audit и Dependency-Check
  13.0.0 по `package.json` и `package-lock.json`, включая инструменты разработки.
  SAST исследует исходный код; SCA сопоставляет компоненты с базами известных
  уязвимостей. Эти методы дополняют проверку поведения работающего API.
]
#listing(6, [Команды проверок в workflow, сокращенно], ```text
npm ci --ignore-scripts
npm test 2>&1 | tee reports/tests.txt
npm run sast
npm audit --audit-level=high --json
FEED='https://nvd.nist.gov/feeds/json/cve/2.0/'
dependency-check.sh --project cybersec-lab1 \
  --scan package.json --scan package-lock.json \
  --format HTML --format JSON --out reports \
  --nvdDatafeed "${FEED}nvdcve-2.0-{0}.json.gz" \
  --disableOssIndex --disableAssembly --failOnCVSS 7
```)
#para[
  Dependency-Check использует npm advisory service и официальные NVD JSON 2.0
  feeds без API-ключа \[4\]. База NVD кешируется. Sonatype OSS Index отключен,
  так как требует отдельной авторизации; проверки NVD и npm сохранены.
  Порог блокировки - CVSS от 7; ошибки сканера или загрузки также завершают job.
]
#para[
  Actions закреплены SHA; архив сканера проверяется SHA-256.
  Workflow получает только `contents: read`. Результаты тестов, JSON и HTML
  сохраняются в artifacts, фактические итоги выводятся в Job summary.
]

#pagebreak()
= Функциональные проверки через curl
#para[
  Скрипт `scripts/capture_http.py` запускает настоящий сервер, создает
  временную БД и отправляет запросы с помощью curl. Выполнено #http.passed
  проверок, ошибок - #http.failed. В публикуемых материалах пароли и JWT
  заменены пометкой REDACTED; после опыта временная БД удаляется.
]
#tablecap(3)[Фактические результаты запросов]
#table(columns: (1fr, 2.2cm), stroke: .5pt,
  table.header(cell([Сценарий], bold: true), cell([HTTP], bold: true)),
  cell([GET /api/data без токена]), cell([401]),
  cell([POST /api/data без токена]), cell([401]),
  cell([Правильный логин и пароль]), cell([200]),
  cell([Неверный пароль]), cell([401]),
  cell([SQL-инъекция в username]), cell([401]),
  cell([Некорректный JWT]), cell([401]),
  cell([Создание заметки с XSS-текстом]), cell([201]),
  cell([Чтение собственной заметки]), cell([200]),
  cell([Вход второго пользователя]), cell([200]),
  cell([Чтение вторым пользователем: пустой список]), cell([200]),
  cell([Неподдерживаемая кодировка JSON]), cell([415]),
  cell([Неподдерживаемое Content-Encoding]), cell([415]),
)
#v(8pt)
#listing(7, [Извлечение из протокола реального ответа], ```text
GET /api/data (Authorization отсутствует)
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer
Content-Type: application/json; charset=utf-8
{"error":"Authentication required"}

GET /api/data (Bearer JWT второго пользователя)
HTTP/1.1 200 OK
{"data":[]}
```)
#note[
  Полный протокол: `output/evidence/http-transcript.txt`;
  структурированные результаты: `output/evidence/http-results.json`.
  Воспроизведение: `python3 scripts/capture_http.py`.
]

#pagebreak()
= Автоматические тесты и SAST
#para[
  Выполнено #ci.tests_total автоматических тестов: пройдено #ci.tests_passed,
  провалов #ci.tests_failed. Проверены выдача JWT, неверный пароль,
  SQL-инъекции, оба метода без токена, сохранение текста, экранирование XSS,
  изоляция пользователей, поврежденные и просроченные токены, неправильные
  алгоритм, issuer и audience, отсутствие exp, alg=none, ограничения JSON,
  HTTP-заголовки, rate limiter и отказ от короткого ключа.
]
#note[
  Регрессионные сценарии проверяют отказ старому JWT после удаления аккаунта
  и повторного использования числового ID; миграцию БД с сохранением заметок;
  ответы 415. Отрицательная проверка pipeline подтверждает, что провал команды
  до `tee` блокирует следующий этап.
]
#para[
  Результат job: #ci.sast_conclusion.
  ESLint проанализировал #ci.eslint_files файлов: ошибок - #ci.eslint_errors,
  предупреждений - #ci.eslint_warnings.
  На рисунке 1 показан оригинальный HTML-отчет ESLint из артефакта GitHub Actions,
  открытый во встроенном браузере. В нем видны все проверенные файлы и число
  обнаруженных проблем. Отдельные счетчики errors и warnings сохранены в JSON.
]
#shot("actions-sast.jpg", 1, [HTML-отчет ESLint из артефакта Actions №#ci.run_number], height: 6cm)
#note[
  Исходные журналы и машиночитаемые отчеты приложены в `output/evidence/`.
  Пустой список findings означает отсутствие обнаруженных правилом проблем,
  но не доказывает отсутствие всех возможных уязвимостей.
]

#pagebreak()
= Результаты SCA и исправление зависимости
#para[
  При первоначальной установке npm audit обнаружил пять moderate-записей,
  связанных с транзитивным `minimatch` в ESLint. Уведомление
  GHSA-g3hv-75wg-m249 описывает риск отказа в обслуживании при обработке
  специальных glob-шаблонов; исправлена версия 11.0.1 \[5\].
]
#note[
  Оригинальный отчет npm audit до исправления не был сохранен. Число пяти
  moderate-записей относится к первоначальному локальному опыту 01.11.2026;
  приложенные отчеты подтверждают только состояние после обновления.
]
#para[
  В `package.json` добавлено `overrides.minimatch=11.0.1`, lockfile обновлен.
  После изменения повторно успешно выполнены статический анализ и тесты.
  Пакеты не исключались из аудита; подавления CVE для этого исправления не применялись.
]
#para[
  Фактический итог npm audit: #ci.npm_total известных уязвимостей.
  Dependency-Check: #ci.dependencies уникальных проанализированных компонентов;
  #ci.vulnerable_dependencies компонентов с найденными уязвимостями.
  Результат SCA job: #ci.sca_conclusion.
]
#shot("actions-sca.jpg", 2, [HTML-отчет Dependency-Check из артефакта Actions №#ci.run_number], height: 8cm)

#pagebreak()
= Репозиторий и успешный pipeline
#para[
  Публичный репозиторий: #link(repo)[Vaskozlov/cybersec-lab1].
  README содержит назначение, описание трех методов, пошаговый запуск,
  команды curl, объяснение мер защиты и ссылки на отчеты.
]
#para[
  Подтвержденный запуск проверок: #link(ci.run_url)[Security CI, запуск №#ci.run_number].
  Состояние: #ci.conclusion. Проверенный commit:
  #text(font: "DejaVu Sans Mono", size: 10pt)[#ci.head_sha].
]
#shot("actions-summary.jpg", 3, [Общий результат pipeline], height: 10.5cm)
#tablecap(4)[Состав материалов для сдачи]
#table(columns: (4.3cm, 1fr), stroke: .5pt,
  table.header(cell([Материал], bold: true), cell([Расположение], bold: true)),
  cell([Код и зависимости]), cell([src/, package.json, package-lock.json]),
  cell([README и workflow]), cell([README.md; .github/workflows/ci.yml]),
  cell([HTTP-доказательства]), cell([output/evidence/http-transcript.txt]),
  cell([Отчеты сканеров]), cell([Actions artifacts и output/evidence/]),
  cell([Скриншоты]), cell([output/screenshots/]),
  cell([PDF и исходник]), cell([output/pdf/; report.typ]),
)

#pagebreak()
= Разбор предупреждений
#para[
  В первом успешном запуске присутствовали предупреждения GitHub Actions
  об устаревшем runtime Node.js 20 и вызовах `punycode` и `url.parse()`
  в старых Actions. Это реальные предупреждения инструментов CI,
  требующие обновления, а не найденные уязвимости кода API.
]
#para[
  Actions обновлены с закреплением SHA: checkout 7.0.1, setup-node 7.1.0,
  upload-artifact 7.0.2 и cache 6.1.0. Их конфигурации используют Node.js 24.
  После обновления pipeline выполнен повторно. Число предупреждений
  в журналах итогового запуска: #ci.action_warning_count.
]
#para[
  Подсказка `git init` об имени начальной ветки не является предупреждением
  безопасности. Она сообщает о настройке Git; checkout затем выбирает
  требуемую ветку `main`. Эта подсказка не означает пропуск проверки
  или проблему приложения.
]
#para[
  В промежуточном запуске GitHub вывел уведомление уровня notice о миграции
  `ubuntu-latest` на Ubuntu 26. Оно относится к инфраструктуре, а не к находке
  безопасности. Для воспроизводимости образ закреплен как `ubuntu-24.04`;
  начальное имя ветки Git явно установлено в `main` в одноразовом runner.
  Предупреждения не скрывались настройками подавления сообщений.
]
#para[
  Единственное точечное исключение ESLint относится к вызову
  `appendFileSync` в скрипте формирования summary. Анализатор отмечает
  нелитеральное имя файла, но путь поступает из `GITHUB_STEP_SUMMARY`,
  создаваемого runner. Скрипт не обрабатывает HTTP-запросы; пользователь
  API не может управлять этим путем. Предполагаемый правилом поток
  недоверенного ввода отсутствует, поэтому предупреждение для данной
  строки признано ложноположительным и снабжено поясняющим комментарием.
]
#para[
  Остальные правила безопасности остаются включенными. Проверка ESLint
  выполняется с `--max-warnings 0`; ошибки загрузки сканеров и обнаружение
  зависимостей с CVSS от 7 по-прежнему блокируют pipeline.
]

#pagebreak()
= Ответы на контрольные вопросы
== Хэширование паролей
#para[
  SHA-256 предназначен для быстрого вычисления: при утечке базы злоумышленник
  способен быстро перебирать пароли, особенно на GPU. Парольные алгоритмы
  bcrypt, scrypt и Argon2 используют соль и регулируемую вычислительную
  стоимость. scrypt дополнительно требует память. Уникальная соль препятствует
  использованию общих заранее вычисленных таблиц и совпадению хэшей одинаковых
  паролей разных пользователей.
]
== Различие SAST и DAST
#para[
  SAST анализирует исходный код без запуска сервиса, например ищет опасные
  вызовы и пути обработки ввода. DAST проверяет работающий сервис извне,
  посылая запросы и оценивая ответы. SCA решает отдельную задачу: проверяет
  известные уязвимости версий зависимостей. В работе использованы SAST и SCA,
  а curl и HTTP-тесты подтверждают поведение конкретных сценариев.
]
== Устройство и проверка JWT
#para[
  Подписанный JWT состоит из заголовка, payload и подписи в base64url.
  Заголовок задает тип и алгоритм, payload содержит claims. Сервер проверяет
  подпись заранее известным ключом и разрешенным алгоритмом, срок действия,
  issuer и audience. В HS256 ключ общий, поэтому его обладатель способен
  выпускать токены. Подпись не обеспечивает конфиденциальность payload.
]
== Риски сторонних библиотек
#para[
  Уязвимости могут находиться как в прямых, так и в транзитивных зависимостях,
  включая инструменты CI. Без регулярного аудита известные CVE сохраняются
  в проекте и могут привести к утечке, обходу доступа или отказу в обслуживании.
  Lockfile фиксирует версии, но требует повторного сканирования и обновления.
  Найденная зависимость minimatch показывает практическую роль SCA.
]

#pagebreak()
#structural[ЗАКЛЮЧЕНИЕ]
#para[
  Разработан REST API с тремя методами, базой SQLite и аутентификацией JWT.
  SQL-инъекции предотвращаются параметризованными запросами. Строки заметок
  экранируются при возврате; пароли хранятся в виде соленых scrypt-хэшей.
  Доступ к заметкам ограничен их владельцем.
]
#para[
  Штатное поведение и негативные сценарии подтверждены автоматическими
  тестами (#ci.tests_passed из #ci.tests_total) и #http.passed запросами curl.
  В CI включены статический анализ
  и проверка зависимостей через npm audit и OWASP Dependency-Check.
  Обнаруженная уязвимая dev-зависимость обновлена; результаты представлены
  реальными журналами, отчетами и скриншотами GitHub Actions.
]
#para[
  Учебный стенд рассчитан на один локальный процесс. Развертывание в интернете
  потребовало бы HTTPS, распределенного ограничения запросов и политики
  отзыва токенов. Нулевой результат сканирования отражает известные сканерам
  проблемы на дату проверки, а не абсолютную гарантию безопасности.
]

#pagebreak()
#structural[СПИСОК ИСПОЛЬЗОВАННЫХ ИСТОЧНИКОВ]
#src(1, [OWASP. SQL Injection Prevention Cheat Sheet], "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")
#src(2, [OWASP. Cross Site Scripting Prevention Cheat Sheet], "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")
#src(3, [OWASP. Password Storage Cheat Sheet], "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html")
#src(4, [OWASP Dependency-Check. Mirroring External Resources], "https://dependency-check.github.io/DependencyCheck/data/mirrornvd.html")
#src(5, [GitHub Advisory Database. GHSA-g3hv-75wg-m249], "https://github.com/advisories/GHSA-g3hv-75wg-m249")
#src(6, [Node.js. SQLite API], "https://nodejs.org/docs/latest-v24.x/api/sqlite.html")
#src(7, [jose. Документация и исходный код], "https://github.com/panva/jose")
#src(8, [GitHub Docs. Workflow syntax for GitHub Actions], "https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax")
#src(9, [Исходный код лабораторной работы], repo)

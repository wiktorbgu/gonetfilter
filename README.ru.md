# GoNetFilter

[English](README.md) | [Русский](README.ru.md)

**Компактные Go-фронтенды для Linux Netfilter: `iptables-legacy`, `ip6tables-legacy` и нативного `nftables`.**

GoNetFilter предназначен для контейнеров MikroTik RouterOS и других ограниченных Linux/router-сред, где ядро предоставляет необходимые API Netfilter, но устанавливать полный набор пользовательских firewall-пакетов нежелательно.

В RouterOS доступные firewall-утилиты зависят от архитектуры устройства: в 64-битных версиях для ARM64 и AMD64 доступны `nft` и `iptables`, а на ARM32-устройствах (ARMv7 и ARMv5) используется legacy-интерфейс `iptables`. GoNetFilter реализует компактные фронтенды `iptables-legacy` / `ip6tables-legacy` для таких legacy-сред, а также нативный фронтенд `nft`.

Проект полезен рядом с сетевыми и VPN-приложениями, такими как **Mihomo, Xray, sing-box, WireGuard/AmneziaWG и другие сетевые утилиты**, когда им нужны базовые правила файервола без установки полноценной пользовательской среды. Для ARMv5 Alpine Linux недоступен, а Debian-среда может быть непропорционально объёмной; на других поддерживаемых архитектурах место всё равно занимают сама ОС и её firewall-пакеты. Это особенно важно на роутерах с небольшим внутренним хранилищем, куда нельзя удобно подключить внешнюю память через USB. GoNetFilter предоставляет самостоятельные утилиты вместо таких пакетов. Проект сжимает бинарники, поскольку утилиты обычно запускаются ненадолго для настройки правил файервола, а не работают как постоянно запущенный сервис; поэтому уменьшение занимаемого места полезно. GoNetFilter использует API Netfilter, таблицы, цели и выражения, поддерживаемые ядром хоста; он не заменяет поддержку со стороны ядра и не настраивает перечисленные приложения автоматически.

Проект собирает отдельные CLI-утилиты и объединённый бинарник `gonetfilter` в стиле BusyBox. Оба бэкенда напрямую взаимодействуют с ядром; ни один из них не запускает системные `iptables` или `nft` как дочерний процесс.

> **Статус проекта:** GoNetFilter реализует ограниченный набор форм команд для целевых сценариев. Это не полная замена upstream-утилит `iptables(8)` или `nft(8)`. Перед развёртыванием проверяйте работу на конкретном целевом ядре.

## Возможности

### `iptables` — IPv4 iptables-legacy

Фронтенд `iptables` использует legacy ABI x_tables через сокеты (`getsockopt` / `setsockopt`), а не `iptables-nft`.

Текущий компактный набор команд включает создание пользовательских цепочек, добавление правил в конец и вставку по позиции в встроенные и пользовательские цепочки (`-I CHAIN [RULENUM]`, по умолчанию позиция 1), стандартные переходы/вердикты цепочек и формы правил, используемые в настройке перенаправления Mihomo:

```sh
iptables -t nat -N mihomo-output
iptables -t nat -I OUTPUT -j mihomo-output
iptables -t nat -A OUTPUT -p tcp -j mihomo-output
iptables -t nat -A mihomo-output -o "$TUN_IFACE" -p tcp -j REDIRECT --to-ports 33643

iptables -t nat -N mihomo-prerouting
iptables -t nat -A PREROUTING -j mihomo-prerouting
iptables -t nat -A mihomo-prerouting -p udp -m udp --dport 53 -j DNAT --to 198.19.0.2
iptables -t nat -A mihomo-prerouting -m addrtype --dst-type LOCAL -j RETURN
iptables -t nat -A mihomo-prerouting -p tcp -j REDIRECT --to-ports 33643

iptables -t filter -N mihomo-input
iptables -t filter -A INPUT -i "$TUN_IFACE" -j mihomo-input
iptables -t filter -A mihomo-input -i "$TUN_IFACE" -j ACCEPT
```

Поддерживаются таблицы IPv4 `filter`, `nat`, `mangle` и `raw` (в `raw` доступны поддерживаемые ядром хуки `PREROUTING` и `OUTPUT`). Если `-t` не указан, просмотр по умолчанию выполняется для таблицы `filter`; поддерживаются `-L`, `-S`, `-v`, `-n` и `--line-numbers`. Реализованный набор операций включает `-N`, `-A`, `-I`, `-L`, `-S`, `REDIRECT`, IPv4 `DNAT` (`--to` и `--to-destination`), `MASQUERADE`, `MARK`, `ACCEPT`, `RETURN`, `DROP`, переходы в пользовательские цепочки, сопоставление UDP-порта назначения, `addrtype --dst-type LOCAL` и точные имена интерфейсов `-i`/`-o`. IPv6-фронтенд — отдельный legacy-бэкенд x_tables со своим ABI и диспетчером. Просмотр и декодирование правил намеренно ограничены и не являются универсальным декодером произвольных match- и target-расширений.

Legacy-бэкенд читает текущую таблицу, вставляет или добавляет правила в указанную позицию цепочки, корректирует смещения hook/underflow и переходов, а затем отправляет полную замену таблицы. При таком чтении/изменении/замене возможна гонка с другими писателями. Не изменяйте одну legacy-таблицу одновременно из нескольких процессов.

### `ip6tables` — IPv6 iptables-legacy

IPv6-фронтенд использует отдельный ABI x_tables `AF_INET6` / `SOL_IPV6` и собственную структуру `ip6t_entry`; он не перенаправляет IPv6-команды в IPv4-бэкенд. Он реализует тот же ограниченный путь управления правилами для IPv6-правил Mihomo: просмотр таблиц `filter`, `nat`, `mangle` и `raw`, пользовательские цепочки, добавление/вставку правил, переходы между цепочками, сопоставление UDP-порта назначения, `REDIRECT`, IPv6 `DNAT`, `ACCEPT`, `RETURN` и `addrtype --dst-type LOCAL`. Это не полная замена ip6tables. Перед развёртыванием проверьте работу на целевом ядре.

Примеры форм IPv6 NAT-правил:

```sh
ip6tables -t nat -A mihomo-prerouting -p udp -m udp --dport 53 -j DNAT --to-destination fdfe:dcba:9876::2
ip6tables -t nat -A mihomo-output -o "$TUN_IFACE" -p tcp -j REDIRECT --to-ports 40707
```

### `nft` — нативный nftables через Netlink

Фронтенд `nft` использует `NETLINK_NETFILTER` через `github.com/google/nftables`. Реализованный набор включает формы команд и выражений для целевых сценариев проекта, в том числе:

- семейства `ip`, `ip6` и `inet`;
- таблицы и base-chain с поддерживаемыми типами, hook, приоритетами и политиками;
- `meta l4proto`, `meta mark`, `meta oiftype` и `iifname`;
- IPv4-совпадения по адресу назначения и исключения CIDR;
- `masquerade`, `redirect` и IPv4/IPv6 `tproxy`;
- `socket transparent`, FIB-поиск типа адреса;
- сопоставление TCP MPTCP option и базовые verdict;
- именованные kernel sets для поддерживаемых протокольных и FIB-поисков.

Примеры команд:

```sh
nft add table ip nat
nft add chain ip nat prerouting '{ type nat hook prerouting priority dstnat; }'
nft add rule ip nat prerouting meta l4proto tcp redirect to :4080

nft add table ip mangle
nft add chain ip mangle prerouting '{ type filter hook prerouting priority mangle; }'
nft add rule ip mangle prerouting iifname eth0 meta l4proto udp meta mark set 110
nft add rule ip mangle prerouting udp dport 443 drop

nft list ruleset
nft --help
```

`nft list ruleset` — средство просмотра для поддерживаемого подмножества выражений, а не полная реализация синтаксиса или форматирования upstream nft. Нельзя считать, что неизвестные типы выражений были корректно интерпретированы.

#### Проверка чтения ruleset

Вывод GoNetFilter сравнивался с системной командой `nft list ruleset` в Alpine-контейнере для ruleset с NAT masquerade и IPv4 CIDR-исключениями, `meta oiftype ether`, `socket transparent`, packet marks, FIB address types, MPTCP option match и IPv4/IPv6 TPROXY. Для этого тестового ruleset вывод совпал.

Это результат для проверенного ruleset и ядра, а не утверждение о полной совместимости nftables со всеми выражениями или версиями ядра.

### Объединённый бинарник

Объединённый исполняемый файл выбирает утилиту по `argv[0]` при запуске через символические ссылки либо по явно указанной подкоманде:

```sh
gonetfilter iptables -t nat -L
gonetfilter nft list ruleset
```

Установка объединённого бинарника и ссылок-алиасов:

```sh
install -m 0755 gonetfilter /usr/sbin/gonetfilter
ln -sf gonetfilter /usr/sbin/iptables
ln -sf gonetfilter /usr/sbin/iptables-legacy
ln -sf gonetfilter /usr/sbin/ip6tables
ln -sf gonetfilter /usr/sbin/ip6tables-legacy
ln -sf gonetfilter /usr/sbin/nft
```

Запуск `nft` без аргументов показывает краткую справку из двух строк; `nft --help` выводит поддерживаемое подмножество команд и примеры.

## Сборка

### Локальная сборка

Требуется Go 1.27 (или версия, указанная в toolchain проекта). Для первой сборки нужен доступ к Go module proxy, чтобы загрузить внешние зависимости. Объединённый бинарник `gonetfilter` показывает версию сборки; если она не задана, выводится `dev`.

```sh
go test ./...
(cd third_party/nftables && go test ./expr)
./scripts/build.sh all all
VERSION=1.2.3 ./scripts/build.sh unified armv7
```

Режимы сборки:

```sh
./scripts/build.sh unified armv7    # объединённый бинарник и ссылки-алиасы
./scripts/build.sh separate armv7   # отдельные бинарники iptables и nft
./scripts/build.sh all armv7        # оба варианта сборки
```

По умолчанию `./scripts/build.sh all all` собирает цели amd64, arm64, ARMv5 и ARMv7. Результаты помещаются в `dist/`. Задайте `VERSION`, чтобы выбрать строку версии в объединённом бинарнике; если переменная не задана, используется `dev`. Версия отображается при запуске `gonetfilter` без аргументов. Отдельные фронтенды `iptables`, `ip6tables` и `nft` версию проекта не показывают. Для релиза с тегом создайте Git-тег отдельно (например, `git tag v1.2.3`) и соберите с `VERSION=1.2.3`; установка `VERSION` не создаёт и не отправляет тег.

### Docker / BuildKit

Устанавливать Go на хосте не требуется. Dockerfile использует Go 1.27 Alpine, запускает тесты, собирает объединённый бинарник для четырёх архитектур, сжимает каждый бинарник через UPX `--best --lzma` и проверяет его командой `upx -t`. Build argument `VERSION` задаёт версию, отображаемую основной командой `gonetfilter` (по умолчанию `dev`).

```sh
docker buildx build --no-cache --build-arg VERSION=1.2.3 --output type=local,dest=./dist .
```

Создаются файлы:

```text
dist/
├── gonetfilter-amd64
├── gonetfilter-arm64
├── gonetfilter-armv5
└── gonetfilter-armv7
```

Среде Docker-сборки нужен доступ к Go module proxy для загрузки внешних зависимостей. `VERSION` встраивается в баннер объединённого `gonetfilter`; на баннеры отдельных фронтендов она не влияет.

### Ручная сборка одного бинарника

Задайте `VERSION`, чтобы выбрать строку версии в объединённом бинарнике; по умолчанию используется `dev`.

```sh
VERSION=1.2.3
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o gonetfilter ./cmd/gonetfilter
```

## Зависимость nftables и локальный патч

Проект использует `github.com/google/nftables` версии `v0.3.0`. Небольшой локальный патч нужен, чтобы upstream-декодер выражений восстанавливал `socket` и `tproxy` при чтении правил из ядра. Исходный код пропатченного модуля хранится в `third_party/nftables`, а корневой `go.mod` использует локальную директиву `replace` для выбора этой копии.

Так патч остаётся доступным для проверки и воспроизводимым без отдельного форка. Вложенный модуль сохраняет собственные `go.mod`, `go.sum` и upstream `LICENSE`. Источник и точное содержимое патча описаны в [`third_party/nftables/PATCHES.md`](third_party/nftables/PATCHES.md) ([Русский](third_party/nftables/PATCHES.ru.md)).

При обновлении зависимости перенесите патч, запустите тесты декодера и корневого модуля, выполните cross-build для целевых архитектур, затем повторите сравнение runtime-чтения с системной утилитой `nft`.

## Требования во время работы

GoNetFilter не выдаёт себе права на изменение файервола и не меняет настройки доступа контейнера RouterOS. Он может использовать только те интерфейсы Netfilter и разрешения, которые предоставляет хост. Ядро должно поддерживать нужный бэкенд, таблицы, цели и выражения; пользовательский бинарник не добавляет отсутствующие модули и не включает недоступные функции ядра. Проверьте режим доступа и поддержку файервола для целевой версии RouterOS/устройства и протестируйте изменения до применения на рабочем роутере.

Для legacy-бэкенда ядро должно предоставлять соответствующий x_tables API и поддержку нужных таблиц/расширений. Для nftables требуется нативная поддержка nftables через Netlink и выражений, используемых в ruleset.

## Структура проекта

```text
cmd/
├── gonetfilter/     # объединённый диспетчер в стиле BusyBox
├── iptables/        # отдельная точка входа IPv4 iptables-legacy
├── ip6tables/       # отдельная точка входа IPv6 ip6tables-legacy
└── nft/             # отдельная точка входа nft-фронтенда
internal/
├── iptables/        # IPv4 legacy x_tables-бэкенд и тесты
├── ip6tables/       # IPv6 legacy x_tables-бэкенд и тесты
└── nft/             # nftables Netlink-фронтенд, builder, readback и тесты
third_party/
└── nftables/        # локально пропатченный модуль google/nftables v0.3.0
scripts/             # скрипт cross-build
Dockerfile           # Docker/BuildKit multi-architecture сборка и UPX-сжатие
docs/                # архитектура и руководство по тестированию на устройстве
```

## Принципы разработки

1. Держите legacy x_tables и native nftables-бэкенды независимыми.
2. Добавляйте regression-тесты для каждой поддерживаемой формы команды и декодируемого выражения.
3. Не запускайте внешние firewall-бинарники из GoNetFilter.
4. Проверяйте размер бинарника, архитектуру, endianness и ABI на целевых устройствах.
5. Не скрывайте и не переписывайте молча выражения, которые не удалось распознать.
6. Сравнивайте чтение nft с системной утилитой `nft` и проверяйте значения, декодированные из kernel Netlink, а не только текстовый вывод.
7. Сравнивайте чтение legacy `iptables` / `ip6tables` с системными утилитами и проверяйте значения, декодированные из ABI x_tables ядра, а не только текстовый вывод.

## Тестирование на устройстве

См. [чек-лист тестирования на устройстве](docs/TESTING.ru.md) ([English](docs/TESTING.md)). Как минимум сравните вывод обеих nft-утилит для одного и того же набора правил:

```sh
nft list ruleset
./nft list ruleset
```

Сохраните оба вывода, версию ядра, архитектуру, точные команды создания правил и код завершения. Для legacy `iptables`/`ip6tables` сравните каждую реализованную таблицу с соответствующей системной legacy-утилитой, если она доступна. Для изменений правил проверяйте состояние ядра и поведение пакетов; успешный возврат CLI сам по себе не доказывает, что правило работает как задумано.

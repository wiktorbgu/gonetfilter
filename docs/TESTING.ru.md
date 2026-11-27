# Чек-лист тестирования на устройстве

[English](TESTING.md) | [Русский](TESTING.ru.md)

Этот чек-лист предназначен для проверки GoNetFilter в контейнерах MikroTik RouterOS и других Linux-контейнерах на роутерах. Ядро и параметры контейнера являются частью тестовой среды; успешная компиляция сама по себе не подтверждает совместимость во время выполнения.

## Перед тестированием

Зафиксируйте:

- модель роутера и версию RouterOS;
- образ контейнера/базовую систему и архитектуру userspace;
- вывод `uname -a` и версию/сборку ядра;
- архитектуру CPU (`amd64`, `arm64` или 32-битный ARM/EABI);
- доступный backend: legacy x_tables или nftables;
- наличие `CAP_NET_ADMIN` у контейнера и использование нужного network namespace.

Не делайте вывод о наличии функций Netfilter только по архитектуре userspace или версии ядра.

## Проверка legacy iptables для IPv4 и IPv6

Команды ниже только читают состояние и позволяют проверить все реализованные legacy-таблицы обеих адресных семейств:

```sh
./iptables -t filter -L -n -v --line-numbers
./iptables -t nat -L -n -v --line-numbers
./iptables -t mangle -L -n -v --line-numbers
./iptables -t raw -L -n -v --line-numbers
./iptables -t filter -S
./iptables -t nat -S
./iptables -t mangle -S
./iptables -t raw -S

./ip6tables -t filter -L -n -v --line-numbers
./ip6tables -t nat -L -n -v --line-numbers
./ip6tables -t mangle -L -n -v --line-numbers
./ip6tables -t raw -L -n -v --line-numbers
./ip6tables -t filter -S
./ip6tables -t nat -S
./ip6tables -t mangle -S
./ip6tables -t raw -S
```

Для проверки поддерживаемых форм правил сравните вывод GoNetFilter с системными legacy-утилитами на одном и том же состоянии ядра. `iptables` и `ip6tables` — отдельные реализации IPv4 и IPv6, проверяйте их независимо. Следующие примеры изменяют активный firewall; выполняйте их только в одноразовом тестовом окружении или в безопасное окно обслуживания.

```sh
./iptables -t nat -A PREROUTING -i br-lan -p tcp -j REDIRECT --to-port 4080
./iptables -t nat -A POSTROUTING -j MASQUERADE
./iptables -t mangle -A PREROUTING -p udp -j MARK --set-mark 110
./iptables -t mangle -A PREROUTING -p udp --dport 443 -j DROP

./iptables -t nat -S
./iptables -t mangle -S
./iptables -t raw -S
```

Замените `br-lan`, порты и mark на значения тестовой конфигурации. При наличии системной утилиты `iptables` её можно использовать как независимый инструмент проверки; GoNetFilter сам её не запускает.

### Короткий тест совместимости перенаправления Mihomo

Выполняйте только в одноразовом тестовом контейнере: команды изменяют активный IPv4 firewall.

```sh
iptables -t nat -N mihomo-output
iptables -t nat -I OUTPUT -j mihomo-output
iptables -t nat -A OUTPUT -p tcp -j mihomo-output
iptables -t nat -A mihomo-output -o Meta -p tcp -j REDIRECT --to-ports 33643
iptables -t nat -N mihomo-prerouting
iptables -t nat -A PREROUTING -j mihomo-prerouting
iptables -t nat -A mihomo-prerouting -p udp -m udp --dport 53 -j DNAT --to 198.19.0.2
iptables -t nat -A mihomo-prerouting -m addrtype --dst-type LOCAL -j RETURN
iptables -t nat -A mihomo-prerouting -p tcp -j REDIRECT --to-ports 33643
iptables -t filter -N mihomo-input
iptables -t filter -A INPUT -i Meta -j mihomo-input
iptables -t filter -A mihomo-input -i Meta -j ACCEPT
iptables -t nat -L -n -v
iptables -t nat -S
iptables -t filter -L -n -v
```

Тест с `-I` проверяет вставку в позицию 1 (по умолчанию) перед существующими правилами OUTPUT. Можно указать номер явно, например `-I OUTPUT 2 ...`. Вызов `iptables -L` без параметров показывает таблицу `filter`. Для диагностики ABI/readback выполните `./iptables --debug-dump nat`: команда выводит смещения записей и сырые байты match/target, помогая разбирать совместимость с правилами, установленными другими реализациями iptables.

IPv4 и IPv6 используют отдельные x_tables ABI. На целевом ядре сравните `iptables -t nat -L -n -v` и `ip6tables -t nat -L -n -v` с системными legacy-утилитами, затем проверьте поддерживаемые операции правил Mihomo в одноразовом контейнере. Путь IPv6 ABI/readback покрыт unit-тестами, но всё ещё требует runtime-проверки на целевом ARM32-ядре.

Важно: обновление legacy-таблицы выполняется через чтение/изменение/полную замену. Во время теста не запускайте несколько процессов, одновременно изменяющих одну таблицу. После каждой вставки проверяйте сохранность существующих правил и корректность счётчиков.

## Сравнение чтения iptables с системными утилитами

После установки тестовых правил через GoNetFilter снимите состояние тех же таблиц системными legacy-утилитами (если они доступны) и GoNetFilter. Например:

```sh
iptables -t nat -L -n -v --line-numbers
./iptables -t nat -L -n -v --line-numbers
iptables -t nat -S
./iptables -t nat -S

ip6tables -t nat -L -n -v --line-numbers
./ip6tables -t nat -L -n -v --line-numbers
ip6tables -t nat -S
./ip6tables -t nat -S
```

Повторите сравнение для `filter`, `mangle` и `raw`, а также для каждой таблицы, доступной на целевом ядре. Сравнивайте порядок цепочек и правил, аргументы match/target, счётчики (где применимо) и сохранность ранее существовавших правил. Если системной legacy-утилиты нет, сохраните вывод GoNetFilter и проверьте состояние ядра другим независимым способом, доступным на устройстве.

## Проверка nftables

Выполняйте тест только если ядро предоставляет native nftables. Создайте отдельную тестовую таблицу, чтобы не менять посторонние правила.

```sh
./nft add table ip gonetfilter_test
./nft add chain ip gonetfilter_test prerouting '{ type nat hook prerouting priority dstnat; }'
./nft add rule ip gonetfilter_test prerouting meta l4proto tcp redirect to :4080
./nft list ruleset
```

Текущий CLI поддерживает ограниченный набор выражений и конфигураций цепочек. Сравните его вывод и установленные в ядре правила с системной командой `nft`, если она доступна.

Удаляйте тестовые таблицы с помощью эталонной системной утилиты или отдельной реализации очистки после появления поддержки удаления; текущий GoNetFilter nft CLI пока не реализует удаление таблиц.

## Проверка на разных архитектурах

Для 32-битного ARM обратите особое внимание на `IPT_SO_SET_REPLACE`: blob записи в `struct ipt_replace` начинается со смещения, выровненного по 8 байтам, даже если заголовок Go с указателями занимает только 92 байта. Реализация выравнивает это смещение до 96 байт. Запустите ABI layout-тесты и проверьте вставку правил на реальном ARMv5/ARMv7-ядре.

Для каждого целевого бинарника:

```sh
file ./iptables
file ./nft
```

Затем выполните `--version` / `--help` на целевом устройстве. Проверьте размеры через `ls -lh` и запишите их вместе с build commit.

## Отчёт о результатах

Для каждой команды зафиксируйте:

- точную команду и код завершения;
- stdout/stderr;
- просмотр ruleset до и после;
- сохранность ранее существовавших правил;
- поведение пакетов, а не только успешный возврат команды;
- архитектуру бинарника и размер файла.

Не заявляйте поддержку функции на семействе роутеров, пока она не прошла runtime-тестирование на соответствующей сборке ядра.

## Сравнение чтения nftables (проверенный набор правил)

Для текущего поддерживаемого пути чтения правил transparent proxy сравните вывод эталонного `nft` и GoNetFilter на одном и том же наборе правил ядра:

```sh
nft list ruleset
./nft list ruleset
```

Регрессионный набор, использованный при разработке, включает:

- `ip nat` postrouting с `meta oiftype ether`, IPv4-исключениями назначения (`127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4` и `255.255.255.255`) и `masquerade`;
- цепочку `inet divert` с `meta l4proto tcp`, `socket transparent 1`, `meta mark set 0x00000123` и `accept`;
- цепочку `inet prerouting` с FIB-типами адресов (`local`, `broadcast`, `multicast`), TCP MPTCP option match, групповой проверкой TCP/UDP-протоколов и IPv4/IPv6 TPROXY-назначениями.

Для этого конкретного набора вывод GoNetFilter сравнивался с эталонным `nft` и совпал в проверенном Alpine-контейнере/ядре. Это результат узкой проверки совместимости, а не утверждение о поддержке всех выражений nftables, типов наборов, версий ядра или синтаксиса CLI.

При повторении теста сохраните оба вывода и проверьте как минимум:

- `meta oiftype ether` (не неизвестное значение и не raw compare);
- четыре IPv4-исключения, при этом одиночный host-адрес отображается без `/32`;
- mark `0x00000123` без перестановки байтов;
- FIB-метки в каноническом порядке;
- `socket transparent 1`;
- семейство, адрес, порт и verdict TPROXY для IPv4 и IPv6.

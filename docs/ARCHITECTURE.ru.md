# Архитектура

[English](ARCHITECTURE.md) | [Русский](ARCHITECTURE.ru.md)

- `internal/iptables`: компактная IPv4-реализация iptables-legacy через вызовы ABI x_tables `AF_INET`.
- `internal/ip6tables`: отдельная IPv6-реализация ip6tables-legacy через `AF_INET6` / `SOL_IPV6` и ABI-структуру `ip6t_entry`.
- `internal/nft`: компактная реализация nftables через `NETLINK_NETFILTER` и `github.com/google/nftables`.
- `cmd/iptables`, `cmd/ip6tables` и `cmd/nft`: тонкие точки входа отдельных CLI-утилит.
- `cmd/gonetfilter`: объединённый диспетчер в стиле BusyBox.
- `third_party/nftables`: локальная замена `github.com/google/nftables v0.3.0` с патчем декодера, описанным в `third_party/nftables/PATCHES.md`.

Объединённый бинарник выбирает режим по имени запуска (`argv[0]`): `iptables`, `iptables-legacy`, `ip6tables`, `ip6tables-legacy`, `nft` или `nftables`. При запуске как `gonetfilter` принимает явную подкоманду `iptables`, `ip6tables` или `nft`.

Объединённый бинарник использует один Go runtime. Символические ссылки не дублируют исполняемый файл на диске. В объединённый бинарник входят оба фронтенда, поэтому он не обязательно меньше каждого отдельного бинарника; сравнивайте его размер с суммой размеров отдельных бинарников.

Ни один фронтенд не запускает системные исполняемые файлы `iptables` или `nft`.

## Путь чтения nftables

`internal/nft` читает таблицы, цепочки, наборы, элементы наборов и правила из ядра через Netlink. Поддерживаемые обращения к именованным наборам разрешаются для протокольных и FIB-наборов; элементы IPv4 interval-set восстанавливаются в канонические CIDR-диапазоны для поддерживаемой формы исключений NAT. Форматирование правил обрабатывает поддерживаемые выражения `meta`, `fib`, `socket`, `tproxy`, TCP option, NAT и verdict.

Локальный патч `google/nftables` необходим, поскольку в v0.3.0 upstream-декодер выражений не регистрировал `socket` и `tproxy`. Без регистрации эти выражения могут теряться при декодировании правил, полученных из ядра. Точные изменения описаны в `third_party/nftables/PATCHES.md`.

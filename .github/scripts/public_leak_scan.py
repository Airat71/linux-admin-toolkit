#!/usr/bin/env python3
"""Проверка репо перед публикацией (ADR-063): запрещённые слова из _shared/public-deny-list.txt в файлах, истории, сообщениях и именах.

Запуск: python3 _shared/scripts/public_leak_scan.py РЕПО [--history | --push ЛОКАЛЬНЫЙ УДАЛЁННЫЙ [--push ...] [--ref ИМЯ]...] [--list ФАЙЛ] [--allow ФАЙЛ] [--known ФАЙЛ] [--paths]
  по умолчанию проверяются отслеживаемые git файлы рабочей копии и их имена; --history добавляет всю историю.
  --push (можно несколько раз, один вызов на весь push): то, что уходит при push. Для ветки, которая уже есть на удалённом репо и чей sha там известен
  локально, УДАЛЁННЫЙ..ЛОКАЛЬНЫЙ; для новой ветки (нулевой УДАЛЁННЫЙ) вся история, достижимая из ЛОКАЛЬНЫЙ: локальным
  refs/remotes/* не доверяем, их можно подделать сменой адреса origin. --ref: имена пушимых веток и тегов. Вызывается хуком pre-push (ADR-063).
  --allow: файл исключений, по умолчанию _shared/public-scan-allow.tsv рядом со списком: «репо<TAB>имя<TAB>маска<TAB>причина». Маска сопоставляется
  с путём файла, а для не файлов с условным путём: <коммит> (сообщение и заголовки коммита), <ссылка> (имя ветки или тега), <тег> (аннотированный тег).
  Исключения лежат в приватной мете, а не в публичном репо: файл исключений рядом с кодом проверяемого репо сам снимал бы проверку.
  --known: уже принятые находки истории (по умолчанию _shared/public-scan-known.tsv рядом со списком): «репо<TAB>имя<TAB>коммит<TAB>причина»;
  они печатаются как KNOWN и не дают код 1.
  --ci: серверный режим (проверка в публичном репо на GitHub): в вывод идут только номер правила, категория находки и короткий sha коммита; слова, пути и
  совпадения не печатаются: журнал Actions публичен, а документация GitHub не обещает скрывать в нём производные части секрета.
  --paths: вместо отчёта печатать пути файлов с находками error, каждый завершён нулевым байтом (имя файла может содержать перевод строки): для выгрузки data room.
Что проверяется: содержимое каждого изменённого файла целиком (не текстовый diff: у merge-коммитов, файлов с атрибутом -diff и бинарных по мнению git
он пуст) и внутри архивов zip, gzip, tar (docx это zip), в UTF-8, UTF-16, UTF-32, cp1251, cp866, KOI8-R и без нулевых байтов; сырой объект каждого
коммита (сообщение в любой кодировке, автор, коммиттер, дополнительные заголовки), имена файлов, веток и тегов, объекты аннотированных тегов, в том
числе вложенных. Подмена объектов (git replace) не учитывается. Двоичные данные сжимаются до печатных отрезков от 4 знаков (5 МБ случайных байтов
сканируются за секунду); сумма содержимого одного архива не больше 200 МБ, файл больше 50 МБ это находка size-limit. Перед сравнением текст приводится к виду NFKC без невидимых символов и знаков
комбинирования, плюс вариант с заменой кириллических и греческих двойников латиницей.
Не проверяется (граница метода): base64 и другие кодирования (HTML, \\u, %xx, hex, rot13), слова с пробелами между буквами или разбитые строкой, leet
(T4lisman), рисунки (текст на картинке); в сжатых двоичных данных короткое слово из четырёх букв выпадает случайно примерно раз на 250 МБ,
такое место снимается исключением по пути с причиной. Это защита от случайной утечки, не от намеренного обхода: список слов защитить от обхода не может.
Код 0: находок уровня error нет. Код 1: есть error, не снятые исключением. Код 2: проверку выполнить не удалось (нет или пуст список слов, ошибка git);
хук считает любой код, кроме 0, блокировкой. Находки warn выводятся и код не меняют: решает человек.
Список запретов лежит только в приватной мете: в публичные репо, их CI и README его не копировать.
"""
import bz2
import fnmatch
import io
import lzma
import os
import re
import subprocess
import sys
import tarfile
import unicodedata
import zipfile
import zlib
from pathlib import Path

DEFAULT_LIST = Path(__file__).resolve().parents[1] / "public-deny-list.txt"
ZERO = "0" * 40
MAX_BYTES = 50_000_000  # больше: находка size-limit уровня error (не проверено, значит не пропускаем); снимается исключением
MAX_ARCHIVE_DEPTH = 2
MAX_ARCHIVE_TOTAL = 200_000_000  # сумма содержимого всех участников архива в одном файле: защита от «бомбы»; больше: находка size-limit
MAX_ARCHIVE_MEMBERS = 2000
LINES_PER_RULE = 3  # сколько совпадений одного файла показывать по одному правилу
HOMOGLYPHS = str.maketrans(
    {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "к": "k", "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ӏ": "l",
     "м": "m", "т": "t", "н": "h", "в": "b", "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "χ": "x", "υ": "u",
     "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y", "К": "K", "І": "I", "Ѕ": "S", "Ј": "J", "М": "M", "Т": "T",
     "Н": "H", "В": "B", "Α": "A", "Ε": "E", "Ο": "O", "Ρ": "P", "Ν": "N", "Τ": "T", "Ι": "I", "Κ": "K", "Χ": "X"})
INVISIBLE_LETTERS = {"ㅤ", "ᅟ", "ᅠ", "ﾠ"}  # буквы хангыля без видимого начертания: категория Lo, а не Cf
CP_ALL_MAX = 8_000_000  # крупнее: из однобайтных кодировок только cp1251 (cp866 и KOI8-R дают такой же «печатный» текст из любых байтов)
FOLD_FROM = 1_000_000  # знаков: в тексте крупнее свёртка NFKD идёт только если есть знаки из блоков, которые она меняет
FOLD_TRIGGER = re.compile("[\u00ad\u00c0-\u036f\u0370-\u03ff\u1100-\u11ff\u1e00-\u1fff\u200b-\u200f\u202a-\u202e\u2060-\u206f\u2100-\u214f\u2460-\u24ff"
                          "\u3000-\u303f\u3160-\u318f\ufb00-\ufb4f\ufe00-\ufe0f\ufeff\uff00-\uffef\U0001d400-\U0001d7ff]")
LATIN = re.compile("[A-Za-z]")
MIXED_SCRIPT = re.compile("\\b(?=\\w{1,64}\\b)\\w*(?:[A-Za-z]\\w*[\u0370-\u04ff]|[\u0370-\u04ff]\\w*[A-Za-z])\\w*")  # слово (до 64 знаков: на длинных отрезках без границ слова выражение было бы квадратичным) со смесью латиницы и кириллицы или греческого
CP_WITH_NUL_MAX = 4_000_000  # крупный двоичный файл в cp1251 не разбираем: любые байты там «печатный» текст, разбор занимал бы десятки секунд
OTHER_CODECS = ("cp1251", "cp866", "koi8-r")
GIT_ENV = {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"}  # git replace подменяет объекты локально, а push отправляет оригиналы
SHORT = 7
PRINTABLE_RUN = re.compile("[^\ufffd\x00-\x08\x0b\x0c\x0e-\x1f]{4,}")  # печатные отрезки от 4 знаков (как утилита strings): самое короткое запретное слово 4 знака
SQUEEZE_FROM = 65_536  # короче не сжимаем: номера строк в обычных файлах остаются точными
CHUNK = 4_000_000  # знаков в куске при разборе большого текста
CHUNK_OVERLAP = 256  # нахлёст кусков: слово на стыке не теряется
CI_CATEGORIES = ("имя ветки или тега", "аннотированный тег", "заголовки коммита", "сообщение", "изменение", "имя файла")  # режим --ci печатает только эти слова
CI_WITH_COMMIT = ("заголовки коммита", "сообщение", "изменение", "имя файла")
PSEUDO_COMMIT, PSEUDO_REF, PSEUDO_TAG = "<коммит>", "<ссылка>", "<тег>"
Rule = tuple[str, str, re.Pattern[str]]


class ScanError(Exception):
    """Проверку выполнить нельзя: код 2, хук блокирует push."""


def load_rules(path: Path) -> list[Rule]:
    if not path.is_file():
        raise ScanError(f"нет списка запретных слов: {path}")
    rules: list[Rule] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split("\t", 2)
        if len(parts) != 3 or parts[0] not in ("error", "warn"):
            raise ScanError(f"{path}:{number}: ожидается «error|warn<TAB>имя<TAB>выражение»")
        try:
            rules.append((parts[0], parts[1], re.compile(parts[2], re.IGNORECASE)))
        except re.error as exc:
            raise ScanError(f"{path}:{number}: выражение не компилируется: {exc}") from exc
    if not any(level == "error" for level, _, _ in rules):
        raise ScanError(f"в {path} нет ни одного правила уровня error: пустой список ничего не проверяет")
    return rules


def load_allow(path: Path, repo_name: str) -> list[tuple[str, str]]:
    if not path.is_file():
        return []
    entries = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        parts = raw.split("\t")
        if raw.startswith("#") or len(parts) < 4 or not parts[3].strip():
            continue  # без причины исключение не действует: причина нужна для разбора
        if parts[0] == repo_name:
            entries.append((parts[1], parts[2]))
    return entries


def allowed(name: str, where: str, allow: list[tuple[str, str]]) -> bool:
    return any(n == name and fnmatch.fnmatch(where, mask) for n, mask in allow)


def git(repo: Path, *args: str, check: bool = True, raw: bool = False):
    done = subprocess.run(["git", "-C", str(repo), "-c", "core.quotePath=false", *args], capture_output=True, env=GIT_ENV)
    if check and done.returncode != 0:
        raise ScanError(f"git {' '.join(args[:3])}: {done.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return done.stdout if raw else done.stdout.decode("utf-8", "replace")


def squeeze(text: str) -> str:
    """Большой текст, в который декодировались двоичные данные (картинка, архив, исполняемый файл), сводится к печатным отрезкам: иначе поиск идёт по
    миллионам бессмысленных знаков (5 МБ случайных байтов занимали 7 секунд). Обычный текст почти не сжимается и остаётся как есть."""
    if len(text) < SQUEEZE_FROM:
        return text
    joined = "\n".join(PRINTABLE_RUN.findall(text))
    return joined if len(joined) * 10 < len(text) * 7 else text


def decode_variants(data: bytes):
    """Тексты, в которые можно прочитать байты, по одному (генератор: рядом живёт один текст, а не шесть копий 50 МБ): UTF-8, без нулевых байтов, UTF-16 и
    UTF-32 (с меткой порядка байтов и без, по признакам), однобайтные русские кодировки. Двоичные файлы не пропускаются: слово в метаданных рисунка или в
    строке исполняемого файла тоже утечка. UTF-16 и UTF-32 без метки берутся только когда байты на них похожи (нулевые байты на одной чётности, старшие
    байты 0x04 кириллицы): иначе крупный двоичный файл разбирался бы в шести кодировках."""
    size = len(data)
    if data[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        yield squeeze(data.decode("utf-32", "replace"))
    elif data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        yield squeeze(data.decode("utf-16", "replace"))
    first = data.decode("utf-8", "replace")
    nuls = data.count(b"\0")
    raw = data
    yield squeeze(first)
    if nuls:
        raw = data.replace(b"\0", b"")
        first = raw.decode("utf-8", "replace")
        yield squeeze(first)
        even = data[0::2].count(b"\0")
        if max(even, nuls - even) * 10 >= size:  # UTF-16 латиницей: нули на одной чётности
            for codec in ("utf-16-le", "utf-16-be"):
                yield squeeze(data.decode(codec, "replace"))
        if nuls * 100 >= size * 40:  # UTF-32 латиницей: три нуля из четырёх байтов
            for codec in ("utf-32-le", "utf-32-be"):
                yield squeeze(data.decode(codec, "replace"))
    cyrillic_high = data.count(b"\x04")
    if cyrillic_high >= 3 and cyrillic_high * 20 >= size:  # UTF-16 с кириллицей: старший байт 0x04; смещение на байт тоже
        sample = data[:20_000]
        best = max(((codec, offset) for offset in (0, 1) for codec in ("utf-16-le", "utf-16-be")),
                   key=lambda co: len(re.findall("[\u0400-\u04ff]", sample[co[1]:].decode(co[0], "replace"))))  # раскладка по образцу: полный разбор один
        yield squeeze(data[best[1]:].decode(best[0], "replace"))
    if "\ufffd" in first and (not nuls or size <= CP_WITH_NUL_MAX):  # не UTF-8: однобайтные русские кодировки (в двоичном контейнере поверх вырезанных нулей)
        for codec in (OTHER_CODECS if size <= CP_ALL_MAX else OTHER_CODECS[:1]):
            yield squeeze(raw.decode(codec, "replace"))


_STRIP_TABLE: dict[int, None] = {}


def strip_table() -> dict[int, None]:
    """Знаки, которые не видны в тексте и ломают слово: форматирующие (Cf), комбинирующие (Mn, Me), невидимые буквы хангыля. Строится один раз."""
    if not _STRIP_TABLE:
        _STRIP_TABLE.update({cp: None for cp in range(sys.maxunicode + 1) if unicodedata.category(chr(cp)) in ("Cf", "Mn", "Me")})
        _STRIP_TABLE.update({ord(ch): None for ch in INVISIBLE_LETTERS})
    return _STRIP_TABLE


def normalized(text: str) -> list[str]:
    """Сам текст; он же в NFKD без невидимых символов и знаков комбинирования (акцент над буквой отделяется и вырезается: слово с акцентом равно слову без него); он же
    с кириллическими и греческими двойниками латиницей, но только слова со смесью письменностей (чистой кириллице двойники не нужны, а проход по ней дорог).
    Чистый ASCII не меняется ни одним из преобразований. Крупный текст без знаков из блоков, которые меняет свёртка, остаётся как есть."""
    if text.isascii():
        return [text]
    if len(text) > FOLD_FROM and not FOLD_TRIGGER.search(text):
        return [text]
    folded = unicodedata.normalize("NFKD", text).translate(strip_table())
    result = [text]
    if folded != text:
        result.append(folded)
    mixed = MIXED_SCRIPT.findall(folded) if LATIN.search(folded) else []
    if mixed:
        result.append("\n".join(word.translate(HOMOGLYPHS) for word in mixed))
    return result


ARCHIVE_LIMIT = "archive-limit"
OVERSIZE, TOO_MANY, UNREADABLE = object(), object(), object()  # участник архива: больше предела, их больше предела, не читается


def archive_kind(data: bytes) -> str:
    """Что это за архив по содержимому, а не по имени. zip ищется по записи в конце (так читаются и самораспаковывающиеся, и дописанные к рисунку)."""
    if len(data) < 22:
        return ""
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:3] == b"BZh":
        return "bz2"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if data[:6] == b"7z\xbc\xaf\x27\x1c" or data[:4] in (b"Rar!", b"\x28\xb5\x2f\xfd"):
        return "unsupported"  # 7z, rar, zstd: читать нечем, но и считать чистыми нельзя
    if data[257:262] == b"ustar":
        return "tar"
    try:
        return "zip" if zipfile.is_zipfile(io.BytesIO(data)) else ""
    except (OSError, ValueError):
        return ""


def bounded(decompressor, data: bytes):
    out = decompressor.decompress(data, MAX_BYTES + 1)
    return OVERSIZE if len(out) > MAX_BYTES else out


def expand_archive(data: bytes, kind: str):
    """Содержимое архива: (имя в архиве, байты). Вместо байтов маркеры OVERSIZE, TOO_MANY, UNREADABLE: молча пропущенный участник был бы дырой."""
    try:
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = zf.infolist()
                for info in infos[:MAX_ARCHIVE_MEMBERS]:
                    if info.is_dir():
                        continue
                    if info.file_size > MAX_BYTES:
                        yield info.filename, OVERSIZE
                        continue
                    try:
                        yield info.filename, zf.read(info)
                    except (zipfile.BadZipFile, zlib.error, RuntimeError, NotImplementedError, EOFError, OSError):
                        yield info.filename, UNREADABLE  # повреждён, зашифрован или неизвестный способ сжатия
                if len(infos) > MAX_ARCHIVE_MEMBERS:
                    yield "…", TOO_MANY
        elif kind == "gzip":
            yield "gz", bounded(zlib.decompressobj(31), data)
        elif kind == "bz2":
            yield "bz2", bounded(bz2.BZ2Decompressor(), data)
        elif kind == "xz":
            yield "xz", bounded(lzma.LZMADecompressor(), data)
        elif kind == "tar":
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                members = tf.getmembers()
                for member in members[:MAX_ARCHIVE_MEMBERS]:
                    if member.isfile():
                        extracted = tf.extractfile(member) if member.size <= MAX_BYTES else None
                        yield member.name, (extracted.read() if extracted else OVERSIZE)
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    yield "…", TOO_MANY
        else:
            yield "", UNREADABLE
    except (zipfile.BadZipFile, tarfile.TarError, zlib.error, lzma.LZMAError, OSError, EOFError, ValueError, RuntimeError, NotImplementedError):
        yield "", UNREADABLE


class Report:
    def __init__(self, rules: list[Rule], allow: list[tuple[str, str]]):
        self.rules, self.allow = rules, allow
        # одно объединённое выражение: чистый текст проверяется за один проход, а не по проходу на правило; подробный разбор только при совпадении
        self.any_rule = re.compile("|".join(f"(?:{pattern.pattern})" for _, _, pattern in rules), re.IGNORECASE)
        self.archive_left = MAX_ARCHIVE_TOTAL
        self.found: list[tuple[str, str, str]] = []
        self.hit_paths: list[str] = []
        self.seen: set[tuple[str, str]] = set()

    def add(self, level: str, name: str, where: str, path: str = "") -> None:
        if (name, where) not in self.seen:
            self.seen.add((name, where))
            self.found.append((level, name, where))
            if level == "error" and path and path not in self.hit_paths:
                self.hit_paths.append(path)

    def limit(self, name: str, where: str, path: str, why: str) -> None:
        """Находка «не проверено»: предел размера, глубины, числа участников или нечитаемый архив. Снимается исключением по имени и пути с причиной."""
        if not allowed(name, path, self.allow):
            self.add("error", name, f"{where}: {why}", path)

    def check_text(self, text: str, where: str, path: str, lines: bool) -> None:
        """where: что печатать в находке; path: что сопоставлять с масками исключений; lines: называть номер строки совпадения.
        Большой текст разбирается кусками по 4 млн знаков с нахлёстом, чтобы нормализация не держала в памяти по копии на весь текст."""
        if len(text) > CHUNK:
            start = 0
            while start < len(text):
                end = min(len(text), start + CHUNK)
                self._check_text(text[start:end], where, path, lines, text.count("\n", 0, start))
                if end == len(text):
                    break
                start = end - CHUNK_OVERLAP
            return
        self._check_text(text, where, path, lines, 0)

    def _check_text(self, text: str, where: str, path: str, lines: bool, offset: int) -> None:
        variants = [v for v in normalized(text) if self.any_rule.search(v)]  # один раз на текст; без совпадений дальше не идём
        if not variants:
            return
        for level, name, pattern in self.rules:
            if allowed(name, path, self.allow):
                continue
            shown = 0
            for variant in variants:
                for match in pattern.finditer(variant):
                    if shown >= LINES_PER_RULE:
                        break
                    shown += 1
                    place = f"{where}:{offset + variant.count(chr(10), 0, match.start()) + 1}" if lines else where
                    self.add(level, name, f"{place}: {match.group(0)[:60]}", path)
                    if not lines:
                        break
                if shown and not lines:
                    break

    def check_blob(self, data: bytes, where: str, path: str, depth: int = 0) -> None:
        if len(data) > MAX_BYTES:
            self.limit("size-limit", where, path, f"файл больше {MAX_BYTES // 1_000_000} МБ, не проверен")
            return
        for text in decode_variants(data):
            self.check_text(text, where, path, lines=True)
        kind = archive_kind(data)
        if not kind:
            return
        if depth >= MAX_ARCHIVE_DEPTH:
            self.limit(ARCHIVE_LIMIT, where, path, f"архив вложен глубже {MAX_ARCHIVE_DEPTH} уровней, не проверен до конца")
            return
        if depth == 0:
            self.archive_left = MAX_ARCHIVE_TOTAL
        for member, content in expand_archive(data, kind):
            label = f"{where} (в архиве, {member})" if member else f"{where} (в архиве)"
            if content is OVERSIZE:
                self.limit("size-limit", label, path, f"файл больше {MAX_BYTES // 1_000_000} МБ, не проверен")
                continue
            if content is TOO_MANY:
                self.limit(ARCHIVE_LIMIT, where, path, f"в архиве больше {MAX_ARCHIVE_MEMBERS} участников, остальные не проверены")
                continue
            if content is UNREADABLE:
                self.limit(ARCHIVE_LIMIT, label, path, "архив не читается (повреждён, зашифрован или формат не поддерживается), не проверен")
                continue
            self.archive_left -= len(content)
            if self.archive_left < 0:
                self.limit("size-limit", where, path, f"архив разворачивается больше {MAX_ARCHIVE_TOTAL // 1_000_000} МБ, не проверен до конца")
                return
            for text in decode_variants(member.encode("utf-8", "replace")):
                self.check_text(text, f"{where} (в архиве, имя {member})", path, lines=False)
            self.check_blob(content, label, path, depth + 1)


def read_objects(repo: Path, oids: list[str]):
    """Содержимое и тип объектов через один процесс git cat-file --batch: (тип, байты) или (None, None), если объекта нет."""
    with subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=GIT_ENV) as proc:
        assert proc.stdin and proc.stdout
        for oid in oids:
            proc.stdin.write(f"{oid}\n".encode())
            proc.stdin.flush()
            header = proc.stdout.readline().split()
            if len(header) < 3 or header[1] == b"missing":
                yield None, None
                continue
            data = proc.stdout.read(int(header[2]))
            proc.stdout.read(1)
            yield header[1].decode(), data
        proc.stdin.close()


def scan_files(repo: Path, report: Report) -> None:
    for raw_name in git(repo, "ls-files", "-z", raw=True).split(b"\0"):
        if not raw_name:
            continue
        rel = raw_name.decode("utf-8", "replace")
        for text in decode_variants(raw_name):  # имя файла в cp1251 тоже имя
            report.check_text(text, f"имя файла {rel}", rel, lines=False)
        path = repo / rel
        if path.is_file() and not path.is_symlink():
            report.check_blob(path.read_bytes(), rel, rel)


def check_commit_objects(repo: Path, commits: list[str], report: Report, how: str) -> None:
    """Сырой объект каждого коммита: заголовки (автор, коммиттер, дополнительные заголовки) и сообщение в любой кодировке."""
    for oid, (kind, data) in zip(commits, read_objects(repo, commits)):
        if kind != "commit" or data is None:
            continue
        headers, _, message = data.partition(b"\n\n")
        short = oid[:SHORT]
        subject = (message.decode("utf-8", "replace").strip().splitlines() or [""])[0][:80]
        for text in decode_variants(headers):
            report.check_text(text, f"{how}, заголовки коммита: {short}", PSEUDO_COMMIT, lines=False)
        for text in decode_variants(message):
            report.check_text(text, f"{how}, сообщение: {short} {subject}", PSEUDO_COMMIT, lines=False)


def changed_blobs(repo: Path, commits: list[str]) -> list[tuple[str, str, bytes, str]]:
    """(коммит, oid файла, путь байтами, режим) для каждого файла, добавленного или изменённого каждым коммитом. diff-tree -m даёт и merge-коммиты (diff
    против каждого родителя, в нём результат разрешения конфликта), --root корневой, -z пути без экранирования (имя с переводом строки или в cp1251 приходит
    целиком, поэтому путь остаётся байтами), коммиты идут от старых к новым: файл приписан коммиту, который его ввёл."""
    if not commits:
        return []
    done = subprocess.run(["git", "-C", str(repo), "diff-tree", "--stdin", "-z", "-m", "--root", "-r", "--no-renames", "--no-abbrev"],
                          input=("\n".join(commits) + "\n").encode(), capture_output=True, env=GIT_ENV)
    if done.returncode != 0:
        raise ScanError(f"git diff-tree: {done.stderr.decode('utf-8', 'replace').strip()[:200]}")
    tokens = done.stdout.split(b"\0")
    result: list[tuple[str, str, bytes, str]] = []
    seen: set[tuple[str, bytes]] = set()
    commit, index = "", 0
    while index < len(tokens):
        token = tokens[index].strip(b"\n")
        if token.startswith(b":") and index + 1 < len(tokens):
            fields = token.decode("ascii", "replace").split()
            path = tokens[index + 1]
            index += 2
            if len(fields) >= 5 and set(fields[3]) != {"0"} and (fields[3], path) not in seen:
                seen.add((fields[3], path))
                result.append((commit[:SHORT], fields[3], path, fields[1]))
            continue
        head = token.split(b" ")[0].decode("ascii", "replace")
        if re.fullmatch(r"[0-9a-f]{40}", head):
            commit = head
        index += 1
    return result


def walk(repo: Path, revargs: list[str], report: Report, how: str) -> None:
    commits = git(repo, "rev-list", "--reverse", *revargs).split()
    check_commit_objects(repo, commits, report, how)
    entries = changed_blobs(repo, commits)
    for (commit, _oid, raw_path, mode), (kind, data) in zip(entries, read_objects(repo, [e[1] for e in entries])):
        path = raw_path.decode("utf-8", "replace")
        for text in decode_variants(raw_path):  # имя файла в cp1251 тоже имя
            report.check_text(text, f"{how}, имя файла: {commit} {path}", path, lines=False)
        if mode != "160000" and kind == "blob" and data is not None:  # 160000: подмодуль, указатель на чужой коммит, не файл
            report.check_blob(data, f"{how}, изменение: {commit} {path}", path)


def scan_history(repo: Path, report: Report) -> None:
    walk(repo, ["--all"], report, "история")


def peel(repo: Path, oid: str, report: Report) -> tuple[str, str]:
    """Снять аннотированные теги (в том числе вложенные), проверяя текст каждого. Вернёт (sha объекта под тегами, его тип)."""
    for _ in range(20):
        kind = git(repo, "cat-file", "-t", oid, check=False).strip()
        if kind != "tag":
            return oid, kind
        raw_tag = git(repo, "cat-file", "tag", oid, raw=True)  # сырой объект: сообщение тега может быть в любой кодировке
        for text in decode_variants(raw_tag):
            report.check_text(text, f"push, аннотированный тег {oid[:SHORT]}", PSEUDO_TAG, lines=False)
        target = re.search(r"^object ([0-9a-f]{40})", raw_tag.decode("ascii", "replace"), re.M)
        if not target:
            return oid, "tag"
        oid = target.group(1)
    raise ScanError("слишком длинная цепочка аннотированных тегов")


def scan_push(repo: Path, pairs: list[tuple[str, str]], refs: list[str], report: Report) -> None:
    """Что уходит при push, одним проходом на все ссылки. Из проверки исключаются только коммиты, которые достижимы из sha удалённых веток, уже
    известных локально: этот sha сообщает сам git из удалённого репо. Новая ветка проверяется целиком: refs/remotes/* локально подделываются."""
    for ref in refs:
        report.check_text(ref, f"push, имя ветки или тега {ref}", PSEUDO_REF, lines=False)
    positives, negatives = [], []
    for local, remote in pairs:
        target, kind = peel(repo, local, report)
        if kind not in ("commit", "blob", "tree"):  # sha не найден или объект непонятный: проверить нечего, а «нечего» не значит «чисто»
            raise ScanError(f"объект {local[:12]} не читается (тип {kind or 'не найден'}): проверка невозможна")
        if kind in ("blob", "tree"):  # тег или ветка на файл или каталог: содержимое читается напрямую
            objects = [line.split(" ", 1) for line in git(repo, "rev-list", "--objects", target).splitlines() if line.strip()]
            for (oid, *name), (otype, data) in zip(objects, read_objects(repo, [o[0] for o in objects])):
                if otype == "blob" and data is not None:
                    label = name[0] if name else target[:SHORT]
                    report.check_blob(data, f"push, изменение: {oid[:SHORT]} {label}", label)
        elif kind == "commit":
            positives.append(target)
        if remote != ZERO and git(repo, "cat-file", "-t", remote, check=False).strip() == "commit":
            negatives.append(remote)
    if positives:
        walk(repo, [*positives, *(["--not", *negatives] if negatives else [])], report, "push")


def load_known(path: Path) -> list[tuple[str, str, str]]:
    if not path.is_file():
        return []
    entries = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        parts = raw.split("\t")
        if len(parts) >= 4 and not raw.startswith("#") and len(parts[2]) >= 7:  # пустой или короткий коммит не должен снимать всё подряд
            entries.append((parts[0], parts[1], parts[2]))
    return entries


def is_known(repo: Path, name: str, where: str, known: list[tuple[str, str, str]]) -> bool:
    commit = where.split(": ", 1)[-1].split(" ", 1)[0]
    return any(r == repo.name and n == name and commit.startswith(c[:SHORT]) for r, n, c in known)


def main(argv: list[str]) -> int:
    if not argv or argv[0].startswith("-"):
        print(__doc__)
        return 2
    repo, history, pairs, rules_path, allow_path, known_path, paths_only, ci = Path(argv[0]), False, [], DEFAULT_LIST, None, None, False, False
    refs, rest = [], argv[1:]
    while rest:
        flag = rest.pop(0)
        if flag == "--history":
            history = True
        elif flag == "--paths":
            paths_only = True
        elif flag == "--ci":
            ci = True
        elif flag == "--list" and rest:
            rules_path = Path(rest.pop(0))
        elif flag == "--allow" and rest:
            allow_path = Path(rest.pop(0))
        elif flag == "--push" and len(rest) >= 2:
            pairs.append((rest.pop(0), rest.pop(0)))
        elif flag == "--ref" and rest:
            refs.append(rest.pop(0))
        elif flag == "--known" and rest:
            known_path = Path(rest.pop(0))
        else:
            print(f"ОШИБКА: непонятный аргумент {flag}", file=sys.stderr)
            return 2
    try:
        rules = load_rules(rules_path)
        report = Report(rules, load_allow(allow_path or rules_path.with_name("public-scan-allow.tsv"), repo.name))
        known = load_known(known_path or rules_path.with_name("public-scan-known.tsv"))
        if pairs:
            scan_push(repo, pairs, refs, report)
        else:
            scan_files(repo, report)
            if history:
                scan_history(repo, report)
        if (repo / ".public-scan-allow").is_file():
            report.add("warn", "allow-file", ".public-scan-allow в публичном репо не учитывается: исключения лежат в мете (_shared/public-scan-allow.tsv)")
    except (ScanError, OSError) as exc:
        print(f"ОШИБКА: проверка не выполнена: {exc}", file=sys.stderr)
        return 2
    if paths_only:
        sys.stdout.write("".join(f"{path}\0" for path in report.hit_paths))
        return 0
    found = [("known" if level == "error" and is_known(repo, name, where, known) else level, name, where) for level, name, where in report.found]
    if ci:
        numbers: dict[str, int] = {}
        for _, name, _ in rules:
            numbers.setdefault(name, len(numbers) + 1)
        for level, name, where in found:
            head, _, tail = where.partition(": ")
            category = next((c for c in CI_CATEGORIES if c in head), "файл")
            token = tail.split(" ", 1)[0]
            has_commit = head.startswith(("push,", "история,")) and category in CI_WITH_COMMIT and re.fullmatch(r"[0-9a-f]{7}", token)
            label = f"правило №{numbers[name]}" if name in numbers else name
            print(f"{level.upper():5} {label}: {category}" + (f", коммит {token}" if has_commit else ""))
        errors = sum(1 for level, _, _ in found if level == "error")
        print(f"{repo.name}: error {errors}, known {sum(1 for lv, _, _ in found if lv == 'known')}, warn {sum(1 for lv, _, _ in found if lv == 'warn')}")
        return 1 if errors else 0
    if paths_only:
        sys.stdout.write("".join(f"{path}\0" for path in report.hit_paths))
        return 0
    found = [("known" if level == "error" and is_known(repo, name, where, known) else level, name, where) for level, name, where in report.found]
    if ci:
        numbers = {}
        for _, name, _ in rules:
            numbers.setdefault(name, len(numbers) + 1)
        for level, name, where in found:
            category = where.split(": ", 1)[0]
            commit = where.split(": ", 1)[1].split(" ", 1)[0] if ": " in where else ""
            print(f"{level.upper():5} правило №{numbers[name]}: {category.split(',')[-1].strip()[:30]}, коммит {commit[:SHORT]}")
        errors = sum(1 for level, _, _ in found if level == "error")
        print(f"{repo.name}: error {errors}, known {sum(1 for lv, _, _ in found if lv == 'known')}, warn {sum(1 for lv, _, _ in found if lv == 'warn')}")
        return 1 if errors else 0
    for level, name, where in found:
        print(f"{level.upper():5} {name}: {where}")
    errors = sum(1 for level, _, _ in found if level == "error")
    print(f"{repo.name}: error {errors}, known {sum(1 for lv, _, _ in found if lv == 'known')}, warn {sum(1 for lv, _, _ in found if lv == 'warn')}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

# START_MODULE_CONTRACT
#   PURPOSE: Детерминированное отображение исходных значений в правдоподобные замены.
#            Ключи идентичности (normalize) по семантическим типам, производная соль,
#            SHA3-отображение в корпус с пробированием, структурная генерация
#            идентификаторов с контрольными суммами.
#   SCOPE: Чистые функции без I/O; не знает про БД, план и Greenmask.
#   DEPENDS: none (stdlib only)
#   LINKS: M-CORPUS (потребляет корпуса), V-M-MAPPER, docs/solution-design.md §3.2-3.4
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   Salt - производная соль HMAC(master[v], recipient, generation)
#   salt_fingerprint - необратимый отпечаток соли для сверки проходов
#   Mapper - отображение значений в замены по корпусам (включая synthetic_address)
#   normalize_fio - ключ идентичности ФИО (леммы + род)
#   normalize_phone - ключ идентичности телефона
#   normalize_email - ключ идентичности email
#   normalize_digits - ключ идентичности числовых идентификаторов
#   feminize - женская форма фамилии
#   FEM_SUFFIX - таблица родовых суффиксов фамилий
#   gen_inn10 - ИНН физлица из хэша с контрольной суммой
#   gen_inn12 - ИНН 12 знаков из хэша с контрольными суммами
#   gen_snils - СНИЛС из хэша с контрольным числом
#   gen_ogrn - ОГРН/ОГРНИП из хэша с контрольной цифрой
#   gen_int_like - целое той же разрядности без коллизий (Фейстель + cycle-walking)
#   pick_int - число в диапазоне по ключу; НЕ инъективна, только для дома/квартиры
#   gen_digits_like - формат-сохраняющая инъективная замена цифр
#   luhn_ok - проверка номера карты по алгоритму Луна
#   gen_luhn_like - замена номера карты с досчётом цифры Луна
#   valid_inn - проверка контрольной суммы ИНН
#   valid_snils - проверка контрольного числа СНИЛС
#   valid_ogrn - проверка контрольной цифры ОГРН
# END_MODULE_MAP
from __future__ import annotations

import hashlib
import hmac as _hmac
import re
from dataclasses import dataclass




@dataclass(frozen=True)
class Salt:
    """Производная соль: HMAC(master[v], recipient ‖ generation). §3.4."""

    master: bytes
    recipient: str
    generation: str
    version: int = 1

    @property
    def effective(self) -> bytes:
        # Версия входит в производную соль первой: ротация MASTER_SALT_VERSION
        # без перевыпуска мастера обязана дать ДРУГИЕ замены, иначе ротация -
        # пустая операция (ревью 2: поле было мёртвым при противоположном
        # заявлении §3.4 и коммита 38854be). Формула ред. C-REVIEW2-FIXES;
        # все производные значения изменились, обратная совместимость копий
        # принята (реальных выданных копий нет).
        msg = f"{self.version}\x00{self.recipient}\x00{self.generation}".encode()
        return _hmac.new(self.master, msg, hashlib.sha256).digest()


def salt_fingerprint(salt: Salt) -> str:
    """Сравнимый необратимый отпечаток производной соли. Нужен, чтобы два прохода
    (родительский и дочерний Cmd-процесс Greenmask) доказали, что работают на одной
    соли: они связаны только переменными окружения."""
    return hashlib.sha256(b"fp\x00" + salt.effective).hexdigest()[:16]


def _h(salt: Salt, *parts: str) -> int:
    """SHA3-256(salt_effective ‖ parts) -> int. Единственная точка хэширования."""
    m = hashlib.sha3_256()
    m.update(salt.effective)
    for p in parts:
        m.update(b"\x00")
        m.update(p.encode())
    return int.from_bytes(m.digest(), "big")






_YO = str.maketrans("ё", "е")


def _norm_word(s: str) -> str:
    return s.strip().lower().translate(_YO)


# START_CONTRACT: normalize_fio
#   PURPOSE: Ключ идентичности ФИО - кортеж лемм (фамилия, имя, отчество) + род.
#   INPUTS: { family/name/patronymic: str - компоненты, пустые допустимы }
#   OUTPUTS: { (fam, nm, pat, gender) - gender: "m"|"f", определяется по отчеству,
#              затем по окончанию фамилии; по умолчанию "m" }
#   SIDE_EFFECTS: none
# END_CONTRACT: normalize_fio
def normalize_fio(family: str = "", name: str = "", patronymic: str = "") -> tuple[str, str, str, str]:
    fam, nm, pat = _norm_word(family), _norm_word(name), _norm_word(patronymic)
    if pat.endswith(("вна", "чна", "шна")):
        gender = "f"
    elif pat.endswith(("вич", "ьич", "мич")):
        gender = "m"
    elif fam.endswith(("ова", "ева", "ина", "ына", "ская", "цкая", "ая")):
        gender = "f"
    else:
        gender = "m"
    # фамилия к мужской лемме: Петрова -> петров, Донская -> донской
    if gender == "f":
        for suf, repl in (("ская", "ский"), ("цкая", "цкий"), ("ова", "ов"), ("ева", "ев"), ("ина", "ин"), ("ына", "ын")):
            if fam.endswith(suf):
                fam = fam[: -len(suf)] + repl
                break
    return fam, nm, pat, gender


FEM_SUFFIX = (("ский", "ская"), ("цкий", "цкая"), ("ов", "ова"), ("ев", "ева"), ("ин", "ина"), ("ын", "ына"))


def feminize(family_lemma: str) -> str:
    for m_suf, f_suf in FEM_SUFFIX:
        if family_lemma.endswith(m_suf):
            return family_lemma[: -len(m_suf)] + f_suf
    return family_lemma  # несклоняемая (Шевченко) - без изменений


def normalize_phone(raw: str) -> str:
    """Только цифры, приведение к +7XXXXXXXXXX."""
    d = re.sub(r"\D", "", raw)
    if len(d) == 11 and d[0] in "78":
        d = "7" + d[1:]
    elif len(d) == 10:
        d = "7" + d
    return "+" + d


def normalize_email(raw: str) -> str:
    """Нижний регистр, обрезка +tag. Ключ - сам email (§3.2)."""
    s = raw.strip().lower()
    local, _, domain = s.partition("@")
    local = local.split("+", 1)[0]
    return f"{local}@{domain}"


def normalize_digits(raw: str) -> str:
    """ИНН/СНИЛС/ОГРН/паспорт: цифры без разделителей."""
    return re.sub(r"\D", "", raw)







class Mapper:
    """Значение -> замена. Корпуса передаются снаружи (M-CORPUS)."""

    def __init__(self, salt: Salt, corpora: dict[str, list[str]]):
        self.salt = salt
        self.c = corpora

    # START_CONTRACT: pick
    #   PURPOSE: Детерминированный выбор из корпуса; линейное пробирование
    #            гарантирует fake(x) != x (критерий §5.4).
    #   INPUTS: { corpus_key: str, *key_parts: str - ключ идентичности,
    #             avoid: str|None - исходное значение, совпадение с которым запрещено }
    #   OUTPUTS: { str - элемент корпуса }
    #   SIDE_EFFECTS: none
    # END_CONTRACT: pick
    def pick(self, corpus_key: str, *key_parts: str, avoid: str | None = None) -> str:
        corpus = self.c[corpus_key]
        idx = _h(self.salt, corpus_key, *key_parts) % len(corpus)
        for i in range(len(corpus)):
            val = corpus[(idx + i) % len(corpus)]
            if avoid is None or _norm_word(val) != _norm_word(avoid):
                return val
        raise ValueError(f"corpus {corpus_key!r} exhausted by probing")  # ponytail: len>=2 гарантирует недостижимость

    def fio(self, family: str = "", name: str = "", patronymic: str = "") -> tuple[str, str, str]:
        """Покомпонентная замена; каждая часть от своего ключа, род сохраняется."""
        fam, nm, pat, g = normalize_fio(family, name, patronymic)
        out_f = out_n = out_p = ""
        if fam:
            out_f = self.pick("family", fam, avoid=fam)
            if g == "f":
                out_f = feminize(out_f)
        if nm:
            out_n = self.pick(f"name_{g}", nm, avoid=nm)
        if pat:
            out_p = self.pick(f"patronymic_{g}", pat, avoid=pat)
        return out_f, out_n, out_p

    def initials(self, family: str, i1: str = "", i2: str = "") -> tuple[str, str, str]:
        """«Петров И.И.»: фамилия консистентна полной форме; инициалы - первые буквы
        фейков от однобуквенных ключей (согласованность по фамилии, §3.2)."""
        f, n, p = self.fio(family, i1, i2)
        return f, (n[:1] if n else ""), (p[:1] if p else "")

    def phone(self, raw: str) -> str:
        key = normalize_phone(raw)
        code = self.c["phone_code"][_h(self.salt, "phone_code", key) % len(self.c["phone_code"])]
        tail = str(_h(self.salt, "phone_tail", key) % 10_000_000).zfill(7)
        fake = f"+7{code}{tail}"
        return fake if fake != key else f"+7{code}{str((int(tail) + 1) % 10_000_000).zfill(7)}"

    def email(self, raw: str) -> str:
        """Ключ - сам email; транслит фейковой фамилии + криптографический суффикс.
        Суффикс - 8 знаков base32 от SHA3 (40 бит): коллизии двух разных исходных
        email практически исключены - держит UNIQUE без таблицы соответствий."""
        key = normalize_email(raw)
        fam = self.pick("family", "email", key)
        domain = self.c["email_domain"][_h(self.salt, "email_domain", key) % len(self.c["email_domain"])]
        suffix = _b32(_h(self.salt, "email_sfx", key))[:8]
        return f"{_translit(fam)}.{suffix}@{domain}"

    def address_component(self, kind: str, value: str) -> str:
        """kind: region|city|street; дом и квартира - pick_int."""
        return self.pick(kind, _norm_word(value), avoid=value)

    # START_CONTRACT: synthetic_address
    #   PURPOSE: Полная замена адресной строки. ЕДИНСТВЕННАЯ реализация на оба
    #            прохода: структурная колонка и тот же адрес в свободном тексте
    #            обязаны дать одну строку, иначе один адрес в базе разъезжается.
    #   INPUTS: { raw: str - исходная строка любой грязности }
    #   OUTPUTS: { str - «Регион, г. Город, ул. Улица, д. N, кв. M» }
    #   SIDE_EFFECTS: none
    # END_CONTRACT: synthetic_address
    def synthetic_address(self, raw: str) -> str:
        key = " ".join(raw.lower().translate(_YO).split())
        region = self.address_component("region", key).title()
        city = self.address_component("city", key + "|c").title()
        street = self.address_component("street", key + "|s").title()
        house = pick_int(self.salt, key + "|h", 1, 99)
        flat = pick_int(self.salt, key + "|f", 1, 250)
        return f"{region}, г. {city}, ул. {street}, д. {house}, кв. {flat}"


_TR = {"а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ж": "zh", "з": "z", "и": "i",
       "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p", "р": "r", "с": "s",
       "т": "t", "у": "u", "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sch",
       "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya"}


def _translit(s: str) -> str:
    return "".join(_TR.get(ch, ch) for ch in s.lower())


_B32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


def _b32(n: int) -> str:
    out = []
    for _ in range(12):
        out.append(_B32_ALPHABET[n & 31])
        n >>= 5
    return "".join(out)





# generate-стратегия (§3.3): тело идентификатора - формат-сохраняющая перестановка
# (4-раундовый Feistel поверх SHA3) исходного тела, контрольная сумма досчитывается.
# Перестановка биективна по построению -> уникальность гарантирована структурно,
# без таблицы соответствий и без разделяемого состояния.


def _fpe(salt: Salt, label: str, x: int, n_digits: int) -> int:
    """Биективная перестановка [0, 10^n_digits): сбалансированный-по-очереди Feistel,
    чётное число раундов возвращает размеры половин на место."""
    n1 = n_digits // 2
    a, b = 10 ** n1, 10 ** (n_digits - n1)
    left, right = x // b, x % b
    for rnd in range(4):
        left = (left + _h(salt, "fpe", label, str(rnd), str(right))) % a
        left, right, a, b = right, left, b, a
    return left * b + right


def _body(src: str, n: int) -> int:
    """Инъективное тело: контрольные цифры исходника отбрасываются (они - функция тела)."""
    d = normalize_digits(src)
    return int(d[:n]) if len(d) >= n else int(d or "0")


def _inn_check(digits: list[int], coefs: list[int]) -> int:
    return sum(d * c for d, c in zip(digits, coefs)) % 11 % 10


def gen_inn10(salt: Salt, src: str) -> str:
    body = [int(ch) for ch in str(_fpe(salt, "inn10", _body(src, 9), 9)).zfill(9)]
    return "".join(map(str, body)) + str(_inn_check(body, [2, 4, 10, 3, 5, 9, 4, 6, 8]))


def gen_inn12(salt: Salt, src: str) -> str:
    body = [int(ch) for ch in str(_fpe(salt, "inn12", _body(src, 10), 10)).zfill(10)]
    n11 = _inn_check(body, [7, 2, 4, 10, 3, 5, 9, 4, 6, 8])
    n12 = _inn_check(body + [n11], [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8])
    return "".join(map(str, body)) + str(n11) + str(n12)


def gen_snils(salt: Salt, src: str) -> str:
    body = [int(ch) for ch in str(_fpe(salt, "snils", _body(src, 9), 9)).zfill(9)]
    s = sum(d * (9 - i) for i, d in enumerate(body)) % 101
    if s == 100:
        s = 0
    return "".join(map(str, body)) + str(s).zfill(2)


def gen_ogrn(salt: Salt, src: str, ip: bool = False) -> str:
    if ip:  # ОГРНИП: 14 цифр + (num mod 13) mod 10
        body = _fpe(salt, "ogrnip", _body(src, 14), 14)
        return str(body).zfill(14) + str(body % 13 % 10)
    body = _fpe(salt, "ogrn", _body(src, 12), 12)  # ОГРН: 12 цифр + (num mod 11) mod 10
    return str(body).zfill(12) + str(body % 11 % 10)


def gen_int_like(salt: Salt, src: str) -> int:
    """Табельный номер и прочие целые под UNIQUE: замена той же разрядности,
    БЕЗ коллизий. Перестановка Фейстеля на [0, 10^n) с cycle-walking внутрь
    [10^(n-1), 10^n) - биекция на множестве n-значных чисел, поэтому разные
    исходники разной разрядности попадают в непересекающиеся диапазоны.

    Прежняя реализация брала `int(src) % size` ДО перестановки: остаток по модулю
    склеивает исходники, различающиеся на размер окна (100001 и 1000001 давали
    одно и то же), - ровно та коллизия, которую запрещал собственный контракт.

    Неподвижная точка (замена совпала с исходником) возможна с вероятностью
    ~10^-n и не маскируется сдвигом: сдвиг ломает инъективность. Такой случай
    ловит построчная проверка fake(x)!=x и лечится сменой поколения соли."""
    digits = normalize_digits(src) or "0"
    n = len(digits)
    if n > 1 and digits[0] == "0":
        # Ведущий ноль означает, что исходник лежит ВНЕ [10^(n-1), 10^n), а
        # cycle-walking биективен только внутри этого множества: «012345»
        # шагнул бы в него и мог совпасть с образом обычного шестизначного.
        # Такая колонка - текстовый идентификатор с набивкой, ей нужна другая
        # стратегия и решение человека. Исходное значение в сообщение не входит:
        # исключения исполнения пишутся в журнал, а колонка может содержать ПДн
        # (ревью 2, «утечки значений в исключения»).
        raise ValueError("gen_int_like: целое с ведущим нулём - инъективность не "
                         "гарантируется; выберите для колонки другую стратегию")
    if n < 2:
        # однозначные: перестановка десяти цифр, порождённая солью. Возврат
        # исходника был бы тождественной заменой, то есть утечкой значения.
        order = sorted(range(10), key=lambda d: _h(salt, "int1", str(d)))
        return order[int(digits)]
    lo = 10 ** (n - 1)
    y = int(digits)
    label = f"int{n}"
    while True:
        y = _fpe(salt, label, y, n)
        if y >= lo:
            return y


def pick_int(salt: Salt, key: str, lo: int, hi: int) -> int:
    """Число в диапазоне по произвольному ключу. НЕ инъективна и не претендует:
    применяется там, где уникальность не нужна и не проверяется, - номер дома и
    квартиры внутри синтетического адреса. Для колонок под UNIQUE - gen_int_like."""
    return lo + _h(salt, f"range{lo}-{hi}", key) % (hi - lo + 1)


def gen_digits_like(salt: Salt, src: str) -> str:
    """Паспорт, номер договора: формат исходного сохранён, цифры переставлены
    Фейстелем. Инъективна при неизменном «скелете» строки (позиции нецифровых
    символов), а разные скелеты дают разные строки, - значит инъективна вообще.
    Это важно: паспорт бывает ключом, а прежняя версия сыпала цифры из хэша и
    коллизий не исключала."""
    digits = normalize_digits(src)
    if not digits:
        return src
    n = len(digits)
    fake = str(_fpe(salt, f"digits{n}", int(digits), n)).zfill(n)
    it = iter(fake)
    return "".join(next(it) if ch.isdigit() else ch for ch in src)


def luhn_ok(s: str) -> bool:
    """Алгоритм Луна: номера банковских карт (13-19 цифр). Нужен свободному
    тексту - карта персональными данными является, а под ИНН/СНИЛС/ОГРН не
    подходит ни по длине, ни по контрольной сумме."""
    if not (13 <= len(s) <= 19) or not s.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(s)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def gen_luhn_like(salt: Salt, src: str) -> str:
    """Замена карты: тело переставляется Фейстелем, последняя цифра
    досчитывается по Луну. Первые шесть цифр (банк-эмитент) не сохраняются -
    они сузили бы круг лиц."""
    body = str(_fpe(salt, "luhn", _body(src, len(src) - 1), len(src) - 1)).zfill(len(src) - 1)
    for check in "0123456789":
        if luhn_ok(body + check):
            return body + check
    return body + "0"  # ponytail: недостижимо, контрольная цифра существует всегда


def valid_inn(s: str) -> bool:
    d = [int(ch) for ch in s]
    if len(d) == 10:
        return d[9] == _inn_check(d[:9], [2, 4, 10, 3, 5, 9, 4, 6, 8])
    if len(d) == 12:
        return (d[10] == _inn_check(d[:10], [7, 2, 4, 10, 3, 5, 9, 4, 6, 8])
                and d[11] == _inn_check(d[:11], [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]))
    return False


def valid_snils(s: str) -> bool:
    if len(s) != 11:
        return False
    body, check = [int(ch) for ch in s[:9]], int(s[9:])
    c = sum(d * (9 - i) for i, d in enumerate(body)) % 101
    return check == (0 if c == 100 else c)


def valid_ogrn(s: str) -> bool:
    if len(s) == 13:
        return int(s[12]) == int(s[:12]) % 11 % 10
    if len(s) == 15:
        return int(s[14]) == int(s[:14]) % 13 % 10
    return False




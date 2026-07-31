# START_MODULE_CONTRACT
#   PURPOSE: Единственная точка обращения к языковой модели. Два поставщика за
#            одним интерфейсом: локальная Ollama и любой OpenAI-совместимый API.
#            Четыре роли конвейера (классификация по метаданным, генерация
#            корпусов, карта 1:1, третий эшелон NER) получают модель отсюда.
#   SCOPE: Транспорт, разбор ответа и ГРАНИЦА БЕЗОПАСНОСТИ. Решений о стратегиях
#          не принимает, в БД не ходит. Ответ модели наружу отдаётся сырым -
#          проверяют его потребители (M-CORPUS, M-POLICY).
#   DEPENDS: none (stdlib: urllib)
#   LINKS: M-CLASSIFIER, M-CORPUS, M-EXECUTOR, M-POSTPROC, V-M-LLM,
#          docs/solution-design.md §4.2 (отклонение), §4.4
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   LLMUnavailable - поставщик не настроен либо недоступен
#   LLMClient - клиент модели: chat(), json_chat(), sees_personal_data
#   from_env - собрать клиента по переменным окружения; None если не настроен
#   classifier_ask - роль 1: метаданные колонок -> семантические типы
#   corpus_generate - роль 2: порождение компонент корпуса
#   direct_map - роль 3: карта 1:1 для не-ПДн значений
#   ner_verdict - роль 4: да | нет | не знаю по фрагменту текста
#   NER_ACCEPTANCE - набор фрагментов с известными ответами для приёмки
#   ner_acceptance - приёмка модели на роль 4 перед прогоном
# END_MODULE_MAP
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

# Хосты, которые считаются «в контуре». Роль 4 видит живой текст с
# персональными данными, и для неё разрешены только они: инструмент
# обезличивания, отправляющий ПДн наружу, отменяет сам себя (§2).
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "host.docker.internal", "ollama")


class LLMUnavailable(RuntimeError):
    """Поставщик не настроен, недоступен или не имеет права на эту роль."""


@dataclass
class LLMClient:
    provider: str                    # ollama | openai
    model: str
    base_url: str
    api_key: str = ""
    timeout: int = 120
    calls: list[str] = field(default_factory=list)   # журнал ролей для отчёта

    @property
    def sees_personal_data(self) -> bool:
        """Разрешено ли показывать этому поставщику живой текст."""
        host = re.sub(r"^https?://", "", self.base_url).split(":")[0].split("/")[0]
        return host in _LOCAL_HOSTS

    def require_local(self, role: str):
        if not self.sees_personal_data:
            raise LLMUnavailable(
                f"роль {role!r} показывает модели живой текст с персональными данными; "
                f"поставщик {self.base_url} не в контуре. Дальше: поднимите локальную "
                f"модель (LLM_PROVIDER=ollama) либо оставьте роль отключённой.")

    # START_CONTRACT: chat
    #   PURPOSE: Один запрос к модели. Единственное место сетевого I/O в проекте.
    #   INPUTS: { prompt: str, system: str, role: str - для журнала }
    #   OUTPUTS: { str - текст ответа }
    #   SIDE_EFFECTS: сетевой вызов; пополняет журнал ролей
    # END_CONTRACT: chat
    def chat(self, prompt: str, system: str = "", role: str = "") -> str:
        self.calls.append(role or "chat")
        messages = ([{"role": "system", "content": system}] if system else []) + \
                   [{"role": "user", "content": prompt}]
        if self.provider == "ollama":
            url = f"{self.base_url}/api/chat"
            # think=false: рассуждающие модели (qwen3 и подобные) иначе тратят
            # минуты на внутренний монолог там, где нужен разбор метаданных.
            payload = {"model": self.model, "messages": messages, "stream": False,
                       "think": False, "options": {"temperature": 0}}
        else:
            url = f"{self.base_url}/v1/chat/completions"
            payload = {"model": self.model, "messages": messages, "temperature": 0}
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {})})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise LLMUnavailable(f"{self.provider} на {self.base_url} недоступен: {e}") from e
        if self.provider == "ollama":
            return data["message"]["content"]
        return data["choices"][0]["message"]["content"]

    def json_chat(self, prompt: str, system: str = "", role: str = ""):
        """Ответ модели как JSON. Модели любят обрамлять его пояснениями и
        ```-блоками, поэтому берётся первый сбалансированный объект или массив."""
        raw = self.chat(prompt, system, role)
        return _first_json(raw)


def _first_json(raw: str):
    text = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.M).strip()
    # <think>…</think> у рассуждающих моделей вырезается
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    # Скобка выбирается по тому, что встретилось РАНЬШЕ: при ответе-массиве
    # поиск «{» находил первый объект ВНУТРИ него и терял остальные элементы.
    candidates = sorted(((text.find(o), o, c) for o, c in (("{", "}"), ("[", "]"))
                         if text.find(o) >= 0))
    for start, opener, closer in candidates:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    return json.loads(text[start:i + 1])
    raise LLMUnavailable(f"ответ модели не содержит JSON: {raw[:200]!r}")


# START_CONTRACT: from_env
#   PURPOSE: Клиент по переменным окружения. Отсутствие настройки - НЕ ошибка:
#            конвейер обязан работать по кэшу без модели и без сети.
#   INPUTS: { окружение: LLM_PROVIDER, LLM_MODEL, LLM_BASE_URL, LLM_API_KEY }
#   OUTPUTS: { LLMClient | None }
#   SIDE_EFFECTS: none
# END_CONTRACT: from_env
def from_env() -> LLMClient | None:
    provider = os.environ.get("LLM_PROVIDER", "").strip().lower()
    if not provider:
        return None
    if provider not in ("ollama", "openai"):
        raise LLMUnavailable(f"неизвестный LLM_PROVIDER {provider!r}; допустимы ollama, openai")
    defaults = {"ollama": ("http://127.0.0.1:11434", "qwen3:8b"),
                "openai": ("https://api.openai.com", "gpt-4o-mini")}
    base, model = defaults[provider]
    return LLMClient(provider=provider,
                     model=os.environ.get("LLM_MODEL", model),
                     base_url=os.environ.get("LLM_BASE_URL", base).rstrip("/"),
                     api_key=os.environ.get("LLM_API_KEY", ""),
                     timeout=int(os.environ.get("LLM_TIMEOUT", "120")))




_CLASSIFY_SYSTEM = (
    "Ты классифицируешь колонки базы данных по семантическому типу. "
    "Тебе дают ТОЛЬКО метаданные: имя колонки, тип, кардинальность, долю NULL, "
    "ключи jsonb. Значений колонок ты не видишь и не должен их запрашивать. "
    "Отвечай ОДНИМ JSON-объектом без пояснений."
)

# Правила против самых частых ошибок небольших моделей. Замерено на демо-схеме
# (69 колонок): без них модель размечала как person_id все суррогатные ключи
# (id, *_id) и как free_text - метки времени и категориальные коды.
_CLASSIFY_RULES = (
    "Правила:\n"
    "- integer/bigint с именем id или *_id - это technical (суррогатный ключ), "
    "а НЕ person_id. person_id - только осмысленный номер человека: табельный, "
    "личный номер, номер пропуска.\n"
    "- timestamp, date без слова «рожден»/«birth» - technical.\n"
    "- короткий код с малой кардинальностью (grade, status, type) - category, "
    "а не free_text.\n"
    "- free_text - только длинный человеческий текст: комментарий, описание, тело заявки.\n"
    "- при сомнении верни null: колонку разберёт человек.\n"
)


# START_CONTRACT: classifier_ask
#   PURPOSE: Роль 1. Голос модели в классификации - по МЕТАДАННЫМ, без образцов
#            значений: это условие §2 (реальные ПДн модели не показываются).
#   INPUTS: { client, meta: колонка -> {type, len, card, null_frac, json_keys},
#             allowed: допустимые семантические типы }
#   OUTPUTS: { dict колонка -> [тип|null, уверенность] - формат кэша голосов }
#   SIDE_EFFECTS: сетевой вызов
# END_CONTRACT: classifier_ask
def classifier_ask(client: LLMClient, meta: dict, allowed: list[str],
                   batch: int = 20) -> dict:
    # Колонки идут пачками, а не одним запросом: на реальной схеме их сотни,
    # и один огромный промпт упирается и в контекст модели, и в таймаут.
    # Пачка ещё и локализует сбой - потерян голос по двадцати колонкам, не по всем.
    if len(meta) > batch:
        items = list(meta.items())
        out: dict = {}
        for i in range(0, len(items), batch):
            out.update(classifier_ask(client, dict(items[i:i + batch]), allowed, batch))
        return out
    prompt = (
        f"Допустимые типы: {', '.join(sorted(allowed))}.\n"
        + _CLASSIFY_RULES +
        "Если тип не определяется по имени и статистике - верни null.\n"
        "Не угадывай: неуверенный ответ дороже пропуска, колонку разберёт человек.\n"
        "Формат ответа - ОБЪЕКТ, ключ которого равен полному имени колонки:\n"
        '{"схема.таблица.колонка": ["тип", 0.9], "схема.таблица.другая": [null, 0]}\n'
        "Массив без имён колонок недопустим: порядок не гарантируется.\n"
        f"Колонки:\n{json.dumps(meta, ensure_ascii=False, indent=1)}"
    )
    raw = client.json_chat(prompt, _CLASSIFY_SYSTEM, role="classify")
    out: dict = {}
    if meta and not _as_pairs(raw):
        # Позиционный массив без имён - самый частый способ ошибиться у мелких
        # моделей. Сопоставлять его с колонками по порядку нельзя: молчаливое
        # смещение на одну колонку разметит СНИЛС как фамилию. Одна попытка
        # переспросить, дальше голос считается несостоявшимся.
        raw = client.json_chat(
            prompt + "\nПредыдущий ответ был отвергнут: имена колонок обязательны.",
            _CLASSIFY_SYSTEM, role="classify-retry")
    for column, value in _as_pairs(raw):
        column = _match_column(str(column), meta)
        if column is None or not isinstance(value, list) or len(value) != 2:
            continue                       # мусор от модели молча не проходит
        sem, conf = value
        if sem is not None and sem not in allowed:
            sem, conf = None, 0.0          # тип вне словаря = «не знаю»
        out[column] = [sem, float(conf) if sem else 0.0]
    return out


def _as_pairs(raw):
    """Ответ модели -> пары (колонка, [тип, уверенность]).

    Форма ответа у моделей плавает: объект, массив объектов, массив троек.
    Разбирать это здесь дешевле, чем требовать от модели дисциплины: цена
    ошибки разбора - потерянный голос, а он и так не единственный."""
    if isinstance(raw, dict):
        return list(raw.items())
    pairs = []
    for item in raw or []:
        if isinstance(item, dict):
            col = item.get("column") or item.get("name") or item.get("колонка")
            if col:
                sem = item.get("type") or item.get("sem_type") or item.get("тип")
                conf = item.get("confidence", item.get("уверенность", 0.0))
                pairs.append((col, [sem, conf]))
            elif len(item) == 1:
                # самая частая форма у локальных моделей: [{"колонка": [тип, conf]}]
                pairs.extend(item.items())
        elif isinstance(item, list) and len(item) == 3:
            pairs.append((item[0], [item[1], item[2]]))
    return pairs


def _match_column(name: str, meta: dict) -> str | None:
    """Модель роняет префикс схемы или таблицы — сопоставляем по хвосту имени.
    Неоднозначное совпадение отбрасывается: угадывать, о какой колонке речь,
    хуже, чем потерять голос."""
    if name in meta:
        return name
    tail = name.rsplit(".", 1)[-1]
    hits = [q for q in meta if q.rsplit(".", 1)[-1] == tail]
    return hits[0] if len(hits) == 1 else None


_CORPUS_SYSTEM = (
    "Ты порождаешь словари вымышленных, но правдоподобных русских значений для "
    "обезличивания баз данных. Реальных людей называть нельзя. "
    "Отвечай ОДНИМ JSON-массивом строк без пояснений."
)

_CORPUS_TASK = {
    "family": "русские фамилии в мужской форме, именительный падеж, строчными",
    "name_m": "русские мужские имена, именительный падеж, строчными",
    "name_f": "русские женские имена, именительный падеж, строчными",
    "patronymic_m": "русские мужские отчества, строчными",
    "patronymic_f": "русские женские отчества, строчными",
    "city": "названия российских городов, строчными",
    "region": "названия российских регионов, строчными",
    "street": "названия улиц без слова «улица», строчными",
    "org": "вымышленные названия компаний без организационно-правовой формы",
    "phone_code": "трёхзначные коды мобильных операторов, только цифры",
    "email_domain": "доменные имена вымышленных почтовых серверов",
}


# START_CONTRACT: corpus_generate
#   PURPOSE: Роль 2. Материал замен порождается моделью с нуля - ни одного
#            настоящего значения она не видит (§4.4).
#   INPUTS: { client, kind: ключ корпуса, count: сколько значений }
#   OUTPUTS: { list[str] - значения; проверяет их M-CORPUS, а не этот модуль }
#   SIDE_EFFECTS: сетевой вызов
# END_CONTRACT: corpus_generate
def corpus_generate(client: LLMClient, kind: str, count: int = 300) -> list[str]:
    task = _CORPUS_TASK.get(kind)
    if task is None:
        raise LLMUnavailable(f"нет задания для корпуса {kind!r}")
    raw = client.json_chat(f"Верни {count} значений: {task}. Без повторов.",
                           _CORPUS_SYSTEM, role=f"corpus:{kind}")
    return [str(v).strip().lower() for v in raw if str(v).strip()]


# START_CONTRACT: direct_map
#   PURPOSE: Роль 3. Осмысленная замена 1:1 для НЕ-ПДн значений (названия
#            контрагентов). Единственная роль, где модель видит значения из базы,
#            и она допущена только к колонкам, признанным не-ПДн (§3.1).
#   INPUTS: { client, values: список уникальных значений }
#   OUTPUTS: { dict исходное -> замена; неполный ответ достраивает вызывающий }
#   SIDE_EFFECTS: сетевой вызов
# END_CONTRACT: direct_map
def direct_map(client: LLMClient, values: list[str]) -> dict[str, str]:
    prompt = (
        "Замени каждое название вымышленным того же вида и близкой длины. "
        "Замены обязаны быть РАЗНЫМИ и не совпадать с исходником. "
        "Верни JSON-объект {исходное: замена}.\n"
        f"{json.dumps(values, ensure_ascii=False)}"
    )
    raw = client.json_chat(prompt, "Ты переименовываешь организации. Только JSON.",
                           role="direct")
    return {k: str(v) for k, v in (raw or {}).items()
            if k in set(values) and str(v).strip() and str(v) != k}


# START_CONTRACT: ner_verdict
#   PURPOSE: Роль 4. Третий эшелон свободного текста: правила и словарь не
#            уверены - решает модель. ЕДИНСТВЕННАЯ роль, видящая живой текст,
#            поэтому допускается только поставщик в контуре.
#   INPUTS: { client, fragment: спорный фрагмент текста }
#   OUTPUTS: { bool - являются ли персональными данными }
#   SIDE_EFFECTS: сетевой вызов
# END_CONTRACT: ner_verdict
def ner_verdict(client: LLMClient, fragment: str) -> bool | None:
    """True - персональные данные, False - нет, None - модель не ответила внятно.

    None критично: вызывающий трактует его как «не знаю» и записывает деградацию.
    Прежняя версия возвращала False на любой неразобранный ответ - и модель,
    отвечающая не тем словом, молча снимала защиту: фрагмент оставался в копии
    БЕЗ отметки, то есть хуже, чем при полностью отключённой модели."""
    client.require_local("ner_verdict")
    raw = client.chat(
        f"Фрагмент: «{fragment}»\nЭто имя человека (ФИО, обращение к человеку)? "
        f"Ответь одним словом: да или нет.",
        "Ты определяешь, содержит ли фрагмент имя человека. Одно слово: да или нет.",
        role="ner")
    answer = re.sub(r"<think>.*?</think>", "", raw, flags=re.S).strip().lower()
    if answer.startswith(("да", "yes", "true")):
        return True
    if answer.startswith(("нет", "no", "false")):
        return False
    return None


# Приёмка модели перед прогоном: роль 4 - защитный механизм, и негодная модель
# понижает защиту молча. Замерено: mistral-nemo:12b отвечает «нет» на «Мария
# Сидорова», то есть оставляет ФИО в копии.
NER_ACCEPTANCE = (
    ("Иванов Пётр Сергеевич", True), ("Мария Сидорова", True),
    ("Согласовал Иванова", True), ("Петрова А.И.", True),
    ("Заявку принял Аглая Востросаблина", True),
    ("Плановое обслуживание станка", False), ("Отгрузка вагонов", False),
    ("Ремонт кровли цеха", False), ("Инвентаризация склада", False),
    ("Замена подшипника насоса", False),
)


def ner_acceptance(client: LLMClient, threshold: float = 0.8) -> tuple[bool, str]:
    """Проверка пригодности модели на роль 4. Возвращает (годна, отчёт)."""
    hits = [(fragment, expected, ner_verdict(client, fragment))
            for fragment, expected in NER_ACCEPTANCE]
    ok = sum(1 for _, e, got in hits if got is e)
    wrong = [f for f, e, got in hits if got is not e]
    return (ok / len(hits) >= threshold,
            f"{ok}/{len(hits)}" + (f"; ошибки: {wrong[:3]}" if wrong else ""))

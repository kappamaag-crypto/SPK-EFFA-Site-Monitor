"""Public, read-only QA monitor. No credentials or page content are persisted."""
from __future__ import annotations

import datetime as dt
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, TimeoutError as BrowserTimeout
from pypdf import PdfReader

BASE = "https://spk-effa.ru"
CATALOGS = ["/blank/", "/ognezaschita/", "/veksa/"]
PRODUCTS = [
    ("Blank Universal", "/blank/universal.html"),
    ("Blank Finish", "/blank/finish.html"),
    ("ЭФФА А-01", "/ognezaschita/effa-a-01.html"),
    ("ЭФФА ЭП-150", "/ognezaschita/effa-ep-150.html"),
    ("VEKSA PR 10", "/veksa/pr-10.html"),
    ("VEKSA PP 11", "/veksa/pp-11.html"),
]
MAX_LINKS = 65
MAX_EXTERNAL = 10
MAX_PDFS = 12
MAX_PDF_BYTES = 18 * 1024 * 1024
TIMEOUT = 15
SENSITIVE_RE = re.compile(
    r"(?:^|[/_-])(admin|logout|login|signin|signup|register|cart|checkout|order|"
    r"unsubscribe|remove|delete|payment|pay|subscribe|request|submit|send|"
    r"callback|quote|api)(?:[/_.-]|$)", re.I
)


def safe_url(value: str, base: str = BASE) -> str | None:
    """Only public HTTP(S) URLs without params, fragments or embedded credentials."""
    if not isinstance(value, str) or not value.strip() or value.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    # Preserve page-relative resolution; only add '/' for a bare origin.
    root = base + "/" if not urlsplit(base).path else base
    candidate = urljoin(root, value.strip())
    try:
        p = urlsplit(candidate)
        if p.scheme != "https" or not p.hostname or p.username or p.password or p.query:
            return None
        hostname = p.hostname.lower().rstrip(".")
        if hostname in ("localhost", "127.0.0.1") or hostname.endswith((".local", ".internal")):
            return None
        if SENSITIVE_RE.search(p.path):
            return None
        # Paths themselves can accidentally carry credentials or private IDs.
        if re.search(r"(?i)(?:token|secret|signature|passwd|password|apikey|api-key|sessionid|access[-_]key)", p.path):
            return None
        if re.search(r"(?i)[a-f0-9]{28,}|[a-z0-9_-]{55,}", p.path):
            return None
        try:
            if not ipaddress.ip_address(hostname).is_global:
                return None
        except ValueError:
            pass
        return urlunsplit(("https", p.netloc.lower(), p.path or "/", "", ""))
    except (ValueError, TypeError):
        return None


def site_url(url: str) -> bool:
    return urlsplit(url).hostname in ("spk-effa.ru", "www.spk-effa.ru")


def public_dns(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        return bool(infos) and all(ipaddress.ip_address(info[4][0]).is_global for info in infos)
    except (OSError, ValueError):
        return False


def safe_request(session: requests.Session, url: str, *, limit: int = 200_000) -> tuple[dict, bytes]:
    """GET, bounded body, guarded redirects; no cookies or cross-request session state."""
    result = {"url": url, "status": "unverified", "http_status": None}
    if not safe_url(url) or not public_dns(urlsplit(url).hostname or ""):
        result["reason"] = "DNS недоступен или адрес не является публичным"
        return result, b""
    current = url
    try:
        for _ in range(5):
            # No cookies, auth, or environment proxy credentials.
            with session.get(current, timeout=TIMEOUT, stream=True, allow_redirects=False) as response:
                status = response.status_code
                if status in (301, 302, 303, 307, 308):
                    dest = safe_url(response.headers.get("Location", ""), current)
                    if not dest or not public_dns(urlsplit(dest).hostname or ""):
                        result["reason"] = "Небезопасный или неподтверждённый редирект"
                        return result, b""
                    current = dest
                    continue
                result.update(http_status=status, status="ok" if 200 <= status < 400 else "error")
                result["final_url"] = current
                result["content_type"] = response.headers.get("Content-Type", "").split(";")[0].lower()[:80]
                body = bytearray()
                for part in response.iter_content(chunk_size=65536):
                    if len(body) + len(part) > limit:
                        result["truncated"] = True
                        break
                    body.extend(part)
                return result, bytes(body)
        result["reason"] = "Слишком много редиректов"
    except (requests.RequestException, OSError) as exc:
        result["reason"] = type(exc).__name__
    return result, b""


def check_pdf(session: requests.Session, url: str) -> dict:
    info, content = safe_request(session, url, limit=MAX_PDF_BYTES)
    if info["status"] != "ok":
        return info
    info["bytes"] = len(content)
    if info.get("truncated"):
        info.update(status="unverified", reason="Размер PDF превышает лимит проверки")
        return info
    if not content.lstrip().startswith(b"%PDF-"):
        info.update(status="error", reason="Ответ не содержит заголовка PDF")
        return info
    try:
        info["pages"] = len(PdfReader(io.BytesIO(content), strict=False).pages)
        if info["pages"] == 0:
            info.update(status="error", reason="PDF не содержит страниц")
    except Exception:
        info.update(status="error", reason="PDF невозможно прочитать")
    if info["status"] == "ok" and info.get("content_type") not in ("application/pdf", "application/x-pdf"):
        info["warning"] = "Content-Type отличается от application/pdf"
    return info


def site_basics() -> dict:
    out = {"dns": "unverified", "https_certificate": "unverified"}
    if not public_dns("spk-effa.ru"):
        out["dns_reason"] = "DNS не разрешился в публичный адрес из GitHub runner"
        return out
    out["dns"] = "ok"
    try:
        context = ssl.create_default_context()
        with socket.create_connection(("spk-effa.ru", 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname="spk-effa.ru") as tls:
                cert = tls.getpeercert()
                expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
                out["https_certificate"] = "ok" if expires > dt.datetime.now(dt.timezone.utc) else "error"
                out["certificate_expires_utc"] = expires.isoformat()
    except (OSError, ssl.SSLError, KeyError) as exc:
        out["https_certificate_reason"] = type(exc).__name__
    return out


def inspect_page(page, url: str, *, detail: bool) -> dict:
    result = {"url": url, "status": "unverified"}
    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=25000)
        if not response:
            result["reason"] = "Браузер не получил HTTP-ответ"
            return result
        result["http_status"] = response.status
        result["status"] = "ok" if 200 <= response.status < 400 else "error"
        # Persist only presence/match flags, not free-text page content (possible PII).
        result["title_present"] = bool(page.title().strip())
        headings = [x.strip() for x in page.locator("h1").all_text_contents()[:3]]
        result["h1_present"] = bool([x for x in headings if x])
        ref_names = [name for name, path in PRODUCTS if urlsplit(url).path == path]
        result["h1_matches_known_product"] = (any(name.casefold() in heading.casefold() for name in ref_names for heading in headings) if ref_names else None)
        final_url = safe_url(page.url)
        result["redirected_to"] = final_url if final_url and final_url != url else None
        result["links"] = page.locator("a[href]").evaluate_all("es => es.map(e => ({href:e.getAttribute('href'), text:(e.innerText||'').trim().slice(0,100)}))")
        if detail:
            # The public H1 identifies the randomly selected SEO product.
            # Keep only a short, restricted title; never save arbitrary page text.
            result["product_title"] = clean_product_title(headings[0]) if headings else None
            result["breadcrumbs"] = page.locator("[aria-label*=breadcrumb i], .breadcrumb, .breadcrumbs").count() > 0
            result["images"] = page.locator("img").evaluate_all("es => es.slice(0,30).map(e => ({url:e.getAttribute('src')||'', alt_present:!!(e.getAttribute('alt')||'').trim(), complete:e.complete, loaded:e.naturalWidth>0, lazy:e.loading==='lazy'}))")
            result["description_present"] = page.locator("meta[name=description]").count() > 0
            result["specification_present"] = page.locator("table, dl, [class*=characteristic], [class*=specification]").count() > 0
            result["price_signal_present"] = page.locator("body").evaluate(r"e => /(?:₽|\bруб\.?|цена)/i.test(e.innerText)")
            # Keep categories rather than free-form CTA text, which may contain contact details.
            result["cta_types"] = page.locator("button, a.button, a.btn, input[type=submit]").evaluate_all("es => [...new Set(es.slice(0,25).map(e => {const t=(e.innerText||e.value||'').toLowerCase(); return /кп|расч[её]т/.test(t)?'КП/расчёт':/документ/.test(t)?'Документация':/заказ|купить/.test(t)?'Заказ':t.trim()?'Прочее':''}).filter(Boolean))]")
            # Never persist raw image src: signed links can contain private query tokens.
            for img in result["images"]:
                img["url"] = safe_url(img["url"], url) or "[скрыто]"
            result["warnings"] = []
            for img in result["images"]:
                if not img["alt_present"]:
                    result["warnings"].append("Изображение без содержательного alt")
                if img["complete"] and not img["loaded"]:
                    result["warnings"].append("Изображение не загрузилось")
        return result
    except BrowserTimeout:
        result["reason"] = "Timeout браузера"
    except Exception as exc:
        result["reason"] = type(exc).__name__
    return result


def clean_product_title(value: str) -> str | None:
    """Keep only plausible, bounded public product names from catalog H1 tags."""
    title = " ".join(value.split())
    if not 4 <= len(title) <= 100 or not any(c.isalpha() for c in title):
        return None
    if not re.fullmatch(r"[\w\s+().№/\-–—]+", title, flags=re.UNICODE):
        return None
    if re.search(r"(?i)\b(email|телефон|адрес|контакты|тел\.)\b", title):
        return None
    return title


def choose_control_candidate(candidates: list[str], previous: dict) -> tuple[str | None, int]:
    """Choose from discovered catalog pages; hold each choice for two audits.

    Randomize after the comparison run, and avoid the previous choice when
    another catalog product exists. Empty live catalogs never become SEO claims.
    """
    choices = sorted(set(candidates))
    if not choices:
        return None, 0
    old = previous.get("control_product") or {}
    old_url = old.get("url")
    if old_url in choices and old.get("consecutive_runs") == 1:
        return old_url, 2
    pool = [url for url in choices if url != old_url] or choices
    return secrets.choice(pool), 1


# Two exact queries for each engine, with separate results; no CAPTCHA bypass.
SEARCH_ENGINES = {
    "Bing": ("https://www.bing.com/search", {"setlang": "ru-RU"}),
    "Google": ("https://www.google.com/search", {"hl": "ru", "gl": "ru", "num": "10"}),
    "Яндекс": ("https://yandex.ru/search/", {"lr": "172"}),  # Ufa fixed region.
}


def organic_links(engine: str, soup: BeautifulSoup) -> list[str]:
    """Best-effort organic results only. Unrecognized pages yield no positions."""
    links = []
    if engine == "Bing":
        for result in soup.select("li.b_algo"):
            anchor = result.select_one("h2 a[href]")
            if anchor:
                links.append(anchor.get("href", ""))
    elif engine == "Google":
        container = soup.select_one("#search")
        if container is None:
            return []
        # Google uses <h3> for organic result headlines. Sponsored modules
        # and ads are explicitly excluded, but unknown layouts remain unverified.
        for heading in container.select("h3"):
            if heading.find_parent(attrs={"data-text-ad": True}) or heading.find_parent(id="tads"):
                continue
            anchor = heading.find_parent("a", href=True)
            if anchor:
                links.append(anchor.get("href", ""))
    elif engine == "Яндекс":
        for result in soup.select("li.serp-item, div.serp-item"):
            if (result.select_one(".serp-adv, [data-fast=\"adv\"], [data-ad=\"true\"]")
                    or "serp-item_type_adv" in result.get("class", [])):
                continue
            anchor = result.select_one(
                "a.OrganicTitle-Link[href], a.organic__url[href], "
                "a.OrganicTitle-LinkText[href], h2 a[href]"
            )
            if anchor:
                links.append(anchor.get("href", ""))
    return links


def search_engine(session: requests.Session, engine: str, query: str, exact_path: str) -> dict:
    """One public GET per query per engine; no CAPTCHA workarounds or ad clicks."""
    endpoint, base_params = SEARCH_ENGINES[engine]
    parameters = {**base_params, ("text" if engine == "Яндекс" else "q"): query}
    result = {"engine": engine, "query": query, "settings": base_params,
              "status": "unverified", "target_path": exact_path,
              "exact_product_position": None, "domain_positions": []}
    try:
        # Isolated, credential-free request. A search engine may deny automated access.
        with session.get(endpoint, params=parameters, timeout=TIMEOUT,
                         headers={"User-Agent": "Mozilla/5.0 (compatible; SPK-EFFA-Monitor/1.0)"},
                         stream=True, allow_redirects=False) as response:
            if response.status_code != 200:
                result["reason"] = f"HTTP {response.status_code}"
                return result
            content = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                if len(content) + len(chunk) > 500_000:
                    break
                content.extend(chunk)
        soup = BeautifulSoup(bytes(content), "html.parser")
        if any(word in soup.get_text(" ", strip=True).lower()[:2500]
               for word in ("verify you are human", "unusual traffic", "докажите, что вы не робот")):
            result["reason"] = "Поисковик запросил подтверждение пользователя"
            return result
        raw = organic_links(engine, soup)
        urls: list[str] = []
        for url in raw:
            safe = safe_url(url, endpoint)
            if safe and safe not in urls:
                urls.append(safe)
        if len(urls) < 3:
            result["reason"] = "Недостаточно распознанных органических результатов (другая разметка или блокировка)"
            return result
        result["status"] = "ok"
        result["organic_results_count"] = len(urls)
        for position, url in enumerate(urls[:20], 1):
            if site_url(url):
                path = urlsplit(url).path
                result["domain_positions"].append({"position": position, "path": path})
                if path == exact_path and result["exact_product_position"] is None:
                    result["exact_product_position"] = position
    except requests.RequestException as exc:
        result["reason"] = type(exc).__name__
    return result


def comparison(report: dict, previous: dict) -> dict:
    result = {"baseline": not bool(previous), "serp": [], "fixed_errors": [], "new_errors": []}
    if not previous:
        return result
    old_serp = {(x.get("engine"), x.get("query"), str(x.get("settings")), x.get("target_path")): x for x in previous.get("search", [])}
    for new in report["search"]:
        old = old_serp.get((new["engine"], new["query"], str(new.get("settings")), new.get("target_path")))
        old_pos = old.get("exact_product_position") if old and old.get("status") == "ok" else None
        new_pos = new.get("exact_product_position") if new.get("status") == "ok" else None
        result["serp"].append({"engine": new["engine"], "query": new["query"], "old_position": old_pos, "new_position": new_pos,
                               "change": old_pos - new_pos if old_pos is not None and new_pos is not None else None})
    old_errors = {(x["url"], x.get("http_status")) for x in previous.get("links", []) + previous.get("pdfs", []) if x.get("status") == "error"}
    new_errors = {(x["url"], x.get("http_status")) for x in report["links"] + report["pdfs"] if x.get("status") == "error"}
    result["fixed_errors"] = sorted(url for url, _ in old_errors - new_errors if any(y.get("url") == url and y.get("status") == "ok" for y in report["links"] + report["pdfs"]))
    result["new_errors"] = sorted(url for url, _ in new_errors - old_errors)
    return result


def run() -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    d = now.astimezone(dt.timezone(dt.timedelta(hours=5))).date()
    previous_file = Path("reports/latest.json")
    try:
        prev = json.loads(previous_file.read_text(encoding="utf-8")) if previous_file.exists() else {}
    except (ValueError, OSError):
        prev = {}
    landing_urls = [BASE + "/"] + [BASE + path for path in CATALOGS]
    report = {"timestamp_utc": now.isoformat(), "date_ufa": d.isoformat(), "base": BASE,
              "time_ufa": now.astimezone(dt.timezone(dt.timedelta(hours=5))).isoformat(),
              "checks": site_basics(), "pages": [], "links": [], "pdfs": [], "search": [],
              "selected_products": [], "control_product": None,
              "catalog_candidates_found": 0,
              "limitations": ["Достоверность позиций ограничена публичной выдачей: регион и разметка могут меняться.",
                              "В случае блокировки поисковой выдачи позиции помечаются как непроверенные.",
                              "Содержимое страниц, cookie, формы и персональные данные не сохраняются."]}
    links: set[str] = set()
    pdfs: set[str] = set()
    discovered: set[str] = set()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(locale="ru-RU", ignore_https_errors=False, service_workers="block")
            # Never let the browser submit forms or make other unsafe-method requests.
            context.route("**/*", lambda route: route.continue_() if route.request.method in ("GET", "HEAD", "OPTIONS") else route.abort())
            def visit(url: str, detail: bool):
                page = context.new_page()
                record = inspect_page(page, url, detail=detail)
                for link in record.pop("links", []):
                    href = safe_url(link.get("href", ""), url)
                    if not href:
                        continue
                    up = urlsplit(href).path
                    if up.lower().endswith(".pdf"):
                        pdfs.add(href)
                    else:
                        links.add(href)
                        if url in landing_urls[1:] and site_url(href) and re.match(r"^/(blank|ognezaschita|veksa)/[^/]+\.html$", up):
                            discovered.add(href)
                report["pages"].append(record)
                page.close()
                return record
            for url in landing_urls:
                visit(url, False)
            product_map = {BASE + path: name for name, path in PRODUCTS}
            # Never select an unverified hardcoded product as a live catalog find.
            candidates = sorted(discovered)
            report["catalog_candidates_found"] = len(candidates)
            control_url, streak = choose_control_candidate(candidates, prev)
            chosen = [control_url] if control_url else []
            alternatives = [url for url in candidates if url != control_url]
            if alternatives:
                chosen.append(secrets.choice(alternatives))
            for url in chosen:
                result = visit(url, True)
                title = result.get("product_title") or product_map.get(url)
                report["selected_products"].append({
                    "name": title or "Название не подтверждено", "url": url
                })
                if url == control_url and result.get("status") == "ok" and title:
                    report["control_product"] = {
                        "name": title, "url": url,
                        "consecutive_runs": streak, "source": "live_catalog",
                    }
            if not candidates:
                report["limitations"].append(
                    "Не обнаружены карточки в доступных каталогах: случайный SEO-товар не выбран."
                )
            elif not report["control_product"]:
                report["limitations"].append(
                    "Выбранная карточка не открылась или не содержит корректного названия; SEO-поиск пропущен."
                )
            browser.close()
    except Exception as exc:
        report["limitations"].append("Браузер недоступен: " + type(exc).__name__)
    known = {"/blank/universal.html": "/docs/blank/Blank_Universal.pdf",
             "/blank/finish.html": "/docs/blank/Blank_Finish.pdf",
             "/ognezaschita/effa-a-01.html": "/docs/effa/EFFA_A-01.pdf",
             "/ognezaschita/effa-ep-150.html": "/docs/effa/EFFA_EP150_and_EP150K.pdf",
             "/veksa/pr-10.html": "/docs/veksa/VEKSA_PR_10.pdf",
             "/veksa/pp-11.html": "/docs/veksa/VEKSA_PP_11.pdf"}
    for item in report["selected_products"]:
        path = urlsplit(item["url"]).path
        if path in known:
            pdfs.add(BASE + known[path])
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": "SPK-EFFA-Public-QA/1.0", "Accept": "*/*"})
    # We do not fetch endpoint links that may cause a state change, nor URLs with query parameters.
    internal = sorted(x for x in links if site_url(x) and x not in landing_urls and x not in [p["url"] for p in report["selected_products"]])[:MAX_LINKS]
    external = sorted(x for x in links if not site_url(x))[:MAX_EXTERNAL]
    for url in internal + external:
        item, _ = safe_request(session, url, limit=2048)
        report["links"].append(item)
    for url in sorted(x for x in pdfs if site_url(x))[:MAX_PDFS]:
        report["pdfs"].append(check_pdf(session, url))
    control = report.get("control_product")
    if control:
        exact_path = urlsplit(control["url"]).path
        for engine in SEARCH_ENGINES:
            for query in [f'"{control["name"]}"', f'"{control["name"]}" spk-effa.ru']:
                report["search"].append(search_engine(session, engine, query, exact_path))
    session.close()
    report["comparison"] = comparison(report, prev)
    return report


def write_report(report: dict):
    out = Path("reports")
    (out / "history").mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    (out / "latest.json").write_text(payload, encoding="utf-8")
    (out / "history" / (report["date_ufa"] + ".json")).write_text(payload, encoding="utf-8")
    pages_ok = sum(x["status"] == "ok" for x in report["pages"])
    errors = [x for kind in ("pages", "links", "pdfs") for x in report[kind] if x["status"] == "error"]
    unver = sum(x.get("status") == "unverified" for kind in ("pages", "links", "pdfs", "search") for x in report[kind])
    rows = [f"# QA-аудит spk-effa.ru — {report['date_ufa']}", "", f"Время Уфа: {report['time_ufa']} (UTC+5)",
            f"Страницы: успешно {pages_ok}/{len(report['pages'])}; подтверждённые HTTP/PDF-ошибки: {len(errors)}; непроверено: {unver}.",
            "", "## Проверенные страницы"]
    for item in report["pages"]:
        rows.append(f"- {item['url']} — {item['status']} (HTTP {item.get('http_status', '—')})")
    rows += ["", "## Выбранные товары (ротация)"]
    for item in report["selected_products"]:
        card = next((p for p in report["pages"] if p["url"] == item["url"]), {})
        rows.append(f"- {item['name']} — {item['url']}; H1: {card.get('h1_present', 'не проверено')}; "
                    f"совпадение H1: {card.get('h1_matches_known_product', 'не проверено')}; "
                    f"описание: {card.get('description_present', 'не проверено')}; "
                    f"характеристики: {card.get('specification_present', 'не проверено')}; "
                    f"ценовой признак: {card.get('price_signal_present', 'не проверено')}; "
                    f"CTA: {', '.join(card.get('cta_types', [])) or 'не обнаружены'}")
    rows += ["", "## PDF"]
    for item in report["pdfs"]:
        rows.append(f"- {item['url']} — {item['status']}; HTTP {item.get('http_status', '—')}; страницы: {item.get('pages', '—')}; тип: {item.get('content_type', '—')}")
    rows += ["", "## Поисковая видимость: Bing, Google, Яндекс"]
    control = report.get("control_product")
    if control:
        rows.append(f"Случайный контрольный товар: **{control['name']}** — {control['url']} "
                    f"(проверка {control['consecutive_runs']}/2); кандидатов каталога: {report['catalog_candidates_found']}.")
    else:
        rows.append("Контрольный товар не выбран: каталог или карточка не проверены; запросы не выполнялись.")
    for item in report["search"]:
        pos = item.get("exact_product_position") if item["status"] == "ok" else "не установлена"
        rows.append(f"- **{item['engine']}** `{item['query']}` — {item['status']}; позиция карточки: {pos}; "
                    f"другие страницы домена: {item.get('domain_positions', [])}; "
                    f"ограничение: {item.get('reason', 'нет')}")
    rows += ["", "## Сравнение с предыдущим прогоном"]
    comp = report["comparison"]
    if comp.get("baseline"):
        rows.append("- Базовая точка, предыдущих результатов нет.")
    for item in comp.get("serp", []):
        delta = item.get("change")
        rows.append(f"- **{item['engine']}** `{item['query']}`: раньше {item.get('old_position')}, сейчас {item.get('new_position')}; "
                    f"изменение: {delta if delta is not None else 'несопоставимо'}")
    rows.append("- Новые подтверждённые ошибки ссылок/PDF: " + (", ".join(comp.get("new_errors", [])) or "нет"))
    rows.append("- Подтверждённые исправления ссылок/PDF: " + (", ".join(comp.get("fixed_errors", [])) or "нет"))
    rows += ["", "## Подтверждённые ошибки HTTP/PDF"]
    for item in errors[:80]:
        rows.append(f"- {item['url']} — HTTP {item.get('http_status', '—')}; {item.get('reason', '')}")
    if not errors:
        rows.append("- Новых подтверждённых HTTP/PDF-ошибок в проверенной выборке нет.")
    rows += ["", "## Предупреждения"]
    warns = []
    for item in report["pages"]:
        for w in sorted(set(item.get("warnings", []))):
            warns.append(f"{item['url']}: {w}")
        if item.get("redirected_to"):
            warns.append(f"{item['url']}: редирект на {item['redirected_to']}")
    for item in report["pdfs"]:
        if item.get("warning"):
            warns.append(f"{item['url']}: {item['warning']}")
    rows += ["- " + w for w in warns[:75]] if warns else ["- Нет зафиксированных предупреждений в проверенной выборке."]
    rows += ["", "## Ограничения и непроверенные элементы"] + ["- " + x for x in report["limitations"]]
    for kind in ("pages", "links", "pdfs", "search"):
        for item in report[kind]:
            if item["status"] == "unverified":
                rows.append("- " + item.get("url", item.get("query", "?")) + ": " + item.get("reason", "нет подтверждённого ответа"))
    (out / "latest.md").write_text("\n".join(rows) + "\n", encoding="utf-8")


if __name__ == "__main__":
    write_report(run())
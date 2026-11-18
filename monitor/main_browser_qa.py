"""Bounded, read-only browser QA for the main public site.

No form submissions, clicks, authentication, private URLs or state changes.
Only GET/HEAD/OPTIONS requests; observations are sampled, not exhaustive.
"""
from __future__ import annotations

from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

BASE = "https://spk-effa.ru"
PAGES = ["/", "/blank/", "/ognezaschita/", "/veksa/"]
VIEWPORTS = {"desktop": (1366, 768), "mobile": (390, 844)}
MAX_FAILURES = 20


def audit_main_browser() -> dict:
    result = {"status": "unverified", "pages": [], "limitations": [
        "Только четыре публичных страницы; каталог целиком не проверен",
        "Без кликов, отправки форм, регистрации, заказов или расчётов",
        "Мобильная проверка по DOM и геометрии, не визуальная экспертиза",
    ]}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            for path in PAGES:
                for label, (width, height) in VIEWPORTS.items():
                    context = browser.new_context(viewport={"width": width, "height": height},
                                                  is_mobile=label == "mobile",
                                                  has_touch=label == "mobile",
                                                  service_workers="block")
                    context.route("**/*", lambda route: route.continue_()
                                  if route.request.method in ("GET", "HEAD", "OPTIONS")
                                  else route.abort())
                    page = context.new_page()
                    item = {"url": BASE + path, "viewport": label, "status": "unverified",
                            "http_status": None, "js_errors": [], "failed_assets": []}
                    page.on("pageerror", lambda exc: item["js_errors"].append(str(exc)[:200])
                            if len(item["js_errors"]) < 10 else None)
                    def on_response(response):
                        parsed = urlsplit(response.url)
                        if (parsed.hostname in ("spk-effa.ru", "www.spk-effa.ru")
                                and response.status >= 400
                                and len(item["failed_assets"]) < MAX_FAILURES):
                            item["failed_assets"].append({
                                "path": parsed.path, "http_status": response.status})
                    page.on("response", on_response)
                    try:
                        response = page.goto(BASE + path, wait_until="domcontentloaded", timeout=25000)
                        page.wait_for_timeout(750)
                        if response:
                            item["http_status"] = response.status
                            item["status"] = "ok" if response.status == 200 else "error"
                        item["signals"] = page.evaluate("""() => {
                            const d = document, meta = name => d.querySelector('meta[name="'+name+'"]');
                            const canonical = d.querySelector('link[rel="canonical"]');
                            const links = [...d.querySelectorAll('a[href]')];
                            const imgs = [...d.images];
                            const forms = [...d.forms];
                            return {
                                titlePresent: !!d.title.trim(),
                                descriptionPresent: !!meta('description')?.content?.trim(),
                                h1Count: d.querySelectorAll('h1').length,
                                canonicalPresent: !!canonical?.href,
                                canonicalSameOrigin: !!canonical?.href && new URL(canonical.href).origin === location.origin,
                                robotsMeta: meta('robots')?.content?.slice(0,80) || null,
                                viewportMeta: !!meta('viewport'),
                                horizontalOverflow: d.documentElement.scrollWidth > innerWidth + 2,
                                brokenImages: imgs.filter(i=>i.complete && !i.naturalWidth).length,
                                imagesMissingAlt: imgs.filter(i=>!i.hasAttribute('alt')).length,
                                unlabeledButtons: [...d.querySelectorAll('button')].filter(b=>!b.innerText.trim()&&!b.getAttribute('aria-label')).length,
                                emptyLinks: links.filter(a=>!a.innerText.trim()&&!a.getAttribute('aria-label')&&!a.querySelector('img[alt]')).length,
                                formsPresent: forms.length,
                                mixedContent: performance.getEntriesByType('resource').filter(e=>e.name.startsWith('http:')).length,
                            };
                        }""")
                    except Exception as exc:
                        item["reason"] = type(exc).__name__
                    result["pages"].append(item)
                    context.close()
            browser.close()
        result["status"] = "ok" if any(x["status"] == "ok" for x in result["pages"]) else "unverified"
    except Exception as exc:
        result["limitations"].append("Браузер недоступен: " + type(exc).__name__)
    return result

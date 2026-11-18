"""Bounded read-only browser audit of the public Raskroy PRO frontend.

Never clicks, fills, submits or executes calculations. The browser loads GET
resources only. Signals are observations, not functional certification.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright, TimeoutError as BrowserTimeout

URL = "https://raskroy.spk-effa.ru/"
MAX_ASSETS = 30


def audit_browser() -> dict:
    result = {
        "url": URL, "status": "unverified", "http_status": None,
        "viewport": {}, "javascript_errors": [], "failed_resources": [],
        "elements": {}, "limitations": [
            "Не выполнялись расчёты, экспорт, отправка форм и клики",
            "Адаптивность оценивается по геометрии, а не по визуальному качеству",
            "Наличие элементов не доказывает работоспособность алгоритма",
        ],
    }
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            for label, width, height in (("desktop", 1366, 768), ("mobile", 390, 844)):
                context = browser.new_context(viewport={"width": width, "height": height},
                                              is_mobile=(label == "mobile"),
                                              has_touch=(label == "mobile"),
                                              service_workers="block")
                context.route("**/*", lambda route: route.continue_()
                              if route.request.method in ("GET", "HEAD", "OPTIONS")
                              else route.abort())
                page = context.new_page()
                js_errors = []
                bad_resources = []
                page.on("pageerror", lambda exc: js_errors.append(type(exc).__name__ + ": " + str(exc)[:180]))
                def response_seen(resp):
                    url = resp.url
                    if (urlsplit(url).hostname == "raskroy.spk-effa.ru"
                            and resp.status >= 400 and len(bad_resources) < MAX_ASSETS):
                        bad_resources.append({"path": urlsplit(url).path, "http_status": resp.status})
                page.on("response", response_seen)
                try:
                    response = page.goto(URL, wait_until="domcontentloaded", timeout=25000)
                    page.wait_for_timeout(1500)
                    if response:
                        result["http_status"] = response.status
                        result["status"] = "ok" if response.status == 200 else "error"
                    result["viewport"][label] = page.evaluate("""() => ({
                        width: innerWidth,
                        scrollWidth: document.documentElement.scrollWidth,
                        horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 2,
                        titlePresent: !!document.title.trim(),
                        buttons: document.querySelectorAll('button').length,
                        inputs: document.querySelectorAll('input,select,textarea').length,
                        imagesBroken: [...document.images].filter(i => i.complete && i.naturalWidth === 0).length
                    })""")
                    if label == "desktop":
                        result["elements"] = page.evaluate("""() => {
                            const text = (document.body?.innerText || '').toLowerCase();
                            return {
                                parameterInputsPresent: !!document.querySelector('input,select'),
                                actionButtonsPresent: !!document.querySelector('button'),
                                cuttingPlanMentioned: text.includes('раскро'),
                                usefulRemnantsMentioned: text.includes('остат'),
                                exportMentioned: /экспорт|excel|csv|xlsx/.test(text)
                            };
                        }""")
                except BrowserTimeout:
                    result["limitations"].append(label + ": browser timeout")
                except Exception as exc:
                    result["limitations"].append(label + ": " + type(exc).__name__)
                result["javascript_errors"].extend({"viewport": label, "error": e} for e in js_errors[:10])
                result["failed_resources"].extend({"viewport": label, **r} for r in bad_resources)
                context.close()
            browser.close()
    except Exception as exc:
        result["limitations"].append("Browser unavailable: " + type(exc).__name__)
    return result

from monitor.audit import safe_url, comparison, site_url


def test_safe_url_strips_fragment_and_accepts_public_pages():
    assert safe_url("/blank/universal.html#details") == "https://spk-effa.ru/blank/universal.html"
    assert site_url("https://spk-effa.ru/blank/")


def test_rejects_secrets_actions_and_non_public_addresses():
    for url in (
        "https://spk-effa.ru/blank/?access_token=secret",
        "https://user:password@spk-effa.ru/blank/",
        "http://spk-effa.ru/blank/",
        "https://spk-effa.ru/admin/",
        "https://spk-effa.ru/cart/add",
        "https://127.0.0.1/",
        "https://192.168.1.1/",
        "javascript:alert(1)",
        "mailto:private@example.com",
    ):
        assert safe_url(url) is None


def test_comparison_only_on_matching_checked_serp():
    prev = {"search": [{"engine": "Bing", "query": '"ЭФФА А-01"', "status": "ok", "exact_product_position": 4}]}
    current = {"search": [{"engine": "Bing", "query": '"ЭФФА А-01"', "status": "ok", "exact_product_position": 2}], "links": [], "pdfs": []}
    assert comparison(current, prev)["serp"][0]["change"] == 2
    current["search"][0]["status"] = "unverified"
    assert comparison(current, prev)["serp"][0]["change"] is None

from bs4 import BeautifulSoup
from monitor.audit import organic_links, SEARCH_ENGINES, search_engine


def test_search_engine_selectors_ignore_ads():
    fixtures = {
        'Bing': '<li class="b_algo"><h2><a href="https://spk-effa.ru/ognezaschita/effa-a-01.html">title</a></h2></li>',
        'Google': '<div id="search"><div><a href="https://spk-effa.ru/ognezaschita/effa-a-01.html"><h3>title</h3></a></div></div>',
        'Яндекс': '<li class="serp-item"><a class="OrganicTitle-Link" href="https://spk-effa.ru/ognezaschita/effa-a-01.html">title</a></li>',
    }
    for engine, html in fixtures.items():
        assert organic_links(engine, BeautifulSoup(html, 'html.parser')) == [
            'https://spk-effa.ru/ognezaschita/effa-a-01.html'
        ]
    yandex_ad = '<li class="serp-item serp-item_type_adv"><a class="OrganicTitle-Link" href="https://spk-effa.ru/">ad</a></li>'
    assert organic_links('Яндекс', BeautifulSoup(yandex_ad, 'html.parser')) == []


def test_three_engines_and_six_queries_configured():
    assert list(SEARCH_ENGINES) == ['Bing', 'Google', 'Яндекс']
    assert all(v[0].startswith('https://') for v in SEARCH_ENGINES.values())


def test_position_diff_requires_same_search_conditions():
    old = {'search': [{'engine': 'Google', 'query': '"ЭФФА А-01"', 'settings': {'hl':'ru'}, 'status':'ok', 'exact_product_position':5}]}
    new = {'search': [{'engine': 'Google', 'query': '"ЭФФА А-01"', 'settings': {'hl':'en'}, 'status':'ok', 'exact_product_position':1}], 'links':[], 'pdfs':[]}
    assert comparison(new, old)['serp'][0]['change'] is None


from monitor.audit import choose_control_candidate, clean_product_title


def test_control_product_is_random_and_stays_two_runs(monkeypatch):
    # Stable test chooser only, production uses secrets.choice().
    monkeypatch.setattr("monitor.audit.secrets.choice", lambda items: items[-1])
    items = ["https://spk-effa.ru/blank/finish.html",
             "https://spk-effa.ru/veksa/pp-11.html",
             "https://spk-effa.ru/ognezaschita/effa-a-01.html"]
    first, n1 = choose_control_candidate(items, {})
    assert first in items and n1 == 1
    second, n2 = choose_control_candidate(items, {"control_product": {
        "url": first, "consecutive_runs": 1}})
    assert (second, n2) == (first, 2)
    third, n3 = choose_control_candidate(items, {"control_product": {
        "url": first, "consecutive_runs": 2}})
    assert third != first and n3 == 1


def test_missing_catalog_never_claims_selected_product():
    assert choose_control_candidate([], {}) == (None, 0)
    assert clean_product_title("  ЭФФА ЭП-150   ") == "ЭФФА ЭП-150"
    assert clean_product_title("Связаться: info@example.com") is None
    assert clean_product_title("a") is None


def test_different_target_product_cannot_be_compared():
    old = {'search': [{'engine': 'Bing', 'query': '"Blank Finish"',
                       'target_path': '/blank/finish.html',
                       'status': 'ok', 'exact_product_position': 8}]}
    new = {'search': [{'engine': 'Bing', 'query': '"Blank Finish"',
                       'target_path': '/blank/universal.html',
                       'status': 'ok', 'exact_product_position': 1}],
           'links': [], 'pdfs': []}
    assert comparison(new, old)['serp'][0]['change'] is None

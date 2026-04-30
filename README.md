# XssRecon

![Status](https://img.shields.io/badge/status-em%20desenvolvimento-brightgreen)

Scanner auxiliar para identificação e validação segura de possíveis vulnerabilidades de **Cross-Site Scripting (XSS)** e reflexões de entrada do usuário em aplicações web.

O script realiza crawling básico, identifica formulários, testa parâmetros de URL, envia canaries controlados e classifica possíveis reflexões conforme o contexto em que aparecem, como texto HTML, atributos, scripts, event handlers, URLs perigosas e sinks DOM/JS.

> [!NOTE]
> Projeto em desenvolvimento.
>
> Este repositório reúne script de apoio para validação técnica e triagem de segurança. O script pode passar por ajustes, refatoração e melhorias de precisão conforme novos cenários forem testados.

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

```text
Validação inicial de possíveis XSS refletidos
Revisão de formulários e parâmetros GET/POST
Identificação de sinks DOM/JS suspeitos
Apoio na triagem de achados automatizados
Geração de evidências em JSON ou CSV
Priorização de pontos que precisam de validação manual no navegador
```

Ele é útil principalmente quando a aplicação possui muitos formulários, parâmetros e páginas, reduzindo o trabalho manual de testar campo por campo.

---

## Limitação importante

O script consegue identificar reflexões e indicadores de risco, mas nem toda reflexão representa XSS explorável.

Sem o uso da opção de validação com navegador, o script não prova execução real de JavaScript. Por isso, alguns resultados são classificados como possíveis XSS ou indicadores DOM/JS e precisam de validação manual complementar.

Na prática: ele aponta onde tem fumaça. Para dizer que é incêndio, valide a execução.

---

## Requisitos

Dependências principais:

```bash
pip install requests beautifulsoup4 colorama
```

Para usar validação com navegador:

```bash
pip install playwright
python -m playwright install chromium
```

---

## Instalação

Clone o repositório e instale as dependências:

```bash
git clone https://github.com/harley-ghostie/xss_recon/
cd xss_recon
```
```bash
pip install requests beautifulsoup4 colorama
```

Para suporte a validação com navegador:

```bash
pip install playwright
python -m playwright install chromium
```

O `playwright` é necessário apenas se for usar a opção `--browser-validate`.

---

## Modo de uso

### Uso básico

Execute o script informando a URL inicial do alvo:

```bash
python3 XssRecon.py https://exemplo.com.br
```

---

### Uso com profundidade de crawling

Use `--depth` para definir até que nível o script deve seguir links internos e `--max-pages` para limitar a quantidade máxima de páginas visitadas.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --depth 2 \
  --max-pages 50
```

---

### Uso com timeout personalizado

Use `--timeout` para definir o tempo máximo de espera por requisição.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --timeout 10
```

---

### Uso exportando resultado em JSON

Use `--json-out` para salvar os resultados em um arquivo JSON.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --json-out resultado.json
```

---

### Uso exportando resultado em CSV

Use `--csv-out` para salvar os resultados em um arquivo CSV.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --csv-out resultado.csv
```

---

### Uso completo com JSON e CSV

```bash
python3 XssRecon.py https://exemplo.com.br \
  --depth 2 \
  --max-pages 50 \
  --timeout 10 \
  --json-out resultado.json \
  --csv-out resultado.csv
```

---

### Uso com cookie autenticado

Use `--cookie` quando for necessário testar áreas autenticadas da aplicação.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --cookie "PHPSESSID=valor; outro_cookie=valor" \
  --depth 2 \
  --max-pages 50 \
  --json-out resultado.json
```

---

### Uso ignorando erro SSL

Use `--insecure` quando o ambiente possuir certificado inválido, expirado, self-signed ou cadeia de confiança interna.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --insecure
```

---

### Uso com validação por navegador

Use `--browser-validate` para tentar confirmar execução real do payload em navegador controlado.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --browser-validate \
  --json-out resultado.json
```

---

### Uso com navegador visível

Use `--headed` junto com `--browser-validate` para acompanhar a execução com o navegador aberto.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --browser-validate \
  --headed
```

---

### Uso exibindo indicadores estáticos DOM/JS

Use `--show-static` para exibir também indicadores estáticos relacionados a possíveis sinks DOM/JS.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --show-static
```

---

### Uso desativando indicadores estáticos

Use `--no-static` para não coletar indicadores estáticos de JavaScript/DOM.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --no-static
```

---

### Uso desativando validação automática

Use `--no-auto-validate` quando quiser apenas fazer crawling e coleta, sem submeter testes automáticos em formulários e parâmetros.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --no-auto-validate
```

---

### Uso permitindo links externos

Use `--allow-external` apenas quando o escopo permitir seguir links fora do host inicial.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --allow-external
```

---

### Limitar testes por página

Use `--max-tests-per-page` para limitar a quantidade de testes automáticos por página analisada.

```bash
python3 XssRecon.py https://exemplo.com.br \
  --max-tests-per-page 10
```

---

## Uso ignorando erro SSL

```bash
python3 XssRecon.py https://exemplo.com.br --insecure
```

Use apenas quando o ambiente de teste possuir certificado inválido, expirado, self-signed ou ambiente interno com cadeia não confiável.

---

## Uso com validação por navegador

```bash
python3 XssRecon.py https://exemplo.com.br --browser-validate
```

Essa opção usa Chromium/Playwright para tentar confirmar se a reflexão realmente executa JavaScript no navegador.

---

## Uso com navegador visível

```bash
python3 XssRecon.py https://exemplo.com.br --browser-validate --headed
```

Útil para acompanhar visualmente a execução durante a validação.

---

## Uso exibindo indicadores estáticos DOM/JS

```bash
python3 XssRecon.py https://exemplo.com.br --show-static
```

Por padrão, os indicadores estáticos podem ser ocultados na tela para reduzir ruído. Essa opção exibe também pontos suspeitos no DOM e JavaScript.

---

## Principais opções

| Opção | Função |
|---|---|
| `url` | URL inicial do alvo. |
| `--depth` | Define a profundidade máxima do crawl. |
| `--max-pages` | Define o número máximo de páginas visitadas. |
| `--timeout` | Define o timeout das requisições. |
| `--cookie` | Permite informar cookie de sessão autenticada. |
| `--insecure` | Desativa verificação SSL. |
| `--allow-external` | Permite seguir links fora do host inicial. |
| `--no-auto-validate` | Desativa testes automáticos em forms e parâmetros. |
| `--show-static` | Exibe indicadores estáticos de DOM/JS. |
| `--no-static` | Não coleta indicadores estáticos. |
| `--max-tests-per-page` | Limita a quantidade de testes automáticos por página. |
| `--json-out` | Exporta o resultado em JSON. |
| `--csv-out` | Exporta o resultado em CSV. |
| `--browser-validate` | Usa Chromium/Playwright para validar execução real. |
| `--headed` | Executa o navegador visível durante a validação. |

## Parâmetros disponíveis

| Parâmetro | Função |
|---|---|
| `url` | URL inicial do alvo. |
| `--depth` | Define a profundidade máxima do crawling. |
| `--max-pages` | Define o número máximo de páginas visitadas. |
| `--timeout` | Define o timeout das requisições em segundos. |
| `--cookie` | Permite informar cookie de sessão autenticada. |
| `--insecure` | Desabilita a validação SSL. |
| `--allow-external` | Permite seguir links fora do host inicial. |
| `--no-auto-validate` | Desativa testes automáticos em formulários e parâmetros. |
| `--show-static` | Exibe indicadores estáticos de DOM/JS. |
| `--no-static` | Não coleta indicadores estáticos de DOM/JS. |
| `--max-tests-per-page` | Limita a quantidade de testes automáticos por página. |
| `--json-out` | Exporta o resultado em JSON. |
| `--csv-out` | Exporta o resultado em CSV. |
| `--browser-validate` | Usa navegador para tentar validar execução real de XSS. |
| `--headed` | Executa o navegador visível durante a validação com `--browser-validate`. |

---

## Saídas geradas

O script pode gerar resultados em:

```text
Tela/console
JSON
CSV
```

O JSON possui estrutura mais amigável para análise posterior, contendo resumo executivo, achados confirmados, possíveis XSS, indicadores DOM/JS e itens brutos.

Exemplo:

```bash
python3 XssRecon.py https://exemplo.com.br --json-out resultado_xss.json
```

Exemplo com CSV:

```bash
python3 XssRecon.py https://exemplo.com.br --csv-out resultado_xss.csv
```

---

## Classificação dos resultados

O script organiza os achados em três grupos principais:

| Classificação | Significado |
|---|---|
| `confirmed_xss` | XSS confirmado com execução no navegador. |
| `possible_xss` | Reflexão ou comportamento suspeito que precisa de validação complementar. |
| `static_indicator` | Indicador estático de possível risco no DOM/JS, sem exploração confirmada. |

---

## Diferença entre reflexão e XSS confirmado

Uma reflexão acontece quando a aplicação devolve na resposta algum valor enviado pelo usuário.

Isso não significa automaticamente que existe XSS. Para ser XSS confirmado, o payload precisa ser interpretado e executado pelo navegador em um contexto inseguro.

Exemplo simples:

```html
Olá, XSSRECON_ABC123
```

Isso é apenas reflexão.

Exemplo mais perigoso:

```html
<script>
var nome = 'XSSRECON_ABC123';
</script>
```

Esse contexto pode ser mais sensível e precisa de validação.

---

## Exemplo de fluxo recomendado

1. Executar o scan básico:

```bash
python3 XssRecon.py https://exemplo.com.br --json-out resultado.json
```

2. Revisar os possíveis XSS/reflexões.

3. Executar com validação por navegador:

```bash
python3 XssRecon.py https://exemplo.com.br --browser-validate --json-out resultado_browser.json
```

4. Validar manualmente os casos restantes.

5. Sanitizar evidências antes de publicar ou compartilhar.

---

## Observações de segurança ⚠️

Use este script apenas em ambientes próprios ou com autorização formal.

O objetivo é apoiar análise defensiva, pentest autorizado e validação controlada de vulnerabilidades. Não utilize contra terceiros sem permissão.

# Kostenoptimalisatie

## Regels

- Gezonde hourly checks produceren lege stdout, nul Telegram-bericht en nul modelcalls.
- Data verzamelen, thresholds, filtering, timestamps, deduplicatie en patroonstatistiek zijn deterministisch.
- Alleen een compacte afwijkingsset gaat naar Ling.
- DeepSeek wordt alleen gestart wanneer Ling `incident` of `needs_troubleshooting` retourneert.
- GLM is uitsluitend een technische DeepSeek-fallback.
- Luna wordt uitsluitend gebruikt bij inhoudelijke onzekerheid/complexiteit.
- OpenRouter-caching staat aan; automatische output is begrensd tot 450/700/800 tokens per tier.

## Testmetingen

| Test | Route | Calls | Gemeten routerkosten |
|---|---|---:|---:|
| A losse waarschuwing | Ling | 1 | $0.000013 |
| B technisch incident | Ling → DeepSeek | 2 | $0.000042 |
| C providerfout | Ling → gesimuleerde DeepSeek-fout → GLM | 2 | $0.000090 |
| D complex | Ling → DeepSeek → Luna | 3 | $0.000364 |
| E gezond | script | 0 | $0 |
| F 10.000 identieke regels | één dedupe-event → Ling → DeepSeek | 2 | $0.000040 |

Alle routertests samen gebruikten circa 3.950 tokens en $0.000638. Eén interactieve Hermes SSH-test met de volledige terminal-toolset gebruikte circa 13.823 tokens en kostte ongeveer $0.0008; dat laat zien waarom automatische controles buiten de algemene agentlus blijven.

## Budget

De bestaande OpenRouter-key heeft een lifetime key limit van $10 en auto-top-up staat uit. Interne calls loggen model, job, tokens, cachetokens, toolcalls, kosten en escalatiereden. Controleer periodiek Hermes `/insights` naast `cost-calls.jsonl`, omdat interactieve Hermes-calls in de Hermes-database en routercalls in het JSONL-bestand worden geboekt.

Een conservatieve schatting bij normale gezonde werking is vrijwel $0 voor de twee monitors. Zelfs met dagelijks één Ling-triage blijft de modelprijs ruim onder één dollar per maand; echte incidenten en vooral langdurige interactieve chats bepalen de praktijkkosten.


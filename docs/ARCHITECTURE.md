# Arquitetura — iris-cortex-module

Integração do **DFIR-IRIS v2.4.29** com o **Cortex 3.x/4.x** (análise feita sobre o código do Cortex
4.1.0, do Cortex4py e dos responders do repositório Cortex-Analyzers).

## 1. Análise técnica

### 1.1 DFIR-IRIS

| Tema | O que o código do IRIS mostra | Consequência |
|---|---|---|
| **Módulos** | Pacotes pip com `IrisModuleInterface`; configuração em *Advanced > Modules*; *manual hooks* por tipo de objeto (`on_manual_trigger_ioc`, `_evidence`, `_case`, `_alert`) aparecem nos menus nativos. Módulos não registram rotas nem UI. | Módulo pip + a mesma extensão web genérica já usada pelo `iris-email-module` (entry point `iris.web_extensions`, patch de ~70 linhas no core). |
| **IOCs** | Tabela `ioc` (valor, `ioc_type` com **160 tipos da taxonomia MISP**, `tlp`, tags, `custom_attributes`). Ligação a casos por `ioc_link` (um IOC pode estar em vários casos) e a alertas por `alert_iocs_association`. | O contexto (caso ou alerta) precisa ser validado junto com o IOC: um IOC só é analisado no contexto de um caso/alerta ao qual está ligado e ao qual o usuário tem acesso. |
| **Evidências** | `case_received_file`: **só metadados** (nome, hash, tamanho). O conteúdo de arquivos fica no **datastore** (`data_store_file`), e arquivos marcados como IOC/protegidos são armazenados em **zip com senha**. | Evidência → observáveis `hash` e `filename`. Arquivo → datastore, com extração segura do zip antes do envio. |
| **TLP** | `tlp`: 1 red, 2 amber, 3 green, 4 clear, 5 amber+strict. | Mapeado para o TLP numérico do Cortex (0–3); `amber+strict` → 3 (conservador). |
| **Exibição de enriquecimento** | `custom_attributes` com abas do tipo `html`, renderizadas no modal do IOC com sanitização (`sanitize_attribute_html`). É o mecanismo usado pelo módulo oficial do VirusTotal. | Resumo dos resultados gravado numa aba **Cortex** do IOC, visível na tela nativa. |
| **Timeline / histórico** | `CasesEvent` + `update_timeline_state(caseid, userid)`; `modification_history` em alertas; `user_activity`. | Cada execução gera evento na timeline do caso ou entrada no histórico do alerta. |
| **Criação de IOCs** | `app.business.iocs.create()` valida pelo schema, executa hooks, cria o vínculo com o caso e registra atividade. | Import de artefatos reutiliza essa função: nenhuma regra de negócio é duplicada. |
| **Assíncrono** | Celery 5 (serializer JSON) com *beat* embutido no worker (`celery worker -B`). | Polling dos jobs no worker; a interface só consulta o banco. Um reconciliador periódico retoma jobs órfãos. |
| **Permissões** | Bitmask fixa (`Permissions` enum): não é possível criar permissões novas sem alterar o core. | Papéis `cortex.*` mapeados para **grupos do IRIS** na configuração do módulo (seção 4). |

### 1.2 Cortex

Endpoints usados (de `conf/routes` do Cortex 4.1.0):

| Uso | Endpoint |
|---|---|
| Saúde / versão | `GET /api/status` |
| Validar credencial e organização | `GET /api/user/current` |
| Analyzers compatíveis com um tipo | `GET /api/analyzer/type/{dataType}` |
| Responders compatíveis com um tipo | `GET /api/responder/type/{dataType}` |
| Executar analyzer | `POST /api/analyzer/{id}/run` |
| Executar responder | `POST /api/responder/{id}/run` |
| Estado de um job | `GET /api/job/{id}` |
| Estado de vários jobs | `POST /api/job/status` |
| Relatório | `GET /api/job/{id}/report` |

Observações que moldam o desenho:

- **Execução**: JSON `{data, dataType, tlp, pap, message, parameters, label}`. Para arquivos, multipart com a
  parte `data` (arquivo) e o campo `_json` (os demais atributos). `force=1` ignora o cache de jobs do Cortex.
- **Responders** recebem em `data` um **objeto no formato TheHive** e declaram `dataTypeList` como
  `thehive:case_artifact`, `thehive:case`, `thehive:alert`… Os responders reais leem `data.data`, `data.dataType`,
  `data._type` (`case_artifact`/`case`/`alert`), `data._id`, `data.tags`, `data.tlp`, `data.title`, `data.caseId`.
  O módulo monta esses objetos a partir do IOC, caso ou alerta do IRIS.
- **Relatório**: `report.summary.taxonomies[] {level, namespace, predicate, value}`, `report.full` (livre, por
  analyzer), `report.artifacts[] {data, dataType, message, tags, tlp}` e, para responders,
  `report.operations[]` (`AddTagToArtifact`, `AddTagToCase`, `AddTagToAlert`, `CreateTask`, `AddCustomFields`…).
- **Segredos**: com uma API key de `orgAdmin`, `/api/analyzer` devolve `configuration` com as API keys dos
  serviços (VirusTotal, Shodan…). **A integração deve usar um usuário com papel `analyze`**, e o cliente descarta
  `configuration` de qualquer resposta.
- **TLP/PAP**: o limite de TLP de cada analyzer (`max_tlp`) está nessa configuração sensível e é aplicado só dentro
  do analyzer. **O IRIS aplica sua própria política** antes de enviar (ex.: nenhum TLP:RED sai para análise externa).
- **Organização**: não há cabeçalho de organização; ela é definida pela API key. Multi-tenant = uma API key por
  cliente do IRIS (`customer_api_keys`).

## 2. Arquitetura

```
DFIR-IRIS (Flask + Celery)
 ├── IrisCortexInterface ........ configuração + "Cortex Actions" nos menus (IOC, evidência, caso, alerta)
 ├── web extension ............... blueprint /cortex-module + iris_cortex.js
 │
 └── iris_cortex_module
      ├── core/ (sem IRIS/Flask)
      │    ├── settings ........... parâmetros, env, segredos, RBAC por grupos
      │    ├── client ............. Cortex API client (retry, erros tipados, limite de payload)
      │    ├── datatypes .......... tipos IRIS ⇄ Cortex, validação de valores, TLP/PAP
      │    ├── observables ........ Observable + objetos TheHive para responders
      │    ├── policy ............. papéis, TLP, responders privilegiados
      │    └── results ............ parser de relatório, taxonomias, artefatos, operações, sanitização
      └── integration/ (IRIS v2.4)
           ├── observables_db ..... carrega IOC/evidência/arquivo/caso/alerta e valida o contexto
           ├── access ............. acesso ao objeto + papéis cortex.*
           ├── service ............ catálogo, execução, resultados, import, operações, histórico
           ├── jobs ............... tasks Celery: poll por job + reconciliador periódico
           ├── audit .............. timeline, histórico do alerta, atividades, aba "Cortex" do IOC
           ├── models ............. iris_cortex_execution
           └── routes ............. API HTTP
                    │
                    ▼
                 Cortex ──► Analyzers / Responders
```

### Fluxo de um analyzer

```
Analista → "Cortex Actions" → modal
  GET  /cortex-module/observables/{kind}/{id}?context=…   observável + analyzers/responders compatíveis
  POST /cortex-module/analyzers/run                        valida papel, acesso, TLP, limites
        → INSERT execution (pending) → POST /api/analyzer/{id}/run → job id → status Waiting
        → task Celery poll_execution(id)
  worker: GET /api/job/{id} a cada poll_interval …
        Success → GET /api/job/{id}/report → parse + sanitização → grava
                → timeline / histórico → aba Cortex do IOC
        Failure / timeout → grava erro → timeline
  modal: GET /cortex-module/executions/{id} a cada 3 s (lê o banco, não o Cortex)
  analista: seleciona artefatos → POST /cortex-module/executions/{id}/import → novos IOCs no caso
```

### Rotas

O IRIS v2 não expõe módulos sob `/api/*` (as rotas nativas são `/case/...`, `/alerts/...`, `/manage/...`);
seguindo o padrão do `iris-email-module`, a API fica em `/cortex-module/*`:

| Método | Rota | Papel |
|---|---|---|
| GET | `/cortex-module/status` | view |
| GET | `/cortex-module/observables/{kind}/{id}` | view |
| POST | `/cortex-module/analyzers/run` | analyzer |
| POST | `/cortex-module/responders/run` | responder |
| GET | `/cortex-module/executions/{id}` | view |
| GET | `/cortex-module/executions/{id}/report` | view |
| POST | `/cortex-module/executions/{id}/import` | analyzer + escrita no caso/alerta |
| POST | `/cortex-module/executions/{id}/operations/{index}/apply` | responder + escrita |
| GET | `/cortex-module/history/{case\|alert}/{id}` | view |
| GET | `/cortex-module/logs` | admin |

## 3. Arquivos

Criados: todo o pacote `iris-cortex-module`. Modificados no core do IRIS: **nenhum além do patch genérico de
extensões** (o mesmo do `iris-email-module`; o Dockerfile só o aplica se ainda não estiver presente).

## 4. RBAC

| Papel | Permite | Grupo(s) — parâmetro | Padrão se vazio |
|---|---|---|---|
| `cortex.view` | ver catálogo, resultados e histórico | `groups_view` | qualquer usuário com acesso ao objeto |
| `cortex.analyzer.execute` | executar analyzers, importar artefatos | `groups_analyzer` | qualquer usuário com **escrita** no objeto |
| `cortex.responder.execute` | executar responders não privilegiados | `groups_responder` | **ninguém** (só admin) |
| `cortex.responder.privileged` | responders listados em `privileged_responders` | `groups_responder_privileged` | **ninguém** (só admin) |
| `cortex.admin` | auditoria completa, todos os papéis | `groups_admin` | administradores do servidor IRIS |

Os papéis se somam ao acesso do IRIS ao objeto: acesso total ao caso (ou `alerts_write` + acesso ao cliente) para
executar; leitura para visualizar.

## 5. Segurança

| Risco | Controle |
|---|---|
| Vazamento da API key | Lida de variável de ambiente / arquivo de secret; nunca gravada no IRIS, logada ou devolvida. |
| Vazamento de segredos de analyzers | `configuration` removido de toda resposta do Cortex; documentação exige usuário `analyze`. |
| Vazamento de dado classificado | Política própria de TLP/PAP (`max_tlp`, `max_pap`) antes do envio. |
| Responder indevido | Deny-by-default, lista de privilegiados, confirmação obrigatória com texto explícito, `request_uuid` contra duplicidade. |
| Dados maliciosos no relatório | Relatório tratado como JSON não confiável: limite de tamanho e profundidade, remoção de caracteres de controle, exibição só como texto (DOM), aba HTML do IOC escapada. |
| Import massivo | Import só dos artefatos selecionados, com limite por requisição, validação de tipo/valor e deduplicação. |
| Arquivos | Limite de tamanho; zip protegido do datastore extraído em memória com limite de descompressão (anti zip-bomb). |
| Indisponibilidade | Timeouts, retry com backoff só em leituras; nunca repete uma execução automaticamente. |
| Abuso | Rate limit separado para analyzers e responders; limite de analyzers por requisição. |

## 6. Evoluções previstas

O desenho já separa os pontos de extensão:

- **Enrichment automático**: hook `on_postload_ioc_create` → `service.run_analyzers()` com um perfil.
- **Analyzer profiles / execução sequencial**: `analyzers/run` já aceita vários analyzers.
- **Aprovação de responders**: novo status `awaiting_approval` antes de `pending`.
- **Score de reputação / correlação**: `results.py` já normaliza as taxonomias por nível.
- **Playbooks / SOAR**: `service` é chamável sem HTTP (as tasks do worker já o usam).

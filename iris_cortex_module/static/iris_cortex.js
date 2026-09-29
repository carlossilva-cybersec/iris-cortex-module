/*
 * DFIR-IRIS <-> Cortex -- "Cortex Actions" dialog.
 *
 * IRIS renders the module's manual hook ("Cortex Actions") in the IOC, evidence, case and alert
 * menus. Those entries call init_module_processing / init_module_processing_alert; this script
 * wraps both and opens the Cortex dialog for our module, leaving every other module untouched.
 *
 * Every value coming from Cortex (reports are untrusted third-party data) is inserted with
 * jQuery .text() or as DOM text nodes -- never as HTML.
 */
(function (window, $) {
    'use strict';

    if (!$ || window.irisCortex) { return; }

    const MODULE_NAME = 'iris_cortex_module';
    const API = '/cortex-module';
    const POLL_MS = 3000;
    const LEVEL_CLASS = { info: 'info', safe: 'success', suspicious: 'warning', malicious: 'danger' };
    const STATUS = {
        pending: ['Pendente', 'secondary'], waiting: ['Na fila', 'secondary'], in_progress: ['Em execução', 'info'],
        success: ['Sucesso', 'success'], failure: ['Falhou', 'danger'], timeout: ['Timeout', 'warning'],
        error: ['Erro', 'danger']
    };
    const KIND_LABEL = { ioc: 'IOC', evidence: 'Evidência', file: 'Arquivo', case: 'Caso', alert: 'Alerta' };

    const state = { kind: null, id: null, ctype: null, cid: null, catalog: null, obsIndex: 0, batch: [],
                    timers: {}, current: null };

    /* -------------------------------------------------------------- helpers */

    const el = (tag, cls, text) => {
        const $e = $(`<${tag}>`);
        if (cls) { $e.addClass(cls); }
        if (text !== undefined && text !== null) { $e.text(String(text)); }
        return $e;
    };
    const badge = (text, kind) => el('span', `badge badge-${kind || 'secondary'} mr-1`, text);
    const statusBadge = (s) => { const [t, k] = STATUS[s] || [s, 'secondary']; return badge(t, k); };
    const verdictBadge = (v) => v ? badge(v, LEVEL_CLASS[v] || 'secondary') : el('span', 'text-muted', '-');
    const fmtDate = (iso) => iso ? iso.replace('T', ' ').slice(0, 19) : '-';
    const csrf = () => $('#csrf_token').val() || '';

    function notify(ok, msg) {
        const fn = ok ? window.notify_success : window.notify_error;
        if (typeof fn === 'function') { fn(msg); } else if (!ok) { window.alert(msg); }
    }

    function apiError(xhr, fallback) {
        const r = xhr && xhr.responseJSON;
        if (r && r.message) { return r.message; }
        if (xhr && xhr.status === 403) { return 'Permissão negada.'; }
        if (xhr && xhr.status === 0) { return 'Sem resposta do IRIS.'; }
        return fallback;
    }

    function get(path) { return $.ajax({ url: API + path, type: 'GET', dataType: 'json' }); }
    function post(path, body) {
        return $.ajax({ url: API + path, type: 'POST', dataType: 'json', contentType: 'application/json;charset=UTF-8',
                        data: JSON.stringify(Object.assign({ csrf_token: csrf() }, body)) });
    }

    function uuid4() {
        if (window.crypto && window.crypto.randomUUID) { return window.crypto.randomUUID(); }
        const b = new Uint8Array(16); window.crypto.getRandomValues(b);
        b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
        const h = Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
        return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    }

    function confirmDialog(title, lines, confirmText, danger) {
        const text = lines.join('\n');
        if (typeof window.swal === 'function') {
            return window.swal({
                title: title, text: text, icon: danger ? 'warning' : 'info', dangerMode: !!danger,
                buttons: { cancel: { text: 'Cancelar', value: false, visible: true, closeModal: true },
                           confirm: { text: confirmText, value: true, closeModal: true } }
            });
        }
        return Promise.resolve(window.confirm(`${title}\n\n${text}`));
    }

    /* -------------------------------------------------------------- JSON tree (text only) */

    function jsonTree(value, depth) {
        depth = depth || 0;
        if (value === null || typeof value !== 'object') {
            return el('span', typeof value === 'string' ? 'text-dark' : 'text-primary',
                      typeof value === 'string' ? value : JSON.stringify(value));
        }
        const isArray = Array.isArray(value);
        const keys = isArray ? value.map((_, i) => i) : Object.keys(value);
        const $details = $('<details>');
        if (depth < 2) { $details.attr('open', 'open'); }
        $('<summary>').text(isArray ? `[${keys.length}]` : `{${keys.length}}`).appendTo($details);
        const $ul = el('ul', 'iris-cortex-tree').appendTo($details);
        keys.forEach(k => {
            const $li = $('<li>').appendTo($ul);
            el('span', 'iris-cortex-key', isArray ? `${k}: ` : `${k}: `).appendTo($li);
            jsonTree(value[k], depth + 1).appendTo($li);
        });
        return $details;
    }

    /* -------------------------------------------------------------- modal skeleton */

    function modal() {
        let $m = $('#iris_cortex_modal');
        if ($m.length) { return $m; }
        $m = $(`
<div class="modal fade" id="iris_cortex_modal" tabindex="-1" role="dialog" aria-hidden="true">
  <div class="modal-dialog modal-xl" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h4 class="modal-title"><i class="fa-solid fa-microscope mr-2"></i>Cortex <small class="text-muted iris-cortex-sub"></small></h4>
        <button type="button" class="close" data-dismiss="modal" aria-label="Fechar"><span aria-hidden="true">&times;</span></button>
      </div>
      <div class="modal-body">
        <div class="iris-cortex-loading text-center p-4"><i class="fas fa-spinner fa-spin"></i> Consultando o Cortex...</div>
        <div class="iris-cortex-body" style="display:none">
          <div class="iris-cortex-picker mb-2"></div>
          <div class="iris-cortex-object card card-body p-2 mb-2"></div>
          <div class="iris-cortex-alerts"></div>
          <ul class="nav nav-tabs nav-line nav-color-secondary" role="tablist">
            <li class="nav-item"><a class="nav-link active" data-tab="analyzers" href="#">Analyzers <span class="badge badge-light iris-cortex-count-a"></span></a></li>
            <li class="nav-item"><a class="nav-link" data-tab="responders" href="#">Responders <span class="badge badge-light iris-cortex-count-r"></span></a></li>
            <li class="nav-item"><a class="nav-link" data-tab="history" href="#">Histórico de execuções</a></li>
          </ul>
          <div class="iris-cortex-tab pt-2" data-tab="analyzers"></div>
          <div class="iris-cortex-tab pt-2" data-tab="responders" style="display:none"></div>
          <div class="iris-cortex-tab pt-2" data-tab="history" style="display:none"></div>
          <div class="iris-cortex-result mt-3" style="display:none"></div>
        </div>
      </div>
      <div class="modal-footer">
        <span class="mr-auto small text-muted iris-cortex-footer"></span>
        <button type="button" class="btn btn-default" data-dismiss="modal">Fechar</button>
      </div>
    </div>
  </div>
</div>`).appendTo('body');
        $m.on('click', '.nav-link[data-tab]', function (e) {
            e.preventDefault();
            showTab($(this).data('tab'));
        });
        $m.on('hidden.bs.modal', stopAllPolling);
        return $m;
    }

    function showTab(name) {
        const $m = modal();
        $m.find('.nav-link[data-tab]').removeClass('active').filter(`[data-tab="${name}"]`).addClass('active');
        $m.find('.iris-cortex-tab').hide().filter(`[data-tab="${name}"]`).show();
        if (name === 'history') { loadHistory(); }
    }

    /* -------------------------------------------------------------- open / catalog */

    function open(kind, id, ctype, cid, batch) {
        id = parseInt(id, 10); cid = parseInt(cid, 10);
        if (!Number.isInteger(id) || !Number.isInteger(cid)) { notify(false, 'Objeto ou contexto inválido.'); return; }
        Object.assign(state, { kind, id, ctype, cid, obsIndex: 0, current: null, batch: batch || state.batch || [] });
        const $m = modal();
        $m.find('.iris-cortex-body').hide();
        $m.find('.iris-cortex-loading').show();
        $m.find('.iris-cortex-result').hide().empty();
        if (!$m.hasClass('show')) { $m.modal({ show: true }); }
        get(`/observables/${kind}/${id}?context_type=${ctype}&context_id=${cid}`)
            .done(r => { state.catalog = r.data; render(); })
            .fail(xhr => { $m.modal('hide'); notify(false, apiError(xhr, 'Não foi possível abrir o Cortex.')); });
    }

    function render() {
        const $m = modal();
        const c = state.catalog, o = c.object;
        $m.find('.iris-cortex-loading').hide();
        $m.find('.iris-cortex-body').show();
        $m.find('.iris-cortex-sub').text(`${KIND_LABEL[o.kind] || o.kind} #${o.id} - ${o.context_type === 'case' ? 'caso' : 'alerta'} #${o.context_id}`);
        $m.find('.iris-cortex-footer').text(`TLP máximo enviado ao Cortex: ${c.max_tlp}. Papéis: ${c.roles.join(', ') || '-'}`);
        renderPicker();
        renderObject();
        const $alerts = $m.find('.iris-cortex-alerts').empty();
        if (c.cortex_error) { el('div', 'alert alert-danger', c.cortex_error).appendTo($alerts); }
        (o.observable_errors || []).forEach(err => el('div', 'alert alert-warning py-1', `Não enviado: ${err}`).appendTo($alerts));
        if (!c.can_write) { el('div', 'alert alert-info py-1', 'Acesso somente leitura: execuções desativadas.').appendTo($alerts); }
        renderAnalyzers();
        renderResponders();
        renderHistoryTable(c.history || []);
        (c.history || []).filter(h => !h.final).forEach(h => startPolling(h.id));
        showTab('analyzers');
    }

    function renderPicker() {
        const $p = modal().find('.iris-cortex-picker').empty();
        const c = state.catalog;
        const options = [];
        (state.batch || []).forEach(b => options.push(b));
        if (c.context_objects) {
            ['ioc', 'evidence', 'file'].forEach(k => (c.context_objects[k] || []).forEach(x =>
                options.push({ kind: k, id: x.id, label: `${KIND_LABEL[k]}: ${x.label}${x.type && k === 'ioc' ? ' (' + x.type + ')' : ''}` })));
        }
        if (!options.length) { return; }
        const $sel = el('select', 'form-control form-control-sm').appendTo(
            el('div', 'form-inline').append(el('label', 'mr-2 small', 'Objeto:')).appendTo($p));
        const self = { kind: c.object.kind, id: c.object.id };
        $('<option>').val('').text(`${KIND_LABEL[self.kind]} #${self.id} (atual)`).appendTo($sel);
        options.forEach(opt => $('<option>').val(`${opt.kind}:${opt.id}`).text(opt.label).appendTo($sel));
        $sel.on('change', function () {
            const v = $(this).val();
            if (!v) { return; }
            const [kind, id] = v.split(':');
            open(kind, id, state.ctype, state.cid);
        });
    }

    function renderObject() {
        const $o = modal().find('.iris-cortex-object').empty();
        const o = state.catalog.object;
        const obs = o.observables || [];
        const $row = el('div', 'd-flex flex-wrap align-items-center').appendTo($o);
        el('strong', 'mr-2', 'Observable:').appendTo($row);
        if (obs.length > 1) {
            const $sel = el('select', 'form-control form-control-sm w-auto mr-3').appendTo($row);
            obs.forEach((x, i) => $('<option>').val(i).text(`${x.label} [${x.data_type}]`).appendTo($sel));
            $sel.val(state.obsIndex).on('change', function () { state.obsIndex = parseInt($(this).val(), 10); renderAnalyzers(); });
        } else {
            el('code', 'mr-3', obs.length ? obs[0].label : o.title).appendTo($row);
        }
        el('strong', 'mr-1', 'Tipo:').appendTo($row);
        el('span', 'mr-3', `${o.iris_type || o.kind}${obs.length ? ' → ' + obs.map(x => x.data_type).join(', ') : ''}`).appendTo($row);
        el('strong', 'mr-1', 'TLP:').appendTo($row);
        badge(['CLEAR', 'GREEN', 'AMBER', 'RED'][o.tlp] || o.tlp, ['light', 'success', 'warning', 'danger'][o.tlp]).appendTo($row);
        if (o.customer) { el('span', 'ml-3 text-muted', `Cliente: ${o.customer}`).appendTo($row); }
    }

    function lastRunOf(workerId) {
        return (state.catalog.history || []).find(h => h.worker_id === workerId);
    }

    function renderAnalyzers() {
        const $t = modal().find('.iris-cortex-tab[data-tab="analyzers"]').empty();
        const list = state.catalog.analyzers.filter(a => a.observable_index === state.obsIndex);
        modal().find('.iris-cortex-count-a').text(state.catalog.analyzers.length || '');
        if (!list.length) {
            el('p', 'text-muted', state.catalog.cortex_error ? 'Cortex indisponível.' :
                'Nenhum analyzer compatível com este observável.').appendTo($t);
            return;
        }
        const $table = el('table', 'table table-sm table-hover').appendTo(el('div', 'table-responsive').appendTo($t));
        $('<thead><tr><th style="width:1%"></th><th>Analyzer</th><th>Descrição</th><th>Status</th><th>Resultado</th><th>Ação</th></tr></thead>').appendTo($table);
        const $tb = $('<tbody>').appendTo($table);
        list.forEach(a => {
            const $tr = $('<tr>').appendTo($tb);
            const $cb = $('<input type="checkbox" class="iris-cortex-a-check">').val(a.id).prop('disabled', !a.allowed);
            $('<td>').append($cb).appendTo($tr);
            $('<td>').append(el('strong', '', a.name)).append(el('div', 'small text-muted', `v${a.version || '?'} - ${(a.dataTypeList || []).join(', ')}`)).appendTo($tr);
            $('<td class="small">').text(a.description || '').appendTo($tr);
            $('<td>').append(a.allowed ? badge('Disponível', 'success') : badge('Bloqueado', 'secondary').attr('title', a.reason))
                .append(a.allowed ? null : el('div', 'small text-muted', a.reason)).appendTo($tr);
            const last = lastRunOf(a.id);
            const $res = $('<td>').appendTo($tr);
            if (last) {
                $res.append(statusBadge(last.status)).append(verdictBadge(last.verdict));
                $('<a href="#" class="small d-block">').text('ver').on('click', e => { e.preventDefault(); showExecution(last.id); }).appendTo($res);
            } else { $res.text('-'); }
            $('<td>').append($('<button class="btn btn-sm btn-primary">').text('Run').prop('disabled', !a.allowed)
                .on('click', () => runAnalyzers([a.id]))).appendTo($tr);
        });
        $('<button class="btn btn-sm btn-outline-primary">').text('Executar selecionados').on('click', () => {
            const ids = $t.find('.iris-cortex-a-check:checked').map(function () { return $(this).val(); }).get();
            if (!ids.length) { notify(false, 'Selecione ao menos um analyzer.'); return; }
            runAnalyzers(ids);
        }).appendTo($t);
    }

    function renderResponders() {
        const $t = modal().find('.iris-cortex-tab[data-tab="responders"]').empty();
        const list = state.catalog.responders;
        modal().find('.iris-cortex-count-r').text(list.length || '');
        if (!list.length) {
            el('p', 'text-muted', state.catalog.object.responder_data_type ?
                'Nenhum responder compatível disponível.' : 'Este objeto não aceita responders.').appendTo($t);
            return;
        }
        const $table = el('table', 'table table-sm table-hover').appendTo(el('div', 'table-responsive').appendTo($t));
        $('<thead><tr><th>Responder</th><th>Tipo</th><th>Descrição</th><th>Status</th><th>Ação</th></tr></thead>').appendTo($table);
        const $tb = $('<tbody>').appendTo($table);
        list.forEach(r => {
            const $tr = $('<tr>').appendTo($tb);
            $('<td>').append(el('strong', '', r.name)).append(el('div', 'small text-muted', `v${r.version || '?'}`)).appendTo($tr);
            $('<td>').append(r.privileged ? badge('Contenção / privilegiado', 'danger') : badge('Padrão', 'info')).appendTo($tr);
            $('<td class="small">').text(r.description || '').appendTo($tr);
            $('<td>').append(r.allowed ? badge('Disponível', 'success') : badge('Bloqueado', 'secondary'))
                .append(r.allowed ? null : el('div', 'small text-muted', r.reason)).appendTo($tr);
            $('<td>').append($(`<button class="btn btn-sm ${r.privileged ? 'btn-danger' : 'btn-warning'}">`).text('Run')
                .prop('disabled', !r.allowed).on('click', () => confirmResponder(r))).appendTo($tr);
        });
    }

    /* -------------------------------------------------------------- run */

    function runAnalyzers(ids) {
        const body = { kind: state.kind, object_id: state.id, context_type: state.ctype, context_id: state.cid,
                       observable_index: state.obsIndex, analyzer_ids: ids };
        post('/analyzers/run', body).done(r => {
            notify(true, r.message);
            r.data.forEach(ex => { upsertHistory(ex); if (!ex.final) { startPolling(ex.id); } });
            if (r.data.length === 1) { showExecution(r.data[0].id, r.data[0]); }
            renderAnalyzers();
        }).fail(xhr => notify(false, apiError(xhr, 'Falha ao executar analyzer.')));
    }

    function confirmResponder(r) {
        const o = state.catalog.object;
        const target = (o.observables && o.observables[0]) ? o.observables[0].label : o.title;
        const lines = [
            `Responder: ${r.name}`,
            `${KIND_LABEL[o.kind] || o.kind}: ${target}`,
            `Ação: ${r.description || 'ação definida pelo responder no Cortex'}`,
            '',
            r.privileged ? 'ATENÇÃO: responder de contenção/alteração externa. A ação será executada no sistema integrado e pode não ser reversível.'
                         : 'O objeto será enviado ao responder, que pode executar ações em sistemas externos.'
        ];
        confirmDialog('Executar responder?', lines, 'Executar Responder', true).then(ok => {
            if (!ok) { return; }
            post('/responders/run', { kind: state.kind, object_id: state.id, context_type: state.ctype,
                                      context_id: state.cid, responder_id: r.id, confirm: true, request_uuid: uuid4() })
                .done(res => { notify(true, res.message); upsertHistory(res.data); startPolling(res.data.id); showExecution(res.data.id, res.data); })
                .fail(xhr => notify(false, apiError(xhr, 'Falha ao executar responder.')));
        });
    }

    /* -------------------------------------------------------------- history & polling */

    function upsertHistory(ex) {
        const h = state.catalog.history || (state.catalog.history = []);
        const i = h.findIndex(x => x.id === ex.id);
        if (i >= 0) { h[i] = ex; } else { h.unshift(ex); }
        renderHistoryTable(h);
    }

    function loadHistory() {
        get(`/history/${state.ctype}/${state.cid}`).done(r => renderHistoryTable(r.data, true))
            .fail(xhr => notify(false, apiError(xhr, 'Falha ao carregar o histórico.')));
    }

    function renderHistoryTable(items, contextWide) {
        const $t = modal().find('.iris-cortex-tab[data-tab="history"]').empty();
        el('p', 'small text-muted mb-1', contextWide ? `Todas as execuções deste ${state.ctype === 'case' ? 'caso' : 'alerta'}.`
                                                     : 'Execuções deste objeto.').appendTo($t);
        if (!items.length) { el('p', 'text-muted', 'Nenhuma execução.').appendTo($t); return; }
        const $table = el('table', 'table table-sm table-striped').appendTo(el('div', 'table-responsive').appendTo($t));
        $('<thead><tr><th>Data (UTC)</th><th>Tipo</th><th>Analyzer / Responder</th><th>Observável</th><th>Status</th><th>Veredito</th><th>Usuário</th><th></th></tr></thead>').appendTo($table);
        const $tb = $('<tbody>').appendTo($table);
        items.forEach(x => {
            const $tr = $('<tr>').attr('data-exec', x.id).appendTo($tb);
            $('<td>').text(fmtDate(x.created_at)).appendTo($tr);
            $('<td>').text(x.worker_type === 'analyzer' ? 'Analyzer' : 'Responder').appendTo($tr);
            $('<td>').text(x.worker_name).appendTo($tr);
            $('<td>').append(el('code', '', x.observable)).appendTo($tr);
            $('<td>').append(statusBadge(x.status)).appendTo($tr);
            $('<td>').append(verdictBadge(x.verdict)).appendTo($tr);
            $('<td>').text(x.user_login).appendTo($tr);
            $('<td>').append($('<button class="btn btn-xs btn-outline-secondary">').text('Ver').on('click', () => showExecution(x.id))).appendTo($tr);
        });
    }

    function startPolling(id) {
        if (state.timers[id]) { return; }
        state.timers[id] = window.setInterval(() => {
            get(`/executions/${id}`).done(r => {
                upsertHistory(r.data);
                if (state.current === id) { renderExecution(r.data); }
                if (r.data.final) {
                    stopPolling(id);
                    renderAnalyzers();
                    notify(r.data.status === 'success', `${r.data.worker_name}: ${(STATUS[r.data.status] || [r.data.status])[0]}`);
                }
            }).fail(() => stopPolling(id));
        }, POLL_MS);
    }

    function stopPolling(id) { window.clearInterval(state.timers[id]); delete state.timers[id]; }
    function stopAllPolling() { Object.keys(state.timers).forEach(stopPolling); }

    /* -------------------------------------------------------------- result panel */

    function showExecution(id, preview) {
        state.current = id;
        if (preview) { renderExecution(preview); }
        get(`/executions/${id}/report`).done(r => renderExecution(r.data))
            .fail(xhr => notify(false, apiError(xhr, 'Falha ao carregar o resultado.')));
    }

    function renderExecution(x) {
        const $r = modal().find('.iris-cortex-result').empty().show();
        const $card = el('div', 'card').appendTo($r);
        const $h = el('div', 'card-header d-flex align-items-center').appendTo($card);
        el('strong', 'mr-2', `${x.worker_type === 'analyzer' ? 'Analyzer' : 'Responder'}: ${x.worker_name}`).appendTo($h);
        statusBadge(x.status).appendTo($h);
        verdictBadge(x.verdict).appendTo($h);
        if (!x.final) { el('span', 'ml-2 small text-muted').append('<i class="fas fa-spinner fa-spin"></i> ').append(document.createTextNode('acompanhando o job...')).appendTo($h); }
        $('<button type="button" class="close ml-auto" aria-label="Fechar">&times;</button>').on('click', () => { state.current = null; $r.hide(); }).appendTo($h);
        const $b = el('div', 'card-body').appendTo($card);

        const $meta = el('dl', 'row mb-2 small').appendTo($b);
        [['Data/hora', fmtDate(x.finished_at || x.created_at) + ' UTC'], ['Job ID', x.cortex_job_id || '-'],
         ['Observável', `${x.observable} [${x.data_type}]`], ['Executado por', x.user_login],
         ['Registro de auditoria', `#${x.id}`]].forEach(([k, v]) => {
            el('dt', 'col-sm-3', k).appendTo($meta); el('dd', 'col-sm-9', v).appendTo($meta);
        });
        if (x.error_message) { el('div', 'alert alert-danger', x.error_message).appendTo($b); }

        if ((x.taxonomies || []).length) {
            el('h6', '', 'Taxonomias').appendTo($b);
            const $tx = el('div', 'mb-2').appendTo($b);
            x.taxonomies.forEach(t => badge(`${t.namespace}:${t.predicate} = ${t.value}`, LEVEL_CLASS[t.level]).appendTo($tx));
        }
        if ((x.highlights || []).length) {
            el('h6', '', 'Resumo').appendTo($b);
            const $tbl = el('table', 'table table-sm table-bordered small').appendTo(el('div', 'table-responsive iris-cortex-scroll').appendTo($b));
            const $tb = $('<tbody>').appendTo($tbl);
            x.highlights.forEach(([k, v]) => $('<tr>').append(el('th', 'w-25', k)).append(el('td', '', v)).appendTo($tb));
        }
        renderArtifacts($b, x);
        renderOperations($b, x);
        if (x.report !== undefined && x.report !== null) {
            el('h6', 'mt-2', `Resultado completo${x.report_truncated ? ' (truncado)' : ''}`).appendTo($b);
            el('div', 'iris-cortex-scroll iris-cortex-json').append(jsonTree(x.report)).appendTo($b);
            const $raw = $('<details class="mt-1">').appendTo($b);
            $('<summary class="small">').text('JSON retornado pelo Cortex').appendTo($raw);
            el('pre', 'iris-cortex-scroll small', JSON.stringify(x.report, null, 2)).appendTo($raw);
        }
    }

    function renderArtifacts($b, x) {
        const arts = x.artifacts || [];
        if (!arts.length) { return; }
        const imported = new Set((x.imported || []).map(i => i.index));
        el('h6', 'mt-2', `Artefatos encontrados (${arts.length})`).appendTo($b);
        const $tbl = el('table', 'table table-sm small').appendTo(el('div', 'table-responsive iris-cortex-scroll').appendTo($b));
        $('<thead><tr><th style="width:1%"></th><th>Tipo</th><th>Valor</th><th>Mensagem</th><th>IRIS</th></tr></thead>').appendTo($tbl);
        const $tb = $('<tbody>').appendTo($tbl);
        arts.forEach(a => {
            const can = a.importable && !imported.has(a.index) && x.status === 'success';
            const $tr = $('<tr>').appendTo($tb);
            $('<td>').append($('<input type="checkbox" class="iris-cortex-art">').val(a.index).prop('disabled', !can)).appendTo($tr);
            $('<td>').text(a.data_type).appendTo($tr);
            $('<td>').append(el('code', '', a.data)).appendTo($tr);
            $('<td>').text(a.message || '').appendTo($tr);
            $('<td>').append(imported.has(a.index) ? badge('importado', 'success') :
                (a.importable ? el('span', 'text-muted', a.iris_type) : el('span', 'text-muted', a.reason))).appendTo($tr);
        });
        if (arts.some(a => a.importable && !imported.has(a.index)) && x.status === 'success') {
            const label = state.ctype === 'case' ? 'Adicionar resultados ao caso' : 'Adicionar resultados ao alerta';
            $('<button class="btn btn-sm btn-success">').text(label).on('click', () => {
                const idx = $tbl.find('.iris-cortex-art:checked').map(function () { return parseInt($(this).val(), 10); }).get();
                if (!idx.length) { notify(false, 'Selecione os itens a adicionar.'); return; }
                confirmDialog('Adicionar como IOCs?', [`${idx.length} item(ns) serão criados como IOCs e vinculados ao ${state.ctype === 'case' ? 'caso' : 'alerta'}.`],
                              'Adicionar', false).then(ok => {
                    if (!ok) { return; }
                    post(`/executions/${x.id}/import`, { indexes: idx }).done(r => {
                        const failed = r.data.results.filter(i => !i.ok);
                        notify(!failed.length, r.message + (failed.length ? ` - ${failed.length} com erro: ${failed.map(f => f.message).join('; ')}` : ''));
                        renderExecution(Object.assign({}, x, r.data.execution, { report: x.report }));
                    }).fail(xhr => notify(false, apiError(xhr, 'Falha ao adicionar resultados.')));
                });
            }).appendTo($b);
        }
    }

    function renderOperations($b, x) {
        const ops = x.operations || [];
        if (!ops.length) { return; }
        el('h6', 'mt-2', 'Operações sugeridas pelo responder').appendTo($b);
        const $ul = el('ul', 'list-group mb-2').appendTo($b);
        ops.forEach(op => {
            const $li = el('li', 'list-group-item d-flex align-items-center py-1').appendTo($ul);
            el('span', 'mr-2 font-weight-bold', op.type).appendTo($li);
            el('code', 'mr-auto small', JSON.stringify(op.params)).appendTo($li);
            if (op.applied) { badge(`aplicada por ${op.applied_by}`, 'success').appendTo($li); }
            else if (!op.supported) { badge('não suportada no IRIS', 'secondary').appendTo($li); }
            else if (x.status === 'success') {
                $('<button class="btn btn-xs btn-outline-primary">').text('Aplicar').on('click', () => {
                    post(`/executions/${x.id}/operations/${op.index}/apply`, {})
                        .done(r => { notify(true, r.message); renderExecution(Object.assign({}, r.data, { report: x.report })); })
                        .fail(xhr => notify(false, apiError(xhr, 'Falha ao aplicar operação.')));
                }).appendTo($li);
            }
        });
    }

    /* -------------------------------------------------------------- hooking */

    function idOf(row) {
        if (row && typeof row === 'object') { return row.ioc_id || row.id || row.case_id || row.alert_id; }
        return row;
    }

    function alertIdFromEvent() {
        const ev = window.event;
        const target = ev && ev.target ? $(ev.target) : null;
        const card = target ? target.closest('[id^="alertCard-"]') : null;
        return card && card.length ? card.attr('id').replace('alertCard-', '') : null;
    }

    function wrap(name, handler) {
        const original = window[name];
        if (typeof original !== 'function' || original.__irisCortexWrapped) { return; }
        const wrapped = function () {
            if (handler.apply(this, arguments) === true) { return false; }
            return original.apply(this, arguments);
        };
        wrapped.__irisCortexWrapped = true;
        window[name] = wrapped;
    }

    function installHooks() {
        wrap('init_module_processing', function (rows, hookName, hookUiName, moduleName, dataType) {
            if (moduleName !== MODULE_NAME) { return false; }
            const ids = (Array.isArray(rows) ? rows : [rows]).map(idOf).filter(v => v !== undefined && v !== null);
            const onAlerts = window.location.pathname.indexOf('/alerts') === 0;
            let ctype = 'case', cid = window.get_caseid ? window.get_caseid() : null;
            if (onAlerts) {
                ctype = 'alert'; cid = alertIdFromEvent();
                if (!cid) { notify(false, 'Abra o Cortex a partir do alerta.'); return true; }
            }
            const kind = dataType === 'case' ? 'case' : dataType;
            if (!['ioc', 'evidence', 'case'].includes(kind)) { return false; }
            const objectId = kind === 'case' ? cid : ids[0];
            const batch = kind !== 'case' && ids.length > 1 ?
                ids.slice(1).map(i => ({ kind, id: i, label: `${KIND_LABEL[kind]} #${i} (selecionado)` })) : [];
            state.batch = batch;
            open(kind, objectId, ctype, cid, batch);
            return true;
        });
        wrap('init_module_processing_alert', function (alertId, hookName, hookUiName, moduleName) {
            if (moduleName !== MODULE_NAME) { return false; }
            state.batch = [];
            open('alert', alertId, 'alert', alertId, []);
            return true;
        });
    }

    installHooks();
    $(installHooks);

    window.irisCortex = { open: open };
})(window, window.jQuery);

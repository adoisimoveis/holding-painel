/* Painel da Holding — app de bolso de Ademir.
 *
 * Segurança (resumo):
 * - Nenhum dado fica no app: tudo é lido do repositório privado pela API do GitHub.
 * - A chave do GitHub e a chave de assinatura ficam CRIPTOGRAFADAS no aparelho (AES-GCM 256, chave
 *   derivada do PIN com PBKDF2-SHA256, 310 mil iterações). Sem o PIN, o que está salvo é ilegível.
 * - 5 PINs errados apagam o cofre. Bloqueio automático após 5 minutos parado ou 60 s fora do app.
 * - Cada operação vira uma issue privada com o comando assinado (HMAC-SHA256). O robô só aceita
 *   assinatura válida, do autor certo, em até 30 minutos, sem repetição.
 * - Operações com dinheiro pedem o PIN de novo.
 * - Todo texto vindo do repositório é escapado antes de aparecer na tela.
 */
(function () {
  "use strict";

  const REPO_PADRAO = "adoisimoveis/holding-agentes";
  const CHAVE_COFRE = "holding-cofre-v1";
  const CHAVE_BIO = "holding-bio-v1";
  const ITERACOES = 310000;
  const MAX_ERROS = 5;
  const BLOQUEIO_PARADO_MS = 5 * 60 * 1000;
  const BLOQUEIO_FORA_MS = 60 * 1000;
  const META_USD = 5000000;
  const META_INICIO = "2026-11-03";
  const META_FIM = "2042-11-03";
  const API = "https://api.github.com";

  // ---------------------------------------------------------------- utilidades
  const $ = (sel, raiz) => (raiz || document).querySelector(sel);
  const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const deb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
  const aleatorio = (n) => crypto.getRandomValues(new Uint8Array(n));
  const usd = (v, d = 0) => (v == null || isNaN(v) ? "—" : "US$ " + Number(v).toLocaleString("pt-BR", { minimumFractionDigits: d, maximumFractionDigits: d }));
  const brl = (v, d = 0) => (v == null || isNaN(v) ? "—" : "R$ " + Number(v).toLocaleString("pt-BR", { minimumFractionDigits: d, maximumFractionDigits: d }));
  const pct = (v, d = 0) => (v == null || isNaN(v) ? "—" : (Number(v) * 100).toLocaleString("pt-BR", { maximumFractionDigits: d }) + "%");
  const dataBR = (iso) => { if (!iso) return "—"; const d = new Date(iso); return isNaN(d) ? esc(iso) : d.toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }); };
  const lerJsonl = (t) => (t || "").split("\n").filter((l) => l.trim()).map((l) => { try { return JSON.parse(l); } catch (e) { return null; } }).filter(Boolean);
  const guardar = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* armazenamento bloqueado */ } };
  const ler = (k) => { try { return JSON.parse(localStorage.getItem(k) || "null"); } catch (e) { return null; } };
  const apagar = (k) => { try { localStorage.removeItem(k); } catch (e) { /* nada */ } };

  function toast(msg) {
    const t = document.createElement("div");
    t.className = "toast"; t.textContent = msg; document.body.appendChild(t);
    setTimeout(() => t.remove(), 3500);
  }

  // ---------------------------------------------------------------- cofre (PIN)
  async function chaveDoPin(pin, salt) {
    const base = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITERACOES, hash: "SHA-256" }, base,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function trancar(segredos, pin) {
    const salt = aleatorio(16), iv = aleatorio(12);
    const k = await chaveDoPin(pin, salt);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k, enc.encode(JSON.stringify(segredos)));
    guardar(CHAVE_COFRE, { v: 1, salt: b64(salt), iv: b64(iv), ct: b64(ct), erros: 0 });
  }
  async function destrancar(pin) {
    const c = ler(CHAVE_COFRE);
    if (!c) throw new Error("sem cofre");
    try {
      const k = await chaveDoPin(pin, deb64(c.salt));
      const txt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: deb64(c.iv) }, k, deb64(c.ct));
      c.erros = 0; guardar(CHAVE_COFRE, c);
      return JSON.parse(dec.decode(txt));
    } catch (e) {
      c.erros = (c.erros || 0) + 1;
      if (c.erros >= MAX_ERROS) { apagar(CHAVE_COFRE); throw new Error("apagado"); }
      guardar(CHAVE_COFRE, c);
      throw new Error("pin");
    }
  }

  // ---------------------------------------------------------------- estado da sessão (só em memória)
  let S = null;          // { token, chave, repo, pin }
  let D = {};            // dados carregados
  let aba = "hoje";
  let tokenVenceHeader = null;
  let ultimoToque = Date.now();
  let saiuEm = null;

  function bloquear() { S = null; D = {}; telaPin(); }
  ["pointerdown", "keydown", "scroll"].forEach((ev) => document.addEventListener(ev, () => { ultimoToque = Date.now(); }, { passive: true }));
  setInterval(() => { if (S && Date.now() - ultimoToque > BLOQUEIO_PARADO_MS) bloquear(); }, 15000);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) saiuEm = Date.now();
    else if (S && saiuEm && Date.now() - saiuEm > BLOQUEIO_FORA_MS) bloquear();
  });

  // ---------------------------------------------------------------- GitHub
  async function gh(caminho, opcoes = {}) {
    const r = await fetch(API + caminho, {
      method: opcoes.method || "GET", cache: "no-store", referrerPolicy: "no-referrer",
      headers: Object.assign({ Authorization: "Bearer " + S.token, "X-GitHub-Api-Version": "2022-11-28",
        Accept: opcoes.accept || "application/vnd.github+json" }, opcoes.body ? { "Content-Type": "application/json" } : {}),
      body: opcoes.body ? JSON.stringify(opcoes.body) : undefined,
    });
    const venc = r.headers.get("github-authentication-token-expiration");
    if (venc) tokenVenceHeader = venc.replace(" UTC", "Z").replace(" ", "T");
    if (r.status === 404) return null;
    if (!r.ok) { const e = new Error("GitHub respondeu " + r.status); e.status = r.status; throw e; }
    if (r.status === 204) return true;
    return opcoes.accept === "application/vnd.github.raw+json" ? r.text() : r.json();
  }
  const bruto = (p) => gh(`/repos/${S.repo}/contents/${p}?ref=main`, { accept: "application/vnd.github.raw+json" });
  const json = async (p) => { const t = await bruto(p); try { return t ? JSON.parse(t) : null; } catch (e) { return null; } };
  const pasta = async (p) => { const r = await gh(`/repos/${S.repo}/contents/${p}?ref=main`); return Array.isArray(r) ? r : []; };

  async function carregar() {
    const [pend, manuais, real, sim, hist, precos, teses, cong, verif, reg, cfg, boletas, posReais, precosReais, aporte, desf, retro, leits, recados, custos] = await Promise.all([
      json("estado/pendentes.json"), json("estado/ordens_manuais.json"), json("estado/carteira_real.json"),
      json("estado/carteira_simulada.json"), bruto("estado/historico.jsonl"), json("estado/precos.json"),
      bruto("estado/teses.jsonl"), json("estado/congelado.json"), json("estado/ultima_verificacao.json"),
      bruto("registro/decisoes.jsonl"), bruto("config.toml"), json("estado/boletas.json"),
      json("estado/posicoes_reais.json"), json("estado/precos_reais.json"), json("estado/aporte.json"),
      json("estado/desfazer.json"), json("estado/retrospectiva.json"), pasta("estado/leituras"),
      json("estado/recados_ceo.json"), bruto("estado/custos.jsonl")]);
    const num = (nome, padrao) => { const m = (cfg || "").match(new RegExp("^" + nome + "\\s*=\\s*([0-9.]+)", "m")); return m ? Number(m[1]) : padrao; };
    const txt = (nome) => { const m = (cfg || "").match(new RegExp("^" + nome + "\\s*=\\s*\"([^\"]*)\"", "m")); return m ? m[1] : null; };
    const ultimas = (leits || []).filter((a) => a.name.endsWith(".json")).sort((a, b) => b.name.localeCompare(a.name)).slice(0, 3);
    const leituras = (await Promise.all(ultimas.map((a) => json(a.path).catch(() => null)))).filter((l) => l && l.status === "proposta");
    D = {
      pendentes: pend || {}, manuais: manuais || {}, historico: lerJsonl(hist), precos: (precos || {}).precos || {},
      teses: lerJsonl(teses), congelado: !!(cong && cong.congelado), verif: verif || {}, registro: lerJsonl(reg),
      cambio: num("cambio_referencia", 5.5), capReal: num("capital_real_brl", 500), capSim: num("capital_simulado_brl", 100000),
      validadeH: num("validade_proposta_horas", 72), carregadoEm: new Date(), boletas: boletas || {},
      posReais: posReais || {}, precosReais: (precosReais || {}).precos || {}, aporte: aporte || null,
      desfazer: desf ? { cmd: desf.cmd, resumo: desf.resumo, quando: desf.quando } : null, retro: retro || null, leituras,
      meta: { valor: num("valor_usd", META_USD), anos: num("anos", 16), inicio: txt("inicio") || META_INICIO, real: num("retorno_real_pessimista_aa", 0.025) },
      tokenVence: tokenVenceHeader || txt("token_vence"),
      recados: Array.isArray(recados) ? recados : [], custos: lerJsonl(custos),
    };
    D.real = real || { caixa_usd: D.capReal / D.cambio, posicoes: {}, pico_usd: D.capReal / D.cambio };
    D.sim = sim || { caixa_usd: D.capSim / D.cambio, posicoes: {}, pico_usd: D.capSim / D.cambio };
    // o que já foi registrado neste aparelho e o robô ainda não confirmou (mostra "Registrado" na hora)
    for (const [k, v] of Object.entries(LOCAL)) if (Date.now() - v.t > 15 * 60000) delete LOCAL[k];
  }
  function valorCarteira(c) {
    let v = c.caixa_usd || 0;
    for (const [t, q] of Object.entries(c.posicoes || {})) v += q * (D.precos[t] || 0);
    return v;
  }

  // carteira real informada por Ademir (estado/posicoes_reais.json): IBKR em dólar, C6 em reais
  function linhasReais() {
    const out = [];
    for (const inst of ["IBKR", "C6"]) {
      const c = (D.posReais || {})[inst] || {};
      for (const [cod, p] of Object.entries(c.posicoes || {})) {
        const cot = D.precosReais[cod];
        out.push({ inst, cod, ativo: p.ativo || cod, q: p.quantidade, pm: p.preco_medio, cot, valor: p.quantidade * (cot || p.preco_medio), semCot: !cot, est: !!p.preco_estimado });
      }
    }
    return out;
  }
  function totalReal() {
    const ls = linhasReais(); const pr = D.posReais || {};
    const usdV = ls.filter((l) => l.inst === "IBKR").reduce((s, l) => s + l.valor, 0) + ((pr.IBKR || {}).caixa || 0);
    const brlV = ls.filter((l) => l.inst === "C6").reduce((s, l) => s + l.valor, 0) + ((pr.C6 || {}).caixa || 0);
    return { usd: usdV, brl: brlV, totalUsd: usdV + brlV / D.cambio, vazio: !ls.length && !usdV && !brlV };
  }

  // ---------------------------------------------------------------- comandos assinados
  const LOCAL = {};          // alvo -> {acao, t}: registro otimista, só em memória
  let ULTIMO = null;         // último comando que pode ser desfeito: {id, resumo, t}
  async function assinar(c) {
    const k = await crypto.subtle.importKey("raw", enc.encode(S.chave), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const texto = [c.id, c.acao, c.alvo || "", c.criado_em, c.nonce].join("|") + (c.dados ? "|" + c.dados : "");
    return hex(await crypto.subtle.sign("HMAC", k, enc.encode(texto)));
  }
  // anexos: pedaços de texto (imagem em base64) enviados como comentários ANTES de o comando valer
  async function enviarComando(acao, alvo, dados, anexos, resumo) {
    const c = { id: "p" + Date.now().toString(36) + hex(aleatorio(3)), acao, alvo: alvo || "",
      criado_em: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), nonce: hex(aleatorio(16)) };
    if (dados) c.dados = dados;
    c.assinatura = await assinar(c);
    const titulo = (anexos && anexos.length ? "rascunho " : "comando ") + c.id;
    const issue = await gh(`/repos/${S.repo}/issues`, { method: "POST", body: { title: titulo, body: JSON.stringify(c) } });
    if (anexos && anexos.length) {
      for (let i = 0; i < anexos.length; i++) await gh(`/repos/${S.repo}/issues/${issue.number}/comments`, { method: "POST", body: { body: "parte " + i + "\n" + anexos[i] } });
      await gh(`/repos/${S.repo}/issues/${issue.number}`, { method: "PATCH", body: { title: "comando " + c.id } });
    }
    await gh(`/repos/${S.repo}/actions/workflows/sistema.yml/dispatches`, { method: "POST", body: { ref: "main", inputs: { tarefa: "aprovacoes" } } });
    if (alvo) LOCAL[alvo] = { acao, t: Date.now() };
    if (["executei", "naoexecutei", "ajustar", "aplicar_leitura"].includes(acao)) ULTIMO = { id: c.id, resumo: resumo || nomeAcao(acao), t: Date.now() };
    if (acao === "desfazer") ULTIMO = null;
    toast("✓ Registrado");
    render();
    acompanhar(issue.number, acao, alvo);
  }
  async function acompanhar(numero, acao, alvo) {
    for (let i = 0; i < 30 && S; i++) {
      await new Promise((r) => setTimeout(r, 10000));
      const iss = await gh(`/repos/${S.repo}/issues/${numero}`).catch(() => null);
      if (iss && iss.state === "closed") {
        const coms = await gh(`/repos/${S.repo}/issues/${numero}/comments`).catch(() => []);
        const res = (coms && coms.length) ? coms[coms.length - 1].body : "Processado.";
        if (!res.startsWith("Aceito")) toast("⛔ " + nomeAcao(acao) + ": " + res);
        await new Promise((r) => setTimeout(r, 4000));
        await carregar().catch(() => {}); render();
        return;
      }
    }
  }
  const nomeAcao = (a) => ({ aprovar: "Aprovar", recusar: "Recusar", executei: "Confirmar compra", naoexecutei: "Não comprei", congelar: "Congelar tudo", descongelar: "Liberar o sistema", aporte: "Dinheiro para a banca", ajustar: "Ajustar carteira", desfazer: "Desfazer", conferi: "Carteira conferida", leitura_print: "Ler o print", aplicar_leitura: "Aplicar a leitura", descartar_leitura: "Descartar a leitura" }[a] || a);

  // ---------------------------------------------------------------- gráficos (SVG próprio, sem bibliotecas)
  function graficoLinha(pontos, opts = {}) {
    const W = 360, H = 190, m = { e: 50, d: 8, t: 10, b: 24 };
    if (pontos.length < 2) return `<p class="mudo">${esc(opts.vazio || "O gráfico aparece a partir do segundo dia de dados.")}</p>`;
    const xs = pontos.map((p) => +new Date(p.x)), ys = pontos.map((p) => p.y);
    let y0 = Math.min(...ys), y1 = Math.max(...ys); if (y0 === y1) { y0 *= 0.98; y1 *= 1.02; }
    const pad = (y1 - y0) * 0.1; y0 -= pad; y1 += pad;
    const X = (x) => m.e + (x - xs[0]) / (xs[xs.length - 1] - xs[0]) * (W - m.e - m.d);
    const Y = (y) => m.t + (1 - (y - y0) / (y1 - y0)) * (H - m.t - m.b);
    const ticks = [0, 1, 2, 3].map((i) => y0 + (y1 - y0) * i / 3);
    const linha = pontos.map((p, i) => (i ? "L" : "M") + X(+new Date(p.x)).toFixed(1) + " " + Y(p.y).toFixed(1)).join("");
    const area = linha + `L${X(xs[xs.length - 1]).toFixed(1)} ${H - m.b}L${X(xs[0]).toFixed(1)} ${H - m.b}Z`;
    const ult = pontos[pontos.length - 1];
    const fmt = opts.fmt || ((v) => v >= 1e6 ? (v / 1e6).toLocaleString("pt-BR", { maximumFractionDigits: 2 }) + " mi" : v >= 1e3 ? (v / 1e3).toLocaleString("pt-BR", { maximumFractionDigits: 1 }) + " mil" : v.toLocaleString("pt-BR", { maximumFractionDigits: 0 }));
    return `<svg class="grafico" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(opts.titulo || "gráfico")}">
      ${ticks.map((t) => `<line x1="${m.e}" x2="${W - m.d}" y1="${Y(t)}" y2="${Y(t)}" stroke="var(--line)"/><text x="${m.e - 6}" y="${Y(t) + 4}" text-anchor="end" font-size="11" fill="var(--muted)">${esc(fmt(t))}</text>`).join("")}
      <path d="${area}" fill="var(--chart-1)" fill-opacity=".12"/>
      <path d="${linha}" fill="none" stroke="var(--chart-1)" stroke-width="2.2" stroke-linejoin="round"/>
      <circle cx="${X(+new Date(ult.x))}" cy="${Y(ult.y)}" r="4.5" fill="var(--chart-1)"/>
      <text x="${m.e}" y="${H - 8}" font-size="11" fill="var(--muted)">${esc(new Date(xs[0]).toLocaleDateString("pt-BR"))}</text>
      <text x="${W - m.d}" y="${H - 8}" text-anchor="end" font-size="11" fill="var(--muted)">${esc(new Date(xs[xs.length - 1]).toLocaleDateString("pt-BR"))}</text>
    </svg>`;
  }
  function rosca(partes, centro) {
    const tot = partes.reduce((s, p) => s + p.v, 0) || 1, R = 62, r = 42, cx = 70, cy = 72;
    let a = -Math.PI / 2;
    const cores = ["var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-4)", "var(--chart-5)"];
    const arcos = partes.map((p, i) => {
      const f = p.v / tot; if (f <= 0) return "";
      if (f >= 0.9999) return `<circle cx="${cx}" cy="${cy}" r="${(R + r) / 2}" fill="none" stroke="${cores[i % 5]}" stroke-width="${R - r}"/>`;
      const a2 = a + f * 2 * Math.PI, g = f > 0.5 ? 1 : 0;
      const P = (ang, rad) => [cx + rad * Math.cos(ang), cy + rad * Math.sin(ang)].map((n) => n.toFixed(2)).join(" ");
      const d = `M${P(a, R)}A${R} ${R} 0 ${g} 1 ${P(a2, R)}L${P(a2, r)}A${r} ${r} 0 ${g} 0 ${P(a, r)}Z`;
      a = a2; return `<path d="${d}" fill="${cores[i % 5]}"/>`;
    }).join("");
    const leg = partes.map((p, i) => `<g transform="translate(152 ${22 + i * 24})"><rect width="11" height="11" rx="3" fill="${cores[i % 5]}"/><text x="17" y="10" font-size="12.5" fill="var(--fg)">${esc(p.n.length > 22 ? p.n.slice(0, 21) + "…" : p.n)}</text><text x="204" y="10" font-size="12.5" font-weight="600" text-anchor="end" fill="var(--fg)">${esc(pct(p.v / tot))}</text></g>`).join("");
    return `<svg class="grafico" viewBox="0 0 360 ${Math.max(146, 30 + partes.length * 24)}" role="img" aria-label="alocação">${arcos}<text x="${cx}" y="${cy + 4}" text-anchor="middle" font-size="11.5" font-weight="700" fill="var(--fg)">${esc(centro || "")}</text>${leg}</svg>`;
  }
  function barrasCenarios(c) {
    const ks = [["otimista", "Otimista", "var(--good)"], ["base", "Base", "var(--chart-2)"], ["pessimista", "Pessimista", "var(--bad)"]];
    const vals = ks.map(([k]) => Number(((c || {})[k] || {}).retorno_12m_pct) || 0);
    const temNeg = vals.some((v) => v < 0), W = 360, z0 = 118, z1 = W - 44;
    const mid = temNeg ? (z0 + z1) / 2 : z0, max = Math.max(5, ...vals.map(Math.abs));
    const k = (temNeg ? (z1 - z0) / 2 : z1 - z0) / max;
    return `<svg class="grafico" viewBox="0 0 ${W} 104" role="img" aria-label="cenários de retorno em 12 meses">
      <line x1="${mid}" x2="${mid}" y1="2" y2="102" stroke="var(--line)"/>
      ${ks.map(([key, n, cor], i) => { const v = vals[i], p = ((c || {})[key] || {}).prob; const w = Math.abs(v) * k; const x = v >= 0 ? mid : mid - w; const y = 6 + i * 33;
        const tx = v >= 0 ? mid + w + 5 : mid - w - 5;
        return `<text x="0" y="${y + 11}" font-size="12.5" fill="var(--fg)">${n}</text><text x="0" y="${y + 25}" font-size="11" fill="var(--muted)">chance ${esc(pct(p))}</text>
        <rect x="${x}" y="${y + 4}" width="${Math.max(w, 1.5)}" height="16" rx="4" fill="${cor}" fill-opacity=".85"/>
        <text x="${tx}" y="${y + 16}" font-size="12" font-weight="650" text-anchor="${v >= 0 ? "start" : "end"}" fill="var(--fg)">${v > 0 ? "+" : ""}${esc(String(v).replace(".", ","))}%</text>`; }).join("")}
    </svg>`;
  }
  function barraProgresso(f) {
    const w = Math.max(0.004, Math.min(1, f)) * 100;
    return `<svg class="grafico" viewBox="0 0 100 6" preserveAspectRatio="none" role="img" aria-label="progresso"><rect width="100" height="6" rx="3" fill="var(--line)"/><rect width="${w}" height="6" rx="3" fill="var(--chart-1)"/></svg>`;
  }

  // ---------------------------------------------------------------- telas
  const ICONES = {
    hoje: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/></svg>',
    carteira: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="6" width="18" height="14" rx="3"/><path d="M3 10h18M16 15h2"/></svg>',
    analises: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/></svg>',
    ajustes: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1"/></svg>',
  };
  const MARCA = '<svg viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="#0B6B57"/><path d="M14 26 32 15l18 11M18 27v19M26 27v19M38 27v19M46 27v19M13 50h38" stroke="#E5ECE8" stroke-width="3.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const MESES = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"];

  // linguagem de gente: os códigos internos ficam escondidos
  function nomeProposta(pid) {
    if (/^B\d{12}$/.test(pid)) return "Plano de " + pid.slice(7, 9) + "/" + pid.slice(5, 7);
    if (/^\d{12}$/.test(pid)) return "Ajuste de " + MESES[+pid.slice(4, 6) - 1];
    if (/^TESTE/.test(pid)) return "Teste do botão";
    return pid;
  }
  function revisao(v) {
    v = v || {};
    const rt = v.red_team || "", sg = v.segunda || "";
    if (/rejeit/i.test(rt) || /rejeit/i.test(sg)) {
      const m = /rejeit/i.test(rt) ? v.red_team_motivo : v.segunda_motivo;
      return `<div class="aviso">⚠️ Um analista independente discordou${m ? ": " + esc(m) : ""}. Releia antes de comprar.</div>`;
    }
    if (/testar/i.test(rt)) return `<div class="aviso">⚠️ Um analista sugere começar com valor pequeno${v.red_team_motivo ? ": " + esc(v.red_team_motivo) : ""}.</div>`;
    if (rt && sg && !/indispon|sem voto/i.test(rt + sg)) return `<span class="chip bom">Revisado por 2 analistas independentes ✓</span>`;
    return `<span class="chip">Revisão independente incompleta</span>`;
  }

  const abertas = () => Object.values(D.boletas || {}).filter((b) => b.status === "aberta" && !LOCAL[b.id]).sort((a, b) => a.id.localeCompare(b.id));
  const pendentes = () => Object.entries(D.pendentes || {}).filter(([pid]) => !LOCAL[pid]).sort((a, b) => new Date(a[1].criada) - new Date(b[1].criada));
  const manuaisSemBoleta = () => Object.entries(D.manuais || {}).filter(([pid]) => !LOCAL[pid] && !Object.values(D.boletas || {}).some((b) => b.proposta === pid));

  function casca(conteudo) {
    const n = abertas().length + pendentes().length + manuaisSemBoleta().length + (D.leituras || []).filter((l) => !LOCAL[l.id]).length;
    const abas = [["hoje", "Hoje"], ["carteira", "Carteira"], ["analises", "Análises"], ["ajustes", "Ajustes"]];
    $("#app").innerHTML = `
      <header class="topo"><div><h1>Painel da Holding</h1><div class="sub">atualizado ${esc(D.carregadoEm ? D.carregadoEm.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }) : "")}</div></div>
        <div class="botoes"><button class="icone-btn" id="b-atualizar" aria-label="Atualizar">↻</button><button class="icone-btn" id="b-bloquear">Bloquear</button></div></header>
      <main>${conteudo}</main>
      <nav class="abas">${abas.map(([k, nome]) => `<button data-aba="${k}" class="${aba === k ? "ativa" : ""}">${ICONES[k]}<span>${nome}</span>${k === "hoje" && n ? `<b class="badge">${n}</b>` : ""}</button>`).join("")}</nav>`;
    document.querySelectorAll("nav.abas button").forEach((b) => b.addEventListener("click", () => { aba = b.dataset.aba; render(); window.scrollTo(0, 0); }));
    $("#b-bloquear").addEventListener("click", bloquear);
    $("#b-atualizar").addEventListener("click", async () => { toast("Atualizando…"); try { await carregar(); render(); } catch (e) { erroRede(e); } });
    ligarComum();
  }

  function render() {
    if (!S) return telaPin();
    const telas = { hoje: telaHoje, carteira: telaCarteira, analises: telaAnalises, ajustes: telaAjustes };
    (telas[aba] || telaHoje)();
  }

  // só aparece quando há algo errado (Apple: silêncio quando está tudo bem)
  function faixaStatus() {
    const v = D.verif || {};
    if (v.registro_integro === false) return `<div class="status congelado"><i class="ponto perigo"></i><b>Registro com problema de integridade.</b> O robô não executa nada.</div>`;
    const horas = v.quando ? (Date.now() - new Date(v.quando)) / 36e5 : null;
    if (horas == null || horas > 26) return `<div class="status"><i class="ponto alerta"></i>O robô não verifica há mais de um dia (última: ${esc(dataBR(v.quando))}).</div>`;
    return "";
  }

  // ---------------------------------------------------------------- Hoje: uma ação por vez
  function proximasDatas() {
    const ult = D.registro.filter((r) => r.tipo === "banca").pop();
    const banca = ult ? new Date(+new Date(ult.quando) + 13 * 864e5) : null;
    const hoje = new Date(); const ciclo = new Date(hoje.getFullYear(), hoje.getMonth() + 1, 1);
    return { banca, ciclo };
  }
  const aporteLivre = () => D.aporte && D.aporte.valor_brl && !D.aporte.usado_em;
  const doMes = (tipo) => { const m = new Date().toISOString().slice(0, 7); return D.registro.filter((r) => r.tipo === tipo && String(r.quando).startsWith(m)); };
  function diasToken() { if (!D.tokenVence) return null; return Math.floor((new Date(D.tokenVence) - Date.now()) / 864e5); }

  function acoes() {
    const lista = [];
    if (D.congelado) lista.push({ k: "congelado" });
    const vistos = ler("recados-vistos") || [];
    (D.recados || []).filter((r) => !vistos.includes(r.id)).slice(-3).forEach((r) => lista.push({ k: "recado", r }));
    (D.leituras || []).filter((l) => !LOCAL[l.id]).forEach((l) => lista.push({ k: "leitura", l }));
    const ab = abertas(); if (ab.length) lista.push({ k: "ordem", b: ab[0], n: ab.length, total: Object.values(D.boletas).filter((b) => b.grupo === ab[0].grupo).length });
    manuaisSemBoleta().forEach(([pid, o]) => lista.push({ k: "manual", pid, o }));
    pendentes().forEach(([pid, p]) => lista.push({ k: "proposta", pid, p }));
    const { banca } = proximasDatas();
    if (!aporteLivre() && (!banca || banca - Date.now() < 4 * 864e5)) lista.push({ k: "aporte" });
    const dt = diasToken(); if (dt != null && dt <= 30) lista.push({ k: "token", dt });
    const conferiu = doMes("carteira_conferida").length || doMes("carteira_sincronizada_print").length;
    if (!totalReal().vazio && !conferiu && new Date().getDate() >= 20) lista.push({ k: "conferir" });
    if (D.retro && ler("retro-vista") !== D.retro.mes) lista.push({ k: "retro" });
    return lista;
  }

  function heroi(a) {
    const quantos = (n) => (n > 1 ? `<span class="chip">${n} para fazer</span>` : "");
    switch (a.k) {
      case "congelado": return `<section class="card heroi perigo"><span class="rotulo">Agora</span><h2>Sistema congelado</h2><span class="mudo">Nenhuma proposta ou ordem nova até você liberar.</span>
        <div class="botoes"><button class="btn prim cheio" data-acao="descongelar">Liberar o sistema</button></div></section>`;
      case "leitura": return cartaoLeitura(a.l);
      case "recado": { const r = a.r, sug = { revisar_tese: "O CEO pediu à banca completa que revise essa tese.", antecipar_banca: "O CEO sugere antecipar a banca completa: informe o dinheiro disponível em Ajustes." }[r.sugestao] || "";
        return `<section class="card heroi"><span class="rotulo">Recado do CEO · ${esc(String(r.data || "").split("-").reverse().slice(0, 2).join("/"))}</span><h2>${esc(r.titulo)}</h2>
          <div class="texto">${esc(r.recado)}</div>${sug ? `<span class="mudo">${esc(sug)}</span>` : ""}
          <div class="botoes"><button class="btn prim cheio" data-recado="${esc(r.id)}">Entendi</button><button class="btn cheio" data-ir-diario="1">Ver o diário</button></div></section>`; }
      case "ordem": { const b = a.b, verbo = b.lado === "vender" ? "Venda" : (b.codigo_ordem ? "Compre" : "Aplique em");
        const quanto = b.codigo_ordem && b.quantidade ? `${qtdTxt(b.quantidade)} ${esc(b.codigo_ordem)}` : esc(b.codigo_ordem || b.ativo);
        return `<section class="card heroi"><div class="linha"><span class="rotulo">Agora · ordem ${esc(Number(b.id.slice(-2)))} de ${esc(a.total)}</span>${quantos(a.n)}</div>
          <h2>${verbo} ${quanto} no ${esc(b.instituicao === "C6" ? "C6" : "IBKR")}</h2>
          <span class="mudo">${esc(b.ativo)} · ${din(b.valor, b.moeda)}${b.preco_limite ? ` · preço ${b.lado === "vender" ? "mínimo" : "máximo"} ${din(b.preco_limite, b.moeda)}` : ""}</span>
          ${b.alerta ? `<div class="aviso">⚠️ ${esc(b.alerta)}</div>` : ""}
          ${botoesBoleta(b)}
          <details><summary>Passo a passo no app</summary><ol class="passos">${(b.passos || []).map((p) => `<li>${esc(p)}</li>`).join("")}</ol></details></section>`; }
      case "manual": return `<section class="card heroi"><span class="rotulo">Agora</span><h2>Confirme a ordem do ${esc(nomeProposta(a.pid).toLowerCase())}</h2>
        <table class="tabela">${Object.entries(a.o.ordens || {}).map(([t, q]) => `<tr><td>${q < 0 ? "Vender" : "Comprar"} ${esc(t)}</td><td class="num">${esc(qtdTxt(Math.abs(q)))}</td><td class="num">${usd(Math.abs(q * ((a.o.precos || {})[t] || 0)), 2)}</td></tr>`).join("")}</table>
        <div class="botoes"><button class="btn decide cheio" data-acao="executei" data-alvo="${esc(a.pid)}">Comprei</button><button class="btn cheio" data-acao="naoexecutei" data-alvo="${esc(a.pid)}">Não comprei</button></div></section>`;
      case "proposta": return cartaoProposta(a.pid, a.p);
      case "aporte": { const { banca } = proximasDatas();
        return `<section class="card heroi"><span class="rotulo">Agora</span><h2>Quanto dinheiro novo você tem para investir?</h2>
          <span class="mudo">Metade vai para o cofre da aposentadoria (no ciclo do mês) e a outra metade a banca${banca ? " de " + esc(banca.toLocaleDateString("pt-BR")) : ""} distribui, defendendo quanto vai em cada ativo. Nada é comprado agora.</span>
          <div class="botoes"><button class="btn prim cheio" id="b-aporte">Informar valor</button></div></section>`; }
      case "token": return `<section class="card heroi"><span class="rotulo">Agora</span><h2>Renove a chave do Painel</h2>
        <span class="mudo">${a.dt > 0 ? `Ela vence em ${esc(a.dt)} dia(s)` : "Ela venceu"}. Leva 2 minutos; o passo a passo está em Ajustes.</span>
        <div class="botoes"><button class="btn prim cheio" data-ir="ajustes">Ver o passo a passo</button></div></section>`;
      case "conferir": return `<section class="card heroi"><span class="rotulo">Agora</span><h2>Confira sua carteira com o extrato</h2>
        <span class="mudo">Uma vez por mês: abra o app de cada banco e compare com a aba Carteira. O jeito mais rápido é mandar um print.</span>
        <div class="botoes"><button class="btn prim cheio" id="b-print">Atualizar pelo print</button><button class="btn cheio" data-acao="conferi" data-alvo="">Está tudo certo</button></div></section>`;
      case "retro": return `<section class="card heroi"><span class="rotulo">Retrospectiva</span><h2>Seu mês de ${esc(MESES[+D.retro.mes.slice(5, 7) - 1])}</h2>
        <div class="texto" id="retro-txt">Carregando…</div><div class="botoes"><button class="btn cheio" id="b-retro-ok">Ok, visto</button></div></section>`;
    }
    return "";
  }

  function telaHoje() {
    const lista = acoes(), h = lista[0];
    const { banca, ciclo } = proximasDatas();
    casca(`
      ${faixaStatus()}
      ${bannerDesfazer()}
      ${h ? heroi(h) : `<section class="card heroi ok"><span class="rotulo">Hoje</span><h2>Tudo em dia ✓</h2>
        <span class="mudo">Nada para você fazer agora.${banca ? ` Próxima banca: ${esc(banca.toLocaleDateString("pt-BR"))}.` : ""} Próximo ajuste do mês: ${esc(ciclo.toLocaleDateString("pt-BR"))}. Você recebe um aviso quando houver algo.</span></section>`}
      ${lista.length > 1 ? `<div class="depois mudo">Depois disso: ${lista.slice(1).map((a) => esc(rotuloAcao(a))).join(" · ")}</div>` : ""}
      ${cartaoMeta()}
      ${cartaoResumoCarteira()}
    `);
    const r = $("#b-retro-ok"); if (r) r.addEventListener("click", () => { guardar("retro-vista", D.retro.mes); render(); });
    if ($("#retro-txt")) bruto(D.retro.arquivo).then((t) => { const el = $("#retro-txt"); if (el) el.textContent = (t || "").replace(/\*/g, ""); }).catch(() => {});
    const rc = $("#resumo-carteira"); if (rc) rc.addEventListener("click", () => { aba = "carteira"; render(); });
  }
  function rotuloAcao(a) {
    return { recado: "ler o recado do CEO", congelado: "liberar o sistema", leitura: "conferir a leitura do print", ordem: `${a.n} ordem(ns) no banco`, manual: "confirmar ordem",
      proposta: "decidir o " + nomeProposta(a.pid || "").toLowerCase(), aporte: "informar o dinheiro da banca", token: "renovar a chave",
      conferir: "conferir a carteira", retro: "ver a retrospectiva" }[a.k] || "";
  }

  // meta como trajetória, no cenário pessimista, e o anel do mês
  function aporteNecessario(atual, meta, meses, realAa) {
    const i = Math.pow(1 + realAa, 1 / 12) - 1, f = Math.pow(1 + i, meses);
    if (meses <= 0) return Math.max(0, meta - atual);
    const falta = meta - atual * f; if (falta <= 0) return 0;
    return i ? falta * i / (f - 1) : falta / meses;
  }
  function anel(fracs) {
    const cores = ["var(--chart-1)", "var(--chart-2)", "var(--chart-3)"], R = [44, 33, 22];
    return `<svg class="anel" viewBox="0 0 100 100" role="img" aria-label="anel do mês">${fracs.map((f, i) => { const c = 2 * Math.PI * R[i];
      return `<circle cx="50" cy="50" r="${R[i]}" fill="none" stroke="${cores[i]}" stroke-opacity=".18" stroke-width="8"/><circle cx="50" cy="50" r="${R[i]}" fill="none" stroke="${cores[i]}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${(Math.max(0.001, Math.min(1, f)) * c).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 50 50)"/>`; }).join("")}</svg>`;
  }
  function cartaoMeta() {
    const tr = totalReal(), atual = tr.vazio ? valorCarteira(D.real) : tr.totalUsd, M = D.meta;
    const ini = new Date(M.inicio + "T12:00:00"), fimMeses = ini.getFullYear() * 12 + ini.getMonth() + M.anos * 12;
    const agora = new Date(), meses = Math.max(0, fimMeses - (agora.getFullYear() * 12 + agora.getMonth()));
    const precisa = aporteNecessario(atual, M.valor, meses, M.real);
    const desfeitos = new Set(D.registro.filter((r) => r.tipo === "desfeito").map((r) => (r.dados || {}).comando));
    const compras = doMes("ordem_executada").map((r) => r.dados || {}).filter((d) => d.lado === "comprar" && !desfeitos.has(d.comando) && !["cofre", "caixa_cofre"].includes(d.classe));
    const aportado = compras.reduce((s, d) => s + d.quantidade * d.preco / (d.moeda === "BRL" ? D.cambio : 1), 0);
    const ritmo = precisa ? aportado / precisa : 1;
    const doGrupoMes = Object.values(D.boletas || {}).filter((b) => String(b.criada).slice(0, 7) === agora.toISOString().slice(0, 7));
    const comprou = doGrupoMes.length ? doGrupoMes.filter((b) => b.status !== "aberta").length / doGrupoMes.length : (compras.length ? 1 : 0);
    const conferiu = doMes("carteira_conferida").length || doMes("carteira_sincronizada_print").length ? 1 : 0;
    return `<section class="card"><span class="rotulo">Meta · ${usd(M.valor)} em poder de compra de hoje</span>
      <div class="meta-grade">${anel([ritmo, comprou, conferiu])}
        <div class="legenda-anel"><span><i class="c1"></i>Aporte do mês: <b>${esc(pct(Math.min(ritmo, 9.99)))}</b> do ritmo</span>
          <span><i class="c2"></i>Ordens do mês: <b>${esc(pct(comprou))}</b> feitas</span>
          <span><i class="c3"></i>Carteira conferida: <b>${conferiu ? "sim" : "ainda não"}</b></span></div></div>
      <span class="mudo">Ritmo no cenário pessimista (${esc((M.real * 100).toLocaleString("pt-BR"))}% ao ano acima da inflação, o pior período de 16 anos da história da estratégia): <b>${usd(precisa)}/mês</b> (≈ ${brl(precisa * D.cambio)}). Este mês: ${usd(aportado)}. Hoje você tem ${usd(atual)}.</span></section>`;
  }
  function cartaoResumoCarteira() {
    const tr = totalReal();
    if (tr.vazio) return `<button class="card cartao-btn" id="resumo-carteira"><h2>Minha carteira real</h2><span class="mudo">Ainda vazia. Lance o que você já tem na IBKR e no C6, ou mande um print do app.</span></button>`;
    return `<button class="card cartao-btn" id="resumo-carteira"><div class="linha"><h2>Minha carteira real</h2><b>${usd(tr.totalUsd)}</b></div><span class="mudo">IBKR ${usd(tr.usd)} · C6 ${brl(tr.brl)}</span></button>`;
  }

  function venceEm(criada) {
    const h = D.validadeH - (Date.now() - new Date(criada)) / 36e5;
    return h <= 0 ? `<span class="chip ruim">vencida</span>` : `<span class="chip ${h < 12 ? "meio" : ""}">vence em ${esc(Math.floor(h))} h</span>`;
  }
  function cartaoProposta(pid, p) {
    if (p.tipo === "banca") {
      const ts = D.teses.filter((t) => t.plano === pid);
      const reg = D.registro.filter((r) => r.tipo === "banca" && (r.dados || {}).plano === pid).pop();
      const dd = (reg || {}).dados || {};
      const comValor = ts.some((t) => Number(t.valor_brl) > 0);
      const total = ts.filter((t) => ["comprar", "manter"].includes(t.direcao)).reduce((s, t) => s + (Number(t.valor_brl) || 0), 0);
      if (comValor) return `<section class="card heroi"><div class="linha"><span class="rotulo">Agora</span>${venceEm(p.criada)}</div>
        <h2>Aprove o ${esc(nomeProposta(pid).toLowerCase())}: ${brl(total)}</h2>
        ${relatorioCEO(ts, dd.aporte_brl, dd.caixa_brl)}
        <span class="mudo">Aprovar gera as ordens banco por banco. Nada é comprado sozinho: você compra no app de cada banco.</span>
        <div class="botoes"><button class="btn decide cheio" data-acao="aprovar" data-alvo="${esc(pid)}">Aprovar</button><button class="btn cheio" data-acao="recusar" data-alvo="${esc(pid)}">Recusar</button></div></section>`;
      return `<section class="card heroi"><div class="linha"><span class="rotulo">Agora</span>${venceEm(p.criada)}</div>
        <h2>Decida o ${esc(nomeProposta(pid).toLowerCase())}</h2>
        <span class="mudo">Plano antigo, sem valores por ativo: ao aprovar, informe quanto quer aplicar.</span>
        ${ts.map((t) => `<details class="item-ceo"><summary><span class="campos3"><span><i>Ação</i><b>${esc(t.ticker || "produto")}</b> · ${esc(t.ativo)}</span><span><i>Peso</i>${esc(t.peso_pct || 0)}%</span></span><span class="ver">por que</span></summary>${cartaoTese(t)}</details>`).join("")}
        <div class="botoes"><button class="btn decide cheio" data-acao="aprovar" data-alvo="${esc(pid)}" data-valor="1">Aprovar</button><button class="btn cheio" data-acao="recusar" data-alvo="${esc(pid)}">Recusar</button></div></section>`;
    }
    if (p.tipo === "teste") return `<section class="card heroi"><div class="linha"><span class="rotulo">Agora</span>${venceEm(p.criada)}</div><h2>Teste do botão</h2><span class="mudo">Não mexe em dinheiro.</span>
        <div class="botoes"><button class="btn prim cheio" data-acao="aprovar" data-alvo="${esc(pid)}">Aprovar teste</button></div></section>`;
    const alvo = p.alvo || {};
    return `<section class="card heroi"><div class="linha"><span class="rotulo">Agora</span>${venceEm(p.criada)}</div>
      <h2>Aprove o ${esc(nomeProposta(pid).toLowerCase())}</h2>
      <span class="mudo">A regra de tendência mantém cada ativo só enquanto o preço está acima da média de 10 meses; abaixo dela, a fatia fica em caixa.</span>
      <table class="tabela"><tr><th>Ativo</th><th class="num">Fatia</th></tr>
      ${Object.entries(alvo).map(([t, w]) => `<tr><td>${esc(t)}</td><td class="num">${esc(pct(w))}</td></tr>`).join("")}
      <tr><td>Caixa</td><td class="num">${esc(pct(1 - Object.values(alvo).reduce((s, w) => s + w, 0)))}</td></tr></table>
      ${p.aprovada ? `<div class="aviso ok">Já aprovado: aguardando preço ou liberação do sistema.</div>` : `<div class="botoes"><button class="btn decide cheio" data-acao="aprovar" data-alvo="${esc(pid)}">Aprovar</button><button class="btn cheio" data-acao="recusar" data-alvo="${esc(pid)}">Recusar</button></div>`}</section>`;
  }

  // ficha padrão de um ativo: sempre os mesmos campos, na mesma ordem (igual ao relatório da banca)
  const NOMES_CLASSE = { acoes_exterior: "ações no exterior", titulos_eua: "títulos dos EUA", ouro: "ouro", renda_fixa_privada: "renda fixa privada", acoes_brasil: "ações no Brasil", fundos_imobiliarios: "fundo imobiliário", fundos_e_previdencia: "fundo / previdência" };
  const instDe = (t) => (t.mercado === "Brasil" ? "C6" : "IBKR");
  const NOME_INST = { IBKR: "IBKR · em dólar", C6: "C6 Bank · em reais" };
  function cartaoTese(t, aporte) {
    const args = (t.argumentos && t.argumentos.length ? t.argumentos : [t.causa]).filter(Boolean).slice(0, 3)
      .map((x) => (typeof x === "string" ? { texto: x, status: "sem_fonte" } : x));
    const MARCA = { conferido: ["bom", "✓ fonte conferida"], fraco: ["meio", "⚠ número curto demais para conferir"], nao_encontrado: ["ruim", "⚠ número não achado na fonte"], fonte_fora_do_ar: ["meio", "⚠ fonte não abriu"], sem_fonte: ["meio", "⚠ sem fonte verificável"] };
    const nConf = args.filter((x) => x.status === "conferido").length;
    const val = Number(t.valor_brl) || 0;
    const rev = t.revisar_em_dias && t.data ? new Date(+new Date(t.data) + t.revisar_em_dias * 864e5).toLocaleDateString("pt-BR") : "não informado";
    const campo = (n, v2) => `<div class="campo-f"><span class="n">${n}</span><span class="v">${v2}</span></div>`;
    const dir = { comprar: "COMPRAR", manter: "MANTER", vender: "VENDER", evitar: "NÃO COMPRAR" }[t.direcao] || (t.direcao || "").toUpperCase();
    return `<div class="tese"><div class="cab"><span class="nome">${esc(t.ativo)}</span><span class="dir ${esc(t.direcao)}">${esc(dir)}</span></div>
      ${campo("Ativo", `<b>${esc(t.ticker || "sem código (produto)")}</b> · ${esc(NOMES_CLASSE[t.classe] || t.classe || "")}`)}
      ${campo("O que é", esc(t.explicacao_simples || "—"))}
      ${campo("Onde", esc(NOME_INST[instDe(t)]))}
      ${campo("Valor", val ? `<b>${brl(val)}</b>${aporte ? ` <span class="mudo">(${esc(Math.round(val / aporte * 100))}% do aporte)</span>` : ""}` : (t.peso_pct ? esc(t.peso_pct) + "% do plano" : "não investir"))}
      ${campo("Por que", `<span class="mudo">fontes conferidas: ${nConf} de ${args.length}</span><ol class="args">${args.map((x) => { const mk = MARCA[x.status] || MARCA.sem_fonte;
        return `<li>${esc(x.texto)} <span class="chip mini-chip ${mk[0]}">${esc(mk[1])}</span>${/^https?:\/\//.test(x.fonte_url || "") ? ` <a class="fonte" href="${esc(x.fonte_url)}" target="_blank" rel="noopener noreferrer">fonte</a>` : ""}</li>`; }).join("")}</ol>`)}
      ${campo("Risco", esc(t.risco_principal || "não informado pela banca"))}
      ${campo("Cenários 12m", barrasCenarios(t.cenarios))}
      ${campo("Vende se", esc(t.gatilho_saida || "—"))}
      ${campo("Revisar em", esc(rev))}
      ${revisao(t.votos)}</div>`;
  }

  // relatório de investimento do CEO: Instituição, Ação, Valor; a ficha abre ao tocar
  function relatorioCEO(ts, aporte, caixa) {
    const compra = ts.filter((t) => ["comprar", "manter"].includes(t.direcao) && Number(t.valor_brl) > 0);
    const evitar = ts.filter((t) => ["vender", "evitar"].includes(t.direcao));
    const grupos = ["IBKR", "C6"].map((i) => [i, compra.filter((t) => instDe(t) === i)]).filter(([, g]) => g.length);
    return `<div class="ceo"><span class="mudo">Dinheiro informado ${aporte ? brl(aporte) : "—"}${caixa ? ` · fica em caixa ${brl(caixa)}` : ""}</span>
      ${grupos.map(([i, g]) => `<div class="grupo-inst"><div class="linha"><b>${esc(NOME_INST[i])}</b><span>${brl(g.reduce((s, t) => s + Number(t.valor_brl), 0))}${i === "IBKR" ? ` <span class="mudo">≈ ${usd(g.reduce((s, t) => s + Number(t.valor_brl), 0) / D.cambio)}</span>` : ""}</span></div>
        ${g.map((t) => `<details class="item-ceo"><summary><span class="campos3"><span><i>Instituição</i>${esc(i)}</span><span><i>Ação</i><b>${esc(t.ticker || "produto")}</b> · ${esc(t.ativo)}</span><span><i>Valor</i><b>${brl(Number(t.valor_brl))}</b></span></span><span class="ver">por que</span></summary>${cartaoTese(t, aporte)}</details>`).join("")}</div>`).join("")}
      ${evitar.length ? `<span class="mudo">🚫 Não comprar: ${esc(evitar.map((t) => t.ticker || t.ativo).join(", "))}</span>` : ""}</div>`;
  }

  // ---------------------------------------------------------------- Carteira: ordens, carteira real, desfazer, print
  const BANCOS = { IBKR: ["IBKR · em dólar", "App Interactive Brokers", "atws.app"], C6: ["C6 Bank · em reais", "App C6 Bank", "com.c6bank.app"] };
  const din = (v, moeda, d = 2) => (moeda === "USD" ? usd(v, d) : brl(v, d));
  const qtdTxt = (q) => (q == null ? "—" : Number(q).toLocaleString("pt-BR", { maximumFractionDigits: 4 }));
  function textoOrdens(lista) {
    const l = ["*Ordens para executar*", ""];
    for (const inst of ["IBKR", "C6"]) {
      const bs = lista.filter((b) => b.instituicao === inst); if (!bs.length) continue;
      const m = bs[0].moeda, tot = bs.reduce((s, b) => s + (b.valor || 0), 0);
      l.push(`🏦 *${BANCOS[inst][0]}* · total ${din(tot, m)}`);
      bs.forEach((b) => l.push(`${b.id.slice(-2)}. ${b.lado === "vender" ? "VENDER" : "COMPRAR"} *${b.codigo_ordem || "produto"}* · ${b.ativo} · ${din(b.valor, m)}` +
        (b.quantidade ? ` · ${qtdTxt(b.quantidade)} un.` : "") + (b.preco_limite ? ` · limite ${din(b.preco_limite, m)}` : "") + (b.alerta ? `\n   ⚠️ ${b.alerta}` : "")));
      l.push("");
    }
    l.push("Ordens limitadas, válidas no dia. Depois de cada uma: Painel → Comprei.");
    return l.join("\n");
  }
  async function copiar(texto, msg) {
    try { await navigator.clipboard.writeText(texto); if (msg) toast(msg); return true; } catch (e) { toast("Não consegui copiar: selecione e copie à mão."); return false; }
  }
  // copia o código e abre o app do banco (Android); se o app não estiver instalado, o Chrome leva à loja
  async function copiarEAbrir(cod, inst) {
    if (cod) await copiar(cod, "Código " + cod + " copiado: cole na busca do app.");
    const pacote = (BANCOS[inst] || [])[2];
    if (pacote && /Android/i.test(navigator.userAgent)) location.href = `intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.LAUNCHER;package=${pacote};end`;
  }
  function botoesBoleta(b) {
    const comprou = b.lado === "vender" ? "Vendi" : b.codigo_ordem ? "Comprei" : "Apliquei";
    return `<div class="botoes"><button class="btn prim cheio" data-abrir="${esc(b.codigo_ordem || "")}" data-inst="${esc(b.instituicao)}">${b.codigo_ordem ? "Copiar código e abrir o app" : "Abrir o app do banco"}</button></div>
      <div class="botoes"><button class="btn decide cheio" data-exec="${esc(b.id)}">${comprou}</button><button class="btn cheio" data-naoexec="${esc(b.id)}">Não ${comprou.toLowerCase()}</button></div>`;
  }
  function cartaoBoleta(b) {
    const venc = b.valida_ate && new Date(b.valida_ate) < new Date();
    const m = b.moeda, produto = !b.codigo_ordem;
    return `<div class="boleta"><div class="cab"><span class="dir ${b.lado === "vender" ? "vender" : "comprar"}">${b.lado === "vender" ? "VENDER" : "COMPRAR"}</span>
        <span class="mudo">Ordem ${esc(Number(b.id.slice(-2)))}</span>${venc ? '<span class="chip ruim">vencida: confira o preço</span>' : ""}</div>
      ${produto ? `<div class="codigo produto">${esc(b.ativo)}</div>` : `<div class="codigo">${esc(b.codigo_ordem)}</div><span>${esc(b.ativo)}${b.bolsa ? " · " + esc(b.bolsa) : ""}</span>`}
      <table class="tabela">
        <tr><td>Valor</td><td class="num"><b>${din(b.valor, m)}</b>${m === "USD" && b.valor_brl ? ` <span class="mudo">(${brl(b.valor_brl)})</span>` : ""}</td></tr>
        ${produto ? "" : `<tr><td>Quantidade</td><td class="num">${b.quantidade ? qtdTxt(b.quantidade) : "pelo preço da tela"}</td></tr>
        <tr><td>Preço ${b.lado === "vender" ? "mínimo" : "máximo"}</td><td class="num">${b.preco_limite ? din(b.preco_limite, m) : "o da tela"} · ordem limitada</td></tr>`}
      </table>
      ${b.alerta ? `<div class="aviso">⚠️ ${esc(b.alerta)}</div>` : ""}
      ${botoesBoleta(b)}
      <details><summary>Passo a passo no ${esc(BANCOS[b.instituicao] ? BANCOS[b.instituicao][1] : b.app)}</summary><ol class="passos">${(b.passos || []).map((p) => `<li>${esc(p)}</li>`).join("")}</ol></details></div>`;
  }
  function bannerDesfazer() {
    const loc = ULTIMO && Date.now() - ULTIMO.t < 10 * 60000 ? ULTIMO : null;
    const srv = !loc && D.desfazer && Date.now() - new Date(D.desfazer.quando) < 10 * 60000 ? { id: D.desfazer.cmd, resumo: D.desfazer.resumo } : null;
    const u = loc || srv; if (!u || LOCAL["desfazer:" + u.id]) return "";
    return `<div class="desfazer"><span>✓ ${esc(u.resumo)}</span><button class="mini" data-desfazer="${esc(u.id)}">Desfazer</button></div>`;
  }
  function telaCarteira() {
    const lista = abertas();
    const feitas = Object.values(D.boletas || {}).filter((b) => b.status !== "aberta" || LOCAL[b.id]).sort((a, b) => String(b.decidida || "9").localeCompare(String(a.decidida || "9"))).slice(0, 12);
    const grupos = ["IBKR", "C6"].map((inst) => [inst, lista.filter((b) => b.instituicao === inst)]).filter(([, bs]) => bs.length);
    casca(`
      ${bannerDesfazer()}
      ${lista.length ? `<section class="card"><div class="linha"><h2>${lista.length} ordem(ns) para fazer no banco</h2><button class="mini" id="b-compartilhar">Compartilhar</button></div>
        <span class="mudo">Uma por vez: copie o código, compre no app do banco e toque em Comprei.</span></section>` : ""}
      ${grupos.map(([inst, bs]) => { const m = bs[0].moeda, tot = bs.reduce((s, b) => s + (b.valor || 0), 0);
        return `<section class="card"><div class="linha"><h2>${esc(BANCOS[inst][0])}</h2><span class="mudo">${din(tot, m)}</span></div>
          ${inst === "IBKR" ? `<span class="mudo">Antes de começar, tenha ${din(tot, m)} de saldo em dólar na IBKR.</span>` : ""}
          ${bs.map(cartaoBoleta).join("")}</section>`; }).join("")}
      ${secaoCarteiraReal()}
      ${feitas.length ? `<section class="card"><h2>Últimos registros</h2><div class="lista">${feitas.map((b) => { const e = b.executado || {}, l = LOCAL[b.id];
        return `<div class="item"><span>${l ? "⏳" : b.status === "executada" ? "✅" : "✖️"}</span><span class="corpo"><span class="t">${esc(b.codigo_ordem || b.ativo)} · ${esc(b.instituicao)}</span><span class="d">${l ? "registrado, confirmando com o robô…" : b.status === "executada" ? `${esc(qtdTxt(e.quantidade))} × ${din(e.preco, b.moeda)} = ${din(e.total, b.moeda)}` : "não executada"}${l ? "" : " · " + esc(dataBR(b.decidida))}</span></span></div>`; }).join("")}</div></section>` : ""}
    `);
    const sh = $("#b-compartilhar");
    if (sh) sh.addEventListener("click", async () => { const t = textoOrdens(lista);
      if (navigator.share) { try { await navigator.share({ title: "Ordens para executar", text: t }); return; } catch (e) { if (e.name === "AbortError") return; } }
      copiar(t, "Ordens copiadas: cole no WhatsApp."); });
    const nv = $("#b-lancar"); if (nv) nv.addEventListener("click", () => ajustar(""));
  }

  function secaoCarteiraReal() {
    const ls = linhasReais(), pr = D.posReais || {}, tr = totalReal();
    const bloco = (inst) => { const moeda = inst === "IBKR" ? "USD" : "BRL"; const l = ls.filter((x) => x.inst === inst); const cx = (pr[inst] || {}).caixa || 0;
      const linha = (titulo, sub, valor, nota, alvo) => `<div class="pos"><div class="pos-t"><b>${titulo}</b><span class="mudo">${sub}</span></div><div class="pos-v"><b>${valor}</b>${nota ? `<span class="mudo">${nota}</span>` : ""}</div><button class="mini" data-ajustar="${esc(alvo)}">Ajustar</button></div>`;
      return `<h3>${esc(NOME_INST[inst])}</h3><div class="lista-pos">
        ${l.map((x) => linha(esc(x.cod), `${esc(x.ativo)} · ${esc(qtdTxt(x.q))} × ${din(x.pm, moeda)}`, din(x.valor, moeda), x.est ? "preço médio estimado: confira" : x.semCot ? "pelo preço médio" : (x.cot && x.pm ? `${x.cot >= x.pm ? "+" : ""}${pct(x.cot / x.pm - 1, 1)} desde a compra` : "preço de hoje"), inst + ":" + x.cod)).join("")}
        ${linha("Saldo em caixa", "dinheiro parado no banco", din(cx, moeda), "", inst + ":CAIXA")}</div>`; };
    return `<section class="card"><div class="linha"><h2>Minha carteira real</h2><b>${usd(tr.totalUsd)}</b></div>
      <span class="mudo">É o que você confirmou: muda quando você toca em Comprei, em Ajustar ou quando aplica a leitura de um print.</span>
      <div class="botoes"><button class="btn prim cheio" id="b-print">Atualizar pelo print</button></div>
      ${bloco("IBKR")}${bloco("C6")}
      <div class="botoes"><button class="btn cheio" id="b-lancar">Lançar outro ativo</button><button class="btn cheio" data-acao="conferi" data-alvo="">Conferi, está certo</button></div></section>`;
  }
  function ajustar(alvo) {
    const [inst0, cod0] = alvo ? alvo.split(":") : ["IBKR", ""];
    const caixa = cod0 === "CAIXA", pos = !caixa && cod0 ? (((D.posReais || {})[inst0] || {}).posicoes || {})[cod0] : null;
    const moeda = (i) => (i === "IBKR" ? "US$" : "R$");
    const f = modal(`<h2>${caixa ? "Saldo em caixa · " + esc(inst0) : cod0 ? "Ajustar " + esc(cod0) : "Lançar ativo"}</h2>
      <span class="mudo">Informe exatamente o que aparece no app do banco. ${caixa ? "" : "Quantidade 0 tira o ativo da carteira."}</span>
      ${alvo ? "" : `<div class="campo"><label for="aj-inst">Banco</label><select id="aj-inst"><option value="IBKR">IBKR (em dólar)</option><option value="C6">C6 Bank (em reais)</option></select></div>
        <div class="campo"><label for="aj-cod">Código do ativo (ex.: VWRA, ITUB4)</label><input id="aj-cod" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="24"></div>`}
      ${caixa ? `<div class="campo"><label for="aj-p">Saldo em caixa (${moeda(inst0)})</label><input id="aj-p" inputmode="decimal" autocomplete="off" value="${esc(String(((D.posReais || {})[inst0] || {}).caixa || "").replace(".", ","))}"></div>`
        : `<div class="campo"><label for="aj-q">Quantidade</label><input id="aj-q" inputmode="decimal" autocomplete="off" value="${pos ? esc(String(pos.quantidade).replace(".", ",")) : ""}"></div>
           <div class="campo"><label for="aj-p">Preço médio <span id="aj-moeda">(${moeda(inst0)})</span></label><input id="aj-p" inputmode="decimal" autocomplete="off" value="${pos ? esc(String(pos.preco_medio).replace(".", ",")) : ""}"></div>`}
      <div class="erro" id="aj-erro"></div><div class="botoes"><button class="btn decide cheio" id="aj-ok">Continuar</button><button class="btn cheio" data-fechar>Cancelar</button></div>`);
    const sel = $("#aj-inst", f); if (sel) sel.addEventListener("change", () => { $("#aj-moeda", f).textContent = "(" + moeda(sel.value) + ")"; });
    const instAtual = () => (sel ? sel.value : inst0);
    eco(f, [["#aj-q", "", () => instAtual() === "IBKR"], ["#aj-p", moeda(inst0)]]);
    $("#aj-ok", f).addEventListener("click", () => {
      const inst = sel ? sel.value : inst0;
      const cod = alvo ? cod0 : ($("#aj-cod", f).value || "").trim().toUpperCase();
      if (!/^[A-Z0-9.\-]{1,24}$/.test(cod)) { $("#aj-erro", f).textContent = "Código inválido: use letras, números, ponto ou traço."; return; }
      const rawQ = caixa ? "1" : $("#aj-q", f).value.trim(), rawP = $("#aj-p", f).value.trim();
      const q = rawQ === "0" ? 0 : numBR(rawQ, inst === "IBKR"), p = rawP === "0" ? 0 : numBR(rawP);
      if (q == null || p == null || (q > 0 && !caixa && p === 0)) { $("#aj-erro", f).textContent = "Preencha quantidade e preço médio."; return; }
      if (pos && q > 0 && (q / pos.quantidade > 5 || pos.quantidade / q > 5) && !f.dataset.avisado) { f.dataset.avisado = "1"; $("#aj-erro", f).textContent = `Isso é ${Math.round(Math.max(q / pos.quantidade, pos.quantidade / q))} vezes o que estava. Confere? Toque em Continuar de novo.`; return; }
      f.remove();
      const resumo = caixa ? `Caixa ${inst}: ${moeda(inst)} ${p.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}` : q === 0 ? `Tirar ${cod} da carteira ${inst}` : `${cod} no ${inst}: ${semGrupo(q, 0)} ${q === 1 ? "unidade" : "unidades"} a ${moeda(inst)} ${semGrupo(p, 2)} cada`;
      confirmar("ajustar", inst + ":" + cod, { tipo: "dados", dados: numStr(q) + ";" + numStr(p), aviso: "Confira: " + resumo + ".", resumo });
    });
  }

  // ---------------------------------------------------------------- sincronizar pelo print
  let PRINT_PENDENTE = null;   // imagem recebida pelo "Compartilhar" do Android
  function cartaoLeitura(l) {
    const atual = (((D.posReais || {})[l.banco] || {}).posicoes) || {};
    const m = l.banco === "IBKR" ? "USD" : "BRL";
    return `<section class="card heroi"><span class="rotulo">Agora</span><h2>Confira o que li no seu print do ${esc(l.banco)}</h2>
      <div class="lista-pos">${(l.posicoes || []).map((p) => { const a = atual[p.codigo] || (/F$/.test(p.codigo) ? atual[p.codigo.slice(0, -1)] : null);
        const mud = a ? (Math.abs(a.quantidade - (p.quantidade || 0)) > 1e-6 ? `antes ${qtdTxt(a.quantidade)}` : "igual") : "novo";
        return `<div class="pos"><div class="pos-t"><b>${esc(p.codigo)}</b><span class="mudo">${esc(p.ativo || "")}</span></div><div class="pos-v"><b>${p.quantidade != null ? esc(qtdTxt(p.quantidade)) : "não li"}</b><span class="mudo">${esc(mud)}${p.preco_medio ? " · médio " + din(p.preco_medio, m) : ""}</span></div><span></span></div>`; }).join("")}
        ${l.caixa != null ? `<div class="pos"><div class="pos-t"><b>Saldo em caixa</b></div><div class="pos-v"><b>${din(l.caixa, m)}</b></div><span></span></div>` : ""}</div>
      ${l.duvidas ? `<div class="aviso">Não li com certeza: ${esc(l.duvidas)}</div>` : ""}
      <span class="mudo">Só os itens acima mudam; o resto da carteira fica como está.</span>
      <div class="botoes"><button class="btn decide cheio" data-acao="aplicar_leitura" data-alvo="${esc(l.id)}">Está certo, aplicar</button><button class="btn cheio" data-acao="descartar_leitura" data-alvo="${esc(l.id)}">Descartar</button></div></section>`;
  }
  async function reduzirImagem(blob) {
    const bmp = await createImageBitmap(blob);
    const k = Math.min(1, 900 / bmp.width), cv = document.createElement("canvas");
    cv.width = Math.round(bmp.width * k); cv.height = Math.round(bmp.height * k);
    cv.getContext("2d").drawImage(bmp, 0, 0, cv.width, cv.height);
    let q = 0.72, url = cv.toDataURL("image/jpeg", q);
    while (url.length > 330000 && q > 0.35) { q -= 0.1; url = cv.toDataURL("image/jpeg", q); }
    return url;
  }
  function telaPrint(blob) {
    const f = modal(`<h2>Atualizar pelo print</h2>
      <span class="mudo">Tire um print da tela de posições (ou de saldo) no app do banco. A imagem é lida por uma IA paga, conferida por você e apagada em seguida.</span>
      ${blob ? "" : `<div class="campo"><label for="pr-arq">Escolha o print</label><input id="pr-arq" type="file" accept="image/*"></div>`}
      <img id="pr-img" class="previa" alt="prévia do print" hidden>
      <div class="campo"><label for="pr-banco">De qual banco é?</label><select id="pr-banco"><option value="IBKR">IBKR (em dólar)</option><option value="C6">C6 Bank (em reais)</option></select></div>
      <div class="erro" id="pr-erro"></div>
      <div class="botoes"><button class="btn decide cheio" id="pr-ok">Enviar para leitura</button><button class="btn cheio" data-fechar>Cancelar</button></div>`);
    let url = null;
    const usar = async (b) => { try { url = await reduzirImagem(b); const im = $("#pr-img", f); im.src = url; im.hidden = false; } catch (e) { $("#pr-erro", f).textContent = "Não consegui abrir essa imagem."; } };
    if (blob) usar(blob);
    const arq = $("#pr-arq", f); if (arq) arq.addEventListener("change", () => arq.files[0] && usar(arq.files[0]));
    $("#pr-ok", f).addEventListener("click", async () => {
      if (!url) { $("#pr-erro", f).textContent = "Escolha o print primeiro."; return; }
      const b64 = url.split(",")[1], sha = hex(await crypto.subtle.digest("SHA-256", enc.encode(b64)));
      const partes = []; for (let i = 0; i < b64.length; i += 60000) partes.push(b64.slice(i, i + 60000));
      const banco = $("#pr-banco", f).value;
      f.remove(); PRINT_PENDENTE = null;
      confirmar("leitura_print", banco + ":" + sha, { tipo: "anexos", anexos: partes, aviso: `Enviar o print do ${banco} para leitura. Nada muda na carteira até você conferir.`, resumo: "print enviado" });
    });
  }

  // ---------------------------------------------------------------- Análises: plano, relatórios, retrospectiva, laboratório
  let secao = "plano", tipoRel = "investimento";
  function telaAnalises() {
    const segs = [["plano", "Plano atual"], ["relatorios", "Relatórios"], ["lab", "Laboratório"]];
    const topo = `<div class="seg">${segs.map(([k, n]) => `<button data-secao="${k}" class="${secao === k ? "ativa" : ""}">${n}</button>`).join("")}</div>`;
    if (secao === "relatorios") return telaRelatorios(topo);
    if (secao === "lab") return telaLab(topo);
    const ultima = D.registro.filter((r) => r.tipo === "banca").pop();
    if (!ultima) { casca(topo + `<section class="card"><h2>Ainda não há plano</h2><span class="mudo">O primeiro plano aparece depois da primeira banca.</span></section>`); return; }
    const d = ultima.dados || {}, al = d.alocacao || {};
    const ts = D.teses.filter((t) => t.plano === d.plano);
    const decidido = D.registro.find((r) => r.tipo === "plano_banca_aprovado" && (r.dados || {}).plano === d.plano);
    casca(topo + `
      <section class="card"><span class="rotulo">${esc(nomeProposta(d.plano))} ${decidido ? '· <span class="chip bom">aprovado</span>' : ""}</span>
        ${rosca([{ n: "Em dólar", v: Number(al.dolar_pct) || 0 }, { n: "No Brasil", v: Number(al.brasil_pct) || 0 }], "")}
        <span>${esc(al.justificativa || "")}</span>
        <span class="mudo">Feito por ${esc(d.especialistas || "?")} analistas de IA com ${esc(d.buscas_na_internet || 0)} pesquisas na internet.</span></section>
      <section class="card"><h2>Por que cada ativo</h2>${ts.map((t) => cartaoTese(t, d.aporte_brl)).join("") || '<span class="mudo">Sem ativos.</span>'}</section>`);
  }
  async function telaRelatorios(topo) {
    const tipos = [["investimento", "Investimento"], ["diario", "Diário"], ["retrospectiva", "Mês"], ["radar", "Radar"], ["banca", "Banca"], ["csc", "Impostos"]];
    casca(topo + `<div class="seg pequeno">${tipos.map(([k, n]) => `<button data-tipo="${k}" class="${tipoRel === k ? "ativa" : ""}">${n}</button>`).join("")}</div><div id="rel" class="carregando">Carregando…</div>`);
    document.querySelectorAll("[data-tipo]").forEach((b) => b.addEventListener("click", () => { tipoRel = b.dataset.tipo; render(); }));
    try {
      const arqs = (await pasta("relatorios/" + tipoRel)).filter((a) => a.name.endsWith(".md")).sort((a, b) => b.name.localeCompare(a.name));
      if (!$("#rel")) return;
      if (!arqs.length) { $("#rel").innerHTML = `<section class="card"><span class="mudo">Nenhum relatório ainda.</span></section>`; return; }
      const texto = await bruto(arqs[0].path);
      const limpo = (texto || "").split(/\n---\n(?:PLANO|CLASSIFICA|ANÁLISE)/)[0].replace(/\*/g, "");
      $("#rel").className = "";
      $("#rel").innerHTML = `<section class="card"><span class="rotulo">${esc(arqs[0].name.replace(".md", ""))}</span><div class="texto">${esc(limpo)}</div></section>
        ${arqs.length > 1 ? `<section class="card"><h3>Anteriores</h3><div class="lista">${arqs.slice(1, 12).map((a) => `<button class="item btn" data-path="${esc(a.path)}"><span class="corpo"><span class="t">${esc(a.name.replace(".md", ""))}</span></span></button>`).join("")}</div></section>` : ""}`;
      document.querySelectorAll("[data-path]").forEach((b) => b.addEventListener("click", async () => {
        const t = await bruto(b.dataset.path);
        modal(`<h2>${esc(b.dataset.path.split("/").pop())}</h2><div class="texto">${esc((t || "").split(/\n---\n(?:PLANO|CLASSIFICA|ANÁLISE)/)[0].replace(/\*/g, ""))}</div><button class="btn" data-fechar>Fechar</button>`);
      }));
    } catch (e) { erroRede(e); }
  }
  function telaLab(topo) {
    const vSim = valorCarteira(D.sim), iniSim = D.capSim / D.cambio;
    const pontos = D.historico.map((h) => ({ x: h.data, y: (h.simulada || {}).valor_usd })).filter((p) => p.y);
    const partes = [];
    for (const [t, q] of Object.entries(D.sim.posicoes || {})) partes.push({ n: t, v: q * (D.precos[t] || 0) });
    partes.push({ n: "Caixa", v: D.sim.caixa_usd || 0 });
    casca(topo + `
      <section class="card"><span class="rotulo">Laboratório · carteira simulada</span><div class="numero pequeno">${usd(vSim)}</div>
        <span class="mudo">Dinheiro de papel (R$ ${esc((D.capSim / 1000).toLocaleString("pt-BR"))} mil) que o robô opera sozinho para testar a estratégia antes de você. ${vSim >= iniSim ? "+" : ""}${pct(vSim / iniSim - 1, 1)} desde o início.</span></section>
      <section class="card"><h2>Evolução</h2>${graficoLinha(pontos, { titulo: "evolução da carteira simulada" })}</section>
      <section class="card"><h2>Onde está o dinheiro de papel</h2>${rosca(partes, usd(vSim))}</section>`);
  }

  // ---------------------------------------------------------------- Ajustes
  function resumoEvento(r) {
    const d = r.dados || {};
    const partes = Object.entries(d).filter(([, v]) => v !== null && typeof v !== "object")
      .map(([k, v]) => k.replace(/_/g, " ") + ": " + v);
    return partes.join(" · ").slice(0, 160);
  }
  function telaAjustes() {
    const eventos = D.registro.slice(-40).reverse();
    const icone = (t) => ({ decisao: "✅", ordem_executada: "🧾", carteira_ajustada: "✏️", desfeito: "↩️", banca: "🏛️", radar: "📡", csc_revisao: "⚖️", comando_painel: "📱", comando_rejeitado: "⛔", acesso_negado: "🚨", expirada: "⌛" }[t] || "•");
    const rejeitados = D.registro.filter((r) => r.tipo === "comando_rejeitado" || r.tipo === "acesso_negado").length;
    const a = D.aporte, livre = aporteLivre(), dt = diasToken(), bio = !!ler(CHAVE_BIO);
    casca(`
      ${faixaStatus()}
      <section class="card"><div class="linha"><h2>Dinheiro para a próxima banca</h2>${livre ? `<span class="chip bom">${brl(a.valor_brl)}</span>` : '<span class="chip meio">não informado</span>'}</div>
        <span class="mudo">${livre ? `Informado em ${esc(dataBR(a.quando))}${a.cofre_brl ? `: ${brl(a.cofre_brl)} para o cofre e ${brl(a.banca_brl)} para a banca` : ""}.` : "A banca só roda depois que você informar. Metade vai para o cofre da aposentadoria."}</span>
        <div class="botoes"><button class="btn cheio" id="b-aporte">${livre ? "Alterar valor" : "Informar valor"}</button></div></section>
      <section class="card"><h2>Entrar e confirmar</h2>
        <div class="linha"><span>${bio ? "Digital ligada neste aparelho" : "Usar a digital no lugar do PIN"}</span>${bio ? `<button class="mini" id="b-bio-off">Desligar</button>` : `<button class="mini" id="b-bio">Ligar</button>`}</div>
        <span class="mudo">O PIN continua valendo como reserva. ${MAX_ERROS} PINs errados apagam as chaves deste aparelho. Bloqueio automático após 5 minutos parado ou 1 minuto fora do app.</span>
        <div class="botoes"><button class="btn cheio" id="b-pin">Trocar PIN</button></div></section>
      <section class="card"><h2>Chave do GitHub neste celular</h2>
        <span class="mudo">${dt == null ? "Validade desconhecida." : dt > 0 ? `Vence em ${esc(new Date(D.tokenVence).toLocaleDateString("pt-BR"))} (${esc(dt)} dias).` : "Vencida."} Você recebe um lembrete 30 dias antes.</span>
        ${dt != null && dt <= 30 ? `<ol class="passos"><li>No computador, abra github.com → foto → Settings → Developer settings → Personal access tokens → Fine-grained tokens.</li><li>Abra <b>painel-celular-holding</b> e toque em <b>Regenerate token</b> (validade de 90 dias) e copie.</li><li>Aqui, toque em <b>Trocar a chave</b> e cole.</li></ol>` : ""}
        <div class="botoes"><button class="btn cheio" id="b-token">Trocar a chave</button></div></section>
      ${cartaoCustos()}
      <section class="card"><h2>Freio de emergência</h2>
        <span class="mudo">Trava propostas, banca e ordens novas até você liberar. Achou algo estranho? Congele primeiro.</span>
        ${D.congelado ? `<button class="btn prim" data-acao="descongelar">Liberar o sistema</button>` : `<button class="btn perigo" data-acao="congelar">Congelar tudo</button>`}
        <span class="mudo">${rejeitados ? `<b>${rejeitados}</b> tentativa(s) bloqueada(s) no histórico.` : "Nenhuma tentativa bloqueada até agora."}</span></section>
      <section class="card"><h2>Histórico</h2><span class="mudo">Tudo o que foi decidido, por quem e quando. Ninguém consegue apagar.</span><div class="lista">
        ${eventos.map((r) => `<div class="item"><span>${icone(r.tipo)}</span><span class="corpo"><span class="t">${esc(r.tipo.replace(/_/g, " "))} · ${esc(r.autor)}</span><span class="d">${esc(dataBR(r.quando))} · ${esc(resumoEvento(r))}</span></span></div>`).join("")}
      </div></section>
      <section class="card"><button class="btn perigo" id="b-apagar">Apagar o Painel deste aparelho</button></section>
    `);
    $("#b-apagar").addEventListener("click", () => modal(`<h2>Apagar deste aparelho?</h2><p>As chaves somem deste celular. Para usar de novo, será preciso configurar outra vez. Nada muda no sistema.</p>
      <div class="botoes"><button class="btn perigo cheio" id="sim-apagar">Apagar</button><button class="btn cheio" data-fechar>Cancelar</button></div>`, () => {
      $("#sim-apagar").addEventListener("click", () => { apagar(CHAVE_COFRE); apagar(CHAVE_BIO); S = null; location.reload(); });
    }));
    $("#b-pin").addEventListener("click", () => novoPin(async (pin) => { await trancar({ token: S.token, chave: S.chave, repo: S.repo }, pin); S.pin = pin; toast("PIN trocado."); }));
    const bOn = $("#b-bio"); if (bOn) bOn.addEventListener("click", ligarBio);
    const bOff = $("#b-bio-off"); if (bOff) bOff.addEventListener("click", () => { apagar(CHAVE_BIO); toast("Digital desligada. Use o PIN."); render(); });
    $("#b-token").addEventListener("click", trocarToken);
  }
  function cartaoCustos() {
    const mes = new Date().toISOString().slice(0, 7);
    const doMesC = (D.custos || []).filter((c) => String(c.quando).startsWith(mes));
    const porTarefa = {}; let total = 0; const semPreco = new Set();
    const nomes = { banca: "Banca completa", fechamento: "Fechamento diário", radar_semanal: "Radar do CEO", csc_mensal: "Impostos (CSC)", verificar_aprovacoes: "Leitura de prints", ciclo_mensal: "Ciclo mensal" };
    doMesC.forEach((c) => { porTarefa[c.tarefa] = (porTarefa[c.tarefa] || 0) + (c.usd || 0); total += c.usd || 0; (c.sem_preco || []).forEach((m) => semPreco.add(m)); });
    return `<section class="card"><div class="linha"><h2>Custo das IAs neste mês</h2><b>${usd(total, 2)}</b></div>
      ${doMesC.length ? `<div class="lista-pos">${Object.entries(porTarefa).sort((a, b) => b[1] - a[1]).map(([t, v]) => `<div class="pos"><div class="pos-t"><b>${esc(nomes[t] || t)}</b></div><div class="pos-v"><b>${usd(v, 2)}</b></div><span></span></div>`).join("")}</div>` : '<span class="mudo">Ainda sem medição neste mês.</span>'}
      <span class="mudo">Preços oficiais por milhão de palavras processadas, conferidos em 08/11/2026.${semPreco.size ? " Sem preço cadastrado (não somado): " + esc([...semPreco].join(", ")) + "." : ""}</span></section>`;
  }
  function trocarToken() {
    const f = modal(`<h2>Trocar a chave do GitHub</h2><div class="campo"><label for="tk-novo">Cole a chave nova (começa com github_pat_)</label><input id="tk-novo" type="password" autocomplete="off" spellcheck="false"></div>
      <div class="campo"><label for="tk-pin">Seu PIN</label><input id="tk-pin" type="password" inputmode="numeric" autocomplete="off" maxlength="12"></div>
      <div class="erro" id="tk-erro"></div><div class="botoes"><button class="btn decide cheio" id="tk-ok">Testar e salvar</button><button class="btn cheio" data-fechar>Cancelar</button></div>`);
    $("#tk-ok", f).addEventListener("click", async () => {
      const token = $("#tk-novo", f).value.trim(), pin = $("#tk-pin", f).value, erro = (m) => { $("#tk-erro", f).textContent = m; };
      if (!/^github_pat_[A-Za-z0-9_]{20,}$/.test(token)) return erro("Isso não parece uma chave fine-grained do GitHub.");
      try { await destrancar(pin); } catch (e) { if (e.message === "apagado") return location.reload(); return erro("PIN incorreto."); }
      const antigo = S.token; S.token = token;
      try { const r = await gh(`/repos/${S.repo}`); if (!r || !r.private) throw new Error("repo"); await gh(`/repos/${S.repo}/issues?per_page=1`); }
      catch (e) { S.token = antigo; return erro("A chave nova não funcionou com o repositório. Confira as permissões."); }
      await trancar({ token, chave: S.chave, repo: S.repo }, pin); S.pin = pin;
      if (ler(CHAVE_BIO)) { apagar(CHAVE_BIO); toast("Chave trocada. Ligue a digital de novo em Ajustes."); } else toast("Chave trocada.");
      f.remove(); tokenVenceHeader = null; await carregar().catch(() => {}); render();
    });
  }

  // ligações comuns a todas as telas
  function ligarComum() {
    document.querySelectorAll("[data-acao]").forEach((b) => b.addEventListener("click", () => confirmar(b.dataset.acao, b.dataset.alvo || "", b.dataset.valor ? { tipo: "valor" } : null)));
    document.querySelectorAll("[data-secao]").forEach((b) => b.addEventListener("click", () => { secao = b.dataset.secao; render(); }));
    document.querySelectorAll("[data-ir]").forEach((b) => b.addEventListener("click", () => { aba = b.dataset.ir; render(); }));
    document.querySelectorAll("[data-abrir]").forEach((b) => b.addEventListener("click", () => copiarEAbrir(b.dataset.abrir, b.dataset.inst)));
    document.querySelectorAll("[data-exec]").forEach((b) => b.addEventListener("click", () => folhaExecucao(D.boletas[b.dataset.exec])));
    document.querySelectorAll("[data-naoexec]").forEach((b) => b.addEventListener("click", () => confirmar("naoexecutei", b.dataset.naoexec, { resumo: "Não executada: " + (D.boletas[b.dataset.naoexec] || {}).codigo_ordem })));
    document.querySelectorAll("[data-ajustar]").forEach((b) => b.addEventListener("click", () => ajustar(b.dataset.ajustar)));
    document.querySelectorAll("[data-desfazer]").forEach((b) => b.addEventListener("click", () => { LOCAL["desfazer:" + b.dataset.desfazer] = { t: Date.now() }; confirmar("desfazer", b.dataset.desfazer, { aviso: "Desfazer o último registro. A carteira volta a ser como era antes dele." }); }));
    const ap = $("#b-aporte"); if (ap) ap.addEventListener("click", () => confirmar("aporte", "", { tipo: "valor", rotulo: "Quanto dinheiro novo existe para a próxima banca? (R$)", aviso: "Metade vai para o cofre da aposentadoria, no ciclo do mês; a outra metade a banca distribui entre os ativos. Nada é comprado agora." }));
    const pr = $("#b-print"); if (pr) pr.addEventListener("click", () => telaPrint(null));
    document.querySelectorAll("[data-recado]").forEach((b) => b.addEventListener("click", () => { const v = ler("recados-vistos") || []; v.push(b.dataset.recado); guardar("recados-vistos", v.slice(-60)); render(); }));
    document.querySelectorAll("[data-ir-diario]").forEach((b) => b.addEventListener("click", () => { aba = "analises"; secao = "relatorios"; tipoRel = "diario"; render(); }));
  }

  // ---------------------------------------------------------------- confirmação (digital ou PIN)
  function modal(html, depois) {
    const f = document.createElement("div");
    f.className = "fundo"; f.innerHTML = `<div class="modal" role="dialog" aria-modal="true">${html}</div>`;
    document.body.appendChild(f);
    f.addEventListener("click", (e) => { if (e.target === f || e.target.hasAttribute("data-fechar")) f.remove(); });
    if (depois) depois(f);
    return f;
  }
  // número digitado: aceita o jeito brasileiro ("5.000" = cinco mil; "36,90") e o americano do app da IBKR ("1,234.56").
  // Começando com 0 ("0.500", "0.125") o ponto é sempre decimal. O "Entendido:" mostra o que foi lido.
  // pontoDecimal: campos de quantidade da IBKR, onde "1.234" é uma ação e um quarto, não mil e duzentas
  const numBR = (v, pontoDecimal) => {
    let t = String(v || "").trim().replace(/[^0-9,.\-]/g, "");
    if (pontoDecimal && !/,/.test(t)) { const n0 = Number(t); return t && isFinite(n0) && n0 > 0 ? n0 : null; }
    if (/,/.test(t) && /\./.test(t)) t = t.lastIndexOf(",") > t.lastIndexOf(".") ? t.replace(/\./g, "").replace(",", ".") : t.replace(/,/g, "");
    else if (/,/.test(t)) t = /^\d{1,3}(,\d{3}){2,}$/.test(t) ? t.replace(/,/g, "") : t.replace(",", ".");
    else if (/^[1-9]\d{0,2}(\.\d{3})+$/.test(t)) t = t.replace(/\./g, "");
    const n = Number(t); return t && isFinite(n) && n > 0 ? n : null;
  };
  // número para o comando assinado: sem notação científica (1e-7), que o robô recusaria
  const numStr = (n) => (Number.isInteger(n) ? String(n) : n.toFixed(8).replace(/\.?0+$/, ""));
  // parte de baixo de toda confirmação: digital (se ligada) ou PIN
  function blocoAutenticar() {
    const bio = !!ler(CHAVE_BIO);
    return `<div class="erro" id="erro-conf"></div>
      ${bio ? `<button class="btn decide" id="ok-bio">Confirmar com a digital</button><button class="link" id="usar-pin">Usar o PIN</button>` : ""}
      <div class="campo" id="campo-pin" ${bio ? "hidden" : ""}><label for="pin-conf">Digite seu PIN para confirmar</label><input id="pin-conf" type="password" inputmode="numeric" autocomplete="off" maxlength="12"></div>
      <div class="botoes"><button class="btn decide cheio" id="ok-conf" ${bio ? "hidden" : ""}>Confirmar</button><button class="btn cheio" data-fechar>Cancelar</button></div>`;
  }
  // liga os botões; validar() devolve os dados do comando ou null (já mostrou o erro)
  function ligarAutenticar(f, validar, aoConfirmar) {
    const erro = (m) => { $("#erro-conf", f).textContent = m; };
    const seguir = async () => {
      const dados = validar(erro); if (dados == null) return false;
      try { await aoConfirmar(dados); f.remove(); return true; } catch (e) { erro(msgErro(e)); return false; }
    };
    const up = $("#usar-pin", f); if (up) up.addEventListener("click", () => { $("#campo-pin", f).hidden = false; $("#ok-conf", f).hidden = false; up.hidden = true; $("#pin-conf", f).focus(); });
    const ob = $("#ok-bio", f); if (ob) ob.addEventListener("click", async () => {
      if (validar(erro) == null) return;
      ob.disabled = true;
      try { await bioVerificar(); } catch (e) { ob.disabled = false; erro("Digital não confirmada. Tente de novo ou use o PIN."); return; }
      ob.textContent = "Enviando…"; if (!(await seguir())) { ob.disabled = false; ob.textContent = "Confirmar com a digital"; }
    });
    $("#ok-conf", f).addEventListener("click", async () => {
      const pin = $("#pin-conf", f).value;
      if (pin !== S.pin) { try { await destrancar(pin); S.pin = pin; } catch (e) { if (e.message === "apagado") return location.reload(); erro("PIN incorreto."); return; } }
      const b = $("#ok-conf", f); b.disabled = true; b.textContent = "Enviando…";
      if (!(await seguir())) { b.disabled = false; b.textContent = "Confirmar"; }
    });
    if (!ob) setTimeout(() => { const p = $("#pin-conf", f); if (p && !p.closest("[hidden]")) p.focus(); }, 50);
  }
  // mostra o número entendido SEM ponto de milhar, para "1.234" nunca parecer igual ao que foi digitado
  const semGrupo = (n, dec) => n.toLocaleString("pt-BR", { useGrouping: false, minimumFractionDigits: dec, maximumFractionDigits: 6 });
  function eco(f, pares) {
    pares.forEach(([sel, pre, pd]) => {
      const el = $(sel, f); if (!el) return;
      const e = document.createElement("span"); e.className = "mudo eco"; el.after(e);
      const upd = () => { const n = numBR(el.value, typeof pd === "function" ? pd() : pd); e.textContent = n ? "Entendido: " + (pre ? pre + " " + semGrupo(n, 2) : semGrupo(n, 0) + (n === 1 ? " unidade" : " unidades")) : ""; };
      el.addEventListener("input", upd); upd();
    });
  }
  function confirmar(acao, alvo, extra) {
    extra = extra || {};
    const textos = {
      aprovar: "Aprovar gera as ordens banco por banco. Nada é comprado sozinho.",
      recusar: "Nada é feito e a recusa fica registrada.",
      executei: "Você confirma que fez a ordem no banco.",
      naoexecutei: "A ordem sai da lista e a carteira não muda.",
      congelar: "O sistema para de gerar propostas e ordens até você liberar.",
      descongelar: "O sistema volta a funcionar normalmente.",
      conferi: "Você conferiu a carteira com o extrato dos bancos e está tudo certo.",
      aplicar_leitura: "Os itens lidos no print substituem os da carteira.",
      descartar_leitura: "A leitura é descartada e a carteira não muda.",
    };
    const campos = extra.tipo === "valor" ? `<div class="campo"><label for="valor-conf">${esc(extra.rotulo || "Quanto quer aplicar neste plano? (R$)")}</label><input id="valor-conf" inputmode="decimal" autocomplete="off" placeholder="ex.: 5.000"></div>` : "";
    const titulo = nomeAcao(acao) + (alvo && !/:[0-9a-f]{64}$/.test(alvo) && acao !== "desfazer" ? " · " + nomeProposta(alvo.replace(":", " · ")) : "");
    const f = modal(`<h2>${esc(titulo)}</h2><span class="mudo">${esc(extra.aviso || (acao === "aprovar" && extra.tipo === "valor" ? "Informe quanto quer aplicar: o sistema monta as ordens banco por banco. Nada é comprado sozinho." : textos[acao] || ""))}</span>${campos}${blocoAutenticar()}`);
    eco(f, [["#valor-conf", "R$"]]);
    ligarAutenticar(f, (erro) => {
      if (extra.tipo === "valor") { const v = numBR($("#valor-conf", f).value); if (!v) { erro("Informe o valor em reais."); return null; } return String(Math.round(v * 100) / 100); }
      return extra.tipo === "dados" ? extra.dados : "";
    }, (dados) => enviarComando(acao, alvo, dados, extra.tipo === "anexos" ? extra.anexos : null, extra.resumo));
  }
  // "Comprei": uma folha só, já preenchida com o previsto, estilo Apple Pay
  function folhaExecucao(b) {
    if (!b) return;
    const produto = !b.codigo_ordem, m = b.moeda === "USD" ? "US$" : "R$", verbo = b.lado === "vender" ? "Vendi" : produto ? "Apliquei" : "Comprei";
    const v2 = (x) => (x == null ? "" : String(x).replace(".", ","));
    const f = modal(`<h2>${verbo}</h2>
      <div class="resumo-folha" id="fx-resumo"></div>
      ${produto ? `<div class="campo"><label for="fx-p">Valor aplicado (${m})</label><input id="fx-p" inputmode="decimal" autocomplete="off" value="${esc(v2(b.valor))}"></div>`
        : `<div class="grade2"><div class="campo"><label for="fx-q">Quantidade</label><input id="fx-q" inputmode="decimal" autocomplete="off" value="${esc(v2(b.quantidade))}"></div>
           <div class="campo"><label for="fx-p">Preço médio (${m})</label><input id="fx-p" inputmode="decimal" autocomplete="off" value="${esc(v2(b.preco_ref ? Math.round(b.preco_ref * 100) / 100 : ""))}" placeholder="do comprovante"></div></div>`}
      <span class="mudo">Corrija só o que for diferente do comprovante do app.</span>
      ${blocoAutenticar()}`);
    const ibkr = b.instituicao === "IBKR";
    const ler2 = () => ({ q: produto ? 1 : numBR($("#fx-q", f).value, ibkr), p: numBR($("#fx-p", f).value) });
    const upd = () => { const { q, p } = ler2(); $("#fx-resumo", f).innerHTML = q && p
      ? `${esc(verbo)} <b>${esc(produto ? b.ativo : semGrupo(q, 0) + " " + b.codigo_ordem)}</b>${produto ? "" : ` a ${esc(m)} ${esc(p.toLocaleString("pt-BR", { minimumFractionDigits: 2, maximumFractionDigits: 4 }))}`} = <b>${esc(din(q * p, b.moeda))}</b> no ${esc(b.instituicao)}`
      : "Preencha quantidade e preço."; };
    f.querySelectorAll("input:not(#pin-conf)").forEach((i) => i.addEventListener("input", upd)); upd();
    eco(f, [["#fx-q", "", ibkr], ["#fx-p", m]]);
    ligarAutenticar(f, (erro) => {
      const { q, p } = ler2();
      if (!q || !p) { erro(produto ? "Informe o valor aplicado." : "Informe a quantidade e o preço."); return null; }
      // validação cruzada: pergunta antes de registrar algo muito diferente do previsto
      if (!f.dataset.avisado) {
        let aviso = "";
        if (!produto && b.quantidade && (q / b.quantidade > 3 || b.quantidade / q > 3)) aviso = `A quantidade é ${Math.round(Math.max(q / b.quantidade, b.quantidade / q))} vezes a prevista (${qtdTxt(b.quantidade)}).`;
        else if (b.valor && (q * p / b.valor > 1.5 || b.valor / (q * p) > 3)) aviso = `O total (${din(q * p, b.moeda)}) está longe do previsto (${din(b.valor, b.moeda)}).`;
        else if (!produto && b.preco_limite && (b.lado === "vender" ? p < b.preco_limite * 0.995 : p > b.preco_limite * 1.005)) aviso = `O preço passou do limite da ordem (${din(b.preco_limite, b.moeda)}).`;
        if (aviso) { f.dataset.avisado = "1"; erro(aviso + " Confere? Se estiver certo, confirme de novo."); return null; }
      }
      return numStr(q) + ";" + numStr(p);
    }, (dados) => { const [q, p] = dados.split(";").map(Number); return enviarComando("executei", b.id, dados, null, `${verbo} ${produto ? b.ativo : qtdTxt(q) + " " + b.codigo_ordem} = ${din(q * p, b.moeda)}`); });
  }

  function msgErro(e) {
    if (e.status === 401) return "A chave do GitHub foi recusada (vencida ou revogada). Troque em Ajustes.";
    if (e.status === 403) return "A chave do GitHub não tem a permissão necessária (Issues e Actions).";
    return "Sem conexão com o GitHub agora. Tente de novo.";
  }
  function erroRede(e) { toast(msgErro(e)); }

  // ---------------------------------------------------------------- digital (passkey com a extensão PRF)
  // A digital destrava um segundo cofre, criptografado com uma chave que só o leitor biométrico do aparelho
  // consegue gerar (PRF). Sem PRF no aparelho, a digital não é oferecida: nunca guardamos a chave aberta.
  const SAL_PRF = enc.encode("painel-holding-prf-v1");
  async function chaveDoPrf(saida) {
    const base = await crypto.subtle.importKey("raw", saida, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(16), info: enc.encode("cofre-holding") }, base,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function bioPrf(idCred) {
    const a = await navigator.credentials.get({ publicKey: { challenge: aleatorio(32), allowCredentials: [{ type: "public-key", id: idCred }],
      userVerification: "required", timeout: 60000, extensions: { prf: { eval: { first: SAL_PRF } } } } });
    const r = a.getClientExtensionResults();
    if (!r.prf || !r.prf.results || !r.prf.results.first) throw new Error("sem-prf");
    return r.prf.results.first;
  }
  async function bioVerificar() { const c = ler(CHAVE_BIO); if (!c) throw new Error("sem-bio"); await bioPrf(deb64(c.id)); }
  async function bioAbrir() {
    const c = ler(CHAVE_BIO); const k = await chaveDoPrf(await bioPrf(deb64(c.id)));
    const txt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: deb64(c.iv) }, k, deb64(c.ct));
    return JSON.parse(dec.decode(txt));
  }
  async function ligarBio() {
    try {
      if (!window.PublicKeyCredential || !(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())) { toast("Este aparelho não oferece digital para o Chrome. Continue com o PIN."); return; }
      const cred = await navigator.credentials.create({ publicKey: { rp: { name: "Painel da Holding" }, user: { id: aleatorio(16), name: "ademir", displayName: "Ademir" },
        challenge: aleatorio(32), pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "preferred" }, timeout: 60000, extensions: { prf: {} } } });
      const ext = cred.getClientExtensionResults();
      if (!ext.prf || ext.prf.enabled === false) { toast("A digital deste aparelho não permite criptografia. Continue com o PIN."); return; }
      const k = await chaveDoPrf(await bioPrf(cred.rawId)), iv = aleatorio(12);
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k, enc.encode(JSON.stringify({ token: S.token, chave: S.chave, repo: S.repo })));
      guardar(CHAVE_BIO, { v: 1, id: b64(cred.rawId), iv: b64(iv), ct: b64(ct) });
      toast("Digital ligada."); render();
    } catch (e) { toast(e.message === "sem-prf" ? "A digital deste aparelho não permite criptografia. Continue com o PIN." : "Não foi possível ligar a digital agora."); }
  }

  // ---------------------------------------------------------------- PIN e configuração
  function teclado(titulo, sub, aoCompletar, extra) {
    let pin = "";
    $("#app").innerHTML = `<div class="tela-cheia"><div class="marca">${MARCA}<h1>${esc(titulo)}</h1><span class="mudo">${esc(sub)}</span></div>
      <div class="pin-pontos" id="pontos"></div><div class="erro" id="erro-pin"></div>
      <div class="teclado">${[1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => `<button data-n="${n}">${n}</button>`).join("")}<button class="sem" data-x="limpar">Limpar</button><button data-n="0">0</button><button class="sem" data-x="ok">OK</button></div>${extra || ""}</div>`;
    const pontos = () => { $("#pontos").innerHTML = Array.from({ length: Math.max(6, pin.length) }, (_, i) => `<i class="${i < pin.length ? "cheio" : ""}"></i>`).join(""); };
    pontos();
    const ok = async () => { if (pin.length < 6) { $("#erro-pin").textContent = "O PIN tem pelo menos 6 dígitos."; return; } const p = pin; pin = ""; pontos(); await aoCompletar(p, (m) => { $("#erro-pin").textContent = m; }); };
    document.querySelectorAll(".teclado button").forEach((b) => b.addEventListener("click", () => {
      if (b.dataset.n != null && pin.length < 12) pin += b.dataset.n;
      else if (b.dataset.x === "limpar") pin = "";
      else if (b.dataset.x === "ok") return ok();
      $("#erro-pin").textContent = ""; pontos();
    }));
  }

  async function depoisDeAbrir() {
    $("#app").innerHTML = `<div class="tela-cheia carregando">Carregando…</div>`;
    try { await carregar(); } catch (e) { erroRede(e); }
    render();
    // print recebido pelo "Compartilhar" do Android enquanto o Painel estava trancado
    try {
      const c = await caches.open("painel-print"), r = await c.match("print-compartilhado");
      if (r) { const blob = await r.blob(); await c.delete("print-compartilhado"); history.replaceState(null, "", location.pathname); telaPrint(blob); }
    } catch (e) { /* sem print */ }
  }
  function telaPin() {
    const c = ler(CHAVE_COFRE);
    if (!c) return telaConfig();
    const bio = !!ler(CHAVE_BIO);
    teclado("Painel da Holding", bio ? "Use a digital ou o PIN" : "Digite seu PIN", async (pin, erro) => {
      erro("Abrindo…");
      try { const seg = await destrancar(pin); S = Object.assign(seg, { pin }); ultimoToque = Date.now(); }
      catch (e) {
        if (e.message === "apagado") { erro(""); apagar(CHAVE_BIO); return telaConfig("PIN errado 5 vezes: as chaves foram apagadas deste aparelho. Configure de novo."); }
        const r = MAX_ERROS - ((ler(CHAVE_COFRE) || {}).erros || 0); return erro(`PIN incorreto. Restam ${r} tentativa(s) antes de apagar.`);
      }
      depoisDeAbrir();
    }, bio ? `<button class="btn prim" id="b-entrar-bio">Entrar com a digital</button>` : "");
    const bb = $("#b-entrar-bio");
    if (bb) bb.addEventListener("click", async () => {
      try { const seg = await bioAbrir(); S = Object.assign(seg, { pin: null }); ultimoToque = Date.now(); depoisDeAbrir(); }
      catch (e) { $("#erro-pin").textContent = "Digital não confirmada. Use o PIN."; }
    });
  }

  function novoPin(aoSalvar) {
    let primeiro = null;
    teclado("Crie um PIN", "6 a 12 dígitos. Não use data de nascimento.", async (pin, erro) => {
      if (!primeiro) { primeiro = pin; $(".marca .mudo").textContent = "Digite o mesmo PIN de novo"; return; }
      if (pin !== primeiro) { primeiro = null; $(".marca .mudo").textContent = "6 a 12 dígitos. Não use data de nascimento."; return erro("Os PINs não conferem. Comece de novo."); }
      if (/^(\d)\1+$/.test(pin) || "0123456789012".includes(pin) || "9876543210987".includes(pin)) { primeiro = null; return erro("PIN fácil demais. Escolha outro."); }
      erro("Protegendo…");
      await aoSalvar(pin);
      $("#app").innerHTML = `<div class="tela-cheia carregando">Carregando dados do sistema…</div>`;
      depoisDeAbrir();
    });
  }

  function telaConfig(aviso) {
    const chave = hex(aleatorio(32));
    $("#app").innerHTML = `<div class="tela-cheia"><div class="config">
      <div class="marca">${MARCA}<h1>Configurar o Painel</h1><span class="mudo">Feito uma vez neste celular. Nada daqui sai do aparelho sem estar criptografado.</span></div>
      ${aviso ? `<div class="aviso">${esc(aviso)}</div>` : ""}
      <section class="card"><h2>1 · Chave de assinatura deste celular</h2>
        <span class="mudo">Copie e cadastre no GitHub como segredo <b>PAINEL_CHAVE</b> (Settings → Secrets and variables → Actions). Ela aparece só agora.</span>
        <div class="chave-box" id="chave">${chave}</div>
        <div class="botoes"><button class="btn" id="copiar">Copiar chave</button></div>
        <div class="campo"><label for="chave-existente">Já cadastrou uma chave antes? Cole aqui (opcional)</label>
          <input id="chave-existente" type="password" autocomplete="off" spellcheck="false" placeholder="64 letras e números"></div></section>
      <section class="card"><h2>2 · Chave de acesso do GitHub</h2>
        <span class="mudo">Token "fine-grained", só para o repositório holding-agentes: Contents <b>leitura</b>, Issues <b>leitura e escrita</b>, Actions <b>leitura e escrita</b>. Validade de 90 dias.</span>
        <div class="campo"><label for="token">Cole o token</label><input id="token" type="password" autocomplete="off" spellcheck="false" placeholder="github_pat_…"></div>
        <div class="campo"><label for="repo">Repositório</label><input id="repo" value="${esc(REPO_PADRAO)}" autocomplete="off" spellcheck="false"></div></section>
      <label class="status"><input type="checkbox" id="cadastrei"> Já cadastrei a chave de assinatura no GitHub</label>
      <div class="erro" id="erro-cfg"></div>
      <button class="btn prim" id="testar">Testar e continuar</button>
    </div></div>`;
    $("#copiar").addEventListener("click", async () => { try { await navigator.clipboard.writeText(chave); toast("Chave copiada."); } catch (e) { const r = document.createRange(); r.selectNodeContents($("#chave")); getSelection().removeAllRanges(); getSelection().addRange(r); toast("Selecionada: copie manualmente."); } });
    $("#testar").addEventListener("click", async () => {
      const token = $("#token").value.trim(), repo = $("#repo").value.trim();
      const colada = $("#chave-existente").value.trim().toLowerCase();
      if (colada && !/^[0-9a-f]{64}$/.test(colada)) { $("#erro-cfg").textContent = "A chave colada não tem o formato certo (64 letras e números)."; return; }
      const chaveFinal = colada || chave;
      const erro = (m) => { $("#erro-cfg").textContent = m; };
      if (!$("#cadastrei").checked) return erro("Cadastre a chave de assinatura no GitHub antes de continuar.");
      if (!/^(github_pat_|ghp_)[A-Za-z0-9_]{20,}$/.test(token)) return erro("Isso não parece um token do GitHub.");
      if (/^ghp_/.test(token)) return erro("Use um token fine-grained (começa com github_pat_), restrito a este repositório.");
      erro("Testando…");
      S = { token, chave: chaveFinal, repo };
      try {
        const r = await gh(`/repos/${repo}`);
        if (!r) { S = null; return erro("Repositório não encontrado com esse token."); }
        if (!r.private) { S = null; return erro("O repositório não é privado. Por segurança, o Painel só funciona com repositório privado."); }
        await gh(`/repos/${repo}/issues?per_page=1`);
      } catch (e) { S = null; return erro(msgErro(e)); }
      novoPin(async (pin) => { await trancar({ token, chave: chaveFinal, repo }, pin); S = { token, chave: chaveFinal, repo, pin }; ultimoToque = Date.now(); });
    });
  }

  // ---------------------------------------------------------------- início
  if ("serviceWorker" in navigator && location.protocol === "https:") navigator.serviceWorker.register("sw.js").catch(() => {});
  if (!window.crypto || !crypto.subtle) { $("#app").innerHTML = `<div class="tela-cheia"><p>Este navegador não tem a criptografia necessária. Abra o Painel pelo Chrome atualizado, em HTTPS.</p></div>`; return; }
  telaPin();
})();

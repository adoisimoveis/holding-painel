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
  let aba = "inicio";
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
    if (r.status === 404) return null;
    if (!r.ok) { const e = new Error("GitHub respondeu " + r.status); e.status = r.status; throw e; }
    if (r.status === 204) return true;
    return opcoes.accept === "application/vnd.github.raw+json" ? r.text() : r.json();
  }
  const bruto = (p) => gh(`/repos/${S.repo}/contents/${p}?ref=main`, { accept: "application/vnd.github.raw+json" });
  const json = async (p) => { const t = await bruto(p); try { return t ? JSON.parse(t) : null; } catch (e) { return null; } };
  const pasta = async (p) => { const r = await gh(`/repos/${S.repo}/contents/${p}?ref=main`); return Array.isArray(r) ? r : []; };

  async function carregar() {
    const [pend, manuais, real, sim, hist, precos, teses, cong, verif, reg, cfg] = await Promise.all([
      json("estado/pendentes.json"), json("estado/ordens_manuais.json"), json("estado/carteira_real.json"),
      json("estado/carteira_simulada.json"), bruto("estado/historico.jsonl"), json("estado/precos.json"),
      bruto("estado/teses.jsonl"), json("estado/congelado.json"), json("estado/ultima_verificacao.json"),
      bruto("registro/decisoes.jsonl"), bruto("config.toml")]);
    const num = (nome, padrao) => { const m = (cfg || "").match(new RegExp("^" + nome + "\\s*=\\s*([0-9.]+)", "m")); return m ? Number(m[1]) : padrao; };
    D = {
      pendentes: pend || {}, manuais: manuais || {}, historico: lerJsonl(hist), precos: (precos || {}).precos || {},
      teses: lerJsonl(teses), congelado: !!(cong && cong.congelado), verif: verif || {}, registro: lerJsonl(reg),
      cambio: num("cambio_referencia", 5.5), capReal: num("capital_real_brl", 500), capSim: num("capital_simulado_brl", 100000),
      validadeH: num("validade_proposta_horas", 72), carregadoEm: new Date(),
    };
    D.real = real || { caixa_usd: D.capReal / D.cambio, posicoes: {}, pico_usd: D.capReal / D.cambio };
    D.sim = sim || { caixa_usd: D.capSim / D.cambio, posicoes: {}, pico_usd: D.capSim / D.cambio };
  }
  function valorCarteira(c) {
    let v = c.caixa_usd || 0;
    for (const [t, q] of Object.entries(c.posicoes || {})) v += q * (D.precos[t] || 0);
    return v;
  }

  // ---------------------------------------------------------------- comandos assinados
  async function assinar(c) {
    const k = await crypto.subtle.importKey("raw", enc.encode(S.chave), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const texto = [c.id, c.acao, c.alvo || "", c.criado_em, c.nonce].join("|");
    return hex(await crypto.subtle.sign("HMAC", k, enc.encode(texto)));
  }
  async function enviarComando(acao, alvo) {
    const c = { id: "p" + Date.now().toString(36) + hex(aleatorio(3)), acao, alvo: alvo || "",
      criado_em: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), nonce: hex(aleatorio(16)) };
    c.assinatura = await assinar(c);
    const issue = await gh(`/repos/${S.repo}/issues`, { method: "POST", body: { title: "comando " + c.id, body: JSON.stringify(c) } });
    await gh(`/repos/${S.repo}/actions/workflows/sistema.yml/dispatches`, { method: "POST", body: { ref: "main", inputs: { tarefa: "aprovacoes" } } });
    acompanhar(issue.number, acao, alvo);
  }
  async function acompanhar(numero, acao, alvo) {
    toast("Enviado. O robô processa em 1 a 3 minutos.");
    for (let i = 0; i < 30 && S; i++) {
      await new Promise((r) => setTimeout(r, 10000));
      const iss = await gh(`/repos/${S.repo}/issues/${numero}`).catch(() => null);
      if (iss && iss.state === "closed") {
        const coms = await gh(`/repos/${S.repo}/issues/${numero}/comments`).catch(() => []);
        const res = (coms && coms.length) ? coms[coms.length - 1].body : "Processado.";
        toast((res.startsWith("Aceito") ? "✅ " : "⛔ ") + nomeAcao(acao) + (alvo ? " " + alvo : "") + ": " + res);
        await carregar().catch(() => {}); render();
        return;
      }
    }
  }
  const nomeAcao = (a) => ({ aprovar: "Aprovar", recusar: "Recusar", executei: "Executei", naoexecutei: "Não executei", congelar: "Congelar", descongelar: "Liberar" }[a] || a);

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
    inicio: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z"/></svg>',
    decisoes: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 11l3 3 8-8"/><path d="M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h9"/></svg>',
    banca: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 10l9-6 9 6M5 10v8M9.5 10v8M14.5 10v8M19 10v8M3 21h18"/></svg>',
    relatorios: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h6"/></svg>',
    mais: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>',
  };
  const MARCA = '<svg viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="#0B6B57"/><path d="M14 26 32 15l18 11M18 27v19M26 27v19M38 27v19M46 27v19M13 50h38" stroke="#E5ECE8" stroke-width="3.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  function casca(conteudo) {
    const nPend = Object.keys(D.pendentes || {}).length + Object.keys(D.manuais || {}).length;
    const abas = [["inicio", "Início"], ["decisoes", "Decisões"], ["banca", "Banca"], ["relatorios", "Relatórios"], ["mais", "Segurança"]];
    $("#app").innerHTML = `
      <header class="topo"><div><h1>Painel da Holding</h1><div class="sub">atualizado ${esc(D.carregadoEm ? D.carregadoEm.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }) : "")}</div></div>
        <div class="botoes"><button class="icone-btn" id="b-atualizar" aria-label="Atualizar">↻</button><button class="icone-btn" id="b-bloquear">Bloquear</button></div></header>
      <main>${conteudo}</main>
      <nav class="abas">${abas.map(([k, n]) => `<button data-aba="${k}" class="${aba === k ? "ativa" : ""}">${ICONES[k]}<span>${n}</span>${k === "decisoes" && nPend ? `<b class="badge">${nPend}</b>` : ""}</button>`).join("")}</nav>`;
    document.querySelectorAll("nav.abas button").forEach((b) => b.addEventListener("click", () => { aba = b.dataset.aba; render(); window.scrollTo(0, 0); }));
    $("#b-bloquear").addEventListener("click", bloquear);
    $("#b-atualizar").addEventListener("click", async () => { toast("Atualizando…"); try { await carregar(); render(); } catch (e) { erroRede(e); } });
  }

  function render() {
    if (!S) return telaPin();
    const telas = { inicio: telaInicio, decisoes: telaDecisoes, banca: telaBanca, relatorios: telaRelatorios, mais: telaSeguranca };
    telas[aba]();
  }

  function faixaStatus() {
    const v = D.verif || {};
    if (D.congelado) return `<div class="status congelado"><i class="ponto perigo"></i><b>Sistema congelado.</b> Nenhuma proposta ou execução até você liberar.</div>`;
    if (v.registro_integro === false) return `<div class="status congelado"><i class="ponto perigo"></i><b>Registro com problema de integridade.</b> O robô não executa nada.</div>`;
    const quando = v.quando ? (Date.now() - new Date(v.quando)) / 36e5 : null;
    const ponto = quando == null || quando > 26 ? "alerta" : "";
    return `<div class="status"><i class="ponto ${ponto}"></i>Sistema ativo · última verificação ${esc(dataBR(v.quando))}${v.registro_integro ? " · registro íntegro" : ""}</div>`;
  }

  function telaInicio() {
    const vSim = valorCarteira(D.sim), vReal = valorCarteira(D.real);
    const iniSim = D.capSim / D.cambio, iniReal = D.capReal / D.cambio;
    const t0 = +new Date(META_INICIO), t1 = +new Date(META_FIM), anos = Math.max(0, (t1 - Date.now()) / 315576e5);
    const pontos = D.historico.map((h) => ({ x: h.data, y: (h.simulada || {}).valor_usd })).filter((p) => p.y);
    const partes = [];
    for (const [t, q] of Object.entries(D.sim.posicoes || {})) partes.push({ n: t, v: q * (D.precos[t] || 0) });
    partes.push({ n: "Caixa", v: D.sim.caixa_usd || 0 });
    const nPend = Object.keys(D.pendentes).length, nMan = Object.keys(D.manuais).length;
    casca(`
      ${faixaStatus()}
      ${nPend + nMan ? `<button class="card cartao-btn" id="ir-decisoes"><div class="linha"><h2>${nPend + nMan} decisão(ões) esperando você</h2><span class="chip meio">abrir</span></div><span class="mudo">Propostas vencem em ${esc(D.validadeH)} horas.</span></button>` : ""}
      <section class="card">
        <span class="rotulo">Meta · US$ 5 milhões</span>
        <div class="linha"><div class="numero pequeno">${usd(vReal, 2)}</div><span class="mudo">${esc(anos.toFixed(1).replace(".", ","))} anos restantes</span></div>
        ${barraProgresso(vReal / META_USD)}
        <span class="mudo">Em poder de compra de hoje. Carteira real: ${esc(pct(vReal / META_USD, 4))} da meta.</span>
      </section>
      <div class="grade2">
        <section class="card"><span class="rotulo">Carteira real</span><div class="numero pequeno">${usd(vReal, 2)}</div>
          <span class="mudo">${vReal >= iniReal ? "+" : ""}${pct(vReal / iniReal - 1, 1)} desde o início · ${brl(vReal * D.cambio)}</span></section>
        <section class="card"><span class="rotulo">Carteira simulada</span><div class="numero pequeno">${usd(vSim)}</div>
          <span class="mudo">${vSim >= iniSim ? "+" : ""}${pct(vSim / iniSim - 1, 1)} desde o início · queda máx. permitida 20%</span></section>
      </div>
      <section class="card"><h2>Evolução da carteira simulada</h2>${graficoLinha(pontos, { titulo: "evolução da carteira simulada" })}</section>
      <section class="card"><h2>Onde está o dinheiro (simulada)</h2>${rosca(partes, usd(vSim))}</section>
    `);
    const b = $("#ir-decisoes"); if (b) b.addEventListener("click", () => { aba = "decisoes"; render(); });
  }

  function venceEm(criada) {
    const h = D.validadeH - (Date.now() - new Date(criada)) / 36e5;
    return h <= 0 ? `<span class="chip ruim">vencida</span>` : `<span class="chip ${h < 12 ? "meio" : ""}">vence em ${esc(Math.floor(h))} h</span>`;
  }
  function blocoProposta(pid, p) {
    if (p.tipo === "banca") {
      const ts = D.teses.filter((t) => t.plano === pid);
      const reg = D.registro.filter((r) => r.tipo === "banca" && (r.dados || {}).plano === pid).pop();
      const al = ((reg || {}).dados || {}).alocacao || {};
      return `<section class="card"><div class="linha"><h2>Plano da banca ${esc(pid)}</h2>${venceEm(p.criada)}</div>
        <span class="mudo">Dólar ${esc(al.dolar_pct ?? "?")}% · Brasil ${esc(al.brasil_pct ?? "?")}% · ${ts.length} teses</span>
        ${ts.map(cartaoTese).join("")}
        <div class="aviso">Aprovar significa: você concorda com o plano e executa por conta própria o que couber no seu capital. O sistema registra e passa a conferir o placar das teses.</div>
        <div class="botoes"><button class="btn decide cheio" data-acao="aprovar" data-alvo="${esc(pid)}">Aprovar plano</button><button class="btn cheio" data-acao="recusar" data-alvo="${esc(pid)}">Recusar</button></div></section>`;
    }
    if (p.tipo === "teste") {
      return `<section class="card"><div class="linha"><h2>Teste do botão ${esc(pid)}</h2>${venceEm(p.criada)}</div><span class="mudo">Não mexe em dinheiro.</span>
        <div class="botoes"><button class="btn prim cheio" data-acao="aprovar" data-alvo="${esc(pid)}">Aprovar teste</button></div></section>`;
    }
    const alvo = p.alvo || {};
    return `<section class="card"><div class="linha"><h2>Ciclo mensal ${esc(pid)}</h2>${venceEm(p.criada)}</div>
      <span class="mudo">Rebalanceamento do cofre em dólar pela regra de tendência de 10 meses.</span>
      <table class="tabela"><tr><th>Ativo</th><th class="num">Peso-alvo</th></tr>
      ${Object.entries(alvo).map(([t, w]) => `<tr><td>${esc(t)}</td><td class="num">${esc(pct(w))}</td></tr>`).join("")}
      <tr><td>Caixa</td><td class="num">${esc(pct(1 - Object.values(alvo).reduce((s, w) => s + w, 0)))}</td></tr></table>
      ${p.aprovada ? `<div class="aviso ok">Já aprovada: aguardando preço ou liberação do sistema.</div>` : `<div class="botoes"><button class="btn decide cheio" data-acao="aprovar" data-alvo="${esc(pid)}">Aprovar</button><button class="btn cheio" data-acao="recusar" data-alvo="${esc(pid)}">Recusar</button></div>`}</section>`;
  }
  function cartaoTese(t) {
    const v = t.votos || {};
    const cls = (x) => /rejeit/i.test(x || "") ? "ruim" : /testar/i.test(x || "") ? "meio" : x ? "bom" : "";
    return `<div class="tese"><div class="cab"><span class="nome">${esc(t.id)} · ${esc(t.ativo)}</span><span class="dir ${esc(t.direcao)}">${esc((t.direcao || "").toUpperCase())} ${t.peso_pct ? esc(t.peso_pct) + "%" : ""}</span></div>
      ${t.ticker ? `<span class="mudo">Código: ${esc(t.ticker)}</span>` : ""}
      ${t.explicacao_simples ? `<span>${esc(t.explicacao_simples)}</span>` : ""}
      <span class="mudo"><b>Por quê:</b> ${esc(t.causa)}</span>
      ${barrasCenarios(t.cenarios)}
      <span class="mudo"><b>Sai se:</b> ${esc(t.gatilho_saida)}</span>
      <div class="chips"><span class="chip ${cls(v.red_team)}">Red Team: ${esc(v.red_team || "sem voto")}</span><span class="chip ${cls(v.segunda)}">2ª IA: ${esc(v.segunda || "sem voto")}</span></div></div>`;
  }

  function telaDecisoes() {
    const pend = Object.entries(D.pendentes).sort((a, b) => new Date(b[1].criada) - new Date(a[1].criada));
    const man = Object.entries(D.manuais);
    casca(`
      ${faixaStatus()}
      ${man.map(([pid, o]) => `<section class="card"><h2>Ordem real para confirmar · ${esc(pid)}</h2>
        <table class="tabela"><tr><th>Ativo</th><th class="num">Cotas</th><th class="num">Valor</th></tr>
        ${Object.entries(o.ordens || {}).map(([t, q]) => `<tr><td>${q < 0 ? "Vender" : "Comprar"} ${esc(t)}</td><td class="num">${esc(Math.abs(q).toFixed(4))}</td><td class="num">${usd(Math.abs(q * ((o.precos || {})[t] || 0)), 2)}</td></tr>`).join("")}</table>
        <span class="mudo">Execute no app da corretora (a mercado, permitir fração) e confirme aqui.</span>
        <div class="botoes"><button class="btn decide cheio" data-acao="executei" data-alvo="${esc(pid)}">Executei</button><button class="btn cheio" data-acao="naoexecutei" data-alvo="${esc(pid)}">Não executei</button></div></section>`).join("")}
      ${pend.map(([pid, p]) => blocoProposta(pid, p)).join("")}
      ${!pend.length && !man.length ? `<section class="card"><h2>Nada esperando você</h2><span class="mudo">Quando houver proposta, ela aparece aqui e você recebe um aviso no celular.</span></section>` : ""}
    `);
    document.querySelectorAll("[data-acao]").forEach((b) => b.addEventListener("click", () => confirmar(b.dataset.acao, b.dataset.alvo)));
  }

  function telaBanca() {
    const ultima = D.registro.filter((r) => r.tipo === "banca").pop();
    if (!ultima) { casca(`<section class="card"><h2>Ainda não há banca</h2></section>`); return; }
    const d = ultima.dados || {}, al = d.alocacao || {};
    const ts = D.teses.filter((t) => t.plano === d.plano);
    const decidido = D.registro.find((r) => r.tipo === "plano_banca_aprovado" && (r.dados || {}).plano === d.plano);
    const planos = new Set(D.teses.map((t) => t.plano));
    casca(`
      <section class="card"><span class="rotulo">Última banca · ${esc(dataBR(ultima.quando))}</span>
        <h2>Plano ${esc(d.plano)} ${decidido ? '<span class="chip bom">aprovado</span>' : ""}</h2>
        ${rosca([{ n: "Dólar (Mesa Internacional)", v: Number(al.dolar_pct) || 0 }, { n: "Brasil (Mesa Brasil)", v: Number(al.brasil_pct) || 0 }], "")}
        <span>${esc(al.justificativa || "")}</span>
        <span class="mudo">${esc(d.especialistas || "?")} especialistas · ${esc(d.buscas_na_internet || 0)} pesquisas na internet · ${esc(d.barradas || 0)} teses barradas pelo compliance</span>
      </section>
      <section class="card"><h2>Teses</h2>${ts.map(cartaoTese).join("") || '<span class="mudo">Sem teses.</span>'}</section>
      <section class="card"><h2>Placar</h2><span class="mudo">${D.teses.length} teses registradas em ${planos.size} banca(s). A conferência de acerto em 1, 3 e 6 meses entra quando as primeiras teses completarem o prazo.</span></section>
    `);
  }

  let tipoRel = "banca";
  async function telaRelatorios() {
    const tipos = [["banca", "Banca"], ["radar", "Radar CEO"], ["csc", "CSC"]];
    casca(`<div class="seg">${tipos.map(([k, n]) => `<button data-tipo="${k}" class="${tipoRel === k ? "ativa" : ""}">${n}</button>`).join("")}</div><div id="rel" class="carregando">Carregando…</div>`);
    document.querySelectorAll("[data-tipo]").forEach((b) => b.addEventListener("click", () => { tipoRel = b.dataset.tipo; telaRelatorios(); }));
    try {
      const arqs = (await pasta("relatorios/" + tipoRel)).filter((a) => a.name.endsWith(".md")).sort((a, b) => b.name.localeCompare(a.name));
      if (!arqs.length) { $("#rel").innerHTML = `<section class="card"><span class="mudo">Nenhum relatório ainda.</span></section>`; return; }
      const texto = await bruto(arqs[0].path);
      const limpo = (texto || "").split(/\n---\n(?:PLANO|CLASSIFICA)/)[0];
      $("#rel").className = "";
      $("#rel").innerHTML = `<section class="card"><span class="rotulo">${esc(arqs[0].name.replace(".md", ""))}</span><div class="texto">${esc(limpo)}</div></section>
        ${arqs.length > 1 ? `<section class="card"><h3>Anteriores</h3><div class="lista">${arqs.slice(1, 12).map((a) => `<button class="item btn" data-path="${esc(a.path)}"><span class="corpo"><span class="t">${esc(a.name.replace(".md", ""))}</span></span></button>`).join("")}</div></section>` : ""}`;
      document.querySelectorAll("[data-path]").forEach((b) => b.addEventListener("click", async () => {
        const t = await bruto(b.dataset.path);
        modal(`<h2>${esc(b.dataset.path.split("/").pop())}</h2><div class="texto">${esc((t || "").split(/\n---\n(?:PLANO|CLASSIFICA)/)[0])}</div><button class="btn" data-fechar>Fechar</button>`);
      }));
    } catch (e) { erroRede(e); }
  }

  function resumoEvento(r) {
    const d = r.dados || {};
    const partes = Object.entries(d).filter(([, v]) => v !== null && typeof v !== "object")
      .map(([k, v]) => k.replace(/_/g, " ") + ": " + v);
    return partes.join(" · ").slice(0, 160);
  }

  function telaSeguranca() {
    const eventos = D.registro.slice(-60).reverse();
    const icone = (t) => ({ decisao: "✅", execucao: "💱", proposta: "📝", banca: "🏛️", radar: "📡", csc_revisao: "⚖️", comando_painel: "📱", comando_rejeitado: "⛔", acesso_negado: "🚨", expirada: "⌛" }[t] || "•");
    const rejeitados = D.registro.filter((r) => r.tipo === "comando_rejeitado" || r.tipo === "acesso_negado").length;
    casca(`
      ${faixaStatus()}
      <section class="card"><h2>Freio de emergência</h2>
        <span class="mudo">Congelar trava novas propostas, a banca e qualquer execução, até você liberar.</span>
        ${D.congelado ? `<button class="btn prim" data-acao="descongelar">Liberar o sistema</button>` : `<button class="btn perigo" data-acao="congelar">Congelar tudo</button>`}</section>
      <section class="card"><h2>Segurança deste aparelho</h2>
        <div class="lista">
          <div class="item"><span class="corpo"><span class="t">Chaves trancadas com seu PIN</span><span class="d">Criptografia AES-256. ${MAX_ERROS} PINs errados apagam tudo deste aparelho.</span></span></div>
          <div class="item"><span class="corpo"><span class="t">Bloqueio automático</span><span class="d">Após 5 minutos parado ou 1 minuto fora do app.</span></span></div>
          <div class="item"><span class="corpo"><span class="t">Operações assinadas</span><span class="d">O robô só aceita comandos assinados por este aparelho, em até 30 minutos, sem repetição.</span></span></div>
          <div class="item"><span class="corpo"><span class="t">Tentativas bloqueadas</span><span class="d">${rejeitados ? `<b>${rejeitados}</b> no registro. Confira o histórico abaixo.` : "Nenhuma até agora."}</span></span></div>
        </div>
        <div class="botoes"><button class="btn" id="b-pin">Trocar PIN</button><button class="btn perigo" id="b-apagar">Apagar deste aparelho</button></div></section>
      <section class="card"><h2>Histórico de decisões</h2><div class="lista">
        ${eventos.map((r) => `<div class="item"><span>${icone(r.tipo)}</span><span class="corpo"><span class="t">${esc(r.tipo.replace(/_/g, " "))} · ${esc(r.autor)}</span><span class="d">${esc(dataBR(r.quando))} · ${esc(resumoEvento(r))}</span></span></div>`).join("")}
      </div></section>
    `);
    document.querySelectorAll("[data-acao]").forEach((b) => b.addEventListener("click", () => confirmar(b.dataset.acao, "")));
    $("#b-apagar").addEventListener("click", () => modal(`<h2>Apagar deste aparelho?</h2><p>As chaves somem deste celular. Para usar de novo, será preciso configurar outra vez. Nada muda no sistema.</p>
      <div class="botoes"><button class="btn perigo cheio" id="sim-apagar">Apagar</button><button class="btn cheio" data-fechar>Cancelar</button></div>`, () => {
      $("#sim-apagar").addEventListener("click", () => { apagar(CHAVE_COFRE); S = null; location.reload(); });
    }));
    $("#b-pin").addEventListener("click", () => novoPin(async (pin) => { await trancar({ token: S.token, chave: S.chave, repo: S.repo }, pin); S.pin = pin; toast("PIN trocado."); }));
  }

  // ---------------------------------------------------------------- confirmação com PIN
  function modal(html, depois) {
    const f = document.createElement("div");
    f.className = "fundo"; f.innerHTML = `<div class="modal" role="dialog" aria-modal="true">${html}</div>`;
    document.body.appendChild(f);
    f.addEventListener("click", (e) => { if (e.target === f || e.target.hasAttribute("data-fechar")) f.remove(); });
    if (depois) depois(f);
    return f;
  }
  function confirmar(acao, alvo) {
    const textos = {
      aprovar: "Você está APROVANDO esta proposta. Se for do ciclo mensal, o robô executa na carteira simulada e, com dinheiro real ligado, manda a ordem para você executar na corretora.",
      recusar: "Você está RECUSANDO esta proposta. Nada é executado e a recusa fica registrada.",
      executei: "Você confirma que EXECUTOU a ordem real na corretora. A carteira real do sistema será atualizada.",
      naoexecutei: "Você confirma que NÃO executou a ordem real. Fica registrado e a carteira real não muda.",
      congelar: "O sistema para de gerar propostas e de executar qualquer coisa até você liberar.",
      descongelar: "O sistema volta a funcionar normalmente.",
    };
    const f = modal(`<h2>${esc(nomeAcao(acao))}${alvo ? " · " + esc(alvo) : ""}</h2><div class="aviso">${esc(textos[acao])}</div>
      <div class="campo"><label for="pin-conf">Digite seu PIN para confirmar</label><input id="pin-conf" type="password" inputmode="numeric" autocomplete="off" maxlength="12"></div>
      <div class="erro" id="erro-conf"></div>
      <div class="botoes"><button class="btn decide cheio" id="ok-conf">Confirmar</button><button class="btn cheio" data-fechar>Cancelar</button></div>`);
    $("#pin-conf", f).focus();
    $("#ok-conf", f).addEventListener("click", async () => {
      const pin = $("#pin-conf", f).value;
      if (pin !== S.pin) {
        try { await destrancar(pin); } catch (e) { if (e.message === "apagado") return location.reload(); $("#erro-conf", f).textContent = "PIN incorreto."; return; }
      }
      $("#ok-conf", f).disabled = true; $("#ok-conf", f).textContent = "Enviando…";
      try { await enviarComando(acao, alvo); f.remove(); } catch (e) { $("#erro-conf", f).textContent = msgErro(e); $("#ok-conf", f).disabled = false; $("#ok-conf", f).textContent = "Confirmar"; }
    });
  }

  function msgErro(e) {
    if (e.status === 401) return "A chave do GitHub foi recusada (vencida ou revogada). Configure uma nova em Segurança.";
    if (e.status === 403) return "A chave do GitHub não tem a permissão necessária (Issues e Actions).";
    return "Sem conexão com o GitHub agora. Tente de novo.";
  }
  function erroRede(e) { toast(msgErro(e)); }

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

  function telaPin() {
    const c = ler(CHAVE_COFRE);
    if (!c) return telaConfig();
    teclado("Painel da Holding", "Digite seu PIN", async (pin, erro) => {
      erro("Abrindo…");
      try { const seg = await destrancar(pin); S = Object.assign(seg, { pin }); ultimoToque = Date.now(); }
      catch (e) {
        if (e.message === "apagado") { erro(""); return telaConfig("PIN errado 5 vezes: as chaves foram apagadas deste aparelho. Configure de novo."); }
        const r = MAX_ERROS - ((ler(CHAVE_COFRE) || {}).erros || 0); return erro(`PIN incorreto. Restam ${r} tentativa(s) antes de apagar.`);
      }
      $("#app").innerHTML = `<div class="tela-cheia carregando">Carregando dados do sistema…</div>`;
      try { await carregar(); render(); } catch (e) { erroRede(e); render(); }
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
      try { await carregar(); } catch (e) { erroRede(e); }
      render();
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

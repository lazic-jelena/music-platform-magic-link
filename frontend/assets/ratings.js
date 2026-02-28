(function () {
  "use strict";

  const API_BASE = (window.API_BASE || "").replace(/\/$/, "");

  function clamp(n, min, max) { return Math.max(min, Math.min(max, n)); }
  function roundToHalf(n) { return Math.round(n * 2) / 2; }

  // Stable guest session id (OK to keep stable)
  function getSessionUserId() {
    let v = sessionStorage.getItem("mp_user_id");
    if (!v) {
      v = "guest_" + Math.random().toString(16).slice(2) + Date.now().toString(16);
      sessionStorage.setItem("mp_user_id", v);
    }
    return v;
  }

  async function readJsonOrText(res) {
    const text = await res.text().catch(() => "");
    if (!text) return { text: "", json: null };
    try { return { text, json: JSON.parse(text) }; }
    catch { return { text, json: null }; }
  }

  // ===== SVG stars =====
  function starSVG(fillRatio, size = 20) {
    const id = "grad_" + Math.random().toString(16).slice(2);
    const w = clamp(fillRatio, 0, 1) * 100;

    const path = "M12 17.27L18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z";

    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("width", String(size));
    svg.setAttribute("height", String(size));
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.style.filter = "drop-shadow(0 1px 0 rgba(0,0,0,.35))";

    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    const lg = document.createElementNS("http://www.w3.org/2000/svg", "linearGradient");
    lg.setAttribute("id", id);
    lg.setAttribute("x1", "0%");
    lg.setAttribute("y1", "0%");
    lg.setAttribute("x2", "100%");
    lg.setAttribute("y2", "0%");

    const s1 = document.createElementNS("http://www.w3.org/2000/svg", "stop");
    s1.setAttribute("offset", w + "%");
    s1.setAttribute("stop-color", "#ffd24d");
    s1.setAttribute("stop-opacity", "1");

    const s2 = document.createElementNS("http://www.w3.org/2000/svg", "stop");
    s2.setAttribute("offset", w + "%");
    s2.setAttribute("stop-color", "#ffffff");
    s2.setAttribute("stop-opacity", "0.20");

    lg.appendChild(s1);
    lg.appendChild(s2);
    defs.appendChild(lg);
    svg.appendChild(defs);

    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", path);
    p.setAttribute("fill", `url(#${id})`);
    p.setAttribute("stroke", "rgba(0,0,0,0.35)");
    p.setAttribute("stroke-width", "0.8");
    svg.appendChild(p);

    return svg;
  }

  function buildStarsDisplay(value) {
    const v = (typeof value === "number") ? clamp(roundToHalf(value), 0, 5) : 0;

    const root = document.createElement("div");
    root.className = "mp-stars";

    for (let i = 1; i <= 5; i++) {
      const full = v >= i ? 1 : (v >= i - 0.5 ? 0.5 : 0);
      root.appendChild(starSVG(full, 20));
    }

    const label = document.createElement("span");
    label.className = "mp-stars-label";
    label.textContent = `${v.toFixed(1)}/5`;
    root.appendChild(label);

    return root;
  }

  function buildStarsPicker(initialValue, onPick) {
    let current = clamp(roundToHalf(Number(initialValue || 0)), 0, 5);

    const wrap = document.createElement("div");
    wrap.className = "mp-stars-picker";
    wrap.setAttribute("role", "slider");
    wrap.setAttribute("aria-valuemin", "0");
    wrap.setAttribute("aria-valuemax", "5");
    wrap.setAttribute("aria-valuenow", String(current));

    const clickable = document.createElement("div");
    clickable.className = "mp-stars-clickable";

    const row = document.createElement("div");
    row.style.display = "inline-flex";
    row.style.gap = "4px";
    row.style.alignItems = "center";

    function renderRow(previewValue) {
      row.innerHTML = "";
      const v = clamp(roundToHalf(Number(previewValue || 0)), 0, 5);
      for (let i = 1; i <= 5; i++) {
        const full = v >= i ? 1 : (v >= i - 0.5 ? 0.5 : 0);
        row.appendChild(starSVG(full, 22));
      }
    }

    const hint = document.createElement("div");
    hint.className = "mp-rating-status";
    hint.textContent = `${current.toFixed(1)} / 5`;

    function setValue(v) {
      current = clamp(roundToHalf(Number(v || 0)), 0, 5);
      wrap.setAttribute("aria-valuenow", String(current));
      renderRow(current);
      hint.textContent = `${current.toFixed(1)} / 5`;
    }

    function calcFromMouse(e) {
      const rect = clickable.getBoundingClientRect();
      const x = clamp(e.clientX - rect.left, 0, rect.width);
      const ratio = rect.width ? (x / rect.width) : 0;
      return roundToHalf(ratio * 5);
    }

    renderRow(current);
    clickable.appendChild(row);
    wrap.appendChild(clickable);
    wrap.appendChild(hint);

    clickable.addEventListener("mousemove", (e) => {
      const v = calcFromMouse(e);
      renderRow(v);
      hint.textContent = `${v.toFixed(1)} / 5 (click)`;
    });

    clickable.addEventListener("mouseleave", () => {
      renderRow(current);
      hint.textContent = `${current.toFixed(1)} / 5`;
    });

    clickable.addEventListener("click", (e) => {
      const v = calcFromMouse(e);
      setValue(v);
      onPick && onPick(current);
    });

    wrap.tabIndex = 0;
    wrap.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowUp") {
        e.preventDefault(); setValue(current + 0.5); onPick && onPick(current);
      }
      if (e.key === "ArrowLeft" || e.key === "ArrowDown") {
        e.preventDefault(); setValue(current - 0.5); onPick && onPick(current);
      }
      if (e.key === "Home") { e.preventDefault(); setValue(0); onPick && onPick(current); }
      if (e.key === "End") { e.preventDefault(); setValue(5); onPick && onPick(current); }
    });

    return { el: wrap, setValue, getValue: () => current };
  }

  // ===== Ratings API =====
  // 1) Prefer: GET /api/ratings/summary?song_id=...  -> { avg, count }
  // 2) Fallback: GET /api/ratings?song_id=...&page=1&limit=100 and compute avg from items
  async function fetchAverage(songId, { signal } = {}) {
    const sid = String(songId);

    // Try summary endpoint (if backend has it)
    {
      const url = `${API_BASE}/api/ratings/summary?song_id=${encodeURIComponent(sid)}`;
      const res = await fetch(url, { credentials: "same-origin", signal, cache: "no-store" });
      if (res.ok) {
        const { json } = await readJsonOrText(res);
        const avg = (json && typeof json.avg === "number") ? json.avg : 0;
        const count = (json && typeof json.count === "number") ? json.count : 0;
        return { avg: clamp(roundToHalf(avg), 0, 5), count: Math.max(0, count) };
      }
    }

    // Fallback: read list and compute
    let page = 1;
    const limit = 100;
    let sum = 0;
    let cnt = 0;

    while (true) {
      const url =
        `${API_BASE}/api/ratings` +
        `?song_id=${encodeURIComponent(sid)}` +
        `&page=${page}&limit=${limit}`;

      const res = await fetch(url, { credentials: "same-origin", signal, cache: "no-store" });
      if (!res.ok) break;

      const { json } = await readJsonOrText(res);
      const items = (json && Array.isArray(json.items)) ? json.items : [];
      for (const it of items) {
        const v = it && it.value;
        if (typeof v === "number") { sum += v; cnt += 1; }
      }

      if (items.length < limit) break;
      page += 1;
      if (page > 50) break; // safety
    }

    const avg = cnt ? (sum / cnt) : 0;
    return { avg: clamp(roundToHalf(avg), 0, 5), count: cnt };
  }

  /**
   * Multi-vote guest: čak i ako backend radi upsert na (song_id,user_id),
   * mi šaljemo UNIKATAN user_id za svaki vote.
   * Tako backend upisuje više redova -> avg/count rastu kako treba.
   */
  async function postVote(songId, value, { signal } = {}) {
    const baseUser = getSessionUserId();
    const v = clamp(roundToHalf(Number(value ?? 0)), 0, 5);

    const voteId = "vote_" + Math.random().toString(16).slice(2) + Date.now().toString(16);

    // ključna stvar: user_id je jedinstven po vote-u
    const userId = `${baseUser}_${voteId}`;

    const res = await fetch(`${API_BASE}/api/ratings`, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        vote_id: voteId,
        song_id: String(songId),
        user_id: userId,
        value: v,
        created_at: new Date().toISOString()
      }),
      signal
    });

    const { text, json } = await readJsonOrText(res);
    if (!res.ok) {
      const msg =
        (json && (json.error || json.message)) ? (json.error || json.message) :
        (text ? text : `Rating failed (${res.status})`);
      throw new Error(msg);
    }
    return json || null;
  }

  // ===== UI stale protection =====
  function withToken(container) {
    const token = Math.random().toString(16).slice(2) + Date.now().toString(16);
    container.__mp_token = token;
    try { container.__mp_abort && container.__mp_abort.abort(); } catch {}
    const ac = new AbortController();
    container.__mp_abort = ac;
    return { token, ac };
  }

  // Read-only avg stars
  function attachAverageUI({ container, songId }) {
    if (!container) return;
    const { token, ac } = withToken(container);

    container.innerHTML = "";
    const wrap = document.createElement("div");
    wrap.className = "mp-stars";
    wrap.textContent = "Loading...";
    container.appendChild(wrap);

    (async () => {
      try {
        const { avg, count } = await fetchAverage(songId, { signal: ac.signal });
        if (container.__mp_token !== token) return;

        container.innerHTML = "";
        const stars = buildStarsDisplay(avg);

        const countEl = document.createElement("span");
        countEl.className = "mp-stars-label";
        countEl.textContent = `(${count})`;
        stars.appendChild(countEl);

        container.appendChild(stars);
      } catch (e) {
        if (container.__mp_token !== token) return;
        if (e && e.name === "AbortError") return;
        container.innerHTML = `<div class="mp-rating-status mp-err">Avg error</div>`;
      }
    })();
  }

  // Vote UI: starts empty, and after each vote resets to empty again
  function attachVoteUI({ container, songId, onAfterVote }) {
    if (!container) return;
    const { token, ac } = withToken(container);

    container.innerHTML = "";

    const status = document.createElement("div");
    status.className = "mp-rating-status";
    status.textContent = "Pick stars to vote (you can vote multiple times as guest).";

    const picker = buildStarsPicker(0, async (picked) => {
      if (container.__mp_token !== token) return;

      status.textContent = "Saving vote...";
      status.classList.remove("mp-err");

      try {
        await postVote(songId, picked, { signal: ac.signal });
        if (container.__mp_token !== token) return;

        const { avg, count } = await fetchAverage(songId, { signal: ac.signal });
        if (container.__mp_token !== token) return;

        status.textContent = `Saved ✓  Avg now: ${avg.toFixed(1)} / 5  (votes: ${count})`;

        // reset picker back to empty for next vote
        picker.setValue(0);

        onAfterVote && onAfterVote({ picked, avg, count });
      } catch (e) {
        if (container.__mp_token !== token) return;
        if (e && e.name === "AbortError") return;
        status.textContent = "Error saving vote: " + (e?.message || String(e));
        status.classList.add("mp-err");
      }
    });

    container.appendChild(picker.el);
    container.appendChild(status);
  }

  window.MPRatings = {
    getSessionUserId,
    buildStarsDisplay,
    attachAverageUI,
    attachVoteUI,
    fetchAverage,
    postVote
  };
})();

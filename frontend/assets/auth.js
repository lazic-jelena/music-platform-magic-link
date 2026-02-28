(function () {
  // API Gateway
  const BASE = "http://localhost:8081";


  // Kandidati: prvo /api (ako gateway koristi prefiks), pa fallback bez /api
  const API = {
    loginCandidates: [
      BASE + "/api/login",
      BASE + "/login"
    ],
    registerCandidates: [
      BASE + "/api/register",
      BASE + "/register"
    ],
    healthCandidates: [
      BASE + "/api/users/health",
      BASE + "/users/health",
      BASE + "/api/health",
      BASE + "/health"
    ],

    forgotCandidates: [
      BASE + "/users/password/forgot",
      BASE + "/password/forgot"
    ],

    resetCandidates: [
      BASE + "/users/password/reset",
      BASE + "/password/reset"
    ]
  };

  function safeJsonParse(s) { try { return JSON.parse(s); } catch { return null; } }

  function getUser() {
    const raw = localStorage.getItem("user");
    if (!raw) return null;
    const u = safeJsonParse(raw);
    return (u && typeof u === "object") ? u : null;
  }

  function setUser(u) {
    localStorage.setItem("user", JSON.stringify(u));
  }

  function clearAuth() {
    ["user", "role", "userRole", "token", "jwt", "access_token"].forEach(k => localStorage.removeItem(k));
  }

  function roleOf(u) {
    const r = (u && (u.role ?? u.Role ?? u.userRole ?? u.user_role)) ?? "";
    return String(r || "").trim().toUpperCase();
  }

  function isAdmin(u) {
    const r = roleOf(u);
    return (r === "A" || r === "ADMIN" || r === "ROLE_ADMIN");
  }

  async function fetchJson(url, options = {}) {
    const res = await fetch(url, { cache: "no-store", ...options });

    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }

    if (!res.ok) {
      const msg = (data && (data.message || data.error)) ? (data.message || data.error) : ("HTTP " + res.status);
      const err = new Error(msg);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  async function postJson(url, payload) {
    return fetchJson(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  }

  async function postJsonWithFallback(urls, payload) {
    let lastErr = null;

    for (const u of urls) {
      try {
        const res = await fetch(u, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          cache: "no-store"
        });

        // 404/405 => probaj sledeći kandidat
        if (res.status === 404 || res.status === 405) {
          lastErr = new Error("HTTP " + res.status + " on " + u);
          lastErr.status = res.status;
          continue;
        }

        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.message || ("HTTP " + res.status));
        return data;
      } catch (e) {
        lastErr = e;
      }
    }

    throw lastErr || new Error("API nedostupan");
  }

  async function login(email, password) {
    if (!email || !password) throw new Error("Unesi email i lozinku.");
    const resp = await postJsonWithFallback(API.loginCandidates, { email, password });
    if (!resp?.success) throw new Error(resp?.message || "Neuspešna prijava.");
    const user = resp?.data;
    if (!user) throw new Error("Login response nema data.");
    setUser(user);
    return user;
  }

  async function register(userData) {
    const resp = await postJsonWithFallback(API.registerCandidates, userData);
    if (!resp?.success) throw new Error(resp?.message || "Registracija neuspešna.");
    return resp;
  }

  async function healthCheck() {
    try {
      const resp = await fetchJson(API.healthCandidates[0], { method: "GET" });
      return !!resp?.success;
    } catch {
      // ako prva ruta ne radi, probaj ostale
      const resp = await postJsonWithFallback(
        API.healthCandidates.map(u => u), // reuse fallback helper
        {} // neće proći jer je GET, pa radimo ručno ispod
      );
      return !!resp?.success;
    }
  }

  // Forgot password (magic link)
  async function forgotPassword(email) {
    if (!email) throw new Error("Unesite email.");
    return postJsonWithFallback(API.forgotCandidates, { email });
  }

  // Reset password (token + newPassword)
  async function resetPassword(token, newPassword) {
    if (!token) throw new Error("Nedostaje token.");
    if (!newPassword) throw new Error("Unesite novu lozinku.");
    return postJsonWithFallback(API.resetCandidates, { token, newPassword });
  }

  function requireAuth(redirectTo = "user_service.html") {
    const u = getUser();
    if (!u) {
      window.location.href = redirectTo;
      return null;
    }
    return u;
  }

  function requireAdmin(redirectTo = "index.html") {
    const u = getUser();
    if (!u) {
      window.location.href = "user_service.html";
      return null;
    }
    if (!isAdmin(u)) {
      window.location.href = redirectTo;
      return null;
    }
    return u;
  }

  window.MPAuth = {
    API,
    getUser,
    setUser,
    clearAuth,
    roleOf,
    isAdmin,
    login,
    register,
    healthCheck,
    forgotPassword,
    resetPassword,
    requireAuth,
    requireAdmin
  };
})();

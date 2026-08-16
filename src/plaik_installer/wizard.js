const I18N = {
  uk: {
    brand: "Встановлення",
    steps: ["Вітання", "Перевірка системи", "Сайт", "База даних", "Адміністратор", "Встановлення"],
    welcomeTitle: "Ласкаво просимо до PLAIK",
    welcomeLead: "Майстер проведе вас кроками класичного веб-інсталятора. CLI sudo plaik setup лишається для автоматизації та відновлення.",
    tokenLabel: "Токен інсталятора",
    tokenHelp: "Токен лише в /etc/plaik/installer.env. Після завершення він буде відкликаний.",
    next: "Далі",
    back: "Назад",
    start: "Почати встановлення",
    checkTitle: "Сумісність системи",
    checkLead: "Інсталятор бачить поточний стан хоста перед записом конфігурації.",
    siteTitle: "Інформація про сайт",
    siteLead: "Домен стане публічною HTTPS-адресою. Без схеми і шляху.",
    domain: "Домен",
    locale: "Локаль",
    timezone: "Часовий пояс",
    dbTitle: "Налаштування бази даних",
    dbLead: "Оберіть знайдену порожню базу, створіть нову на loopback postgres або введіть існуючу вручну.",
    source: "Джерело",
    useDetected: "Використати знайдену порожню",
    create: "Створити порожню",
    manual: "Вказати вручну",
    restore: "Відновлення (окрема процедура)",
    restoreHelp: "Restore вимкнено. Dump restore — окрема operational recovery, не Stage 2.",
    host: "Хост",
    port: "Порт",
    database: "База даних",
    migrator: "Користувач міграцій",
    runtime: "Користувач runtime",
    checkpoint: "Користувач checkpoint",
    password: "Пароль",
    ssl: "SSL mode",
    adminTitle: "Обліковий запис адміністратора",
    adminLead: "Це перший super-admin. Пароль щонайменше 12 символів.",
    email: "Email",
    installTitle: "Встановлення",
    installLead: "Застосовуємо перевірку, конфігурацію, базу, адміністратора і фіналізацію сервісів.",
    doneTitle: "PLAIK встановлено",
    doneLead: "Інсталятор буде вимкнено. Далі відкрийте публічний сайт і control-center.",
    handoffTitle: "Фіналізація не завершилась",
    handoffLead: "Core вже COMPLETED, але Web/Admin ще не підтверджені, або інсталятор ще активний. Повторіть фіналізацію або виконайте sudo plaik setup.",
    retryFinalize: "Повторити фіналізацію",
    fail: "Крок не виконано"
  },
  en: {
    brand: "Installation",
    steps: ["Welcome", "System compatibility", "Site", "Database", "Administrator", "Installation"],
    welcomeTitle: "Welcome to PLAIK",
    welcomeLead: "This wizard is the normal Stage 2 path. sudo plaik setup remains for automation and recovery.",
    tokenLabel: "Installer token",
    tokenHelp: "The token lives only in /etc/plaik/installer.env and is revoked after completion.",
    next: "Next",
    back: "Back",
    start: "Start installation",
    checkTitle: "System compatibility",
    checkLead: "The installer inspects host state before writing configuration.",
    siteTitle: "Site information",
    siteLead: "The domain becomes the public HTTPS URL. No scheme or path.",
    domain: "Domain",
    locale: "Locale",
    timezone: "Timezone",
    dbTitle: "Database configuration",
    dbLead: "Use a detected empty database, create one on loopback postgres, or enter an existing database.",
    source: "Source",
    useDetected: "Use detected empty database",
    create: "Create empty database",
    manual: "Enter manually",
    restore: "Restore (separate procedure)",
    restoreHelp: "Restore is disabled. Dump restore is operational recovery, not Stage 2.",
    host: "Host",
    port: "Port",
    database: "Database",
    migrator: "Migration user",
    runtime: "Runtime user",
    checkpoint: "Checkpoint user",
    password: "Password",
    ssl: "SSL mode",
    adminTitle: "Administrator account",
    adminLead: "This is the first super-admin. Password must be at least 12 characters.",
    email: "Email",
    installTitle: "Installation",
    installLead: "Applying checks, configuration, database, administrator and service finalization.",
    doneTitle: "PLAIK is installed",
    doneLead: "The installer will be disabled. Continue to the public site and control-center.",
    handoffTitle: "Service finalization did not finish",
    handoffLead: "Core is COMPLETED, but Web/Admin are not confirmed or the installer is still active. Retry finalization or run sudo plaik setup.",
    retryFinalize: "Retry finalization",
    fail: "This step failed"
  }
};

const STEP = {
  not_started: 0,
  requirements_checked: 2,
  configured: 5,
  database_ready: 4,
  admin_ready: 5,
  theme_ready: 5,
  completed: 6
};

const state = {
  lang: "uk",
  step: 0,
  token: sessionStorage.getItem("plaik-installer-token") || "",
  installState: "not_started",
  handoff: {status: "not_started", detail: ""},
  requirements: null,
  inventory: null,
  form: {
    domain: "",
    locale: "uk-UA",
    timezone: "Europe/Kyiv",
    source: "manual",
    host: "127.0.0.1",
    port: "5432",
    database: "plaik",
    username: "plaik_migrator",
    runtime_username: "plaik_runtime",
    checkpoint_username: "plaik_checkpoint",
    migrator_password: "",
    runtime_password: "",
    checkpoint_password: "",
    ssl_mode: "require",
    email: "",
    admin_password: ""
  }
};

const $ = (id) => document.getElementById(id);
const t = () => I18N[state.lang];
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
}
function headers() {
  const result = {"Content-Type": "application/json", "Accept": "application/json"};
  if (state.token) result["X-Installer-Token"] = state.token;
  return result;
}
async function api(method, path, body) {
  const response = await fetch(path, {
    method,
    headers: headers(),
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await response.text();
  let data = {};
  if (text) {
    try { data = JSON.parse(text); } catch { data = {detail: text}; }
  }
  if (!response.ok) {
    const detail = data.detail;
    throw new Error(typeof detail === "string" ? detail : t().fail);
  }
  return data;
}
function field(name, label, type, value, extra="") {
  return `<div class="field"><label for="${name}">${escapeHtml(label)}</label>
    <input id="${name}" name="${name}" type="${type}" value="${escapeHtml(value)}" ${extra}></div>`;
}
function renderSteps() {
  $("steps").innerHTML = t().steps.map((label, index) => {
    const cls = index < state.step ? "done" : index === state.step ? "current" : "";
    const mark = index < state.step ? "✓" : String(index + 1);
    return `<li class="${cls}"><button type="button"><span class="num">${mark}</span><span>${escapeHtml(label)}</span></button></li>`;
  }).join("");
  $("brand-sub").textContent = t().brand;
}
function flash(message, kind) {
  return message ? `<div class="flash ${kind}">${escapeHtml(message)}</div>` : "";
}
function actions(back, nextLabel) {
  return `<div class="actions">
    <button type="button" class="ghost" id="back" ${back ? "" : "disabled"}>${escapeHtml(t().back)}</button>
    <button type="submit" class="primary" id="next">${escapeHtml(nextLabel || t().next)}</button>
  </div>`;
}
function applyInventory(inventory) {
  state.inventory = inventory || null;
  const suggested = inventory && inventory.suggested;
  if (suggested) {
    if (state.form.source !== "manual" && state.form.source !== "create") {
      state.form.source = "use-detected";
    }
    if (state.form.source === "use-detected") {
      state.form.host = suggested.host;
      state.form.port = String(suggested.port);
      state.form.database = suggested.database;
    }
  } else if (state.form.source === "use-detected") {
    state.form.source = inventory && inventory.create_supported ? "create" : "manual";
  }
}
function applyConfiguration(configuration) {
  if (!configuration) return;
  const url = configuration.public_url || "";
  state.form.domain = url.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  state.form.locale = configuration.locale || state.form.locale;
  state.form.timezone = configuration.timezone || state.form.timezone;
  const database = configuration.database || {};
  if (database.host) state.form.host = database.host;
  if (database.port) state.form.port = String(database.port);
  if (database.database) state.form.database = database.database;
  if (database.username) state.form.username = database.username;
  if (database.runtime_username) state.form.runtime_username = database.runtime_username;
  if (database.checkpoint_username) state.form.checkpoint_username = database.checkpoint_username;
  if (database.ssl_mode) state.form.ssl_mode = database.ssl_mode;
  if (configuration.installation_id) state.installationId = configuration.installation_id;
}
function detectedFieldsLocked() {
  return state.form.source === "use-detected" ? "readonly" : "";
}
function readForm() {
  document.querySelectorAll("#panel [name]").forEach((node) => {
    if (node.type === "password" || node.type === "text" || node.type === "email" || node.type === "number" || node.tagName === "SELECT") {
      state.form[node.name] = node.value;
    }
  });
  const token = $("token");
  if (token) {
    state.token = token.value.trim();
    sessionStorage.setItem("plaik-installer-token", state.token);
  }
  if (state.form.source === "use-detected") {
    applyInventory(state.inventory);
  }
}
function welcome() {
  return `<h1>${escapeHtml(t().welcomeTitle)}</h1>
    <p class="lead">${escapeHtml(t().welcomeLead)}</p>
    <form id="step-form" class="grid">
      ${field("token", t().tokenLabel, "password", state.token)}
      <p class="lead">${escapeHtml(t().tokenHelp)}</p>
      ${actions(false, t().next)}
    </form>`;
}
function checks() {
  const items = [
    ...(state.requirements?.checks || []),
    ...(state.requirements?.observations || [])
  ];
  const rows = items.map((item) => `<li><span class="dot ${item.passed ? "ok" : "bad"}"></span>
    <div><strong>${escapeHtml(item.id)}</strong><div class="lead">${escapeHtml(item.detail)}</div></div></li>`).join("");
  return `<h1>${escapeHtml(t().checkTitle)}</h1>
    <p class="lead">${escapeHtml(t().checkLead)}</p>
    <form id="step-form">
      <ul class="checks">${rows || `<li>${escapeHtml(t().fail)}</li>`}</ul>
      ${actions(true)}
    </form>`;
}
function site() {
  return `<h1>${escapeHtml(t().siteTitle)}</h1>
    <p class="lead">${escapeHtml(t().siteLead)}</p>
    <form id="step-form" class="grid two">
      ${field("domain", t().domain, "text", state.form.domain, "required")}
      ${field("locale", t().locale, "text", state.form.locale, "required")}
      ${field("timezone", t().timezone, "text", state.form.timezone, "required")}
      ${actions(true)}
    </form>`;
}
function database() {
  const suggested = state.inventory && state.inventory.suggested;
  const createSupported = Boolean(state.inventory && state.inventory.create_supported);
  const lock = detectedFieldsLocked();
  return `<h1>${escapeHtml(t().dbTitle)}</h1>
    <p class="lead">${escapeHtml(t().dbLead)}</p>
    <form id="step-form" class="grid two">
      <div class="field"><label for="source">${escapeHtml(t().source)}</label>
        <select id="source" name="source">
          <option value="use-detected"${state.form.source === "use-detected" && suggested ? " selected" : ""}${suggested ? "" : " disabled"}>${escapeHtml(t().useDetected)}</option>
          <option value="create"${state.form.source === "create" ? " selected" : ""}${createSupported ? "" : " disabled"}>${escapeHtml(t().create)}</option>
          <option value="manual"${state.form.source === "manual" ? " selected" : ""}>${escapeHtml(t().manual)}</option>
          <option value="restore" disabled>${escapeHtml(t().restore)}</option>
        </select>
      </div>
      <p class="lead" style="grid-column:1/-1">${escapeHtml(t().restoreHelp)}</p>
      ${field("host", t().host, "text", state.form.host, lock)}
      ${field("port", t().port, "number", state.form.port, lock)}
      ${field("database", t().database, "text", state.form.database, lock)}
      ${field("username", t().migrator, "text", state.form.username)}
      ${field("runtime_username", t().runtime, "text", state.form.runtime_username)}
      ${field("checkpoint_username", t().checkpoint, "text", state.form.checkpoint_username)}
      ${field("migrator_password", t().password + " (migrator)", "password", "", "required")}
      ${field("runtime_password", t().password + " (runtime)", "password", "", "required")}
      ${field("checkpoint_password", t().password + " (checkpoint)", "password", "", "required")}
      <div class="field"><label for="ssl_mode">${escapeHtml(t().ssl)}</label>
        <select id="ssl_mode" name="ssl_mode">
          ${["require","verify-ca","verify-full","prefer"].map((mode) =>
            `<option value="${mode}"${state.form.ssl_mode === mode ? " selected" : ""}>${mode}</option>`).join("")}
        </select>
      </div>
      ${actions(true)}
    </form>`;
}
function admin() {
  return `<h1>${escapeHtml(t().adminTitle)}</h1>
    <p class="lead">${escapeHtml(t().adminLead)}</p>
    <form id="step-form" class="grid">
      ${field("email", t().email, "email", state.form.email, "required")}
      ${field("admin_password", t().password, "password", "", "required minlength=12")}
      ${actions(true, t().start)}
    </form>`;
}
function install() {
  return `<h1>${escapeHtml(t().installTitle)}</h1>
    <p class="lead">${escapeHtml(t().installLead)}</p>
    <div class="progress"><span id="bar"></span></div>
    <div class="log" id="log"></div>`;
}
function done() {
  return `<div class="done-box">
    <h1>${escapeHtml(t().doneTitle)}</h1>
    <p class="lead">${escapeHtml(t().doneLead)}</p>
  </div>`;
}
function handoffFailed() {
  const detail = state.handoff && state.handoff.detail ? `<p>${escapeHtml(state.handoff.detail)}</p>` : "";
  return `<div class="done-box">
    <h1>${escapeHtml(t().handoffTitle)}</h1>
    <p class="lead">${escapeHtml(t().handoffLead)}</p>
    ${detail}
    <form id="step-form"><button type="submit" class="primary">${escapeHtml(t().retryFinalize)}</button></form>
  </div>`;
}
function render(error) {
  renderSteps();
  const views = [welcome, checks, site, database, admin, install];
  $("panel").innerHTML = flash(error, "bad") + (
    state.step >= 6 && state.handoff && state.handoff.status === "ready"
      ? done()
      : (state.installState === "completed" && (!state.handoff || state.handoff.status !== "ready")
        ? handoffFailed()
        : views[Math.min(state.step, 5)]())
  );
  $("top-title").textContent = t().steps[Math.min(state.step, 5)];
  const form = $("step-form");
  if (form) {
    form.addEventListener("submit", onNext);
    const back = $("back");
    if (back) back.addEventListener("click", () => { if (state.step > 0) { state.step -= 1; render(); } });
    const source = $("source");
    if (source) source.addEventListener("change", () => { readForm(); render(); });
  }
}
async function onNext(event) {
  event.preventDefault();
  readForm();
  try {
    if (state.installState === "completed" && (!state.handoff || state.handoff.status !== "ready")) {
      await continueInstall();
      return;
    }
    if (state.step === 0) {
      await resumeFromServer();
      return;
    }
    if (state.step === 1) {
      if (state.installState === "not_started") {
        await api("POST", "/api/install/transition", {target: "requirements_checked"});
        state.installState = "requirements_checked";
      }
    } else if (state.step === 4) {
      await continueInstall();
      return;
    }
    state.step += 1;
    render();
  } catch (error) {
    render(error.message || t().fail);
  }
}
function logLine(text) {
  const log = $("log");
  if (!log) return;
  const row = document.createElement("div");
  row.textContent = text;
  log.appendChild(row);
}
function setBar(percent) {
  const bar = $("bar");
  if (bar) bar.style.width = percent + "%";
}
function configurationPayload() {
  return {
    schema_version: 1,
    profile: "standard",
    mode: "production",
    installation_id: state.installationId || ("plaik-" + Math.random().toString(16).slice(2, 10)),
    group_id: "default-group",
    store_id: "default-store",
    locale: state.form.locale,
    timezone: state.form.timezone,
    public_url: "https://" + state.form.domain.replace(/^https?:\/\//, "").replace(/\/.*$/, ""),
    database: {
      backend: "postgresql",
      host: state.form.host,
      port: Number(state.form.port),
      database: state.form.database,
      username: state.form.username,
      credential: {provider: "local", key: "database/migrator", version: "v1"},
      runtime_username: state.form.runtime_username,
      runtime_credential: {provider: "local", key: "database/runtime", version: "v1"},
      checkpoint_username: state.form.checkpoint_username,
      checkpoint_credential: {provider: "local", key: "database/checkpoint", version: "v1"},
      ssl_mode: state.form.ssl_mode
    },
    sealed: false,
    sealed_at: null
  };
}
async function currentInstallState() {
  const payload = await api("GET", "/api/install/state");
  state.installState = payload.state;
  state.handoff = payload.handoff || {status: "not_started", detail: ""};
  return payload.state;
}
async function continueInstall() {
  const password = state.form.admin_password;
  state.step = 5;
  render();
  let guard = 0;
  while (guard < 12) {
    guard += 1;
    const current = await currentInstallState();
    if (current === "not_started") {
      setBar(10); logLine("requirements");
      await api("POST", "/api/install/transition", {target: "requirements_checked"});
    } else if (current === "requirements_checked") {
      const existing = await api("GET", "/api/install/configuration");
      if (existing.configuration) {
        applyConfiguration(existing.configuration);
      } else {
        setBar(25); logLine("credentials");
        await api("POST", "/api/install/credentials", {
          migrator_password: state.form.migrator_password,
          runtime_password: state.form.runtime_password,
          checkpoint_password: state.form.checkpoint_password
        });
        if (state.form.source === "use-detected") applyInventory(state.inventory);
        if (state.form.source === "create") {
          setBar(32); logLine("create-database");
          await api("POST", "/api/install/provision", {
            host: state.form.host,
            port: Number(state.form.port),
            database: state.form.database,
            username: state.form.username,
            runtime_username: state.form.runtime_username,
            checkpoint_username: state.form.checkpoint_username
          });
        }
        setBar(40); logLine("configuration");
        await api("PUT", "/api/install/configuration", configurationPayload());
      }
      await api("POST", "/api/install/transition", {target: "configured"});
    } else if (current === "configured") {
      setBar(55); logLine("database");
      await api("POST", "/api/install/transition", {target: "database_ready"});
    } else if (current === "database_ready") {
      if (!password) {
        state.step = 4;
        render();
        return;
      }
      setBar(75); logLine("administrator");
      await api("POST", "/api/install/admin", {email: state.form.email, password});
      await api("POST", "/api/install/transition", {target: "admin_ready"});
    } else if (current === "admin_ready") {
      setBar(88); logLine("theme");
      await api("POST", "/api/install/transition", {target: "theme_ready"});
    } else if (current === "theme_ready") {
      await api("POST", "/api/install/transition", {target: "completed"});
    } else if (current === "completed") {
      setBar(100); logLine("finalize");
      if (state.handoff && state.handoff.status === "ready") {
        state.step = 6;
        render();
        return;
      }
      const result = await api("POST", "/api/install/finalize");
      state.handoff = result.handoff || state.handoff;
      if (!state.handoff || state.handoff.status !== "ready") {
        throw new Error((state.handoff && state.handoff.detail) || t().handoffTitle);
      }
      state.step = 6;
      render();
      return;
    } else {
      throw new Error(t().fail);
    }
  }
  throw new Error(t().fail);
}
async function resumeFromServer() {
  const current = await currentInstallState();
  if (current === "completed" && state.handoff.status === "ready") {
    state.step = 6;
    render();
    return;
  }
  if (current !== "completed") {
    const req = await api("GET", "/api/install/requirements");
    state.requirements = req;
    applyInventory(req.inventory);
    const cfg = await api("GET", "/api/install/configuration");
    applyConfiguration(cfg.configuration);
  }
  state.step = STEP[current] ?? 0;
  if (current === "not_started") state.step = 1;
  if (current === "completed") state.step = 5;
  render();
  if (current === "configured" || current === "admin_ready" || current === "theme_ready" || current === "completed") {
    await continueInstall();
  }
}
$("lang").value = state.lang;
$("lang").addEventListener("change", (event) => { state.lang = event.target.value; document.documentElement.lang = state.lang; render(); });
if (state.token) {
  resumeFromServer().catch(() => render());
} else {
  render();
}

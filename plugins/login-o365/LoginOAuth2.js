((rl) => {
  const client_id = rl.pluginSettingsGet("login-o365", "client_id"),
    allowAnyDomain = !!rl.pluginSettingsGet("login-o365", "allow_any_domain"),
    isSupportedEmail = (email) => {
      email = (email || "").toLowerCase();
      if (!email.includes("@")) return false;
      if (allowAnyDomain) return true;
      return /@(outlook\.com|hotmail\.com|live\.com)$/.test(email);
    },
    startOAuth = (op, opts = {}) => {
      const email = (opts.email || "").toLowerCase();
      const name = opts.name || "";
      const returnHash = opts.return || "";

      // Server mints a signed state + correct redirect_uri and returns full authUrl.
      rl.pluginRemoteRequest((iError, data) => {
        const url = data?.Result?.authUrl;
        if (!iError && url) {
          document.location = url;
        }
      }, "LoginO365AuthUrl", {
        op: op,
        email: email,
        name: name,
        return: returnHash,
      });
    };

  // The callback cannot finish an add: it arrives cross-site, so SameSite=Strict
  // withholds the session cookie and there is no way to tell who is logged in.
  // It parks the tokens and names them in the fragment instead. Take the secret
  // out of the URL straight away, since the fragment is the one place it would
  // otherwise linger (browser history); it never travels in a request, so logs
  // and Referer headers were never exposed to it.
  const takeClaim = () => {
      const hash = location.hash,
        at = hash.indexOf("?");
      if (0 > at) return null;
      const params = new URLSearchParams(hash.slice(at + 1)),
        secret = params.get("o365claim");
      if (!secret) return null;
      params.delete("o365claim");
      const rest = params.toString();
      history.replaceState(null, "", location.pathname + location.search
        + hash.slice(0, at) + (rest ? "?" + rest : ""));
      return secret;
    },
    pending = takeClaim();

  if (pending) {
    sessionStorage.setItem("o365claim", pending);
  }

  // Only cleared once the server has actually taken it, so a claim attempted
  // before the session is usable can still be retried rather than lost.
  let claiming = false;
  const claimIfPending = () => {
    const secret = sessionStorage.getItem("o365claim");
    if (!secret || claiming) return;
    claiming = true;
    rl.pluginRemoteRequest((iError) => {
      claiming = false;
      if (!iError) {
        sessionStorage.removeItem("o365claim");
        rl.app?.loadAccountsAndIdentities?.();
      }
    }, "LoginO365Claim", { pickup: secret });
  };

  if (client_id) {
    addEventListener("sm-user-login", (e) => {
      const email = (e.detail.get("Email") || "").toLowerCase();
      if (isSupportedEmail(email)) {
        e.preventDefault();
        startOAuth("login", { email });
      }
    });

    addEventListener("rl-view-model", (e) => {
      // Any logged-in view will do, and the settings accounts view is not one of
      // them: it never reaches buildViewModel, so it raises no event here.
      if ("Login" !== e.detail.viewModelTemplateID) {
        claimIfPending();
      }

      if ("Login" === e.detail.viewModelTemplateID) {
        const
		  container = e.detail.viewModelDom.querySelector("#plugin-Login-BottomControlGroup"),
          btn = Element.fromHTML('<button type="button">Outlook</button>'),
          div = Element.fromHTML('<div class="controls"></div>');
        btn.onclick = () => {
          // Best-effort: try to read the email field if present.
          const input = e.detail.viewModelDom.querySelector('input[type="email"], input[name="Email"], input[name="email"], input');
          const email = (input?.value || "").toLowerCase();
          if (!email || isSupportedEmail(email)) {
            startOAuth("login", { email });
          }
        };
        div.append(btn);
        container && container.append(div);
      }

      // "Add account" popup (Settings → Accounts → Add account)
      if ("PopupsAccount" === e.detail.viewModelTemplateID) {
        // Only for the "Add account" mode, not "Edit account".
        if (typeof e.detail.isNew === "function" && !e.detail.isNew()) {
          return;
        }
        const root = e.detail.viewModelDom;
        if (!root) return;

        const footer = root.querySelector("footer");
        const form = root.querySelector("#accountform");
        const addButton = root.querySelector("button.buttonAddAccount");
        if (!footer || !form || !addButton) return;

        // Avoid inserting duplicates when view model is re-rendered.
        if (root.querySelector(".plugin-o365-add-account")) return;

        const btn = Element.fromHTML(
          '<button type="button" class="btn plugin-o365-add-account" style="margin-left: 6px;">Outlook</button>'
        );

        btn.onclick = () => {
          const email = (form.querySelector('input[name="email"]')?.value || "").trim().toLowerCase();
          const name = (form.querySelector('input[name="name"]')?.value || "").trim();
          if (!email || !isSupportedEmail(email)) {
            return;
          }
          startOAuth("add", { email, name, return: document.location.hash || "#/settings/accounts" });
        };

        // Put the button next to the default Add Account submit button.
        footer.insertBefore(btn, addButton.nextSibling);
      }
    });
  }
})(window.rl);

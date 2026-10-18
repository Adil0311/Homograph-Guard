(() => {
  "use strict";
  const $ = id => document.getElementById(id);

  function render(result) {
    const labels = {
      low: ["Low", "No strong homograph indicators detected."],
      medium: ["Moderate", "Indicators present that warrant manual verification."],
      high: ["High", "Domain exhibits multiple suspicious indicators."],
      critical: ["Critical", "Domain exhibits strong signs of homograph impersonation."]
    };
    const [title, summary] = labels[result.level] || ["Unknown", ""];
    $("status").className = "status " + result.level;
    $("statusTitle").textContent = `${title} Risk`;
    $("statusSummary").textContent = summary;
    $("domain").textContent = result.hostname;
    $("asciiDomain").textContent = result.asciiHost !== result.hostname
      ? "ASCII/IDNA form: " + result.asciiHost : "ASCII/IDNA form: identical to domain";
    $("score").textContent = `${result.score}/100`;
    $("meterFill").style.width = `${result.score}%`;
    $("meterFill").style.background = result.level === "critical" || result.level === "high"
      ? "#b42318" : result.level === "medium" ? "#d99a00" : "#18794e";

    const list = $("findings");
    list.replaceChildren();
    for (const finding of result.findings) {
      const li = document.createElement("li");
      li.textContent = finding;
      list.appendChild(li);
    }

    const chars = $("characters");
    chars.replaceChildren();
    if (!result.chars.length) {
      chars.textContent = "None (standard pure ASCII domain)";
    } else {
      for (const item of result.chars) {
        const chip = document.createElement("span");
        chip.className = "char-chip";
        if (item.imitates) {
          chip.title = `Character: ${item.char} (${item.script}) | Codepoint: ${item.codePoint} | Imitates Latin letter: '${item.imitates}'`;
          chip.textContent = `${item.char} (${item.script}) → '${item.imitates}'`;
        } else {
          chip.title = `Character: ${item.char} | Script: ${item.script} | Codepoint: ${item.codePoint}`;
          chip.textContent = `${item.char} · ${item.codePoint} (${item.script})`;
        }
        chars.appendChild(chip);
      }
    }
  }

  async function scan() {
    $("error").hidden = true;
    try {
      const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      const tab = tabs[0];
      if (!tab || !tab.url) throw new Error("Unable to read active tab URL.");
      const url = new URL(tab.url);
      if (!["http:", "https:"].includes(url.protocol)) {
        throw new Error("This browser page cannot be analyzed. Open an HTTP or HTTPS website.");
      }
      render(HomographDetector.analyze(tab.url));
    } catch (err) {
      $("status").className = "status neutral";
      $("statusTitle").textContent = "Analysis Unavailable";
      $("statusSummary").textContent = "Browser restricts extension access on internal or protected pages.";
      $("error").textContent = err.message || String(err);
      $("error").hidden = false;
      $("domain").textContent = "—";
      $("asciiDomain").textContent = "";
      $("score").textContent = "—";
      $("meterFill").style.width = "0";
      $("findings").replaceChildren();
      $("characters").textContent = "—";
    }
  }

  $("rescan").addEventListener("click", scan);
  scan();
})();
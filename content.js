/* Homograph Guard - Content Script for Proactive Link Inspection
 * Detects deceptive IDN links on hover and displays an alert tooltip
 * before the user clicks. 100% client-side, zero network overhead.
 */
(() => {
  "use strict";

  // Cache to store analysis results and avoid redundant parsing
  const cache = new Map();
  let tooltip = null;
  let currentTargetLink = null;

  /**
   * Creates or returns the singleton tooltip element
   */
  function getTooltip() {
    if (tooltip && document.body.contains(tooltip)) {
      return tooltip;
    }

    tooltip = document.createElement("div");
    tooltip.className = "hg-tooltip";
    document.body.appendChild(tooltip);
    return tooltip;
  }

  /**
   * Positions the tooltip above or below the target anchor element
   */
  function positionTooltip(el, anchorRect) {
    const margin = 8;
    const scrollX = window.scrollX || window.pageXOffset;
    const scrollY = window.scrollY || window.pageYOffset;

    const elWidth = el.offsetWidth;
    const elHeight = el.offsetHeight;

    // Prefer placing tooltip above the link; if not enough space, place below
    let top = anchorRect.top + scrollY - elHeight - margin;
    if (anchorRect.top - elHeight - margin < 0) {
      top = anchorRect.bottom + scrollY + margin;
    }

    // Align horizontally with the start of the link, clamped to viewport bounds
    let left = anchorRect.left + scrollX;
    const maxLeft = scrollX + window.innerWidth - elWidth - margin;
    if (left > maxLeft) {
      left = Math.max(scrollX + margin, maxLeft);
    }
    if (left < scrollX + margin) {
      left = scrollX + margin;
    }

    el.style.top = `${Math.round(top)}px`;
    el.style.left = `${Math.round(left)}px`;
  }

  /**
   * Hides the active tooltip
   */
  function hideTooltip() {
    if (tooltip) {
      tooltip.classList.remove("hg-visible");
    }
    currentTargetLink = null;
  }

  /**
   * Displays the security warning tooltip for a suspicious link
   */
  function showWarning(anchor, result) {
    const tip = getTooltip();
    tip.replaceChildren();

    // 1. Header
    const header = document.createElement("div");
    header.className = "hg-tooltip-header";

    const badge = document.createElement("span");
    badge.className = "hg-tooltip-badge";
    badge.textContent = result.level === "critical" ? "Critical Risk" : "High Risk";

    const title = document.createElement("span");
    title.className = "hg-tooltip-title";
    title.textContent = "Homograph Link Detected";

    header.appendChild(badge);
    header.appendChild(title);
    tip.appendChild(header);

    // 2. Target Domain Name
    const domain = document.createElement("div");
    domain.className = "hg-tooltip-domain";
    domain.textContent = result.hostname;
    tip.appendChild(domain);

    // 3. Primary Finding
    const finding = document.createElement("div");
    finding.className = "hg-tooltip-findings";
    const primaryFinding = result.findings.find(f => /mixed-script|deceptive|Punycode/i.test(f)) || result.findings[0];
    finding.textContent = primaryFinding || "Deceptive characters detected in link destination.";
    tip.appendChild(finding);

    // 4. Character Chips (Unmasked Lookalikes)
    if (result.chars && result.chars.length > 0) {
      const chipsContainer = document.createElement("div");
      chipsContainer.className = "hg-tooltip-chips";

      for (const item of result.chars.slice(0, 4)) {
        const chip = document.createElement("span");
        chip.className = "hg-tooltip-chip";
        chip.textContent = item.imitates
          ? `${item.char} (${item.script}) → '${item.imitates}'`
          : `${item.char} (${item.script})`;
        chipsContainer.appendChild(chip);
      }
      tip.appendChild(chipsContainer);
    }

    // 5. Footer Watermark
    const footer = document.createElement("div");
    footer.className = "hg-tooltip-footer";
    const brand = document.createElement("span");
    brand.textContent = "🛡️ Homograph Guard";
    const hint = document.createElement("span");
    hint.textContent = "Click with caution";
    footer.appendChild(brand);
    footer.appendChild(hint);
    tip.appendChild(footer);

    // Position and reveal
    const rect = anchor.getBoundingClientRect();
    positionTooltip(tip, rect);
    tip.classList.add("hg-visible");
    currentTargetLink = anchor;
  }

  /**
   * Event listener for mouseover: inspect links on hover
   */
  document.addEventListener("mouseover", (event) => {
    const anchor = event.target.closest("a[href]");
    if (!anchor) return;

    const href = anchor.href;
    if (!href || (!href.startsWith("http://") && !href.startsWith("https://"))) {
      return;
    }

    // Check memory cache first
    let result = cache.get(href);
    if (!result) {
      try {
        result = HomographDetector.analyze(href);
        cache.set(href, result);
      } catch (_) {
        return;
      }
    }

    // Only alert on High or Critical homograph attacks
    if (result && (result.level === "critical" || result.level === "high")) {
      showWarning(anchor, result);
    }
  }, { passive: true });

  /**
   * Event listener for mouseout: dismiss tooltip when leaving anchor
   */
  document.addEventListener("mouseout", (event) => {
    const anchor = event.target.closest("a[href]");
    if (anchor && anchor === currentTargetLink) {
      // Check if mouse moved into another element inside the same anchor
      const related = event.relatedTarget;
      if (related && anchor.contains(related)) {
        return;
      }
      hideTooltip();
    }
  }, { passive: true });

  /**
   * Hide tooltip on window scroll
   */
  window.addEventListener("scroll", hideTooltip, { passive: true });
})();

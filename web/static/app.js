(() => {
  "use strict";

  async function copyText(text) {
    if (!navigator.clipboard || !window.isSecureContext) {
      throw new Error("clipboard unavailable");
    }
    await navigator.clipboard.writeText(text);
  }

  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy-target]");
    if (!button) return;
    const target = document.getElementById(button.dataset.copyTarget);
    const status = document.getElementById(button.dataset.copyStatus || "copy-status");
    if (!target) return;
    try {
      await copyText(target.textContent.trim());
      if (status) status.textContent = button.dataset.copySuccess || "클립보드에 복사했습니다.";
    } catch (_) {
      if (status) status.textContent = "자동 복사에 실패했습니다. 내용을 직접 선택해 복사하세요.";
      target.focus();
    }
  });
})();

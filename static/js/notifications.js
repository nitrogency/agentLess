document.addEventListener('DOMContentLoaded', () => {
  const bell = document.getElementById('notification-bell');
  const indicator = document.getElementById('notification-indicator');
  const dropdown = document.getElementById('notification-dropdown');
  const recentEl = document.getElementById('notification-recent');
  const countHigh = document.getElementById('notif-count-high');
  const countMedium = document.getElementById('notif-count-medium');
  const countLow = document.getElementById('notif-count-low');
  const markAllBtn = document.getElementById('mark-all-seen');

  if (!bell || !dropdown) return;

  const fetchSummary = async () => {
    try {
      const res = await fetch('/notifications/summary', { credentials: 'same-origin' });
      if (!res.ok) return;
      const data = await res.json();
      const unseen = data.unseen || 0;
      const byLevel = data.byLevel || {};
      if (indicator) {
        indicator.classList.toggle('active', unseen > 0);
      }
      if (countHigh) countHigh.textContent = byLevel.high ?? 0;
      if (countMedium) countMedium.textContent = byLevel.medium ?? 0;
      if (countLow) countLow.textContent = byLevel.low ?? 0;

      // Flicker logic: check user prefs on bell data attributes
      const prefHigh = (bell.getAttribute('data-flicker-high') === 'true');
      const prefMedium = (bell.getAttribute('data-flicker-medium') === 'true');
      const prefLow = (bell.getAttribute('data-flicker-low') === 'true');
      const shouldFlicker = (
        (prefHigh && (byLevel.high || 0) > 0) ||
        (prefMedium && (byLevel.medium || 0) > 0) ||
        (prefLow && (byLevel.low || 0) > 0)
      );
      bell.classList.toggle('flicker', shouldFlicker);

      if (recentEl && Array.isArray(data.recent)) {
        if (data.recent.length === 0) {
          recentEl.innerHTML = '<div class="empty">No new notifications</div>';
        } else {
          recentEl.innerHTML = '';
          data.recent.forEach((n) => {
            const item = document.createElement('div');
            item.className = 'notification-item';
            const title = n.title || (n.security_level ? (n.security_level + ' event') : 'Notification');
            const level = (n.security_level || '').toString().toLowerCase();
            item.innerHTML = `
              <div class="item-title ${level}">${escapeHtml(title)}</div>
              <div class="item-message">${escapeHtml(n.message || '')}</div>
            `;
            item.addEventListener('click', () => {
              if (level === 'high' || level === 'medium' || level === 'low') {
                window.location.href = `/logs?security_level=${encodeURIComponent(level)}`;
              } else {
                window.location.href = '/logs';
              }
            });
            recentEl.appendChild(item);
          });
        }
      }
    } catch (_) {
      // ignore fetch errors silently
    }
  };

  const toggleDropdown = () => {
    const isHidden = dropdown.classList.contains('hidden');
    dropdown.classList.toggle('hidden');
    bell.setAttribute('aria-expanded', String(isHidden));
  };

  // Clicking bell toggles dropdown and marks seen
  bell.addEventListener('click', async (e) => {
    e.stopPropagation();
    toggleDropdown();
    try {
      await fetch('/notifications/mark-seen', { method: 'POST', credentials: 'same-origin' });
      // immediately update indicator and re-pull summary (counts will drop to 0 unseen)
      if (indicator) indicator.classList.remove('active');
      bell.classList.remove('flicker');
      fetchSummary();
    } catch (_) {}
  });

  // Clicking outside closes dropdown
  document.addEventListener('click', (e) => {
    if (!dropdown.classList.contains('hidden')) {
      if (!bell.contains(e.target)) {
        dropdown.classList.add('hidden');
        bell.setAttribute('aria-expanded', 'false');
      }
    }
  });

  // Category clicks -> navigate to logs with filter
  dropdown.addEventListener('click', (e) => {
    const target = e.target.closest('.notification-category');
    if (target) {
      const level = target.getAttribute('data-level');
      if (level) {
        window.location.href = `/logs?security_level=${encodeURIComponent(level)}`;
      }
    }
  });

  if (markAllBtn) {
    markAllBtn.addEventListener('click', async () => {
      try {
        await fetch('/notifications/mark-seen', { method: 'POST', credentials: 'same-origin' });
        if (indicator) indicator.classList.remove('active');
        bell.classList.remove('flicker');
        fetchSummary();
      } catch (_) {}
    });
  }

  // Poll periodically
  fetchSummary();
  setInterval(fetchSummary, 15000);
});

function escapeHtml(str) {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

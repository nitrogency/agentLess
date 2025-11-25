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

  // Get CSRF token from meta tag
  const getCSRFToken = () => {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  };
  
  // Update CSRF token in meta tag (after token rotation)
  const updateCSRFToken = (newToken) => {
    if (newToken) {
      const meta = document.querySelector('meta[name="csrf-token"]');
      if (meta) {
        meta.setAttribute('content', newToken);
      }
    }
  };

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
              <button class="notification-close" aria-label="Remove notification">&times;</button>
            `;
            // Handle main notification click (navigation)
            item.addEventListener('click', (e) => {
              // Don't navigate if clicking the close button or anything inside it
              if (e.target.closest('.notification-close')) {
                return;
              }
              
              // Navigate to logs page with appropriate filter
              let url = '/logs?';
              
              // If notification has a search term (from custom rule), use that
              if (n.search_term && n.search_term.trim() !== '') {
                url += `search=${encodeURIComponent(n.search_term)}`;
              } 
              // Otherwise, filter by security level
              else if (level === 'high' || level === 'medium' || level === 'low') {
                url += `security_level=${encodeURIComponent(level)}`;
              }
              
              window.location.href = url;
            });
            
            // Handle close button click
            const closeBtn = item.querySelector('.notification-close');
            closeBtn.addEventListener('click', async (e) => {
              e.stopPropagation(); // Prevent navigation
              
              // Immediately hide the notification with animation
              item.style.transition = 'all 0.2s ease-out';
              item.style.opacity = '0';
              item.style.maxHeight = item.offsetHeight + 'px';
              item.style.transform = 'translateX(100%)';
              
              // Remove from DOM after animation
              setTimeout(() => {
                item.remove();
                // Check if this was the last notification
                if (recentEl.children.length === 0) {
                  recentEl.innerHTML = '<div class="empty">No recent notifications</div>';
                }
              }, 200);
              
              // Update backend and refresh counts
              try {
                const response = await fetch(`/notifications/${n.id}/mark-seen`, { 
                  method: 'POST', 
                  credentials: 'same-origin',
                  headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': getCSRFToken()
                  }
                });
                if (!response.ok) {
                  console.error('Failed to mark notification as seen:', response.status);
                  // Could show user feedback here if needed
                } else {
                  // Update CSRF token from response header (token rotation)
                  const newToken = response.headers.get('X-CSRF-Token');
                  updateCSRFToken(newToken);
                }
                fetchSummary(); // Refresh notification counts only
              } catch (error) {
                console.error('Error marking notification as seen:', error);
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

  // Clicking bell toggles dropdown (without marking as seen)
  bell.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleDropdown();
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
      // Get all notification items
      const notificationItems = recentEl.querySelectorAll('.notification-item');
      
      if (notificationItems.length > 0) {
        // Animate all notifications out with staggered timing
        notificationItems.forEach((item, index) => {
          setTimeout(() => {
            item.style.transition = 'all 0.2s ease-out';
            item.style.opacity = '0';
            item.style.transform = 'translateX(100%)';
          }, index * 50); // Stagger by 50ms each
        });
        
        // Remove all items after animation and show empty state
        setTimeout(() => {
          recentEl.innerHTML = '<div class="empty">No recent notifications</div>';
        }, notificationItems.length * 50 + 200);
      }
      
      // Immediately update visual indicators
      if (indicator) indicator.classList.remove('active');
      bell.classList.remove('flicker');
      
      // Update backend in background
      try {
        const response = await fetch('/notifications/mark-seen', { 
          method: 'POST', 
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCSRFToken()
          }
        });
        if (!response.ok) {
          console.error('Failed to mark all notifications as seen:', response.status);
        } else {
          // Update CSRF token from response header (token rotation)
          const newToken = response.headers.get('X-CSRF-Token');
          updateCSRFToken(newToken);
        }
        fetchSummary(); // Refresh counts
      } catch (error) {
        console.error('Error marking all notifications as seen:', error);
      }
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

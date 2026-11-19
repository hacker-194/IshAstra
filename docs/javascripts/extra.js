// Strix Documentation - Custom JavaScript

// ============================================
// Version Badge Injection
// ============================================
(function() {
  'use strict';

  // Inject version badge into nav
  function injectVersionBadge() {
    const version = document.querySelector('[data-md-version]')?.dataset.mdVersion || '3.5.0';
    const navTitle = document.querySelector('.md-header__title');
    if (navTitle && !navTitle.querySelector('.strix-version-badge')) {
      const badge = document.createElement('span');
      badge.className = 'strix-version-badge';
      badge.textContent = version;
      navTitle.appendChild(badge);
    }
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectVersionBadge);
  } else {
    injectVersionBadge();
  }
})();

// ============================================
// Copy Code Button Enhancement
// ============================================
(function() {
  'use strict';

  function enhanceCopyButtons() {
    const copyButtons = document.querySelectorAll('.md-clipboard');

    copyButtons.forEach(button => {
      button.addEventListener('click', function() {
        const originalText = this.innerHTML;
        this.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/></svg> Copied!';
        this.style.color = '#00cc88';

        setTimeout(() => {
          this.innerHTML = originalText;
          this.style.color = '';
        }, 2000);
      });
    });
  }

  // Observe for dynamically added code blocks
  const observer = new MutationObserver(enhanceCopyButtons);
  observer.observe(document.body, { childList: true, subtree: true });

  // Initial run
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', enhanceCopyButtons);
  } else {
    enhanceCopyButtons();
  }
})();

// ============================================
// API Endpoint Hover Tooltips
// ============================================
(function() {
  'use strict';

  function addApiTooltips() {
    const endpoints = document.querySelectorAll('.strix-api-endpoint');

    endpoints.forEach(endpoint => {
      const method = endpoint.querySelector('.strix-api-method');
      if (method) {
        const methodText = method.textContent.toLowerCase();
        const descriptions = {
          'get': 'Retrieve resource',
          'post': 'Create resource',
          'put': 'Replace resource',
          'patch': 'Update resource',
          'delete': 'Delete resource'
        };

        endpoint.title = descriptions[methodText] || 'API endpoint';
        endpoint.style.cursor = 'help';
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', addApiTooltips);
  } else {
    addApiTooltips();
  }
})();

// ============================================
// Smooth Scroll for Anchor Links
// ============================================
(function() {
  'use strict';

  function smoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', function(e) {
        const targetId = this.getAttribute('href');
        if (targetId === '#') return;

        const target = document.querySelector(targetId);
        if (target) {
          e.preventDefault();
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });

          // Update URL without scrolling
          history.pushState(null, null, targetId);

          // Focus for accessibility
          target.focus({ preventScroll: true });
        }
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', smoothScroll);
  } else {
    smoothScroll();
  }
})();

// ============================================
// Table of Contents Active State
// ============================================
(function() {
  'use strict';

  function updateTocActive() {
    const tocLinks = document.querySelectorAll('.md-nav__link--active');
    const headings = document.querySelectorAll('.md-content h2, .md-content h3');

    if (!headings.length) return;

    let currentHeading = null;
    const scrollPos = window.scrollY + 100;

    headings.forEach(heading => {
      if (heading.offsetTop <= scrollPos) {
        currentHeading = heading;
      }
    });

    if (currentHeading) {
      const id = currentHeading.id;
      tocLinks.forEach(link => {
        link.classList.remove('md-nav__link--active');
        if (link.getAttribute('href') === '#' + id) {
          link.classList.add('md-nav__link--active');
        }
      });
    }
  }

  // Throttle scroll handler
  let ticking = false;
  window.addEventListener('scroll', () => {
    if (!ticking) {
      window.requestAnimationFrame(() => {
        updateTocActive();
        ticking = false;
      });
      ticking = true;
    }
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', updateTocActive);
  } else {
    updateTocActive();
  }
})();

// ============================================
// Keyboard Navigation Enhancement
// ============================================
(function() {
  'use strict';

  function enhanceKeyboardNav() {
    // Escape key closes search
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const searchInput = document.querySelector('.md-search__input');
        if (searchInput && document.activeElement === searchInput) {
          searchInput.blur();
        }

        // Close any open dropdowns
        document.querySelectorAll('[data-md-toggle]:checked').forEach(checkbox => {
          checkbox.checked = false;
        });
      }
    });

    // Alt+Left/Right for previous/next page
    document.addEventListener('keydown', (e) => {
      if (e.altKey && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) {
        const navLink = document.querySelector(
          e.key === 'ArrowLeft'
            ? '.md-footer__link--prev'
            : '.md-footer__link--next'
        );
        if (navLink) {
          e.preventDefault();
          navLink.click();
        }
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', enhanceKeyboardNav);
  } else {
    enhanceKeyboardNav();
  }
})();

// ============================================
// Dark/Light Mode Sync
// ============================================
(function() {
  'use strict';

  function syncTheme() {
    const themeToggle = document.querySelector('[data-md-color-scheme]');
    if (!themeToggle) return;

    // Listen for system theme changes
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

    mediaQuery.addEventListener('change', (e) => {
      // Only auto-switch if user hasn't explicitly set a preference
      const userPreference = localStorage.getItem('md-color-scheme');
      if (!userPreference) {
        // Theme will be handled by Material theme's built-in logic
      }
    });

    // Store user preference
    const observer = new MutationObserver((mutations) => {
      mutations.forEach(mutation => {
        if (mutation.attributeName === 'data-md-color-scheme') {
          const scheme = document.body.getAttribute('data-md-color-scheme');
          localStorage.setItem('md-color-scheme', scheme);
        }
      });
    });

    observer.observe(document.body, { attributes: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', syncTheme);
  } else {
    syncTheme();
  }
})();

// ============================================
// Search Analytics (Privacy-Friendly)
// ============================================
(function() {
  'use strict';

  function trackSearch() {
    const searchInput = document.querySelector('.md-search__input');
    if (!searchInput) return;

    let searchTimeout;
    searchInput.addEventListener('input', () => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        const query = searchInput.value.trim();
        if (query.length >= 3) {
          // Fire custom event for analytics (if enabled)
          document.dispatchEvent(new CustomEvent('strix:search', {
            detail: { query, timestamp: Date.now() }
          }));
        }
      }, 300);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', trackSearch);
  } else {
    trackSearch();
  }
})();

// ============================================
// Mermaid Diagram Zoom
// ============================================
(function() {
  'use strict';

  function addMermaidZoom() {
    const mermaidContainers = document.querySelectorAll('.mermaid');

    mermaidContainers.forEach(container => {
      // Add click-to-zoom
      container.style.cursor = 'zoom-in';
      container.addEventListener('click', function() {
        this.classList.toggle('mermaid--zoomed');
        this.style.cursor = this.classList.contains('mermaid--zoomed') ? 'zoom-out' : 'zoom-in';
      });
    });

    // Add styles for zoom
    if (!document.getElementById('mermaid-zoom-styles')) {
      const style = document.createElement('style');
      style.id = 'mermaid-zoom-styles';
      style.textContent = `
        .mermaid {
          transition: transform 0.2s ease, cursor 0.2s ease;
          transform-origin: center center;
        }
        .mermaid.mermaid--zoomed {
          transform: scale(1.5);
          cursor: zoom-out;
          z-index: 1000;
          position: relative;
        }
        @media (max-width: 48em) {
          .mermaid.mermaid--zoomed {
            transform: scale(1.2);
          }
        }
      `;
      document.head.appendChild(style);
    }
  }

  // Run after Mermaid renders
  if (window.mermaid) {
    mermaid.init(undefined, document.querySelectorAll('.mermaid'));
  }

  const observer = new MutationObserver((mutations) => {
    mutations.forEach(mutation => {
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === 1 && node.classList?.contains('mermaid')) {
          addMermaidZoom();
        }
      });
    });
  });

  observer.observe(document.body, { childList: true, subtree: true });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', addMermaidZoom);
  } else {
    addMermaidZoom();
  }
})();

// ============================================
// Reading Progress Indicator
// ============================================
(function() {
  'use strict';

  function addReadingProgress() {
    // Create progress bar
    const progressBar = document.createElement('div');
    progressBar.id = 'strix-reading-progress';
    progressBar.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      height: 3px;
      background: linear-gradient(90deg, #0066cc, #00cc88);
      z-index: 9999;
      transform-origin: left;
      transform: scaleX(0);
      transition: transform 0.1s linear;
      pointer-events: none;
    `;
    document.body.appendChild(progressBar);

    // Update on scroll
    let ticking = false;
    window.addEventListener('scroll', () => {
      if (!ticking) {
        window.requestAnimationFrame(() => {
          const scrollTop = window.scrollY;
          const docHeight = document.documentElement.scrollHeight - window.innerHeight;
          const progress = docHeight > 0 ? scrollTop / docHeight : 0;
          progressBar.style.transform = `scaleX(${Math.min(progress, 1)})`;
          ticking = false;
        });
        ticking = true;
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', addReadingProgress);
  } else {
    addReadingProgress();
  }
})();

// ============================================
// External Link Indicators
// ============================================
(function() {
  'use strict';

  function markExternalLinks() {
    const links = document.querySelectorAll('.md-content a[href^="http"]');

    links.forEach(link => {
      const hostname = new URL(link.href).hostname;
      const currentHost = window.location.hostname;

      if (hostname !== currentHost && !link.querySelector('.strix-external-icon')) {
        const icon = document.createElement('span');
        icon.className = 'strix-external-icon';
        icon.innerHTML = ' <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="12" height="12"><path fill="currentColor" d="M14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7zM14 19H5v-2h9v2zm0-4H5v-2h9v2zm0-4H5V9h9v2z"/></svg>';
        icon.style.opacity = '0.6';
        icon.style.marginLeft = '0.25rem';
        icon.style.verticalAlign = 'middle';
        link.appendChild(icon);
        link.setAttribute('rel', 'noopener noreferrer');
        link.setAttribute('target', '_blank');
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', markExternalLinks);
  } else {
    markExternalLinks();
  }
})();

// ============================================
// Performance Monitoring
// ============================================
(function() {
  'use strict';

  // Report page load performance
  window.addEventListener('load', () => {
    setTimeout(() => {
      const perfData = {
        loadTime: performance.timing.loadEventEnd - performance.timing.navigationStart,
        domReady: performance.timing.domContentLoadedEventEnd - performance.timing.navigationStart,
        firstPaint: performance.getEntriesByType('paint').find(e => e.name === 'first-paint')?.startTime,
        firstContentfulPaint: performance.getEntriesByType('paint').find(e => e.name === 'first-contentful-paint')?.startTime,
      };

      // Fire custom event for analytics
      document.dispatchEvent(new CustomEvent('strix:performance', {
        detail: perfData
      }));
    }, 0);
  });
})();

console.log('📚 Strix Documentation loaded - v3.5.0');
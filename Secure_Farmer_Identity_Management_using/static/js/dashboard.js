// dashboard.js — animated count-up for stat cards
document.addEventListener('DOMContentLoaded', function () {
  const counters = document.querySelectorAll('[data-count-to]');
  counters.forEach(function (el) {
    const target = parseFloat(el.getAttribute('data-count-to'));
    if (isNaN(target)) return;
    const duration = 900;
    const start = performance.now();
    const isDecimal = target % 1 !== 0;

    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const value = target * eased;
      el.textContent = isDecimal ? value.toFixed(1) : Math.round(value).toLocaleString('en-IN');
      if (progress < 1) requestAnimationFrame(tick);
      else el.textContent = isDecimal ? target.toFixed(1) : target.toLocaleString('en-IN');
    }
    requestAnimationFrame(tick);
  });
});

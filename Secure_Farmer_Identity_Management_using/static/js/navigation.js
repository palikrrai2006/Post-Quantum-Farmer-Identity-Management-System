// navigation.js — sidebar open/close for mobile, active link highlight
document.addEventListener('DOMContentLoaded', function () {
  const sidebar = document.getElementById('appSidebar');
  const toggleBtns = document.querySelectorAll('.sidebar-toggle-btn');
  const backdrop = document.getElementById('sidebarBackdrop');

  function openSidebar() {
    if (!sidebar) return;
    sidebar.classList.add('open');
    if (backdrop) backdrop.classList.add('show');
  }
  function closeSidebar() {
    if (!sidebar) return;
    sidebar.classList.remove('open');
    if (backdrop) backdrop.classList.remove('show');
  }

  toggleBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      if (sidebar && sidebar.classList.contains('open')) {
        closeSidebar();
      } else {
        openSidebar();
      }
    });
  });

  if (backdrop) backdrop.addEventListener('click', closeSidebar);

  // Close sidebar automatically when a link is tapped (mobile)
  document.querySelectorAll('.app-sidebar .nav-link').forEach(function (link) {
    link.addEventListener('click', function () {
      if (window.innerWidth < 992) closeSidebar();
    });
  });

  // Auto-dismiss flash messages after a few seconds
  document.querySelectorAll('.auto-dismiss').forEach(function (el) {
    setTimeout(function () {
      el.classList.add('fade-out-msg');
      setTimeout(function () { el.remove(); }, 400);
    }, 5000);
  });
});

// animations.js — scroll reveal for .reveal elements, staggered chain activation
document.addEventListener('DOMContentLoaded', function () {
  const revealEls = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window && revealEls.length) {
    const io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('in-view');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15 });
    revealEls.forEach(function (el) { io.observe(el); });
  } else {
    revealEls.forEach(function (el) { el.classList.add('in-view'); });
  }

  // Homepage trust-chain: light up nodes in sequence once visible
  const chain = document.querySelector('.trust-chain[data-auto-animate="true"]');
  if (chain) {
    const nodes = chain.querySelectorAll('.chain-node');
    const chainIO = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        nodes.forEach(function (node, i) {
          setTimeout(function () { node.classList.add('done'); }, i * 160);
        });
        chainIO.disconnect();
      });
    }, { threshold: 0.2 });
    chainIO.observe(chain);
  }
});

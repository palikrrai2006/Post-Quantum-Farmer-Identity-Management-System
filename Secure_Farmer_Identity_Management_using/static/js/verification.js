// verification.js — UI-only behaviour for the government verification screen.
// The actual verification (blockchain lookup, IPFS, SHA3, ML-DSA, ML-KEM,
// AES-256-GCM, SourceAFIS matching) happens server-side in the existing
// POST /government/verify/<farmer_id> route. This script only presents that
// wait with the trust-chain animation; the true/false result rendered below
// always comes from the server response, never from this script.
document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('verifyForm');
  const fileInput = document.getElementById('verifyImageInput');
  const dropZone = document.getElementById('verifyDropZone');
  const previewBox = document.getElementById('verifyPreview');
  const previewImg = document.getElementById('verifyPreviewImg');
  const overlay = document.getElementById('verifyOverlay');
  const submitBtn = document.getElementById('verifySubmitBtn');

  function showPreview(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function (e) {
      if (previewImg) previewImg.src = e.target.result;
      if (previewBox) previewBox.classList.remove('d-none');
      if (dropZone) dropZone.classList.add('d-none');
      if (submitBtn) submitBtn.disabled = false;
    };
    reader.readAsDataURL(file);
  }

  if (fileInput) {
    fileInput.addEventListener('change', function () {
      if (fileInput.files && fileInput.files[0]) showPreview(fileInput.files[0]);
    });
  }

  if (dropZone) {
    ['dragenter', 'dragover'].forEach(function (evt) {
      dropZone.addEventListener(evt, function (e) { e.preventDefault(); dropZone.classList.add('dragging'); });
    });
    ['dragleave', 'drop'].forEach(function (evt) {
      dropZone.addEventListener(evt, function (e) { e.preventDefault(); dropZone.classList.remove('dragging'); });
    });
    dropZone.addEventListener('drop', function (e) {
      const file = e.dataTransfer.files[0];
      if (file && fileInput) {
        fileInput.files = e.dataTransfer.files;
        showPreview(file);
      }
    });
  }

  if (form) {
    form.addEventListener('submit', function () {
      if (overlay) {
        overlay.classList.remove('d-none');
        const nodes = overlay.querySelectorAll('.chain-node');
        nodes.forEach(function (node, i) {
          setTimeout(function () { node.classList.add('done'); }, i * 240);
        });
      }
    });
  }

  // If the page loaded with a result already present, scroll to it.
  const resultBanner = document.querySelector('.result-banner');
  if (resultBanner) {
    resultBanner.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
});

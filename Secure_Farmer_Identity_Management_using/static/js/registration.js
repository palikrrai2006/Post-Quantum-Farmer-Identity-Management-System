// registration.js — UI-only behaviour for the fingerprint enrollment page.
// The real work (SourceAFIS / AES / ML-KEM / ML-DSA / SHA3 / IPFS / chain) is
// performed server-side by the existing POST /center/enroll/<farmer_id> route.
// This file only makes the wait feel guided; it never fabricates a result.
document.addEventListener('DOMContentLoaded', function () {
  const fingerRadios = document.querySelectorAll('input[name="finger_position"]');
  const fileInput = document.getElementById('fingerprintImageInput');
  const previewBox = document.getElementById('fingerprintPreview');
  const previewImg = document.getElementById('fingerprintPreviewImg');
  const dropZone = document.getElementById('fingerprintDropZone');
  const enrollForm = document.getElementById('enrollFingerprintForm');
  const overlay = document.getElementById('processingOverlay');
  const nextStepBtn = document.getElementById('goToCaptureStep');
  const backStepBtn = document.getElementById('backToFingerStep');
  const step1 = document.getElementById('stepPanelFinger');
  const step2 = document.getElementById('stepPanelCapture');
  const stepItems = document.querySelectorAll('.stepper-bar .step-item');

  function markStep(activeIndex) {
    stepItems.forEach(function (item, i) {
      item.classList.remove('active', 'completed');
      if (i < activeIndex) item.classList.add('completed');
      if (i === activeIndex) item.classList.add('active');
    });
  }

  fingerRadios.forEach(function (radio) {
    radio.addEventListener('change', function () {
      document.querySelectorAll('.finger-pick').forEach(function (el) { el.classList.remove('picked'); });
      if (radio.checked) {
        const label = document.querySelector('label[for="' + radio.id + '"]');
        if (label) label.closest('.finger-pick').classList.add('picked');
        if (nextStepBtn) nextStepBtn.disabled = false;
      }
    });
  });

  // ── KEY FIX: if every finger radio is disabled, all fingers are enrolled.
  // Convert the Continue button into a direct link to the summary page.
  var allDisabled = fingerRadios.length > 0 && Array.from(fingerRadios).every(function (r) { return r.disabled; });
  if (allDisabled && nextStepBtn) {
    nextStepBtn.disabled = false;
    nextStepBtn.textContent = '';
    nextStepBtn.innerHTML = 'Complete Registration <i class="bi bi-check-lg ms-1"></i>';
    // Derive summary URL: replace "/enroll/" with "/registration/" in current path
    var summaryUrl = window.location.pathname.replace('/enroll/', '/registration/');
    nextStepBtn.addEventListener('click', function () {
      window.location.href = summaryUrl;
    });
  }

  if (!allDisabled && nextStepBtn) {
    nextStepBtn.addEventListener('click', function () {
      if (step1 && step2) {
        step1.classList.remove('active');
        step2.classList.add('active');
        markStep(1);
      }
    });
  }

  if (backStepBtn) {
    backStepBtn.addEventListener('click', function () {
      if (step1 && step2) {
        step2.classList.remove('active');
        step1.classList.add('active');
        markStep(0);
      }
    });
  }

  function showPreview(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function (e) {
      if (previewImg) previewImg.src = e.target.result;
      if (previewBox) previewBox.classList.remove('d-none');
      if (dropZone) dropZone.classList.add('d-none');
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

  if (enrollForm) {
    enrollForm.addEventListener('submit', function () {
      if (overlay) {
        overlay.classList.remove('d-none');
        const nodes = overlay.querySelectorAll('.chain-node');
        nodes.forEach(function (node, i) {
          setTimeout(function () { node.classList.add('done'); }, i * 260);
        });
      }
      // form submits normally to the existing Flask route — no fetch/AJAX involved
    });
  }
});

# KISAN-ID Frontend — Integration Guide

This zip contains ONLY frontend files: `templates/` and `static/`.
Your `app.py` and all backend logic are untouched.

## How to install

1. Unzip into your existing Flask project root, so it merges as:
   your-project/
     app.py                (yours, unchanged)
     config.py, auth/, services/, registration/, verification/, storage/  (yours, unchanged)
     templates/             <- replaced by this zip
     static/                <- replaced by this zip

2. If you already have a `templates/` or `static/` folder, back it up first,
   then overwrite with the ones in this zip — every `render_template()`
   path used in your `app.py` is matched exactly:
   - index.html
   - auth/farmer_login.html, auth/center_login.html,
     auth/government_login.html, auth/admin_login.html
   - farmer/dashboard.html, farmer/profile.html, farmer/land.html,
     farmer/benefits.html, farmer/schemes.html, farmer/fingerprints.html
   - center/dashboard.html, center/register_farmer.html,
     center/fingerprint_enrollment.html, center/registration_result.html
   - government/dashboard.html, government/farmer_search.html,
     government/farmer_details.html, government/schemes_management.html

3. Run as before: `python app.py`

No Python files were added or modified. No routes, form field names,
POST parameters, Jinja variable names, or session keys were renamed.

## Design notes

- Bootstrap 5 + Bootstrap Icons via CDN, Poppins/Inter/Roboto Mono via
  Google Fonts CDN — no local font/icon files needed.
- Signature visual: the "Trust Chain" — a reusable pipeline component
  (SourceAFIS → AES-256-GCM → ML-KEM-1024 → ML-DSA-87 → SHA3-256 → IPFS →
  Blockchain) used on the homepage, the fingerprint enrollment page, and
  the government verification page.
- Portal theme colors switch automatically from `session.role` (green =
  Farmer, blue = Registration Center, navy = Government) — see
  `templates/shared/sidebar.html` and `static/css/style.css`.

## Assumptions you should double-check

I don't have your `config.py` or `services/*.py`, so two kinds of things
were inferred rather than known for certain:

1. **Role constant strings.** Sidebar/navbar portal switching matches on
   a case-insensitive *substring* of `session.role` (e.g. `'farmer' in
   role`, `'admin' in role`) rather than an exact string, specifically so
   it keeps working no matter what `config.ROLE_FARMER` etc. actually
   equal. If your role strings are unusual, check
   `templates/shared/sidebar.html` and `templates/shared/navbar.html`.

2. **Object field names** for `farmer`, `land` records, `benefits`,
   `schemes`, and `verify_result` (e.g. `farmer.village`,
   `benefit.amount`, `verify_result.score`) were inferred from the
   route code and column names implied in `app.py`. Every place I
   wasn't certain a field exists, I added an inline
   `<!-- TODO: ... -->` comment and a safe fallback (`|default('—')`)
   so a missing attribute won't crash the page — it'll just show a
   placeholder. Search each template for `TODO` to find these and
   adjust field names if your actual service layer differs.

3. `verify_result` in `government/farmer_details.html` is read as
   `verify_result.score`, `.threshold`, `.cid`, `.tx_hash` /
   `.transaction_hash` — rename these to match whatever
   `verify_single_finger()` actually returns.

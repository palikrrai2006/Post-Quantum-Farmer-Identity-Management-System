"""
app.py
======
Main Flask application. Three portals (Farmer / Government / Certified
Registration Center) plus Admin, all backed by server-side RBAC
(auth/decorators.py) — never frontend-only authorization.

Run:
    python app.py
Then open:
    http://127.0.0.1:5000
"""

import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

import config
from storage.db import init_db
from auth.authentication import authenticate, get_user_by_id
from auth.decorators import login_required, require_role
from services import farmer_service, land_service, benefit_service, scheme_service, audit_service
from services import center_service
from registration.register_farmer import register_new_farmer
from registration.register_fingerprint import (
    enroll_fingerprint, DuplicateFingerError, FingerLimitExceededError, RegistrationTransactionError,
)
from verification.verify_farmer import verify_single_finger, verify_multi_finger, VerificationRejected

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config["UPLOAD_FOLDER"] = config.UPLOAD_FOLDER

init_db()


# ----------------------------------------------------------------------
# HOME (portal selection — no login form here)
# ----------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        role = session["role"]
        if role == config.ROLE_FARMER:
            return redirect(url_for("farmer_dashboard"))
        if role == config.ROLE_GOVERNMENT_OFFICER:
            return redirect(url_for("government_dashboard"))
        if role == config.ROLE_REGISTRATION_CENTER_OPERATOR:
            return redirect(url_for("center_dashboard"))
        if role == config.ROLE_ADMIN:
            return redirect(url_for("admin_dashboard"))
    # Shows the 3-card portal picker (Farmer / Registration Center / Government)
    return render_template("index.html")


# ----------------------------------------------------------------------
# SHARED LOGIN HELPER (logic only — each portal still gets its own
# template and its own route, so there is no single generic login page)
# ----------------------------------------------------------------------
def _handle_portal_login(allowed_roles, login_template, dashboard_endpoint):
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = authenticate(username, password)

        if user is None:
            audit_service.log_action(None, None, "LOGIN_FAILED", ip_address=request.remote_addr, result="FAILED")
            flash("Invalid username or password.", "error")
            return render_template(login_template)

        if user["role"] not in allowed_roles:
            # Right credentials, wrong portal — never cross-redirect roles.
            audit_service.log_action(
                user["user_id"], user["role"], "LOGIN_WRONG_PORTAL", ip_address=request.remote_addr, result="FAILED"
            )
            flash("These credentials are not valid for this portal.", "error")
            return render_template(login_template)

        session["user_id"] = user["user_id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        if user["role"] == config.ROLE_FARMER:
            session["farmer_id"] = _farmer_id_for_user(user["user_id"])

        audit_service.log_action(user["user_id"], user["role"], "LOGIN_SUCCESS", ip_address=request.remote_addr)
        return redirect(url_for(dashboard_endpoint))

    return render_template(login_template)


def _farmer_id_for_user(user_id):
    from storage.db import db_cursor
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT farmer_id FROM farmers WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
    return row["farmer_id"] if row else None


@app.route("/logout")
def logout():
    if "user_id" in session:
        audit_service.log_action(session["user_id"], session.get("role"), "LOGOUT")
    session.clear()
    return redirect(url_for("index"))


# ----------------------------------------------------------------------
# FARMER PORTAL
# ----------------------------------------------------------------------
@app.route("/farmer", methods=["GET", "POST"])
def farmer_portal_login():
    if "user_id" in session and session.get("role") == config.ROLE_FARMER:
        return redirect(url_for("farmer_dashboard"))

    if request.method == "POST":
        auth_step = request.form.get("auth_step")
        
        if auth_step == "check_id":
            # Step 1: Validate Farmer ID
            farmer_id = request.form.get("farmer_id", "").strip().upper()
            farmer = farmer_service.get_farmer(farmer_id)
            if not farmer:
                flash("Invalid Farmer ID. Please check and try again.", "error")
                return render_template("auth/farmer_login.html")
            
            # Farmer ID is valid, show Step 2 (Auth options)
            return render_template("auth/farmer_login.html", step="auth", farmer_id=farmer_id)
            
        elif auth_step == "verify_otp":
            # Step 2A: OTP Verification
            farmer_id = request.form.get("farmer_id")
            otp_entered = request.form.get("otp")
            if otp_entered == "123456": # Mock OTP validation
                farmer = farmer_service.get_farmer(farmer_id)
                session["user_id"] = farmer["user_id"]
                session["username"] = farmer["name"]
                session["role"] = config.ROLE_FARMER
                session["farmer_id"] = farmer_id
                audit_service.log_action(farmer["user_id"], config.ROLE_FARMER, "LOGIN_SUCCESS_OTP", ip_address=request.remote_addr)
                return redirect(url_for("farmer_dashboard"))
            else:
                flash("Invalid OTP. Please try again.", "error")
                return render_template("auth/farmer_login.html", step="auth", farmer_id=farmer_id, auth_mode="otp")
                
        elif auth_step == "verify_biometric":
            # Step 2B: Biometric Verification
            farmer_id = request.form.get("farmer_id")
            if "fingerprint_image" not in request.files:
                flash("Please upload a fingerprint image.", "error")
                return render_template("auth/farmer_login.html", step="auth", farmer_id=farmer_id, auth_mode="biometric")
                
            image_file = request.files["fingerprint_image"]
            if image_file.filename == '':
                flash("No selected file.", "error")
                return render_template("auth/farmer_login.html", step="auth", farmer_id=farmer_id, auth_mode="biometric")

            # We don't know the position for login usually, but our verify_single_finger expects a position.
            # However, `verify_single_finger` is for officer verification. Let's do a basic check.
            # For demo purposes, we will assume it's a match if an image is uploaded (or we could use verify_single_finger if we ask for position).
            # To be more realistic, let's ask for position in the login form, or loop through enrolled fingers.
            finger_position = request.form.get("finger_position", "LEFT_THUMB")
            image_path = os.path.join(config.UPLOAD_FOLDER, f"login_{farmer_id}_{finger_position}.png")
            image_file.save(image_path)
            
            farmer = farmer_service.get_farmer(farmer_id)
            try:
                # Use user_id of the farmer themselves since they are logging in
                result = verify_single_finger(farmer_id, finger_position, image_path, farmer["user_id"], config.ROLE_FARMER)
                if result:
                    session["user_id"] = farmer["user_id"]
                    session["username"] = farmer["name"]
                    session["role"] = config.ROLE_FARMER
                    session["farmer_id"] = farmer_id
                    audit_service.log_action(farmer["user_id"], config.ROLE_FARMER, "LOGIN_SUCCESS_BIOMETRIC", ip_address=request.remote_addr)
                    flash("Biometric match confirmed! Identity securely extracted and verified against Blockchain and IPFS.", "success")
                    return redirect(url_for("farmer_dashboard"))
            except VerificationRejected:
                flash("Biometric verification failed. Fingerprint does not match.", "error")
                return render_template("auth/farmer_login.html", step="auth", farmer_id=farmer_id, auth_mode="biometric")
            except Exception as e:
                flash(f"Error during biometric verification: {str(e)}", "error")
                return render_template("auth/farmer_login.html", step="auth", farmer_id=farmer_id, auth_mode="biometric")

    return render_template("auth/farmer_login.html", step="id")


@app.route("/farmer/dashboard")
@require_role(config.ROLE_FARMER)
def farmer_dashboard():
    farmer = farmer_service.get_farmer(session["farmer_id"])
    return render_template("farmer/dashboard.html", farmer=farmer)


@app.route("/farmer/profile")
@require_role(config.ROLE_FARMER)
def farmer_profile():
    farmer = farmer_service.get_farmer(session["farmer_id"])
    return render_template("farmer/profile.html", farmer=farmer)


@app.route("/farmer/land")
@require_role(config.ROLE_FARMER)
def farmer_land():
    records = land_service.get_land_records(session["farmer_id"])
    return render_template("farmer/land.html", records=records)


@app.route("/farmer/land/correction", methods=["POST"])
@require_role(config.ROLE_FARMER)
def farmer_request_land_correction():
    land_service.request_land_correction(session["farmer_id"], request.form["details"])
    flash("Correction request submitted.", "success")
    return redirect(url_for("farmer_land"))


@app.route("/farmer/benefits")
@require_role(config.ROLE_FARMER)
def farmer_benefits():
    benefits = benefit_service.get_benefits_for_farmer(session["farmer_id"])
    return render_template("farmer/benefits.html", benefits=benefits)


@app.route("/farmer/schemes")
@require_role(config.ROLE_FARMER)
def farmer_schemes():
    schemes = scheme_service.list_schemes(status="ACTIVE")
    return render_template("farmer/schemes.html", schemes=schemes)


@app.route("/farmer/fingerprints")
@require_role(config.ROLE_FARMER)
def farmer_fingerprints():
    farmer_id = session["farmer_id"]
    enrolled = {f["finger_position"] for f in farmer_service.get_enrolled_fingers(farmer_id)}
    return render_template(
        "farmer/fingerprints.html",
        enrolled=enrolled,
        all_positions=config.VALID_FINGER_POSITIONS,
        min_required=config.MIN_FINGERPRINTS,
        max_allowed=config.MAX_FINGERPRINTS,
    )


# ----------------------------------------------------------------------
# CERTIFIED REGISTRATION CENTER PORTAL
# ----------------------------------------------------------------------
@app.route("/registration", methods=["GET", "POST"])
def registration_portal_login():
    if "user_id" in session and session.get("role") == config.ROLE_REGISTRATION_CENTER_OPERATOR:
        return redirect(url_for("center_dashboard"))
    return _handle_portal_login(
        allowed_roles={config.ROLE_REGISTRATION_CENTER_OPERATOR},
        login_template="auth/center_login.html",
        dashboard_endpoint="center_dashboard",
    )


@app.route("/center/dashboard")
@require_role(config.ROLE_REGISTRATION_CENTER_OPERATOR)
def center_dashboard():
    today_reg   = farmer_service.count_todays_registrations()
    total_reg   = farmer_service.count_all_farmers()
    complete_reg = farmer_service.count_complete_farmers()
    pending_reg = total_reg - complete_reg
    recent_farmers = farmer_service.get_all_farmers(limit=10)
    return render_template("center/dashboard.html",
                           today_registrations=today_reg,
                           completed_registrations=complete_reg,
                           pending_registrations=pending_reg,
                           total_registered=total_reg,
                           recent_farmers=recent_farmers)


@app.route("/center/register", methods=["GET", "POST"])
@require_role(config.ROLE_REGISTRATION_CENTER_OPERATOR)
def center_register():
    if request.method == "POST":
        farmer_id = register_new_farmer(
            name=request.form["name"], date_of_birth=request.form["date_of_birth"],
            gender=request.form["gender"], phone=request.form["phone"],
            address=request.form["address"], village=request.form["village"],
            taluk=request.form["taluk"], district=request.form["district"],
            state=request.form["state"],
            registration_center_id=session.get("center_id", 1),
            operator_user_id=session["user_id"],
        )
        flash(f"Farmer {farmer_id} created. Proceed to fingerprint enrollment.", "success")
        return redirect(url_for("center_enroll", farmer_id=farmer_id))
    return render_template("center/register_farmer.html")


@app.route("/center/enroll/<farmer_id>", methods=["GET", "POST"])
@require_role(config.ROLE_REGISTRATION_CENTER_OPERATOR)
def center_enroll(farmer_id):
    if request.method == "POST":
        finger_position = request.form["finger_position"]
        image_file = request.files["fingerprint_image"]
        image_path = os.path.join(config.UPLOAD_FOLDER, f"{farmer_id}_{finger_position}.png")
        image_file.save(image_path)

        try:
            result = enroll_fingerprint(
                farmer_id=farmer_id, finger_position=finger_position, image_path=image_path,
                registration_center_id=session.get("center_id", 1), operator_user_id=session["user_id"],
            )
            flash(f"{finger_position} enrolled ({result['fingerprint_count']}/{config.MAX_FINGERPRINTS}).", "success")
        except DuplicateFingerError as e:
            flash(str(e), "error")
        except FingerLimitExceededError as e:
            flash(str(e), "error")
        except RegistrationTransactionError as e:
            flash(str(e), "error")

        return redirect(url_for("center_enroll", farmer_id=farmer_id))

    enrolled = {f["finger_position"] for f in farmer_service.get_enrolled_fingers(farmer_id)}
    return render_template(
        "center/fingerprint_enrollment.html", farmer_id=farmer_id, enrolled=enrolled,
        all_positions=config.VALID_FINGER_POSITIONS,
        min_required=config.MIN_FINGERPRINTS, max_allowed=config.MAX_FINGERPRINTS,
    )


@app.route("/center/registration/<farmer_id>")
@require_role(config.ROLE_REGISTRATION_CENTER_OPERATOR)
def center_registration_result(farmer_id):
    farmer = farmer_service.get_farmer(farmer_id)
    fingers = farmer_service.get_enrolled_fingers(farmer_id)
    return render_template("center/registration_result.html", farmer=farmer, fingers=fingers)


# ----------------------------------------------------------------------
# GOVERNMENT PORTAL
# ----------------------------------------------------------------------
@app.route("/government", methods=["GET", "POST"])
def government_portal_login():
    if "user_id" in session and session.get("role") == config.ROLE_GOVERNMENT_OFFICER:
        return redirect(url_for("government_dashboard"))
    return _handle_portal_login(
        allowed_roles={config.ROLE_GOVERNMENT_OFFICER},
        login_template="auth/government_login.html",
        dashboard_endpoint="government_dashboard",
    )


@app.route("/government/dashboard")
@require_role(config.ROLE_GOVERNMENT_OFFICER)
def government_dashboard():
    total_farmers    = farmer_service.count_all_farmers()
    verified_farmers = farmer_service.count_complete_farmers()
    total_fingerprints = farmer_service.count_enrolled_fingerprints()
    today_verif      = audit_service.count_todays_verifications()
    total_schemes    = len(scheme_service.list_schemes())
    total_centers    = center_service.count_centers()
    return render_template("government/dashboard.html",
                           total_farmers=total_farmers,
                           verified_farmers=verified_farmers,
                           total_fingerprints=total_fingerprints,
                           today_verifications=today_verif,
                           total_schemes=total_schemes,
                           total_centers=total_centers)


@app.route("/government/farmers")
@require_role(config.ROLE_GOVERNMENT_OFFICER)
def government_farmer_search():
    query = request.args.get("q", "")
    results = farmer_service.search_farmers(query) if query else []
    return render_template("government/farmer_search.html", results=results, query=query)


@app.route("/government/farmer/<farmer_id>")
@require_role(config.ROLE_GOVERNMENT_OFFICER)
def government_farmer_details(farmer_id):
    farmer = farmer_service.get_farmer(farmer_id)
    fingers = farmer_service.get_enrolled_fingers(farmer_id)
    land = land_service.get_land_records(farmer_id)
    benefits = benefit_service.get_benefits_for_farmer(farmer_id)
    audit_service.log_action(session["user_id"], session["role"], "VIEW_FARMER_PROFILE", target_farmer_id=farmer_id)
    return render_template("government/farmer_details.html", farmer=farmer, fingers=fingers,
                           land=land, benefits=benefits)


@app.route("/government/verify/<farmer_id>", methods=["GET", "POST"])
@require_role(config.ROLE_GOVERNMENT_OFFICER)
def government_verify(farmer_id):
    result = None
    error = None
    if request.method == "POST":
        finger_position = request.form["finger_position"]
        image_file = request.files["fingerprint_image"]
        image_path = os.path.join(config.UPLOAD_FOLDER, f"verify_{farmer_id}_{finger_position}.png")
        image_file.save(image_path)
        try:
            result = verify_single_finger(farmer_id, finger_position, image_path,
                                           session["user_id"], session["role"])
        except VerificationRejected as e:
            error = "IDENTITY VERIFICATION FAILED"
    enrolled = {f["finger_position"] for f in farmer_service.get_enrolled_fingers(farmer_id)}
    return render_template("government/farmer_details.html", farmer=farmer_service.get_farmer(farmer_id),
                           fingers=farmer_service.get_enrolled_fingers(farmer_id),
                           land=land_service.get_land_records(farmer_id),
                           benefits=benefit_service.get_benefits_for_farmer(farmer_id),
                           verify_result=result, verify_error=error, enrolled_positions=enrolled)


@app.route("/government/land/<farmer_id>", methods=["POST"])
@require_role(config.ROLE_GOVERNMENT_OFFICER)
def government_manage_land(farmer_id):
    land_service.create_land_record(
        farmer_id=farmer_id, survey_number=request.form["survey_number"],
        land_area=float(request.form["land_area"]), area_unit=request.form["area_unit"],
        village=request.form["village"], taluk=request.form["taluk"],
        district=request.form["district"], state=request.form["state"],
        land_type=request.form["land_type"], ownership_type=request.form["ownership_type"],
        verified_by=session["user_id"],
    )
    audit_service.log_action(session["user_id"], session["role"], "LAND_RECORD_CREATED", target_farmer_id=farmer_id)
    return redirect(url_for("government_farmer_details", farmer_id=farmer_id))


@app.route("/government/benefits/<farmer_id>", methods=["POST"])
@require_role(config.ROLE_GOVERNMENT_OFFICER)
def government_manage_benefits(farmer_id):
    action = request.form.get("action")
    if action == "create":
        benefit_service.create_benefit(
            scheme_id=request.form.get("scheme_id") or None, farmer_id=farmer_id,
            benefit_name=request.form["benefit_name"], description=request.form.get("description", ""),
            amount=float(request.form["amount"]),
        )
    elif action == "approve":
        benefit_service.approve_benefit(int(request.form["benefit_id"]), session["user_id"])
    elif action == "reject":
        benefit_service.reject_benefit(int(request.form["benefit_id"]), session["user_id"])
    elif action == "pay":
        benefit_service.record_payment(int(request.form["benefit_id"]), request.form["payment_reference"])
    audit_service.log_action(session["user_id"], session["role"], f"BENEFIT_ACTION:{action}", target_farmer_id=farmer_id)
    return redirect(url_for("government_farmer_details", farmer_id=farmer_id))


@app.route("/government/schemes", methods=["GET", "POST"])
@require_role(config.ROLE_GOVERNMENT_OFFICER)
def government_schemes_view():
    if request.method == "POST":
        scheme_service.create_scheme(
            scheme_name=request.form["scheme_name"], description=request.form.get("description", ""),
            eligibility=request.form.get("eligibility", ""), start_date=request.form.get("start_date"),
            end_date=request.form.get("end_date"),
        )
    schemes = scheme_service.list_schemes()
    return render_template("government/schemes_management.html", schemes=schemes)


@app.route("/government/audit")
@require_role(config.ROLE_GOVERNMENT_OFFICER)
def government_audit_logs():
    logs = audit_service.get_all_audit_logs(limit=500)
    audit_service.log_action(session["user_id"], session["role"], "VIEW_AUDIT_LOGS")
    return render_template("government/audit_logs.html", logs=logs)


@app.route("/government/blockchain")
@require_role(config.ROLE_GOVERNMENT_OFFICER)
def government_blockchain_status():
    import config as cfg
    blockchain_info = {
        "rpc_url": cfg.BLOCKCHAIN_RPC_URL,
        "contract_address": cfg.CONTRACT_ADDRESS,
        "ipfs_api": cfg.IPFS_API_BASE_URL,
        "ipfs_gateway": cfg.IPFS_GATEWAY_BASE_URL,
    }
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(cfg.BLOCKCHAIN_RPC_URL))
        blockchain_info["connected"] = w3.is_connected()
        if blockchain_info["connected"]:
            blockchain_info["block_number"] = w3.eth.block_number
            blockchain_info["chain_id"] = w3.eth.chain_id
        else:
            blockchain_info["block_number"] = "N/A"
            blockchain_info["chain_id"] = cfg.CHAIN_ID
    except Exception:
        blockchain_info["connected"] = False
        blockchain_info["block_number"] = "N/A"
        blockchain_info["chain_id"] = cfg.CHAIN_ID
    total_fp = farmer_service.count_enrolled_fingerprints()
    return render_template("government/blockchain_status.html",
                           info=blockchain_info, total_anchored=total_fp)


@app.route("/government/centers", methods=["GET", "POST"])
@require_role(config.ROLE_GOVERNMENT_OFFICER)
def government_centers():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create_center":
            center_service.create_center(
                center_name=request.form["center_name"],
                registration_number=request.form["registration_number"],
                address=request.form.get("address", ""),
                district=request.form.get("district", ""),
                state=request.form.get("state", ""),
            )
            audit_service.log_action(session["user_id"], session["role"], "CREATE_CENTER")
            flash("Registration center created successfully.", "success")
        elif action == "create_operator":
            try:
                center_service.create_operator(
                    username=request.form["username"],
                    password=request.form["password"],
                    center_id=int(request.form["center_id"]),
                )
                audit_service.log_action(session["user_id"], session["role"], "CREATE_OPERATOR")
                flash(f"Operator '{request.form['username']}' created successfully.", "success")
            except Exception as e:
                flash(f"Could not create operator: {e}", "error")
        return redirect(url_for("government_centers"))
    centers = center_service.list_centers()
    operators = center_service.list_operators()
    return render_template("government/centers.html", centers=centers, operators=operators)


@app.route("/government/reports")
@require_role(config.ROLE_GOVERNMENT_OFFICER)
def government_reports():
    all_farmers   = farmer_service.get_all_farmers(limit=1000)
    total_farmers = farmer_service.count_all_farmers()
    complete      = farmer_service.count_complete_farmers()
    total_fp      = farmer_service.count_enrolled_fingerprints()
    total_verif   = audit_service.count_total_verifications()
    total_schemes = len(scheme_service.list_schemes())
    total_centers = center_service.count_centers()
    # Monthly enrollment breakdown (SQLite)
    from storage.db import db_cursor
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT strftime('%Y-%m', created_at) AS month, COUNT(*) AS cnt "
            "FROM farmers GROUP BY month ORDER BY month DESC LIMIT 12"
        )
        monthly_data = [dict(row) for row in cur.fetchall()]
    return render_template("government/reports.html",
                           total_farmers=total_farmers,
                           complete=complete,
                           total_fingerprints=total_fp,
                           total_verifications=total_verif,
                           total_schemes=total_schemes,
                           total_centers=total_centers,
                           monthly_data=monthly_data,
                           all_farmers=all_farmers)


# ----------------------------------------------------------------------
# ADMIN (minimal — user & center management; not one of the 3 public
# portal cards, kept reachable at its own dedicated URL)
# ----------------------------------------------------------------------
@app.route("/admin", methods=["GET", "POST"])
def admin_portal_login():
    if "user_id" in session and session.get("role") == config.ROLE_ADMIN:
        return redirect(url_for("admin_dashboard"))
    return _handle_portal_login(
        allowed_roles={config.ROLE_ADMIN},
        login_template="auth/admin_login.html",
        dashboard_endpoint="admin_dashboard",
    )


@app.route("/admin/dashboard")
@require_role(config.ROLE_ADMIN)
def admin_dashboard():
    logs = audit_service.get_all_audit_logs(limit=500)
    return render_template("government/audit_logs.html", logs=logs)


# ----------------------------------------------------------------------
# PUBLIC — System Architecture / Research Showcase
# ----------------------------------------------------------------------
@app.route("/architecture")
def system_architecture():
    return render_template("architecture.html")


@app.errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def page_not_found(e):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template("errors/500.html"), 500


if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
"""
registration/register_farmer.py
=================================
Step 1 of certified-center registration: create the Farmer ID + profile.
Fingerprint enrollment (step 2) happens separately, per finger, in
registration/register_fingerprint.py — this keeps "one farmer" and
"N fingerprints" as clearly separate concepts (spec section 1/2).
"""

from services.farmer_service import generate_next_farmer_id, create_farmer
from services.audit_service import log_action
from services import land_service
import random


def register_new_farmer(name, date_of_birth, gender, phone, address, village, taluk,
                         district, state, registration_center_id, operator_user_id):
    farmer_id = generate_next_farmer_id()
    create_farmer(
        farmer_id=farmer_id, name=name, date_of_birth=date_of_birth, gender=gender,
        phone=phone, address=address, village=village, taluk=taluk, district=district,
        state=state, registration_center_id=registration_center_id,
    )
    
    # Automatically generate a mock land record for the new farmer
    land_area = round(random.uniform(0.5, 10.0), 2)
    survey_number = f"SURVEY-{random.randint(100, 9999)}"
    land_type = random.choice(["Irrigated", "Rainfed", "Dryland"])
    ownership_type = random.choice(["Self-Owned", "Leased", "Joint"])
    
    land_service.create_land_record(
        farmer_id=farmer_id, survey_number=survey_number, land_area=land_area, area_unit="Acres",
        village=village, taluk=taluk, district=district, state=state,
        land_type=land_type, ownership_type=ownership_type, verified_by=operator_user_id
    )

    log_action(
        user_id=operator_user_id, role="REGISTRATION_CENTER_OPERATOR",
        action="FARMER_CREATED", target_farmer_id=farmer_id, result="SUCCESS",
    )
    return farmer_id

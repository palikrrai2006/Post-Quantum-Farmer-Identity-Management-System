"""
seed_initial_users.py
=======================

One-time bootstrap script.

Creates:

1. ADMIN
2. GOVERNMENT_OFFICER
3. REGISTRATION_CENTER_OPERATOR
4. Registration Center

Run once:

    python seed_initial_users.py

After running, use the credentials printed below to log in.
"""

from storage.db import init_db, db_cursor
from auth.authentication import create_user

# ==========================================================
# DEFAULT DEMO CREDENTIALS
# ==========================================================

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin@2026#"

GOVT_USERNAME = "govt_officer1"
GOVT_PASSWORD = "Gov@2026#"

CENTER_USERNAME = "center_operator1"
CENTER_PASSWORD = "Center@2026#"


def seed():
    init_db()

    # ------------------------------------------------------
    # ADMIN
    # ------------------------------------------------------
    admin_id = create_user(
        ADMIN_USERNAME,
        ADMIN_PASSWORD,
        "ADMIN"
    )

    print(f"Created ADMIN (user_id={admin_id})")

    # ------------------------------------------------------
    # GOVERNMENT OFFICER
    # ------------------------------------------------------
    govt_id = create_user(
        GOVT_USERNAME,
        GOVT_PASSWORD,
        "GOVERNMENT_OFFICER"
    )

    print(f"Created GOVERNMENT_OFFICER (user_id={govt_id})")

    # ------------------------------------------------------
    # REGISTRATION CENTER OPERATOR
    # ------------------------------------------------------
    operator_id = create_user(
        CENTER_USERNAME,
        CENTER_PASSWORD,
        "REGISTRATION_CENTER_OPERATOR"
    )

    print(f"Created REGISTRATION_CENTER_OPERATOR (user_id={operator_id})")

    # ------------------------------------------------------
    # CREATE DEFAULT REGISTRATION CENTER
    # ------------------------------------------------------
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO registration_centers
            (
                center_name,
                registration_number,
                address,
                district,
                state,
                operator_user_id,
                status
            )
            VALUES
            (?, ?, ?, ?, ?, ?, 'ACTIVE')
            """,
            (
                "Central Certified Registration Center",
                "CRC-0001",
                "Main Street",
                "Bengaluru",
                "Karnataka",
                operator_id,
            ),
        )

        center_id = cur.lastrowid

    print(f"Created Registration Center (center_id={center_id})")

    # ------------------------------------------------------
    # SEED REAL GOVERNMENT SCHEMES & BENEFITS
    # ------------------------------------------------------
    schemes_data = [
        ("PM-KISAN", "Pradhan Mantri Kisan Samman Nidhi - ₹6,000 per year minimum income support.", "All landholding farmers", "2019-02-01", "2030-12-31"),
        ("PMFBY", "Pradhan Mantri Fasal Bima Yojana - Crop insurance against non-preventable natural risks.", "Farmers growing notified crops", "2016-02-18", "2030-12-31"),
        ("KCC", "Kisan Credit Card - Concessional credit for agricultural expenses.", "All farmers, sharecroppers, tenant farmers", "1998-08-01", "2030-12-31"),
        ("PMKSY", "Pradhan Mantri Krishi Sinchayee Yojana - Subsidies for micro-irrigation and water conservation.", "Farmers with arable land", "2015-07-01", "2030-12-31")
    ]
    
    with db_cursor() as cur:
        # Check if schemes exist
        cur.execute("SELECT COUNT(*) as count FROM government_schemes")
        if cur.fetchone()["count"] == 0:
            for s in schemes_data:
                cur.execute(
                    """INSERT INTO government_schemes (scheme_name, description, eligibility, start_date, end_date)
                       VALUES (?, ?, ?, ?, ?)""", s
                )
            print("Seeded real Government Schemes.")
            
        # Randomly assign to existing farmers
        cur.execute("SELECT farmer_id FROM farmers")
        farmers = [row["farmer_id"] for row in cur.fetchall()]
        
        cur.execute("SELECT scheme_id, scheme_name FROM government_schemes")
        schemes = cur.fetchall()
        
        if farmers and schemes:
            import random
            assigned_count = 0
            for farmer_id in farmers:
                # 70% chance a farmer gets at least one benefit
                if random.random() > 0.3:
                    # Pick 1 or 2 random schemes
                    num_schemes = random.choice([1, 2])
                    assigned_schemes = random.sample(schemes, num_schemes)
                    
                    for scheme in assigned_schemes:
                        # Check if they already have it
                        cur.execute("SELECT 1 FROM benefits WHERE farmer_id = ? AND scheme_id = ?", (farmer_id, scheme["scheme_id"]))
                        if not cur.fetchone():
                            amount = 6000.0 if scheme["scheme_name"] == "PM-KISAN" else random.choice([2000.0, 5000.0, 10000.0])
                            status = random.choice(['APPROVED', 'PAID', 'PENDING'])
                            cur.execute(
                                """INSERT INTO benefits (scheme_id, farmer_id, benefit_name, description, amount, status, approved_by)
                                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                (scheme["scheme_id"], farmer_id, f"{scheme['scheme_name']} Allocation", "Automated assignment", amount, status, govt_id)
                            )
                            assigned_count += 1
            if assigned_count > 0:
                print(f"Randomly assigned {assigned_count} scheme benefits to existing farmers.")

    print("\n==========================================")
    print("Change these passwords before production.")
    print("==========================================")


if __name__ == "__main__":
    seed()
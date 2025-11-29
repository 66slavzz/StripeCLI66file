# interactive_card_cli_2025_audit.py
# Stripe Manual Card Entry CLI with FULL AUDIT LOGGING (PCI-Compliant)
# Run with: python interactive_card_cli_2025_audit.py

import stripe
import json
import os
import uuid
import logging
from datetime import datetime
from getpass import getpass
import re

# === CONFIG ===
CUSTOMER_DB = "customers_2025.json"
AUDIT_LOG = "audit_log_2025.jsonl"  # One JSON line per event (append-only)

# Set Stripe API version
stripe.api_version = "2025-11-17.clover"

# === PCI-COMPLIANT AUDIT LOGGER ===
class PCIAuditLogger:
    def __init__(self, logfile):
        self.logfile = logfile

    def _redact_card(self, number):
        if not number or len(number) < 8:
            return "****"
        return f"{number[:4]}********{number[-4:]}"

    def _write_log(self, level, message, extra=None):
        log_entry = {
            "timestamp_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "request_id": str(uuid.uuid4()),
            "level": level,
            "event": message,
            **(extra or {})
        }
        with open(self.logfile, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        print(f"[{level}] {message}")

    def info(self, msg, **kwargs):
        self._write_log("INFO", msg, kwargs)

    def warn(self, msg, **kwargs):
        self._write_log("WARN", msg, kwargs)

    def error(self, msg, **kwargs):
        self._write_log("ERROR", msg, kwargs)

# Initialize logger
audit = PCIAuditLogger(AUDIT_LOG)

# === DATABASE & VALIDATION ===
def load_customers():
    if os.path.exists(CUSTOMER_DB):
        with open(CUSTOMER_DB, "r") as f:
            return json.load(f)
    return {}

def save_customers(db):
    with open(CUSTOMER_DB, "w") as f:
        json.dump(db, f, indent=2)

def validate_card_number(number):
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    total = sum(digits[-2::-2] * 2 if i % 2 == 0 else digits[i] for i, d in enumerate(digits[::-1]))
    return total % 10 == 0

def list_customers():
    customers = load_customers()
    if not customers:
        audit.info("No customers found in database")
        print("No customers found.")
        return
    print("\n=== Existing Customers ===")
    for email, cid in customers.items():
        print(f"Email: {email} | Customer ID: {cid}")
    audit.info("Customer list viewed", customer_count=len(customers))

# === MAIN FUNCTION ===
def create_or_update_customer():
    request_id = str(uuid.uuid4())
    audit.info("Card entry session started", request_id=request_id)

    email = input("Customer Email: ").strip().lower()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        audit.warn("Invalid email format", email=email, request_id=request_id)
        print("Invalid email.")
        return

    name = input("Full Name: ").strip()
    if not name:
        audit.warn("Missing customer name", email=email, request_id=request_id)
        print("Name required.")
        return

    customers = load_customers()
    existing_id = customers.get(email)

    if existing_id:
        audit.info("Existing customer found", email=email, customer_id=existing_id, request_id=request_id)
        print(f"Found existing customer: {existing_id}")
        if input("Update this customer? (y/n): ").lower() != "y":
            audit.info("Update cancelled by user", email=email, request_id=request_id)
            return
        customer_id = existing_id
    else:
        try:
            customer = stripe.Customer.create(email=email, name=name, metadata={"source": "moto_cli_2025"})
            customer_id = customer.id
            customers[email] = customer_id
            save_customers(customers)
            audit.info("New customer created", email=email, customer_id=customer_id, request_id=request_id)
            print(f"New customer created: {customer_id}")
        except Exception as e:
            audit.error("Customer creation failed", error=str(e), email=email, request_id=request_id)
            print("Failed to create customer.")
            return

    # === CARD INPUT ===
    print("\n--- Enter Card Details ---")
    raw_number = input("Card Number: ").strip().replace(" ", "")
    if not validate_card_number(raw_number):
        audit.warn("Luhn check failed", redacted_card=audit._redact_card(raw_number), request_id=request_id)
        print("Invalid card number.")
        return
    redacted_card = audit._redact_card(raw_number)

    exp_month = input("Expiry Month (1-12): ").strip()
    exp_year = input("Expiry Year: ").strip()
    cvc = getpass("CVV/CVC: ").strip()

    # === BILLING ===
    print("\n--- Billing Address (AVS) ---")
    line1 = input("Address Line 1: ").strip()
    zip_code = input("ZIP/Postal Code: ").strip()

    audit.info("Attempting card attachment and verification", 
               customer_id=customer_id, redacted_card=redacted_card, request_id=request_id)

    try:
        pm = stripe.PaymentMethod.create(
            type="card",
            card={
                "number": raw_number,
                "exp_month": int(exp_month),
                "exp_year": int(exp_year),
                "cvc": cvc,
            },
            billing_details={
                "name": name,
                "email": email,
                "address": {
                    "line1": line1,
                    "postal_code": zip_code,
                    "country": "US"
                }
            }
        )

        stripe.PaymentMethod.attach(pm.id, customer=customer_id)
        stripe.Customer.modify(customer_id, invoice_settings={"default_payment_method": pm.id})

        pi = stripe.PaymentIntent.create(
            amount=100,
            currency="usd",
            payment_method=pm.id,
            customer=customer_id,
            confirm=True,
            capture_method="manual",
            setup_future_usage="off_session",
            metadata={"verified_via": "moto_cli_audit_2025", "request_id": request_id}
        )

        if pi.status == "succeeded":
            stripe.PaymentIntent.cancel(pi.id)
            audit.info("CARD SUCCESSFULLY VERIFIED AND ATTACHED",
                       customer_id=customer_id,
                       payment_method_id=pm.id,
                       last4=pm.card.last4,
                       brand=pm.card.brand,
                       avs=pm.card.checks.address_postal_code_check,
                       cvv=pm.card.checks.cvc_check,
                       request_id=request_id)
            print("\nCARD VERIFIED SUCCESSFULLY!")
            print(f"Last 4: {pm.card.last4} | Brand: {pm.card.brand.title()}")
            print(f"AVS: {pm.card.checks.address_postal_code_check} | CVV: {pm.card.checks.cvc_check}")
        else:
            audit.warn("Verification failed", status=pi.status, request_id=request_id)
            print("Verification failed.")

    except stripe.error.CardError as e:
        audit.warn("Card declined", 
                   decline_code=e.code, 
                   redacted_card=redacted_card,
                   request_id=request_id)
        print(f"Card declined: {e.user_message}")
    except Exception as e:
        audit.error("Unexpected error during processing", error=str(e), request_id=request_id)
        print("Processing failed.")

# === MAIN ===
if __name__ == "__main__":
    key = input("Enter Stripe Secret Key: ").strip()
    if not key:
        print("No key. Exiting.")
        exit()
    stripe.api_key = key

    if key.startswith("sk_test_"):
        print("TEST MODE ACTIVE")

    audit.info("CLI started", api_key_prefix=key[:10], api_version=stripe.api_version)

    while True:
        print("\n" + "="*60)
        print("1. Add/Update Card (with full audit)")
        print("2. List Customers")
        print("3. View Last 10 Audit Logs")
        print("4. Exit")
        choice = input("Choose: ").strip()

        if choice == "1":
            create_or_update_customer()
        elif choice == "2":
            list_customers()
        elif choice == "3":
            print("\n--- Last 10 Audit Events ---")
            if os.path.exists(AUDIT_LOG):
                with open(AUDIT_LOG, "r") as f:
                    lines = f.readlines()[-10:]
                    for line in lines:
                        print(line.strip())
            else:
                print("No logs yet.")
        elif choice == "4":
            audit.info("CLI shutdown by user")
            print("Goodbye!")
            break
        else:
            print("Invalid option.")

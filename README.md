# StripeCLI66file
payment processer ; apple pay method 

# StripeCLI66file

A production-grade, PCI-compliant Stripe CLI for manual card entry (MOTO), customer creation/update, card verification with AVS/CVV, and full audit logging.  
Perfect for call centers, phone orders, testing, or backend payment automation.

Supports Stripe API 2025-11-17.clover – fully up to date as of November 2025.

## Features

- Manual card entry (card number, expiry, CVC  
- Luhn algorithm validation before sending to Stripe  
- Create new or update existing Stripe customers (by email)  
- $1 test authorization (immediately voided) → forces real AVS + CVV check  
- Sets card as default + `setup_future_usage='off_session'` (ready for subscriptions & payouts)  
- Full PCI-DSS compliant audit logging (JSONL) – no raw card data ever logged  
- Card numbers redacted: `4242********4242`  
- Unique request IDs + UTC timestamps for every action  
- View last 10 audit events directly in the CLI  
- Local customer database (`customers_2025.json`)  
- Interactive menu + test/live mode detection  

## Installation

```bash
git clone https://github.com/66slavzz/StripeCLI66file.git
cd StripeCLI66file
pip install stripe>=12.0.0

Quick Start
python main.py

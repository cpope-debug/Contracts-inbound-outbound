import os
import sys
import time
import base64
import requests
import logging
from flask import Flask, render_template, request, flash
from dotenv import load_dotenv
from datetime import datetime
from collections import defaultdict

load_dotenv()
app = Flask(__name__)

# Secret key for flash messages
app.secret_key = os.getenv('FLASK_SECRET_KEY') or os.urandom(24)

# ---- Logging Configuration (stdout for Render) ----
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ---- Token Caching ----
cached_token = None
token_expiry = 0

# ---- Rate Limiting ----
request_counts = defaultdict(list)

def _client_ip():
    # Respect X-Forwarded-For behind proxy/LB
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or 'unknown'

def rate_limit(identifier, max_requests=30, window=60):
    """Simple rate limiting: max_requests per window (seconds)"""
    now = time.time()
    request_counts[identifier] = [t for t in request_counts[identifier] if now - t < window]
    if len(request_counts[identifier]) >= max_requests:
        return False
    request_counts[identifier].append(now)
    return True

# ---- Input Validation ----
def validate_date(date_str):
    """Validate date format and reasonable range"""
    try:
        date_obj = datetime.strptime(date_str, '%Y-%m-%d')
        current_year = datetime.now().year
        if date_obj.year < 2020 or date_obj.year > current_year + 2:
            return False, "Date must be between 2020 and 2 years in the future"
        return True, None
    except ValueError:
        return False, "Invalid date format. Please use YYYY-MM-DD"

def validate_quantity(qty, max_qty=10000):
    """Validate quantity is a reasonable integer"""
    if not qty or qty.strip() == '' or qty == '0':
        return True, None  # Empty or zero is valid
    try:
        qty_int = int(qty)
        if qty_int < 0:
            return False, "Quantity cannot be negative"
        if qty_int > max_qty:
            return False, f"Quantity cannot exceed {max_qty}"
        return True, None
    except (ValueError, TypeError):
        return False, "Quantity must be a valid number"

# ---- Token Management ----
def get_token():
    global cached_token, token_expiry
    if cached_token and time.time() < token_expiry:
        return cached_token

    url = "https://secure-wms.com/AuthServer/api/Token"
    client_id = os.getenv("CLIENT_ID") or os.getenv("EXTENSIV_CLIENT_ID")
    client_secret = os.getenv("CLIENT_SECRET") or os.getenv("EXTENSIV_CLIENT_SECRET")
    tpl_key = os.getenv("TPL_CODE") or os.getenv("EXTENSIV_TPL_KEY")

    if not client_id or not client_secret:
        logger.error("Missing CLIENT_ID or CLIENT_SECRET")
        raise ValueError("CLIENT_ID and CLIENT_SECRET must be set in environment variables")

    credentials = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')

    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "client_credentials",
        **({"tpl": tpl_key} if tpl_key else {}),
        "user_login_id": "4"
    }
    try:
        r = requests.post(url, headers=headers, data=data, timeout=30)
        r.raise_for_status()
        token_data = r.json()
        cached_token = token_data["access_token"]
        token_expiry = time.time() + token_data.get("expires_in", 3600) - 60
        logger.info("Successfully obtained access token")
        return cached_token
    except requests.exceptions.RequestException as e:
        logger.error(f"Token request failed: {str(e)}")
        raise e

def get_api_headers():
    """Get headers for API requests"""
    if not cached_token or time.time() >= token_expiry:
        get_token()
    return {
        'Authorization': f'Bearer {cached_token}',
        'Content-Type': 'application/json',
        'Accept': '*/*',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'User-Agent': 'gunicorn/flask-app'
    }

# ---- Helper Functions ----
def get_mattress_lot_number():
    """
    Query available mattress inventory and return lot number string matching 'Dusk and Dawn' or 'BA'
    Returns the lot number as a string
    """
    try:
        headers = get_api_headers()
        
        # Use proper RQL syntax based on documentation
        # Query for Mattress SKU with wildcards to match "Dusk and Dawn" or "BA"
        # RQL: (lotNumber contains "Dusk" OR lotNumber == "BA") AND sku == "Mattress"
        # Using wildcard: lotNumber==*Dusk* for "contains Dusk"
        
        # Try query with lot number filter
        inventory_url = "https://secure-wms.com/inventory?rql=(lotNumber==*Dusk*,lotNumber==BA);itemIdentifier.sku==Mattress;availableQty=gt=0"
        
        logger.info(f"Querying mattress inventory with RQL: {inventory_url}")
        r = requests.get(inventory_url, headers=headers, timeout=30)
        
        if r.status_code == 200:
            inventory_data = r.json()
            total = inventory_data.get('totalResults', 0) or inventory_data.get('TotalResults', 0)
            logger.info(f"Query successful! Total results: {total}")
            
            if total == 0:
                # Fallback: Query all Mattress inventory and filter in code
                logger.info("No results with lot filter, trying broader query...")
                inventory_url = "https://secure-wms.com/inventory?rql=itemIdentifier.sku==Mattress;availableQty=gt=0"
                r = requests.get(inventory_url, headers=headers, timeout=30)
                
                if r.status_code == 200:
                    inventory_data = r.json()
                    total = inventory_data.get('totalResults', 0) or inventory_data.get('TotalResults', 0)
                    logger.info(f"Broader query successful! Total results: {total}")
                    
                    if total == 0:
                        # Last resort: get all inventory and filter for Mattress in code
                        logger.info("Still no results, trying query without SKU filter...")
                        inventory_url = "https://secure-wms.com/inventory?rql=availableQty=gt=0"
                        r = requests.get(inventory_url, headers=headers, timeout=30)
                        if r.status_code == 200:
                            inventory_data = r.json()
                            total = inventory_data.get('totalResults', 0) or inventory_data.get('TotalResults', 0)
                            logger.info(f"Query without SKU filter: Total results: {total}")
        
        if r.status_code != 200:
            logger.warning(f"Query failed: {r.status_code}, Response: {r.text[:300]}")
            return None
        
        # Parse inventory response - check both possible structures
        items = []
        if isinstance(inventory_data, dict):
            # Try _embedded.item structure first
            if '_embedded' in inventory_data:
                items = inventory_data['_embedded'].get('item', [])
            # Try ResourceList structure (the actual format)
            elif 'ResourceList' in inventory_data:
                items = inventory_data['ResourceList']
            
            logger.info(f"Processing {len(items)} inventory items")
            
            # Filter for Mattress items if we got all inventory
            mattress_items = []
            for item in items:
                sku = item.get('itemIdentifier', {}).get('sku', '')
                if not sku:
                    sku = item.get('sku', '')
                
                # Check if this is a Mattress item (case insensitive, partial match)
                if 'mattress' in sku.lower():
                    mattress_items.append(item)
            
            if mattress_items:
                logger.info(f"Found {len(mattress_items)} Mattress items after filtering")
                items = mattress_items
            
            for item in items:
                lot_num = item.get('lotNumber', '')
                available_qty = item.get('availableQty', 0)
                sku = item.get('itemIdentifier', {}).get('sku', 'unknown')
                
                logger.info(f"  - SKU: {sku}, Lot: '{lot_num}', Available: {available_qty}")
                
                if lot_num and available_qty > 0:
                    lot_lower = lot_num.lower().strip()
                    lot_upper = lot_num.strip().upper()
                    
                    # Check if lot matches "Dusk and Dawn" (any capitalization) or "BA"
                    if 'dusk' in lot_lower and 'dawn' in lot_lower:
                        logger.info(f"✓ Found matching 'Dusk and Dawn' lot: '{lot_num}' with {available_qty} available")
                        return lot_num.strip()
                    elif lot_upper == 'BA':
                        logger.info(f"✓ Found matching 'BA' lot: '{lot_num}' with {available_qty} available")
                        return lot_num.strip()
            
            logger.warning(f"Found {len(items)} Mattress items but none with matching lot numbers (Dusk and Dawn / BA)")
            # Log all lots found for debugging
            all_lots = [item.get('lotNumber', 'N/A') for item in items]
            logger.info(f"Available lots: {all_lots}")
            return None
        else:
            logger.warning(f"Unexpected response structure: {list(inventory_data.keys()) if isinstance(inventory_data, dict) else type(inventory_data)}")
            return None
            
    except Exception as e:
        logger.error(f"Error querying mattress lots: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return None

# ---- Routes ----
@app.route("/")
def index():
    """Main form page - No login required"""
    return render_template("form.html")

@app.route("/create-receipt-and-order", methods=["POST"])
def create_receipt_and_order():
    ip_address = _client_ip()

    # Rate limiting
    if not rate_limit(f"ip_{ip_address}", max_requests=30, window=60):
        logger.warning(f"Rate limit exceeded for IP: {ip_address}")
        flash('Too many requests. Please wait a minute.', 'error')
        return """
        <!DOCTYPE html>
        <html>
        <head>
        <title>Rate Limit Exceeded</title>
        <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .error { color: red; }
        .back-button { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #007cba; color: white; text-decoration: none; border-radius: 4px; }
        </style>
        </head>
        <body>
        <h1 class="error">Too Many Requests</h1>
        <p>Please wait a minute before submitting again.</p>
        <a href="/" class="back-button">← Back to Form</a>
        </body>
        </html>
        """, 429

    # Validate date
    date = request.form.get("date", "").strip()
    date_valid, date_error = validate_date(date)
    if not date_valid:
        logger.warning(f"Invalid date submitted: {date} from IP: {ip_address}")
        return error_response(f'Date validation error: {date_error}'), 400

    # SCRAM items
    scram_quantities = {
        "Big Post Pallet": request.form.get("bigPost", "0"),
        "GWA Order": request.form.get("gwa", "0"),
        "MUJI Pallet": request.form.get("muji", "0"),
        "Peace Lilly Order": request.form.get("peaceLilly", "0"),
        "Relax House Order": request.form.get("relaxHouse", "0"),
        "Mattress": request.form.get("mattress", "0"),
    }

    # Toshiba items
    toshiba_quantities = {
        "Toshiba/ S&H Carton": request.form.get("toshibaCarton", "0"),
    }

    # Validate all quantities
    all_quantities = {**scram_quantities, **toshiba_quantities}
    for sku, qty in all_quantities.items():
        qty_valid, qty_error = validate_quantity(qty)
        if not qty_valid:
            logger.warning(f"Invalid quantity for {sku}: {qty} from IP: {ip_address}")
            return error_response(f'Validation error for {sku}: {qty_error}'), 400

    # Check if we need to query for mattress lots
    mattress_lot = None
    mattress_qty = scram_quantities.get("Mattress", "0")
    if mattress_qty and mattress_qty.strip() and mattress_qty != '0':
        try:
            qty_int = int(mattress_qty)
            if qty_int > 0:
                logger.info("Mattress quantity detected, querying for lot numbers")
                mattress_lot = get_mattress_lot_number()
        except (ValueError, TypeError):
            pass

    # Filter and convert quantities for SCRAM RECEIPT (excluding Mattress)
    scram_receipt_lines = []
    for sku, qty in scram_quantities.items():
        # Skip Mattress for receipts
        if sku == "Mattress":
            continue
        if qty and qty.strip() and qty != '0':
            try:
                qty_int = int(qty)
                if qty_int > 0:
                    scram_receipt_lines.append({"sku": sku, "expectedQty": qty_int})
            except (ValueError, TypeError):
                continue

    # Filter and convert quantities for SCRAM ORDER (including Mattress with lot)
    scram_order_lines = []
    for sku, qty in scram_quantities.items():
        if qty and qty.strip() and qty != '0':
            try:
                qty_int = int(qty)
                if qty_int > 0:
                    order_item = {"sku": sku, "orderedQty": qty_int}
                    
                    # Add lot number string for Mattress if we found one
                    if sku == "Mattress" and mattress_lot:
                        order_item["lotNumber"] = mattress_lot
                        logger.info(f"Adding Mattress to order with lot: {mattress_lot}")
                    
                    scram_order_lines.append(order_item)
            except (ValueError, TypeError):
                continue

    # Filter and convert quantities for Toshiba
    toshiba_receipt_lines = []
    toshiba_order_lines = []
    for sku, qty in toshiba_quantities.items():
        if qty and qty.strip() and qty != '0':
            try:
                qty_int = int(qty)
                if qty_int > 0:
                    toshiba_receipt_lines.append({"sku": sku, "expectedQty": qty_int})
                    toshiba_order_lines.append({"sku": sku, "orderedQty": qty_int})
            except (ValueError, TypeError):
                continue

    # Environment variables
    customer_id = os.getenv("EXTENSIV_CUSTOMER_ID", "25")
    facility_id = os.getenv("EXTENSIV_FACILITY_ID", "2")

    # Timestamp for unique references
    timestamp = str(int(time.time()))[-6:]

    # Log the submission
    logger.info(f"Form submission - Date: {date}, SCRAM items: {len(scram_order_lines)}, Toshiba items: {len(toshiba_receipt_lines)}, IP: {ip_address}")

    results = []
    try:
        headers = get_api_headers()

        # Process SCRAM items
        if scram_receipt_lines or scram_order_lines:
            # Only create receipt if there are items (Mattress excluded)
            receipt_created = False
            if scram_receipt_lines:
                scram_receipt_payload = {
                    "customerIdentifier": {"id": int(customer_id)},
                    "facilityIdentifier": {"id": int(facility_id)},
                    "warehouseTransactionSourceEnum": 7,
                    "transactionEntryType": 4,
                    "isReturn": False,
                    "referenceNum": f"SCRAM-R-{date}-{timestamp}",
                    "arrivalDate": f"{date}T00:00:00",
                    "expectedDate": f"{date}T00:00:00",
                    "notes": "SCRAM Inbound via form",
                    "receiveItems": [
                        {"itemIdentifier": {"sku": item["sku"]}, "qty": float(item["expectedQty"])}
                        for item in scram_receipt_lines
                    ]
                }

                logger.info(f"Submitting SCRAM receipt: {scram_receipt_payload['referenceNum']}")
                r1 = requests.post("https://secure-wms.com/inventory/receivers", json=scram_receipt_payload, headers=headers, timeout=30)
                logger.info(f"SCRAM receipt status: {r1.status_code}")
                receipt_created = True
            
            # Always create order if there are order items
            order_created = False
            if scram_order_lines:
                # Build order items with proper structure
                order_items = []
                for item in scram_order_lines:
                    order_item = {
                        "itemIdentifier": {"sku": item["sku"]},
                        "qty": float(item["orderedQty"])
                    }
                    
                    # Add lot number string if present (for Mattress)
                    if "lotNumber" in item:
                        order_item["lotNumber"] = item["lotNumber"]
                    
                    order_items.append(order_item)
                
                scram_order_payload = {
                    "customerIdentifier": {"id": int(customer_id)},
                    "facilityIdentifier": {"id": int(facility_id)},
                    "referenceNum": f"SCRAM-O-{date}-{timestamp}",
                    "entryType": 4,
                    "orderType": "Standard",
                    "notes": "SCRAM Outbound order from form",
                    "orderItems": order_items
                }

                logger.info(f"Submitting SCRAM order: {scram_order_payload['referenceNum']}")
                r2 = requests.post("https://secure-wms.com/orders", json=scram_order_payload, headers=headers, timeout=30)
                logger.info(f"SCRAM order status: {r2.status_code}")
                order_created = True

            results.append({
                'section': 'SCRAM',
                'items': len(scram_order_lines),
                'receipt': {'status': r1.status_code, 'response': r1.text} if receipt_created else None,
                'order': {'status': r2.status_code, 'response': r2.text} if order_created else None
            })

        # Process Toshiba items
        if toshiba_receipt_lines:
            toshiba_receipt_payload = {
                "customerIdentifier": {"id": int(customer_id)},
                "facilityIdentifier": {"id": int(facility_id)},
                "warehouseTransactionSourceEnum": 7,
                "transactionEntryType": 4,
                "isReturn": False,
                "referenceNum": f"Toshiba/S&H-R-{date}-{timestamp}",
                "arrivalDate": f"{date}T00:00:00",
                "expectedDate": f"{date}T00:00:00",
                "notes": "Toshiba/S&H Inbound via form",
                "receiveItems": [
                    {"itemIdentifier": {"sku": item["sku"]}, "qty": float(item["expectedQty"])}
                    for item in toshiba_receipt_lines
                ]
            }

            toshiba_order_payload = {
                "customerIdentifier": {"id": int(customer_id)},
                "facilityIdentifier": {"id": int(facility_id)},
                "referenceNum": f"Toshiba/S&H-O-{date}-{timestamp}",
                "entryType": 4,
                "orderType": "Standard",
                "notes": "Toshiba/S&H Outbound order from form",
                "orderItems": [
                    {"itemIdentifier": {"sku": item["sku"]}, "qty": float(item["orderedQty"])}
                    for item in toshiba_order_lines
                ]
            }

            logger.info(f"Submitting Toshiba receipt: {toshiba_receipt_payload['referenceNum']}")
            r3 = requests.post("https://secure-wms.com/inventory/receivers", json=toshiba_receipt_payload, headers=headers, timeout=30)
            logger.info(f"Submitting Toshiba order: {toshiba_order_payload['referenceNum']}")
            r4 = requests.post("https://secure-wms.com/orders", json=toshiba_order_payload, headers=headers, timeout=30)
            logger.info(f"Toshiba results - Receipt: {r3.status_code}, Order: {r4.status_code}")

            results.append({
                'section': 'Toshiba / S&H',
                'items': len(toshiba_receipt_lines),
                'receipt': {'status': r3.status_code, 'response': r3.text},
                'order': {'status': r4.status_code, 'response': r4.text}
            })

        # Build response HTML
        response_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
        <title>Form Submission Results</title>
        <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .success {{ color: green; }}
        .error {{ color: red; }}
        .section-box {{ background: #f9f9f9; padding: 20px; margin: 20px 0; border-radius: 8px; border: 2px solid #ddd; }}
        .response-box {{ background: #f5f5f5; padding: 15px; margin: 10px 0; border-left: 4px solid #007cba; }}
        .back-button {{ display: inline-block; margin-top: 20px; padding: 10px 20px; background: #007cba; color: white; text-decoration: none; border-radius: 4px; }}
        .info-box {{ background: #e7f3ff; padding: 10px; border-radius: 4px; margin-bottom: 20px; }}
        .lot-info {{ background: #fff3cd; padding: 10px; border-radius: 4px; margin: 10px 0; border-left: 4px solid #ffc107; }}
        h2 {{ color: #333; }}
        h3 {{ color: #555; }}
        </style>
        </head>
        <body>
        <h1>Form Submission Results</h1>
        <div class="info-box">
          <p><strong>Date:</strong> {date}</p>
          <p><strong>Submitted:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        """

        # Add lot info if mattress was ordered
        if mattress_lot:
            response_html += f"""
            <div class="lot-info">
              <p><strong>📦 Mattress Lot Selection:</strong> Automatically selected lot "{mattress_lot}"</p>
            </div>
            """
        elif mattress_qty and mattress_qty != '0':
            response_html += """
            <div class="lot-info">
              <p><strong>⚠️ Mattress Lot:</strong> No matching lot found (Dusk and Dawn/BA). Order created without lot specification.</p>
            </div>
            """

        if not results:
            response_html += """
            <div class="section-box">
              <p><strong>No items to process.</strong> All quantities were zero or empty.</p>
            </div>
            """
        else:
            for result in results:
                response_html += f"""
                <div class="section-box">
                  <h2>{result['section']}</h2>
                  <p><strong>Items processed:</strong> {result['items']} items</p>
                """
                
                if result.get('receipt'):
                    receipt_class = 'success' if result['receipt']['status'] in [200, 201] else 'error'
                    response_html += f"""
                  <h3>Receipt Creation</h3>
                  <div class="response-box">
                    <p><strong>Status:</strong> <span class="{receipt_class}">{result['receipt']['status']}</span></p>
                    <p><strong>Response:</strong></p>
                    <pre>{result['receipt']['response']}</pre>
                  </div>
                    """
                
                if result.get('order'):
                    order_class = 'success' if result['order']['status'] in [200, 201] else 'error'
                    response_html += f"""
                  <h3>Order Creation</h3>
                  <div class="response-box">
                    <p><strong>Status:</strong> <span class="{order_class}">{result['order']['status']}</span></p>
                    <p><strong>Response:</strong></p>
                    <pre>{result['order']['response']}</pre>
                  </div>
                    """
                
                response_html += """
                </div>
                """

        response_html += """
        <a href="/" class="back-button">← Back to Form</a>
        </body>
        </html>
        """
        return response_html

    except requests.exceptions.Timeout:
        logger.error("Request timeout")
        return error_response("Request timeout. The API took too long to respond. Please try again.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        return error_response(f"API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return error_response(f"An unexpected error occurred: {str(e)}")

def error_response(message):
    """Generate error response HTML"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
    <title>Error</title>
    <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; }}
    .error {{ color: red; }}
    .back-button {{ display: inline-block; margin-top: 20px; padding: 10px 20px; background: #007cba; color: white; text-decoration: none; border-radius: 4px; }}
    </style>
    </head>
    <body>
    <h1 class="error">Error Processing Request</h1>
    <p><strong>Error:</strong> {message}</p>
    <p>If this problem persists, please contact IT support.</p>
    <a href="/" class="back-button">← Back to Form</a>
    </body>
    </html>
    """

@app.route("/test-auth")
def test_auth():
    """Test endpoint to verify authentication is working"""
    try:
        token = get_token()
        logger.info("Authentication test successful")
        return f"""
        <h2>Authentication Test</h2>
        <p><strong>Status:</strong> <span style="color: green;">SUCCESS</span></p>
        <p><strong>Token obtained:</strong> Yes (length: {len(token)})</p>
        <p><strong>Token expires:</strong> {datetime.fromtimestamp(token_expiry).isoformat()}</p>
        <p><a href="/">← Back to Form</a></p>
        """
    except Exception as e:
        logger.error(f"Authentication test failed: {str(e)}")
        return f"""
        <h2>Authentication Test</h2>
        <p><strong>Status:</strong> <span style="color: red;">FAILED</span></p>
        <p><strong>Error:</strong> {str(e)}</p>
        <p><a href="/">← Back to Form</a></p>
        """

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return """
    <h1>404 - Page Not Found</h1>
    <p><a href="/">Go to Home</a></p>
    """, 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {str(e)}")
    return """
    <h1>500 - Internal Server Error</h1>
    <p>Something went wrong. Please try again later.</p>
    <p><a href="/">Go to Home</a></p>
    """, 500

if __name__ == "__main__":
    # Local development only. On Render we use Gunicorn.
    print("Running in LOCAL DEVELOPMENT mode (debug=True)")
    app.run(debug=True, host='0.0.0.0', port=5000) 

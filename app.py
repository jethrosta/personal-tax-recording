import streamlit as st
import boto3
import re
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload
import io
from PIL import Image, ExifTags
import datetime

# --- Konfigurasi AWS dan Google Sheets ---
aws_access_key = st.secrets["aws"]["aws_access_key_id"]
aws_secret_key = st.secrets["aws"]["aws_secret_access_key"]
region = st.secrets["aws"]["region"]
sheet_id = '1Bagw_IiVFHX942ACSTRs9ET3IdP1iIjCnSo3IOUJ73U'
folder_id = '1bsWOEg0Pp_yzekRYSnqXqbtriiChwZqi'
spreadsheet_url = 'https://docs.google.com/spreadsheets/d/1Bagw_IiVFHX942ACSTRs9ET3IdP1iIjCnSo3IOUJ73U/edit?usp=sharing'

textract_client = boto3.client(
    'textract',
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name=region
)
# Safely decode private key
def parse_gcp_creds(secrets):
    return {
        "type": secrets["type"],
        "project_id": secrets["project_id"],
        "private_key_id": secrets["private_key_id"],
        "private_key": secrets["private_key"].replace("\\n", "\n"),  # <- important fix
        "client_email": secrets["client_email"],
        "client_id": secrets["client_id"],
        "auth_uri": secrets["auth_uri"],
        "token_uri": secrets["token_uri"],
        "auth_provider_x509_cert_url": secrets["auth_provider_x509_cert_url"],
        "client_x509_cert_url": secrets["client_x509_cert_url"],
    }
# Construct credentials
creds_dict = parse_gcp_creds(st.secrets["gcp_service_account"])

def correct_image_orientation(image_file):
    image = Image.open(image_file)
    
    try:
        # Ambil orientation tag dari EXIF
        for orientation in ExifTags.TAGS.keys():
            if ExifTags.TAGS[orientation] == 'Orientation':
                break

        exif = image._getexif()
        if exif is not None:
            orientation_value = exif.get(orientation, None)

            if orientation_value == 3:
                image = image.rotate(180, expand=True)
            elif orientation_value == 6:
                image = image.rotate(270, expand=True)
            elif orientation_value == 8:
                image = image.rotate(90, expand=True)
    except Exception as e:
        print("No EXIF orientation found or error:", e)

    return image

def extract_text_from_image(image_bytes):
    response = textract_client.detect_document_text(Document={'Bytes': image_bytes})
    full_text = '\n'.join(block['Text'] for block in response['Blocks'] if block['BlockType'] == 'LINE')
    return full_text.strip()

def get_next_available_row(sheet_id, credentials):
    sheets_service = build('sheets', 'v4', credentials=credentials)
    sheet = sheets_service.spreadsheets()
    result = sheet.values().get(spreadsheetId=sheet_id, range='Sheet1!A:A').execute()
    values = result.get('values', [])
    return len(values) + 1

def send_to_sheets(sheet_id, store_name, date, tax, total, items, image_url):
    SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]    
    credentials = service_account.Credentials.from_service_account_info(
        creds_dict,
        scopes=SCOPES
    )

    try:
        sheets_service = build('sheets', 'v4', credentials=credentials)
        next_row = get_next_available_row(sheet_id, credentials)

        item_rows = []
        for i, (name, price) in enumerate(items):
            if i == 0:
                item_rows.append([
                    store_name,
                    date,
                    name,
                    f"${price}",
                    f"${tax}",
                    f"${total}",
                    image_url
                ])
            else:
                item_rows.append([
                    '', '', name, f"${price}", '', '', ''
                ])

        sheets_service.spreadsheets().values().update(
            spreadsheetId=sheet_id,
            range=f'Sheet1!A{next_row}',
            valueInputOption='RAW',
            body={'values': item_rows}
        ).execute()
        return True
    except HttpError as err:
        st.error(f"Error sending to Google Sheets: {err}")
        return False
    except Exception as e:
        st.error(f"Unexpected error: {str(e)}")
        return False


def parse_walmart(full_text):
    lines = full_text.splitlines()
    store_name = next((line.strip() for line in lines if re.match(r'^[A-Za-z\s&/.]+$', line.strip()) and len(line.strip()) > 3), 'Not found')
    
    date_match = re.findall(r'(\d{2}/\d{2}/\d{2})\s*\n\s*(\d{2}:\d{2}:\d{2})', full_text)
    transaction_date = f"{date_match[-1][0]} {date_match[-1][1]}" if date_match else "Not found"

    total_match = re.search(r'\bTOTAL\b[^\n]*\n([\d,]+\.\d{2})', full_text, re.IGNORECASE)
    total = total_match.group(1) if total_match else "Not found"

    tax_match = re.search(r'6.2000.*?\n([\d,]+\.\d{2})', full_text, re.IGNORECASE)
    tax = tax_match.group(1) if tax_match else "Not found"

    filtered_items = []
    exclude_keywords = {'TOTAL', 'TAX', 'CHANGE', 'DEBIT', 'SALE', 'SUBTOTAL', 'AID', 'NETWORK', 'TERMINAL', 'PAY FROM', 'US DEBIT', 'REF #', 'Get free', 'Scan for', 'Low prices'}
    item_pattern = re.compile(r'^[A-Z][A-Z0-9\s]+$')
    price_pattern = re.compile(r'^\d+\.\d{2}\s*[XT]?$')

    current_item = None
    for line in lines:
        line = line.strip()
        if any(keyword in line.upper() for keyword in exclude_keywords):
            continue
        if item_pattern.match(line) and not price_pattern.match(line):
            current_item = line
        elif price_pattern.match(line) and current_item:
            price = line.split()[0]
            filtered_items.append((current_item, price))
            current_item = None

    return store_name, transaction_date, tax, total, filtered_items

def parse_kum_and_go(full_text):
    store_name_match = re.match(r'^([A-Za-z&\s]+)', full_text)
    store_name = store_name_match.group(1).strip() if store_name_match else "Not found"

    date_match = re.search(r'(?m)^(\d{1,2}/\d{1,2}/\d{4})\s*[\r\n]+(\d{1,2}:\d{2}:\d{2}\s+[AP]M)$', full_text)
    transaction_date = f"{date_match.group(1)} {date_match.group(2)}" if date_match else "Not found"

    total_match = re.search(r'(?<!Sub\s)Total\s*=?\s*\$?([\d,]+\.\d{2})', full_text, re.IGNORECASE)
    total = total_match.group(1) if total_match else "Not found"

    tax_match = re.search(r'Tax\s*=?\s*\$?([\d,]+\.\d{2})', full_text, re.IGNORECASE)
    tax = tax_match.group(1) if tax_match else "Not found"

    item_pattern = re.compile(r'^([A-Z&\s]{3,}?)\s+\d+\s+[\d\.]+\s+([\d\.]+)$', re.MULTILINE)
    items = item_pattern.findall(full_text)

    filtered_items = []
    exclude_keywords = {'TOTAL', 'TAX', 'CHANGE', 'DEBIT', 'SALE', 'SUBTOTAL', 'WIRELESS FEE'}
    for name, price in items:
        if any(keyword in name.upper() for keyword in exclude_keywords):
            continue
        filtered_items.append((name.strip(), price))

    return store_name, transaction_date, tax, total, filtered_items

def parse_generic(full_text):
    store_name_match = re.match(r'^(.+?)\s+#\d+', full_text)
    store_name = store_name_match.group(1).strip() if store_name_match else "Not found"

    date_match = re.search(r'(\d{2}/\d{2}/\d{4})\s+(\d{1,2}:\d{2}:\d{2}\s+[APM]{2})', full_text)
    transaction_date = f"{date_match.group(1)} {date_match.group(2)}" if date_match else "Not found"

    total_match = re.search(r'Total\s*=?\s*\$?([\d,]+\.\d{2})', full_text)
    total = total_match.group(1) if total_match else "Not found"

    tax_match = re.search(r'Tax\s*=?\s*\$?([\d,]+\.\d{2})', full_text, re.IGNORECASE)
    tax = tax_match.group(1) if tax_match else "Not found"

    item_pattern = re.compile(r'([A-Z\s]{3,}?)\s+\$?([\d,]+\.\d{2})')
    items = item_pattern.findall(full_text)

    filtered_items = []
    exclude_keywords = {'TOTAL', 'TAX', 'CHANGE', 'DEBIT', 'SALE', 'SUBTOTAL'}
    for name, price in items:
        if any(keyword in name.strip().upper() for keyword in exclude_keywords):
            continue
        filtered_items.append((name.strip(), price))

    return store_name, transaction_date, tax, total, filtered_items

def parse_wells_fargo(full_text):
    first_line = full_text.splitlines()[0]
    store_name_match = re.match(r'^([A-Z&.\-\s]+)$', first_line.strip())
    store_name = store_name_match.group(1).strip() if store_name_match else "Not found"

    date_match = re.search(r'Date:\s*(\d{2}/\d{2}/\d{2})\s*.*?Time:\s*(\d{2}:\d{2}\s*[AP]M)', full_text, re.IGNORECASE)
    transaction_date = f"{date_match.group(1)} {date_match.group(2)}" if date_match else "Not found"

    total_match = re.search(r'Amount:\s*=?\s*\$?([\d,]+\.\d{2})', full_text, re.IGNORECASE)
    total = total_match.group(1) if total_match else "Not found"

    return store_name, transaction_date, "N/A", total, []

def parse_get_n_go(full_text):
    store_name_match = re.match(r'^(.+?)\s+#\d+', full_text)
    store_name = store_name_match.group(1).strip() if store_name_match else "Not found"

    date_match = re.search(r'(\d{2}/\d{2}/\d{4})\s+(\d{1,2}:\d{2}:\d{2}\s+[APM]{2})', full_text)
    transaction_date = f"{date_match.group(1)} {date_match.group(2)}" if date_match else "Not found"

    total_match = re.search(r'Total\s*=?\s*\$?([\d,]+\.\d{2})', full_text)
    total = total_match.group(1) if total_match else "Not found"

    tax_match = re.search(r'Tax\s*=?\s*\$?([\d,]+\.\d{2})', full_text, re.IGNORECASE)
    tax = tax_match.group(1) if tax_match else "Not found"

    item_pattern = re.compile(r'([A-Z\s]{3,}?)\s+\$?([\d,]+\.\d{2})')
    items = item_pattern.findall(full_text)

    filtered_items = []
    exclude_keywords = {'TOTAL', 'TAX', 'CHANGE', 'DEBIT', 'SALE', 'SUBTOTAL'}
    for name, price in items:
        if any(keyword in name.strip().upper() for keyword in exclude_keywords):
            continue
        filtered_items.append((name.strip(), price))

    return store_name, transaction_date, tax, total, filtered_items

def parse_pizza_ranch(full_text):
    lines = full_text.splitlines()
    store_name = next((line.strip() for line in lines if re.match(r'^[A-Za-z\s#]+$', line.strip()) and len(line.strip()) > 3), 'Not found')

    date_time_match = re.search(r'Date:\s*(\d{1,2}/\d{1,2}/\d{2}),?\s*(\d{1,2}:\d{2}\s*[AP]M)', full_text, re.IGNORECASE)
    transaction_date = f"{date_time_match.group(1)} {date_time_match.group(2)}" if date_time_match else "Not found"

    total_match = re.search(r'Total:\s*\$\s*([\d,]+\.\d{2})(?![^\n]*Paid)', full_text)
    total = total_match.group(1) if total_match else "Not found"

    tax_match = re.search(r'Total Tax:\s*\$\s*([\d,]+\.\d{2})', full_text, re.IGNORECASE)
    tax = tax_match.group(1) if tax_match else "Not found"

    filtered_items = []
    exclude_keywords = {
        'TOTAL', 'TAX', 'CHANGE', 'DEBIT', 'SALE', 'SUBTOTAL', 
        'ORDER', 'DINEIN', 'SERVER', 'DATE', 'TERMINAL', 
        'TRANSACTION', 'REFERENCE', 'ENTRY', 'CHIP', 'ISSUER',
        'APPROVAL', 'RESPONSE', 'VERIFIED', 'COUNT', 'PAID',
        'VISIT', 'MERCHANT', 'CALL', 'REWARDS', 'COPY', 'BILL',
        'XXXX', 'AUTH', 'MODE', 'ARC', 'ARQC', 'US DEBIT'
    }

    for i, line in enumerate(lines[:-1]):
        line = line.strip()
        next_line = lines[i+1].strip() if i+1 < len(lines) else ""
        
        if any(keyword in line.upper() for keyword in exclude_keywords):
            continue
        
        price_match = re.match(r'^\$\d+\.\d{2}$', next_line)
        if price_match and line and not any(char.isdigit() for char in line):
            price = price_match.group(0).replace('$', '')
            filtered_items.append((line, price))

    if not filtered_items:
        buffet_match = re.search(r'^([A-Za-z\s]+Buffet)\s*\n\s*\$\s*([\d,]+\.\d{2})', full_text, re.MULTILINE)
        if buffet_match:
            filtered_items.append((buffet_match.group(1).strip(), buffet_match.group(2)))

    return store_name, transaction_date, tax, total, filtered_items

def parse_kpot(full_text):
    lines = full_text.splitlines()
    store_name = next((line.strip() for line in lines if re.match(r'^[A-Za-z\s&]+$', line.strip()) and len(line.strip()) > 3), 'Not found')

    date_time_match = re.search(r'Ordered:\s*(\d{1,2}/\d{1,2}/\d{2})\s*(\d{1,2}:\d{2}\s*[AP]M)', full_text, re.IGNORECASE)
    transaction_date = f"{date_time_match.group(1)} {date_time_match.group(2)}" if date_time_match else "Not found"

    total_match = re.search(r'Total\s*\n\s*\$\s*([\d,]+\.\d{2})', full_text)
    total = total_match.group(1) if total_match else "Not found"

    tax_match = re.search(r'Tax\s*\n\s*\$\s*([\d,]+\.\d{2})', full_text, re.IGNORECASE)
    tax = tax_match.group(1) if tax_match else "Not found"

    filtered_items = []
    exclude_keywords = {
        'TOTAL', 'TAX', 'TIP', 'DISCOUNT', 'SUBTOTAL', 'PRE-DISCOUNT',
        'INPUT', 'TYPE', 'VISA', 'DEBIT', 'XXXX', 'TIME', 'TRANSACTION',
        'AUTHORIZATION', 'APPROVED', 'APPROVAL', 'CODE', 'PAYMENT',
        'APPLICATION', 'LABEL', 'TERMINAL', 'CARD', 'READER', 'GRACE',
        'SUGGESTED', 'ADDITIONAL', 'PERCENTAGES', 'POWERED', 'CHECK',
        'TABS', 'TABLE', 'GUEST', 'COUNT', 'SERVER', 'ORDERED'
    }

    for i, line in enumerate(lines[:-1]):
        line = line.strip()
        next_line = lines[i+1].strip() if i+1 < len(lines) else ""
        
        if any(keyword in line.upper() for keyword in exclude_keywords):
            continue
        
        item_match = re.match(r'^\d+\s+([A-Za-z\s]+)$', line)
        price_match = re.match(r'^\$\d+\.\d{2}$', next_line)
        
        if item_match and price_match:
            item_name = item_match.group(1).strip()
            price = price_match.group(0).replace('$', '')
            filtered_items.append((item_name, price))
        elif re.match(r'^[A-Za-z\s]+$', line) and price_match and len(line) > 3:
            price = price_match.group(0).replace('$', '')
            filtered_items.append((line.strip(), price))

    return store_name, transaction_date, tax, total, filtered_items

def parse_hy_vee(full_text):
    lines = full_text.splitlines()
    store_name = 'Not found'
    for line in lines:
        if re.match(r'^[A-Za-z\s]+$', line.strip()) and len(line.strip()) > 3:
            if "RECEIPT" not in line and "REPRINT" not in line:
                store_name = line.strip()
                break

    date_time_match = re.search(r'(\d{2}/\d{2}/\d{2})\s+(\d{1,2}:\d{2}\s+[AP]M)', full_text)
    transaction_date = f"{date_time_match.group(1)} {date_time_match.group(2)}" if date_time_match else "Not found"

    total_match = re.search(r'TOTAL\s+([\d,]+\.\d{2})', full_text)
    total = total_match.group(1) if total_match else "Not found"

    tax_matches = re.findall(r'@\s+[\d.]+%\s+=\s+([\d,]+\.\d{2})', full_text)
    tax = str(sum(float(t.replace(',', '')) for t in tax_matches)) if tax_matches else "Not found"

    filtered_items = []
    exclude_keywords = {
        'TOTAL', 'TAX', 'SUBTOTAL', 'DEBIT', 'PURCHASE', 'VISA', 'CHIP',
        'REF#', 'TRANSACTION', 'APPROVED', 'US DEBIT', 'AAC', 'ONLINE',
        'VERIFIED', 'MODE', 'AID', 'TVR', 'TAO', 'ISL', 'AN', 'CASHIER',
        'DATE', 'TIME', 'STORE', 'POS', 'EMD', 'TRX', 'TELL', 'VISIT',
        'SURVEY', 'RULES', 'PURCHASE', 'NECESSARY', 'SWEEPSTAKES'
    }

    current_item = None
    for line in lines:
        line = line.strip()
        
        if any(keyword in line.upper() for keyword in exclude_keywords):
            continue
        
        if re.match(r'^\d{5,}$', line):
            continue
        
        if re.match(r'^[A-Z][A-Z0-9\s&]+$', line) and not re.match(r'^[A-Z]+\s+[A-Z]+\s*$', line):
            current_item = line
        elif current_item and re.match(r'^[\d,]+\.\d{2}\s+[xtf]$', line.lower()):
            price = re.sub(r'[xtf]\s*$', '', line, flags=re.IGNORECASE).strip()
            filtered_items.append((current_item, price))
            current_item = None
        elif current_item and re.match(r'^[\d,]+\.\d{2}$', line):
            filtered_items.append((current_item, line))
            current_item = None

    return store_name, transaction_date, tax, total, filtered_items

def parse_hyvee_fast_fresh(full_text):
    store_name_match = re.match(r'^([A-Za-z&\-\s]+)', full_text)
    store_name = store_name_match.group(1).strip() if store_name_match else "Not found"

    date_match = re.search(r'Date:\s*(\d{2}/\d{2}/\d{2})', full_text)
    time_match = re.search(r'Time:\s*(\d{2}:\d{2}:\d{2})', full_text)
    transaction_date = f"{date_match.group(1)} {time_match.group(1)}" if date_match and time_match else "Not found"

    total_match = re.search(r'TOTAL SALE\s*\$\s*([\d,]+\.\d{2})', full_text)
    total = total_match.group(1) if total_match else "Not found"

    tax = "0.00"

    filtered_items = []
    exclude_keywords = {
        'INVOICE', 'PUMP', 'GALLONS', 'PRICE', 'DEBIT', 
        'TOTAL', 'MERCH', 'TERM', 'PURCHASE', 'CHIP',
        'SEG', 'REF', 'APPR', 'CODE', 'TRANSACTION',
        'APPROVED', 'ARQC', 'ONLINE', 'VERIFIED', 'MODE',
        'AID', 'TVR', 'IAD', 'TSI', 'ARC', 'THANK YOU'
    }

    lines = full_text.splitlines()
    for i, line in enumerate(lines):
        line = line.strip()
        
        if any(keyword in line.upper() for keyword in exclude_keywords):
            continue
        
        if re.match(r'^[A-Z]+$', line) and i+1 < len(lines):
            next_line = lines[i+1].strip()
            price_match = re.match(r'^\$\s*([\d,]+\.\d{2})$', next_line)
            if price_match:
                filtered_items.append((f"{line} GAS", price_match.group(1)))
                break

    if not filtered_items:
        product_match = re.search(r'Product\s+Amount\s+([A-Z]+)\s+\$\s*([\d,]+\.\d{2})', full_text)
        if product_match:
            filtered_items.append((f"{product_match.group(1)} GAS", product_match.group(2)))

    pump_match = re.search(r'Pump\s+Gallons\s+Price\s+(\d+)\s+([\d,]+\.\d{3})\s+\$\s*([\d,]+\.\d{2})', full_text)
    if pump_match:
        filtered_items.append((f"PUMP {pump_match.group(1)}: {pump_match.group(2)} gallons @ ${pump_match.group(3)}/gal", ""))

    return store_name, transaction_date, tax, total, filtered_items

def parse_holiday_stationstore(full_text):
    lines = full_text.splitlines()
    store_name = next((line.strip() for line in lines if re.match(r'^[A-Za-z\s]+$', line.strip()) and len(line.strip()) > 3 and "Order Number" not in line), 'Not found')

    date_time_match = re.match(r'(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)', full_text)
    transaction_date = date_time_match.group(1) if date_time_match else "Not found"

    total_match = re.search(r'(?<!Sub.\s)Total:\s*\$\s*([\d,]+\.\d{2})', full_text)
    total = total_match.group(1) if total_match else "Not found"

    tax_match = re.search(r'Tax:\s*\$\s*([\d,]+\.\d{2})', full_text)
    tax = tax_match.group(1) if tax_match else "Not found"

    filtered_items = []
    exclude_keywords = {
        'ORDER', 'NUMBER', 'REGISTER', 'SUB', 'TOTAL', 'TAX', 
        'DISCOUNT', 'MASTERCARD', 'CHANGE', 'SALE', 'CARD', 'NUM',
        'CHIP', 'READ', 'TERMINAL', 'APPROVAL', 'SEQUENCE', 'USD',
        'DEBIT', 'MODE', 'AID', 'TVR', 'IAD', 'TSI', 'ARC', 'ARCC',
        'THANK', 'COME', 'AGAIN', 'HOLIDAY', 'STATIONSTORE'
    }

    for line in full_text.splitlines():
        line = line.strip()
        
        if any(keyword in line.upper() for keyword in exclude_keywords):
            continue
        
        if not line or re.match(r'^[\d\s]+$', line):
            continue
        
        item_match = re.match(r'^(T\s+)?(.+?)\s+(-?\$?\d+\.\d{2})(\s*[A-Z]*)?$', line)
        if item_match:
            item_name = item_match.group(2).strip()
            price = item_match.group(3).replace('$', '')
            filtered_items.append((item_name, price))
        elif re.match(r'^([\d.]+\s+[A-Z]+\s+.+?\s+-?\$?\d+\.\d{2})', line):
            parts = line.rsplit(' ', 1)
            filtered_items.append((parts[0].strip(), parts[1].replace('$', '')))

    return store_name, transaction_date, tax, total, filtered_items

def parse_corners_pantry(full_text):
    lines = [line.strip() for line in full_text.splitlines() if line.strip()]
    store_name = next((line for line in lines if not re.match(r'^\d', line) and 
                      not any(x in line.lower() for x in ['street', 'ave', 'st', 'register']) and
                      len(line) > 3), 'Not found')

    date_time_match = re.search(r'(\d{2}/\d{2}/\d{2}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)', full_text)
    transaction_date = date_time_match.group(1) if date_time_match else "Not found"

    total_match = re.search(r'Total\s*=\s*\$\s*([\d,]+\.\d{2})', full_text)
    total = total_match.group(1) if total_match else "Not found"

    tax_match = re.search(r'Tax\s*=\s*\$\s*([\d,]+\.\d{2})', full_text)
    tax = tax_match.group(1) if tax_match else "Not found"

    filtered_items = []
    exclude_keywords = {
        'STREET', 'REGISTER', 'TRANS', 'DO', 'ID', 'CASHIER', 'SUBTOTAL',
        'TAX', 'TOTAL', 'CHANGE', 'DUE', 'DEBIT', 'INVOICE', 'AUTH',
        'REF', 'US', 'DEBIT', 'AID', 'ARDC', 'PTN', 'VERIFIED',
        'SIGNATURE', 'REQUIRED', 'MAESTRO', 'DOA', 'TERMINAL', 'SEQ',
        'NUM', 'SALE', 'ENTRY', 'CHIP', 'BATCH', 'WORKSTATION', 'SAVE',
        'FUEL', 'OFFER', 'VISIT', 'COMPLETE', 'SURVEY', 'TELL', 'VISIT',
        'SERVICE', 'GIFT', 'CARD', 'CARDHOLDER', 'COPY', '---'
    }

    for i, line in enumerate(full_text.splitlines()):
        line = line.strip()
        
        if any(keyword in line.upper() for keyword in exclude_keywords):
            continue
        
        if not line or re.match(r'^[\d\s-]+$', line):
            continue
        
        if i+1 < len(full_text.splitlines()):
            next_line = full_text.splitlines()[i+1].strip()
            price_match = re.match(r'^\$\d+\.\d{2}', next_line)
            if price_match and not any(keyword in line.upper() for keyword in exclude_keywords):
                price = price_match.group(0).replace('$', '')
                filtered_items.append((line, price))
                continue
        
        item_match = re.match(r'^([A-Z][A-Z\s]+)\s+\$(\d+\.\d{2})', line)
        if item_match:
            item_name = item_match.group(1).strip()
            price = item_match.group(2)
            filtered_items.append((item_name, price))
            continue

    return store_name, transaction_date, tax, total, filtered_items

def parse_caseys(full_text):
    store_name = full_text.split('\n')[0].strip()

    date_match = re.search(r'(\d{1,2}/\d{1,2}/\d{2})', full_text)
    time_match = re.search(r'(\d{2}:\d{2}:\d{2})', full_text)
    transaction_date = f"{date_match.group(1)} {time_match.group(1)}" if date_match and time_match else "Not found"

    total_match = re.search(r'(?<!Sub)Total\s*\n\s*([\d,]+\.\d{2})', full_text)
    total = total_match.group(1) if total_match else "Not found"

    state_tax_match = re.search(r'State Tax\s*\n\s*([\d,]+\.\d{2})', full_text)
    local_tax_match = re.search(r'Local/City Tax\s*\n\s*([\d,]+\.\d{2})', full_text)
    tax = str(float(state_tax_match.group(1)) + float(local_tax_match.group(1))) if state_tax_match and local_tax_match else "Not found"

    filtered_items = []
    exclude_keywords = {
        'REGISTER', 'RECEIPT', 'TYPE', 'SALE', 'SUBTOTAL', 'TAX',
        'TOTAL', 'RECEIVED', 'DEBIT', 'CHIP', 'READ', 'TRAN', 'RESPONSE',
        'APPROVED', 'CARD', 'NUM', 'MERCHANT', 'TERMINAL', 'DEVICE',
        'APPROVAL', 'DATE/TIME', 'BATCH', 'SEQ', 'REFERENCE', 'USD',
        'AID', 'TVR', 'IAD', 'TSI', 'ARQC', 'ISSUER', 'VERIFIED', 'VISIT'
    }

    lines = full_text.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        if any(keyword in line.upper() for keyword in exclude_keywords):
            i += 1
            continue
        
        item_match = re.match(r'^(\d+)\s+([A-Za-z].*)$', line)
        if item_match:
            quantity = item_match.group(1)
            item_name = item_match.group(2)
            
            if i+1 < len(lines):
                price_line = lines[i+1].strip()
                price_match = re.match(r'^([\d,]+\.\d{2})$', price_line)
                if price_match:
                    filtered_items.append((f"{quantity} {item_name}", price_match.group(1)))
                    i += 2
                    continue
        i += 1

    return store_name, transaction_date, tax, total, filtered_items

def parse_caseys_store(full_text):
    store_name_match = re.match(r'^([A-Za-z&\-\s]+)', full_text)
    store_name = store_name_match.group(1).strip() if store_name_match else "Not found"

    date_match = re.search(r'Date:\s*(\d{2}/\d{2}/\d{2})', full_text)
    time_match = re.search(r'Time:\s*(\d{2}:\d{2}:\d{2})', full_text)
    transaction_date = f"{date_match.group(1)} {time_match.group(1)}" if date_match and time_match else "Not found"

    total_match = re.search(r'Total Sale\s*\$\s*([\d,]+\.\d{2})', full_text)
    total = total_match.group(1) if total_match else "Not found"

    tax = "0.00"

    filtered_items = []
    exclude_keywords = {
        'INVOICE', 'PUMP', 'GALLONS', 'PRICE', 'DEBIT', 
        'TOTAL', 'MERCH', 'TERM', 'PURCHASE', 'CHIP',
        'SEG', 'REF', 'APPR', 'CODE', 'TRANSACTION',
        'APPROVED', 'ARQC', 'ONLINE', 'VERIFIED', 'MODE',
        'AID', 'TVR', 'IAD', 'TSI', 'ARC', 'THANK YOU'
    }

    lines = full_text.splitlines()
    for i, line in enumerate(lines):
        line = line.strip()
        
        if any(keyword in line.upper() for keyword in exclude_keywords):
            continue
        
        if re.match(r'^[A-Z]+$', line) and i+1 < len(lines):
            next_line = lines[i+1].strip()
            price_match = re.match(r'^\$\s*([\d,]+\.\d{2})$', next_line)
            if price_match:
                filtered_items.append((f"{line} GAS", price_match.group(1)))
                break

    if not filtered_items:
        product_match = re.search(r'Product\s+Amount\s+([A-Z]+)\s+\$\s*([\d,]+\.\d{2})', full_text)
        if product_match:
            filtered_items.append((f"{product_match.group(1)} GAS", product_match.group(2)))

    pump_match = re.search(r'Pump\s+Gallons\s+Price\s+(\d+)\s+([\d,]+\.\d{3})\s+\$\s*([\d,]+\.\d{2})', full_text)
    if pump_match:
        filtered_items.append((f"PUMP {pump_match.group(1)}: {pump_match.group(2)} gallons @ ${pump_match.group(3)}/gal", ""))

    return store_name, transaction_date, tax, total, filtered_items

def upload_image_to_drive(image_bytes, filename="receipt.jpg", folder_id=None):
    SCOPES = ["https://www.googleapis.com/auth/drive"]
    credentials = service_account.Credentials.from_service_account_info(
        creds_dict,
        scopes=SCOPES
    )

    try:
        drive_service = build('drive', 'v3', credentials=credentials)

        file_metadata = {'name': filename}
        if folder_id:
            file_metadata['parents'] = [folder_id]

        media = MediaIoBaseUpload(io.BytesIO(image_bytes), mimetype='image/jpeg')

        file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()

        # Set permission to public
        drive_service.permissions().create(
            fileId=file['id'],
            body={'type': 'anyone', 'role': 'reader'}
        ).execute()

        return f"https://drive.google.com/uc?id={file['id']}"
    except Exception as e:
        st.error(f"Error uploading to Google Drive: {str(e)}")
        return None

# === Streamlit UI ===
st.title("🧾 Christo Personal Tax Reduction")

format_option = st.selectbox("Select Receipt Format", ["Walmart", "Kum & Go", "Wells Fargo", "Pizza Ranch", "Kpot", "HyVee", "HyVee Fast & Fresh ", "Holiday Station Store", "Corner's Pantry", "Casey's", "Casey's Store", "Generic"])
uploaded_file = st.file_uploader("Upload a receipt image", type=["jpg", "jpeg", "png"])

if uploaded_file:
    image_bytes = uploaded_file.read()
    full_text = extract_text_from_image(image_bytes)

    if format_option == "Walmart":
        store_name, date, tax, total, items = parse_walmart(full_text)
    elif format_option == "Kum & Go":
        store_name, date, tax, total, items = parse_kum_and_go(full_text)
    elif format_option == "Wells Fargo":
        store_name, date, tax, total, items = parse_wells_fargo(full_text)
    elif format_option == "Pizza Ranch":
        store_name, date, tax, total, items = parse_pizza_ranch(full_text)
    elif format_option == "Kpot":
        store_name, date, tax, total, items = parse_kpot(full_text)
    elif format_option == "HyVee":
        store_name, date, tax, total, items = parse_hy_vee(full_text)
    elif format_option == "HyVee Fast 7 Fresh":
        store_name, date, tax, total, items = parse_hyvee_fast_fresh(full_text)
    elif format_option == "Holiday Station Store":
        store_name, date, tax, total, items = parse_holiday_stationstore(full_text)
    elif format_option == "Corner's Pantry":
        store_name, date, tax, total, items = parse_corners_pantry(full_text)
    elif format_option == "Casey's":
        store_name, date, tax, total, items = parse_caseys(full_text)
    elif format_option == "Casey's Store":
        store_name, date, tax, total, items = parse_caseys_store(full_text)
    else:
        store_name, date, tax, total, items = parse_generic(full_text)

    image = correct_image_orientation(uploaded_file)
    st.image(image, caption="Uploaded Receipt", use_container_width=True)

    st.subheader("✏️ Editable Receipt Data")
    store_name = st.text_input("Store Name", store_name)
    # Try parsing date string
    try:
        parsed_date = datetime.datetime.strptime(date, "%dd-%mm-%YYYY").date()
    except (TypeError, ValueError):
        parsed_date = datetime.date.today()

    date = st.date_input("Transaction Date", parsed_date)
    tax = st.text_input("Tax", tax)
    total = st.text_input("Total", total)

    st.write("**Items (editable):**")
    edited_items = []
    for idx, (name, price) in enumerate(items):
        col1, col2 = st.columns([3, 1])
        with col1:
            item_name = st.text_input(f"Item Name {idx+1}", value=name, key=f"name_{idx}")
        with col2:
            item_price = st.text_input(f"Price {idx+1}", value=price, key=f"price_{idx}")
        edited_items.append((item_name, item_price))

    if st.button("📤 Submit to Google Sheets"):
        try:
            image_url = upload_image_to_drive( image_bytes, filename=uploaded_file.name, folder_id=folder_id)
            success = send_to_sheets(sheet_id,  store_name, date, tax, total, edited_items, image_url)
            if success:
                st.success("✅ Data and image successfully submitted to Google Sheets!")
                st.markdown(f"[📷 View Image in Drive]({image_url})")
                st.markdown(f"[🔗 View Google Sheets]({spreadsheet_url})")
        except Exception as e:
            st.error(f"Error during submission: {e}")

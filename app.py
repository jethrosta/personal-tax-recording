import cv2
import numpy as np
from imutils.perspective import four_point_transform 
from PIL import Image 
import io
import streamlit as st 
import re
from google.oauth2 import service_account 
from googleapiclient.discovery import build 
from googleapiclient.errors import HttpError 
from googleapiclient.http import MediaIoBaseUpload 
import io
from PIL import Image, ExifTags 
import datetime
import base64
from mistralai import Mistral

# --- Konfigurasi Mistral AI dan Google Sheets ---
mistral_api_key = st.secrets["mistralai"]["mistral_api_key"]
# Google Sheets / Drive credentials
sheet_id = st.secrets["google"]["sheet_id"]
folder_id = st.secrets["google"]["folder_id"]
spreadsheet_url = st.secrets["google"]["spreadsheet_url"]

# Fungsi untuk mengubah ukuran gambar
def resizer(image, width=500):
    h, w, c = image.shape
    height = int((h / w) * width)
    return cv2.resize(image, (width, height)), (width, height)

# Fungsi untuk memindai dokumen
def document_scanner(image):
    img_re, size = resizer(image)
    detail = cv2.detailEnhance(img_re, sigma_s=20, sigma_r=0.15)
    gray = cv2.cvtColor(detail, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (5,5),1)
    edge = cv2.Canny(blur,75,200)
    kernel = np.ones((5,5),np.uint8)
    dilate = cv2.dilate(edge,kernel,iterations=1)
    closing = cv2.morphologyEx(dilate, cv2.MORPH_CLOSE, kernel)

    cnts, _ = cv2.findContours(closing, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    cnts = sorted(cnts, key=cv2.contourArea, reverse=True)

    four_points = None
    for c in cnts:
        peri = cv2.arcLength(c, True)
        approx = cv2.approxPolyDP(c, 0.02 * peri, True)
        if len(approx) == 4:
            four_points = np.squeeze(approx)
            break

    if four_points is None:
        raise Exception("Document boundary not found")

    multiplier = image.shape[1] / size[0]
    four_points = (four_points * multiplier).astype(int)
    wrap = four_point_transform(image, four_points)
    return wrap

# Fungsi untuk memindai dan mengekstrak gambar
def scan_and_extract(image_bytes):
    pil = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    np_img = np.array(pil)[:, :, ::-1]
    
    # Scan dokumen
    try:
        scanned = document_scanner(np_img)
        is_success, buffer = cv2.imencode(".jpg", scanned)
        if not is_success:
            raise Exception("Encoding failed")
        return buffer.tobytes()
    except Exception as e:
        st.warning(f"⚠️ Scan gagal: {e}. Menggunakan gambar asli.")
        return image_bytes

# Fungsi untuk mendekode kredensial GCP
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

# Mengonfigurasi kredensial
creds_dict = parse_gcp_creds(st.secrets["gcp_service_account"])

# Fungsi untuk memperbaiki orientasi gambar ketika ditampilkan ke user
def correct_image_orientation(image_file):
    image = Image.open(image_file)
    
    try:
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

# Fungsi untuk mengekstrak teks dari gambar menggunakan layanan OCR
def extract_text_from_image(image_bytes):
    """
    Extracts text from an image using Mistral AI's OCR service.
    
    Args:
        image_bytes (bytes): The image data in bytes.
        
    Returns:
        str: The extracted text from the image, or an error message if OCR fails.
    """
    try:
        # inisialisasi Client Mistral AI
        client = Mistral(api_key=mistral_api_key)

        # Encode image bytes to base64
        base64_image = base64.b64encode(image_bytes).decode('utf-8')

        # Call Mistral AI OCR service
        ocr_response = client.ocr.process(model="mistral-ocr-latest",
                                            document={
                                                "type": "image_url",
                                                "image_url": f"data:image/jpeg;base64,{base64_image}"
                                            },
                                            include_image_base64=True
                                        )
        
        # Mengakses teks dari ocr_response.pages[0].markdown
        if ocr_response and ocr_response.pages and len(ocr_response.pages) > 0:
            full_text = ocr_response.pages[0].markdown
        else:
            full_text = ""
            st.warning("Respons OCR dari Mistral AI tidak mengandung struktur 'pages' atau 'markdown' yang diharapkan. Mohon periksa format respons.")
            st.code(str(ocr_response)) # Tampilkan respons mentah untuk debugging

        return full_text.strip()
    except Exception as e:
        st.error(f"Error extracting text with Mistral AI OCR: {e}")
        return f"Error: Failed to extract text - {e}"

# Fungsi untuk mendapatkan baris berikutnya yang tersedia di Google Sheets
def get_next_available_row(sheet_id, credentials):
    sheets_service = build('sheets', 'v4', credentials=credentials)
    sheet = sheets_service.spreadsheets()
    result = sheet.values().get(spreadsheetId=sheet_id, range='Sheet1').execute()
    values = result.get('values', [])
    return len(values) + 1

# Fungsi untuk mengirim data ke Google Sheets
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
        if not items:
            # Fallback jika tidak ada item
            item_rows.append([
                store_name,
                date,
                '',         # Item kosong
                '',         # Price kosong
                f"${tax}",
                f"${total}",
                image_url
            ])
        else:
            for i, (name, price) in enumerate(items):
                if i == 0:
                    item_rows.append([
                        store_name,
                        date,
                        name,
                        float(price.replace(',', '')),
                        f"${tax}",
                        f"${total}",
                        image_url
                    ])
                else:
                    item_rows.append([
                        '', '', name, float(price.replace(',', '')), '', '', ''
                    ])

        sheets_service.spreadsheets().values().append(
            spreadsheetId=sheet_id,
            range='Sheet1',
            valueInputOption='RAW',
            insertDataOption='INSERT_ROWS',
            body={'values': item_rows}
        ).execute()
        return True
    except HttpError as err:
        st.error(f"Error sending to Google Sheets: {err}")
        return False
    except Exception as e:
        st.error(f"Unexpected error: {str(e)}")
        return False

# Fungsi untuk mem-parsing teks dari struk Walmart
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

# Fungsi untuk mem-parsing teks dari struk Kum & Go
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

# Fungsi untuk mem-parsing teks dari struk generik
def parse_generic(full_text):
    first_line = full_text.strip().split('\n')[0]  # Get the first line
    store_name = ' '.join(first_line.strip().split()) 

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

# Fungsi untuk mem-parsing teks dari struk Wells Fargo
def parse_wells_fargo(full_text):
    first_line = full_text.splitlines()[0]
    store_name_match = re.match(r'^([A-Z&.\-\s]+)$', first_line.strip())
    store_name = store_name_match.group(1).strip() if store_name_match else "Not found"

    date_match = re.search(r'Date:\s*(\d{2}/\d{2}/\d{2})\s*.*?Time:\s*(\d{2}:\d{2}\s*[AP]M)', full_text, re.IGNORECASE)
    transaction_date = f"{date_match.group(1)} {date_match.group(2)}" if date_match else "Not found"

    total_match = re.search(r'Amount:\s*=?\s*\$?([\d,]+\.\d{2})', full_text, re.IGNORECASE)
    total = total_match.group(1) if total_match else "Not found"

    return store_name, transaction_date, "N/A", total, []

# Fungsi untuk mem-parsing teks dari struk Get N Go
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

# Fungsi untuk mem-parsing teks dari struk Pizza Ranch
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

# Fungsi untuk mem-parsing teks dari struk K-Pot
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

# Fungsi untuk mem-parsing teks dari struk Hy-Vee
def parse_hy_vee(full_text):
    lines = full_text.splitlines()
    store_name = 'Not found'
    for line in lines:
        if re.match(r'^[A-Za-z\s]+$', line.strip()) and len(line.strip()) > 3:
            if "RECEIPT" not in line and "REPRINT" not in line:
                store_name = line.strip()
                break

    date_time_match = re.search(r'(\d{2}/\d{2}/\d{2})\s+(\d{1,2}:\d{2}\s*[AP]M)', full_text)
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

# Fungsi untuk mem-parsing teks dari struk Hy-Vee Fast Fresh
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

# Fungsi untuk mem-parsing teks dari struk Holiday Station Store
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

# Fungsi untuk mem-parsing teks dari struk Corners Pantry
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

# Fungsi untuk mem-parsing teks dari struk Casey's
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

# Fungsi untuk mem-parsing teks dari struk Casey's Store
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

# Fungsi untuk mengirim gambar ke drive
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
    with st.spinner("📐 Scanning dokumen..."):
        clean_bytes = scan_and_extract(image_bytes)

    with st.spinner("🧾 Proses OCR via Mistral AI..."):
        full_text = extract_text_from_image(clean_bytes)

    # Pastikan full_text bukan string error dari fungsi extract_text_from_image
    if full_text.startswith("Error:"):
        st.error(f"Gagal memproses OCR: {full_text}")
    else:
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
        elif format_option == "HyVee Fast & Fresh": # Perbaikan nama opsi di sini
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

        # Attempt to parse the detected date, or fallback to today's date
        try:
            parsed_date = datetime.datetime.strptime(date, "%m/%d/%Y").date()
        except (TypeError, ValueError):
            parsed_date = datetime.date.today()

        # Let user edit the date
        date_obj = st.date_input("Transaction Date", parsed_date)
        date = date_obj.strftime("%m/%d/%Y")

        tax = st.text_input("Tax", str(tax) if tax is not None else "")
        total = st.text_input("Total", str(total) if total is not None else "")

        # ------------------- ITEM HANDLING SECTION -------------------

        st.subheader("🛍️ Items (Editable, Addable, Removable)")

        # Inisialisasi state list untuk menyimpan item
        if "manual_items" not in st.session_state:
            st.session_state.manual_items = items.copy()

        # Tampilkan item yang bisa diedit dan dihapus
        edited_items = []
        for idx, (name, price) in enumerate(st.session_state.manual_items):
            col1, col2, col3 = st.columns([3, 1.5, 0.5])
            with col1:
                item_name = st.text_input(f"Item Name {idx+1}", value=name, key=f"name_{idx}")
            with col2:
                item_price = st.text_input(f"Price {idx+1}", value=price, key=f"price_{idx}")
            with col3:
                if st.button("🗑️", key=f"delete_{idx}"):
                    st.session_state.manual_items.pop(idx)
                    st.rerun()
            edited_items.append((item_name, item_price))

        # Tambah item baru
        st.markdown("---")
        st.subheader("➕ Tambah Item Manual")
        with st.form("add_item_form"):
            new_item_name = st.text_input("Nama Item")
            new_item_price = st.text_input("Harga Item ($)")
            submitted = st.form_submit_button("Tambah Item")
            if submitted:
                if new_item_name and new_item_price:
                    st.session_state.manual_items.append((new_item_name.strip(), new_item_price.strip()))
                    st.success(f"Item '{new_item_name}' berhasil ditambahkan.")
                    st.rerun()
                else:
                    st.error("Mohon isi nama dan harga item.")

        # Gunakan versi final item
        edited_items = st.session_state.manual_items

        # ------------------- SUBMIT SECTION -------------------
        
        if st.button("📤 Submit to Google Sheets"):
            #with st.spinner("Mengirim data dan gambar... Mohon tunggu 🙏"):
                try:
                    image_url = upload_image_to_drive(image_bytes, filename=uploaded_file.name, folder_id=folder_id)
                    success = send_to_sheets(sheet_id, store_name, date, tax, total, edited_items, image_url)
                    if success:
                        st.success("✅ Data dan gambar berhasil dikirim ke Google Sheets!")
                        st.markdown(f"[📷 Lihat Gambar di Drive]({image_url})")
                        st.markdown(f"[🔗 Lihat Google Sheets]({spreadsheet_url})")
                except Exception as e:
                    st.error(f"Terjadi kesalahan selama pengiriman: {e}")

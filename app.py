import streamlit as st
import boto3
import re
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload
import io
from PIL import Image, ExifTags

# --- Konfigurasi AWS dan Google Sheets ---
aws_access_key = st.secrets["aws"]["aws_access_key_id"]
aws_secret_key = st.secrets["aws"]["aws_secret_access_key"]
region = st.secrets["aws"]["region"]
sheet_id = '1Bagw_IiVFHX942ACSTRs9ET3IdP1iIjCnSo3IOUJ73U'
folder_id = '1bsWOEg0Pp_yzekRYSnqXqbtriiChwZqi'

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

format_option = st.selectbox("Select Receipt Format", ["Walmart", "Kum & Go", "Wells Fargo", "Generic"])
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
    else:
        store_name, date, tax, total, items = parse_generic(full_text)

    image = correct_image_orientation(uploaded_file)
    st.image(image, caption="Uploaded Receipt", use_container_width=True)

    st.subheader("✏️ Editable Receipt Data")
    store_name = st.text_input("Store Name", store_name)
    date = st.text_input("Transaction Date", date)
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
        except Exception as e:
            st.error(f"Error during submission: {e}")

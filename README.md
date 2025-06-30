# 🧾 Automated Tax Receipt Recording System using OCR and Google Integration

This project was designed to streamline my father's tax deduction process by automating the collection and organization of receipt data throughout the year. The core challenge was the absence of a system that could digitize and extract relevant information from receipts in a fast and structured way.

To solve this, I developed a receipt recording system powered by Optical Character Recognition (OCR) and integrated with Mistral AI's advanced OCR API. The system captures receipt images, extracts key data fields (such as merchant, date, total amount, and tax category), and logs them automatically into a Google Spreadsheet. Additionally, the original receipt images are uploaded to Google Drive, with direct links included in the spreadsheet for verification and archival purposes.

<div align="center">
   <img src="https://github.com/jethrosta/personal-tax-recording/blob/main/images/Screenshot 2025-06-15 at 14.30.00.png">
   <br>
   <img src="https://github.com/jethrosta/personal-tax-recording/blob/main/images/bills_ocr_record.gif">
</div>

## ✨ Features

- **Multi-format support**: Parses receipts from various stores (Walmart, Kum & Go, Wells Fargo, Pizza Ranch, etc.)
- **OCR Processing**: Uses [Mistral AI](https://mistral.ai/) for accurate text extraction from receipt images
- **Preprocessing Data**: Corrects image orientation using OpenCV
- **Cloud Storage**: Stores receipt images in Google Drive with public links
- **Data Organization**: Records all receipt data in Google Sheets
- **Editable Interface**: Allows manual correction of extracted data before submission

## 🛠️ Technologies Used

- **Python 3**
- **Streamlit** (Web UI)
- **Mistral AI** (OCR)
- **Google Sheets API** (Data storage)
- **Google Drive API** (Image storage)
- **OpenCV** (Image processing)

## 🔧 Setup Instructions

### Prerequisites
- Mistral AI Account with basic OCR
- Google Cloud project with Sheets and Drive APIs enabled
- Python 3.8+

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/receipt-recorder.git
   cd receipt-recorder
2. Install dependency:
   ```bash
   pip install -r requirements.txt
3. Set up your secrets:
   - Create a `.streamlit/secrets.toml` file with your credentials
   ```bash
    [mistral]
    mistral_api_key = "your_mistral_key"
    [google]
    sheet_id = "your_google_sheet_id"
    folder_id = "your_google_drive_folder_id"
    spreadsheet_url = "your_google_sheet_url"
    
    [gcp_service_account]
    type = "service_account"
    project_id = "your_project_id"
    private_key_id = "your_private_key_id"
    private_key = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
    client_email = "your_service_account_email"
    client_id = "your_client_id"
    auth_uri = "https://accounts.google.com/o/oauth2/auth"
    token_uri = "https://oauth2.googleapis.com/token"
    auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
    client_x509_cert_url = "your_cert_url"
    ```
### Running the Application

```bash
streamlit run app.py
```

## 📜 Usage

1. Select the receipt format from the dropdown
2. Upload a receipt image (JPG, JPEG, or PNG)
3. Review and edit the extracted data:
   - Store name
   - Transaction date
   - Tax amount
   - Total amount
   - Individual items
4. Click "Submit to Google Sheets" to save the data

## 🌟 Supported Receipt Formats

- Walmart
- Kum & Go
- Wells Fargo
- Pizza Ranch
- Kpot
- HyVee
- HyVee Fast & Fresh
- Holiday Station Store
- Corner's Pantry
- Casey's
- Generic (fallback parser)

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 📜 License
[MIT License](LICENSE) 

## 🙏 Acknowledgments
- Built to solve my father's 3-year receipt organization challenge
- Developed in just 3 days using Python and cloud services


You can customize this further by:
1. Adding actual screenshots
2. Including a demo video/gif
3. Adding more detailed setup instructions
4. Including troubleshooting tips
5. Adding a features roadmap

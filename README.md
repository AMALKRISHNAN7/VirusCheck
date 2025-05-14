# VirusCheck

VirusCheck is a Django-based web application similar to VirusTotal . It allows users to scan URLs, file hashes, files, and IP addresses to determine if they are malicious. The application generates reports , stores scan results, and provides a verdict on scanned items.

## Features
- Scan URLs, file hashes, files, and IP addresses.
- Generate detailed reports with charts and tables.
- Save scan history for future reference.
- Indicate whether a scanned item is malicious or not.
- User-friendly interface with Bootstrap styling.

## Installation
### Prerequisites
- Python 3.x
- Django
- Virtual environment ( recommended )

### Setup Steps
1. Clone the repository:
   ```sh
   git clone https://github.com/AMALKRISHNAN7/VirusCheck.git
   cd VirusCheck
   ```
2. Create and activate a virtual environment:
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
4. Apply database migrations:
   ```sh
   python manage.py migrate
   ```
5. Run the development server:
   ```sh
   python manage.py runserver
   ```
6. Access the application in your browser at `http://127.0.0.1:8000/`

## Usage
1. Upload a file, enter a URL, hash, or IP address.
2. Click the "Scan" button to analyze the input.
3. View the detailed scan results in the report section.
4. Check the scan history for past results.

## Contact
For any issues or suggestions, open an issue in the repository or contact me.


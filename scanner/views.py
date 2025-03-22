import requests
from django.shortcuts import render
from .models import ScanResult
from .forms import ScanForm
import requests
import json  

# Replace with your VirusTotal API Key
VIRUSTOTAL_API_KEY = "-----------API KEY------------"

def check_ip_virustotal(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    print(f"[DEBUG] VirusTotal API Request: {url}") 

    response = requests.get(url, headers=headers)
    
    print(f"[DEBUG] VirusTotal Response Status: {response.status_code}") 

    if response.status_code == 200:
        data = response.json()
        print(f"[DEBUG] VirusTotal Raw Data: {data}") 
        
        malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        
        print(f"[DEBUG] VirusTotal Malicious Count: {malicious_count}")  # Print malicious count
        
        return malicious_count > 0 
    
    print("[ERROR] VirusTotal API Request Failed!") 
    return False  # Default to non-malicious if API fails


def scan(request):
    form = ScanForm()
    results = ScanResult.objects.all()

    if request.method == "POST":
        form = ScanForm(request.POST, request.FILES)
        if form.is_valid():
            scan_type = form.cleaned_data["scan_type"]
            input_value = form.cleaned_data["input_value"]

            print(f"[DEBUG] Raw scan_type from form: '{scan_type}'") 
            scan_type = scan_type.strip().lower()  
            print(f"[DEBUG] Normalized scan_type: '{scan_type}'") 
            print(f"[DEBUG] Received scan request: Type={scan_type}, Input={input_value}")

            is_malicious = False 

            if scan_type in ["ip", "ip address"]:  
                print("[DEBUG] Calling check_ip_virustotal()...")  
                try:
                    is_malicious = check_ip_virustotal(input_value)
                    print(f"[DEBUG] VirusTotal Result: {is_malicious}")
                except Exception as e:
                    print(f"[ERROR] check_ip_virustotal() crashed: {e}") 

            # Save scan result
            scan_result = ScanResult.objects.create(
                scan_type=scan_type,
                input_value=input_value,
                is_malicious=is_malicious
            )

    return render(request, "scanner/scan.html", {"form": form, "results": results})



def report(request, scan_id):
    scan_result = ScanResult.objects.get(id=scan_id)
    return render(request, "scanner/report.html", {"scan_result": scan_result})

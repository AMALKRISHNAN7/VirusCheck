from django import forms
from .models import ScanResult

class ScanForm(forms.ModelForm):
    class Meta:
        model = ScanResult
        fields = ["scan_type", "input_value"]

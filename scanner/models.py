from django.db import models

class ScanResult(models.Model):
    SCAN_TYPES = [
        ("url", "URL"),
        ("hash", "Hash"),
        ("file", "File"),
        ("ip", "IP Address"),
    ]

    scan_type = models.CharField(max_length=10, choices=SCAN_TYPES)
    input_value = models.CharField(max_length=255)
    result = models.TextField()
    is_malicious = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.scan_type}: {self.input_value} ({'Malicious' if self.is_malicious else 'Safe'})"

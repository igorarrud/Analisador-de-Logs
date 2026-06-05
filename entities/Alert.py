class Alert:
    def __init__(self, origin_IP, timestamp, risk_level):
        self.origin_IP = origin_IP
        self.timpestamp = timestamp
        self.risk_level = risk_level

    # Instanciar objeto e passar esse método para DetectionEngine
    def send_alert(self):
        print(f"Suspicious activity by {self.origin_IP}, Risk Level: {self.risk_level}, at {self.timpestamp}")
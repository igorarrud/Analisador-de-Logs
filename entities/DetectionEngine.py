from entities.Alert import Alert

class DetectionEngine:

    def __init__(self):
        self.fail_history = {}
        # fail_history {IP: {"risk_level": int, "last_pkt_size": float, "size_repetition" : int, "timestamp": str}}

    def add_IP_in_history(self, IP, risk_level, last_pkt_size, timestamp):
        if IP not in self.fail_history:
            self.fail_history[IP] = {'risk_level': risk_level,
                                     'last_pkt_size': last_pkt_size,
                                     'size_repetition': 0,
                                     'timestamp': timestamp}
            


    def update_IP_values_in_history(self, IP, current_line_risk, current_pkt_size, current_timestamp):
        if IP in self.fail_history:
            self.fail_history[IP]['risk_level'] += current_line_risk
            if self.fail_history[IP]['last_pkt_size'] == current_pkt_size:
                self.fail_history[IP]['size_repetition'] += 1
            else:
                self.fail_history[IP]['size_repetition'] = 0
            self.fail_history[IP]['timestamp'] = current_timestamp
            


    def calculate_interval(self, current_IP, current_timestamp):
        if current_IP in self.fail_history:
            last_pkt_time = self.fail_history[current_IP]['timestamp']
            interval = current_timestamp - last_pkt_time
            return interval




    def delete_risk(self, IP):
        if IP in self.fail_history:
            del self.fail_history[IP]
        else:
            print("I know it was you, Fredo, *** male kisses ***, you broke my heart")



    def analyze_event(self, dict_event):
        current_IP = dict_event['SRC_ADD']
        current_pkt_rate = float(dict_event['PKT_RATE'])
        current_pkt_size = float(dict_event['PKT_SIZE'])
        current_timestamp = float(dict_event['PKT_RESEVED_TIME'])
        pkt_type = dict_event['PKT_TYPE']
        interval = None

        current_line_risk = 0

        if current_IP in self.fail_history:
            interval = self.calculate_interval(current_IP, current_timestamp)

            # resetting, long period without large pkt
            if interval > 300:
                self.delete_risk(current_IP)


        # Traffic rate too high
        if (current_pkt_rate > 300):
            if current_IP not in self.fail_history:
                current_line_risk += 1

            if interval and interval <= 1:
                current_line_risk += 5
            
            if interval and 1 < interval <= 300:
                current_line_risk += 1
            

        # Checking if UDP package has a high rate and size, typical of DDOS attacks 
        if (pkt_type == "b'cbr'" or pkt_type == "b'udp'"):
            if current_pkt_rate > 300.0:
                current_line_risk += 5

            if current_IP in self.fail_history:
                if self.fail_history[current_IP]['last_pkt_size'] == current_pkt_size:
                    current_line_risk += 5

        # Detection of suspicious Ping
        if (pkt_type == "b'ping'" and current_pkt_size >= 1500):
            current_line_risk += 4


        ### CREATE OR UPDATE VALUE ###

        if current_line_risk == 0:
            return
        # if there is a risk, but this ip isn't in the history, add it
        elif current_line_risk > 0 and current_IP not in self.fail_history:
            self.add_IP_in_history(current_IP, current_line_risk, current_pkt_size, timestamp=current_timestamp)
        else:
            self.update_IP_values_in_history(current_IP, current_line_risk, current_pkt_size, current_timestamp)


        ### CHECK IF IS NEEDED TO CALL AN ALERT ###

        if self.fail_history[current_IP]['risk_level'] > 10:    
            new_alert = Alert(current_IP, 
                              self.fail_history[current_IP]['risk_level'], 
                              self.fail_history[current_IP]["timestamp"])
            return new_alert.send_alert()
         
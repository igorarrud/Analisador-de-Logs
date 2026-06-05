class LogParser:
    def __init__(self, header, separator=','):
        self.header = header
        self.separator = separator

    def parse_line(self, line):
        formatted_line = line.split(self.separator)
        dict_event = dict(zip(self.header, formatted_line))

        if 'PKT_RESEVED_TIME' in dict_event:
            dict_event['PKT_RESEVED_TIME'] = str(dict_event['PKT_RESEVED_TIME'])

        return dict_event

        
        


        
    
    
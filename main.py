from entities.LogReader import LogReader
from entities.LogParser import LogParser
from entities.DetectionEngine import DetectionEngine
from entities.Alert import Alert

def main():
     arquivo = LogReader("archive\\final-dataset.csv")

     # doesn't store any value yet
     lines = arquivo.open_archive()

     # gets the header from lines
     header = next(lines).strip()
     header_list = header.split(",")

     parser = LogParser(header=header_list)
     engine = DetectionEngine()

     for line in lines:
        dict_event = parser.parse_line(line)
    
        engine.analyze_event(dict_event)


if __name__ == '__main__':
     main()

     


















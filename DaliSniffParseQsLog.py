import re
import time
import sys

class DALI_PACKET:
    def __init__(self, seqNum, packetType, timeDelta, date, time, data):
        self.seqNum = str(seqNum)
        self.packetType = packetType
        self.timeDelta = timeDelta
        self.date = date
        self.time = time
        self.data = data

    def __str__(self):
        return "Seq #: " + self.seqNum + " Packet Type: " + self.packetType + " Delta Time: " + self.timeDelta + " Data: " + self.data

def outputDaliPacketListToCsv(serialNumber, loop, packetList):
    pass

def outputDaliPacketListToDaliMonitorDmd(serialNumber, loop, packetList):
    current_date = time.strftime("%Y-%m-%d_%H-%M-%S")
    fileName = current_date + "-" + serialNumber + "-" + loop + ".dmd"
    with open(fileName, "wb") as dmd_file:
        #Add header information
        header = "1144414C49204D6F6E69746F7220446174610C000000"
        dmd_file.write(bytearray.fromhex(header))
        #Add packet count
        dmd_file.write((len(packetList)).to_bytes(4, byteorder='little'))
        #Add packets
        for packet in packetList:

            #Create the date and time
            year = int(packet.date[0:4]).to_bytes(2, byteorder='little')
            month = int(packet.date[5:7]).to_bytes(2, byteorder='little')
            day = int(packet.date[8:10]).to_bytes(2, byteorder='little')
            
            hour = int(packet.time[0:2]).to_bytes(2, byteorder='little')
            minute = int(packet.time[3:5]).to_bytes(2, byteorder='little')
            second = int(packet.time[6:8]).to_bytes(2, byteorder='little')

            dmd_file.write(day + month + year + hour + minute + second)
            
            packet_time = "0000" #placeholder for ms

            write_data = packet_time

            #print(write_data)
            #print(packet.packetType)
            
            if packet.packetType == "00":
                #ECO_DALI_SNIFFING_PACKET_8_BIT_MESSAGE
                write_data = write_data + "0100"
                write_data = write_data + packet.data[0:2] + "0000"
            elif packet.packetType == "01":
                #ECO_DALI_SNIFFING_PACKET_16_BIT_MESSAGE
                write_data = write_data + "0200"
                write_data = write_data + packet.data[2:4] + packet.data[0:2] + "00"
            elif packet.packetType == "02":
                #ECO_DALI_SNIFFING_PACKET_24_BIT_MESSAGE
                write_data = write_data + "0300"
                write_data = write_data + packet.data[4:6] + packet.data[2:4] + packet.data[0:2]
            elif packet.packetType == "03":
                #ECO_DALI_SNIFFING_PACKET_FRAMING_ERROR
                write_data = write_data + "0100FDFFFF"
            elif packet.packetType == "04":
                #ECO_DALI_SNIFFING_PACKET_DALI_MESSAGES_DROPPED
                write_data = write_data + "0300FFFFFF"

            #print(write_data)

            #Some constant value 
            write_data = write_data + "000200000000"
            dmd_file.write(bytearray.fromhex(write_data))

try:
    droppedFile = sys.argv[1] 
except IndexError:
    print("No file dropped")
    droppedFile = "test.txt"

f = open(droppedFile, 'r')

Lines = f.readlines() 

packet_dict = {}

qs_packet_regex = r'.*(?P<Date>\d{4}-\d{2}-\d{2}).*(?P<Time>\d{2}:\d{2}:\d{2}).*(?P<SerialNum>[A-Fa-f0-9]{8})[A-Fa-f0-9]{4}00FFFFFFFFFF0210(?P<Loop>[A-Fa-f0-9]{2})(?P<NumPackets>[A-Fa-f0-9]{2})(?P<SeqNum>[A-Fa-f0-9]{2})(?P<PacketData>.*)'
proc_log_regex = r'.*(?P<Date>\d{4}-\d{2}-\d{2}).*(?P<Time>\d{2}:\d{2}:\d{2}).*DALI-Sniff: (?P<SerialNum>[A-Fa-f0-9]{8}).*\{(?P<Loop>[A-Fa-f0-9]{2})(?P<NumPackets>[A-Fa-f0-9]{2})(?P<SeqNum>[A-Fa-f0-9]{2})(?P<PacketData>.*)'

for line in Lines:
    m = re.match(qs_packet_regex, line)
    if m:

        #print(m.group(0))
        
        serial_number = m.group('SerialNum')
        loop = m.group('Loop')
        starting_seq_num = m.group('SeqNum')
        number_packets = m.group('NumPackets')
        full_packet_data = m.group('PacketData')
        packet_date = m.group('Date')
        packet_time = m.group('Time')

        if (serial_number not in packet_dict.keys()):
            packet_dict[serial_number] = {}

        if (loop not in packet_dict[serial_number].keys()):
            packet_dict[serial_number][loop] = []

        for x in range(int(number_packets, 16)):
            seq_num = int(starting_seq_num, 16) + x
            time_delta = full_packet_data[0:4]
            packet_type = full_packet_data[4:6]
            packet_data = full_packet_data[6:12]

            full_packet_data = full_packet_data[12:]

            #print("PACKET " + str(seq_num) + ": Delta-" + time_delta + " Type-"+packet_type + " Data-"+packet_data)
            
            packet_dict[serial_number][loop].append(DALI_PACKET(seq_num, packet_type, time_delta, packet_date, packet_time, packet_data))

for sn in packet_dict.keys():
    for loop in packet_dict[sn].keys():
        #print(packet_dict[sn][loop])
        outputDaliPacketListToDaliMonitorDmd(sn, loop, packet_dict[sn][loop])
    



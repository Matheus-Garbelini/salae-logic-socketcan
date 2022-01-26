# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting
from struct import pack
from binascii import hexlify
import socket
import struct

def build_can_frame(can_id, data):
    """ CAN frame packing/unpacking (see 'struct can_frame' in <linux/can.h>)
    /**
     * struct can_frame - basic CAN frame structure
     * @can_id:  the CAN ID of the frame and CAN_*_FLAG flags, see above.
     * @can_dlc: the data length field of the CAN frame
     * @data:    the CAN frame payload.
     */
    struct can_frame {
        canid_t can_id;  /* 32 bit CAN_ID + EFF/RTR/ERR flags */
        __u8    can_dlc; /* data length code: 0 .. 8 */
        __u8    data[8] __attribute__((aligned(8)));
    };
    """
    can_dlc = len(data)
    data = data.ljust(8, b'\x00')
    return struct.pack("=IB3x8s", can_id, can_dlc, data)

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    canbus_interface = StringSetting()

    # Internal variables
    socket_can = None    # socket for canbus (can be virtual)
    can_id = 0           # Current CAN identifier 
    can_len = 0          # Current CAN data length 
    can_data = b''       # Current CAN data 
    can_crc = 0          # Current CAN crc (not send via socketcan)
    can_extended = False # (not send via socketcan)
    packet_number = 0

    def __init__(self):
        '''
        Initialize HLA.
        Settings can be accessed using the same name used above.
        '''

        print("Selected CAN interface:", self.canbus_interface)

        if self.socket_can is None:
            print("Trying to open socket on interface ", self.canbus_interface)
            self.socket_can = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
            if self.socket_can == -1:
                self.socket_can = None
                raise OSError("Could bind to " + self.canbus_interface + ", is the interface name correct???")
            
            print('Binding socket to channel=%s', self.canbus_interface)
            try:
                self.socket_can.bind((self.canbus_interface,))
            except OSError:
                raise OSError("Could bind to " + self.canbus_interface + ", is the interface name correct???")         


    def decode(self, frame: AnalyzerFrame): 
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        # Return the data frame itself
        # print(frame.type)
        if 'identifier_field' in frame.type:
            self.can_data = b'' # Reset can frame data
            self.can_id = frame.data['identifier']
            # print(frame.data)
            if 'extended' in frame.data:
                self.can_id |= 0x80000000 # Set extended ID flag
            if 'remote_frame' in frame.data:
                self.can_id |= 0x40000000 # Set remote request frame flag

        elif 'control_field' in frame.type:
            self.can_len = frame.data['num_data_bytes']
        elif 'data_field' in frame.type:
            self.can_data += frame.data['data']
        elif 'crc_field' in frame.type:
            self.can_crc = frame.data['crc']
        elif 'ack_field' in frame.type:
            try:
                if self.socket_can:
                    self.socket_can.send(build_can_frame(self.can_id, self.can_data))
                    self.packet_number += 1
                    print(self.packet_number, 
                        "ID", hex(self.can_id).upper(), 
                        "LEN", self.can_len, 
                        hexlify(self.can_data).decode().upper(), 
                        "CRC", hex(self.can_crc).upper(),
                        "to", self.canbus_interface)
            except OSError:
                print("Failed to send: %s", self.can_data)
            pass
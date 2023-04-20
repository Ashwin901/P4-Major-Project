from math import sqrt, ceil
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

controller = SimpleSwitchThriftAPI(9092)

processing_delay = controller.register_read("process_delay")

print("The processing delay is: ",processing_delay[0]/1000000,"s")
from math import sqrt
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

controller = SimpleSwitchThriftAPI(9090)

flows = controller.register_read("total_flows")
srtt = controller.register_read("rtt_val")
# arr = controller.register_read("arr")
# pc = controller.register_read("port_capacity")
pc = 10

# print("The array is: ", arr)
print("The number of flows are: ", flows[0])
print("The value of smoothed rtt is: ", srtt[0])

# buffer_size = pc[0] * srtt[0] / sqrt(flows)

# print("Setting queue depth")
# controller.set_queue_depth(buffer_size)
# print("Queue depth adjusted")
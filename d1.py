import time
import chipwhisperer as cw
import random
import h5py
import numpy as np

wave_count = 10
point_count = 15000
progress_indent = 1
reprogram = True
reprogram_path = "simpleserial-aes-CW303.hex"
# output_path = "/var/www/html/2-3-100k"
output_path = "d1"

def phex(arr):
    return " ".join("{:02x}".format(c) for c in arr)

def thex(arr):
    return " ".join("{:03x}".format(c) for c in arr)

scope = cw.scope()
scope.default_setup()
target = cw.target(scope)
#set point count
scope.adc.samples = point_count

# print scope status
# print(scope)
print("Connected to chipwhisperer")

print("Configuring target")
# program target
if reprogram:
    cw.program_target(scope, cw.programmers.XMEGAProgrammer, reprogram_path)

print("Sanity check:")

key = bytearray([0x0d, 0x0e, 0x0f, 0x00, 0x09, 0x0a, 0x0b, 0x0c, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04])
#revert key
# key.reverse()
print("\tkey: ", phex(key))

rk = bytearray([0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87])

plain = bytearray([0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67])
#revert plain
# plain.reverse()
print("\tplaintext: ", phex(plain))

print("Starting up device")
time.sleep(1)
# set key
target.simpleserial_write('k', key)
ciphertext = target.simpleserial_read('r', 16)
print("\tktext: ", phex(ciphertext))
time.sleep(1)
target.simpleserial_write('m', rk)
time.sleep(1)
target.simpleserial_write('p', plain)
ciphertext = target.simpleserial_read('r',16)
#data = target.simpleserial_read('r',20)
#ciphertext = data[:16]
#cycles = int.from_bytes(data[16:20], byteorder='little')
#print("cycles =", cycles)
print("\tciphertext: ", phex(ciphertext))

# open file to write
h5file = h5py.File(output_path + "/trace.h5", "w")
traces = h5file.create_dataset(
    "traces",
    shape=(wave_count, point_count),
    dtype=np.int16
)
plaintexts = h5file.create_dataset(
    "plaintext",
    shape=(wave_count,16),
    dtype=np.uint8
)
ciphertexts = h5file.create_dataset(
    "ciphertext",
    shape=(wave_count,16),
    dtype=np.uint8
)

print("samples:", scope.adc.samples)
print("timeout:", scope.adc.timeout)
print(scope.clock)
print(scope.trigger)

# start timer
start = time.time()

# loop for wave_count times
for i in range(wave_count):
    scope.arm()
    plain = bytearray(
        [random.randint(0,255) for _ in range(16)]
    )
    target.simpleserial_write('p', plain)
    scope.capture()
    ciphertext = target.simpleserial_read('r', 16)
    trace = scope.get_last_trace()
    trace = np.array(
        [int(x*1024+512) for x in trace],
        dtype=np.int16
    )
    traces[i,:] = trace
    plaintexts[i,:] = plain
    ciphertexts[i,:] = ciphertext
    # show progress with time as hh:mm:ss and estimated time left
    if i % progress_indent == 0:
        print("progress: ", i, '/', wave_count , "    ", "time elapsed: ", time.strftime("%H:%M:%S", time.gmtime(time.time() - start)), "    ", "time left: ", time.strftime("%H:%M:%S", time.gmtime((time.time() - start) / (i + 1) * (wave_count - i - 1))))

# disconnect scope
h5file.close()
scope.dis()

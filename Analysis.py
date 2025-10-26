import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import sys

csvfile = sys.argv[1]

df = pd.read_csv(csvfile)

valid_d = (df['num_ans_RR_default']>0)
valid_c = (df['num_ans_RR_custom']>0)
valid_r = (df['num_ans_RR_custom_RD']>0)
valid_c_c = (df['num_ans_custom_Cache']>0)


print('queries answered by resolver :')
print('\tdefault\t:',round(100*valid_d.mean(),2),'%')
print('\tcustom\t:',round(100*valid_c.mean(),2),'%')
print('\tcustom_RD\t:',round(100*valid_r.mean(),2),'%')
print('\tcustom_Cache\t:',round(100*valid_c_c.mean(),2),'%')

latency_d = df["lookup_time_default"].where(valid_d)
latency_c = df["lookup_time_custom"].where(valid_c)
latency_r = df["lookup_time_custom_RD"].where(valid_r)
latency_c_c = df["lookup_time_custom_Cache"].where(valid_c_c)

plt.hist(latency_d,alpha=0.5)
plt.hist(latency_c,alpha=0.5)
plt.hist(latency_r,alpha=0.5)
plt.hist(latency_c_c,alpha=0.5)

plt.legend(["default","custom","custom_RD","custom_Cache"])
plt.xlabel('latency (ms)')
plt.ylabel('frequency')
plt.title(csvfile.split('.')[0] + ' DNS resolution latency')
plt.savefig(csvfile.split('.')[0] + '_latency.png',format='PNG')

avg_latency_d = latency_d.mean()
avg_latency_c = latency_c.mean()
avg_latency_r = latency_r.mean()
avg_latency_c_c = latency_c_c.mean()

print('average latency for queries answered by resolver :')
print('\tdefault\t:',round(avg_latency_d,2),'ms')
print('\tcustom\t:',round(avg_latency_c,2),'ms')
print('\tcustom_RD\t:',round(avg_latency_r,2),'ms')
print('\tcustom_Cache\t:',round(avg_latency_c_c,2),'ms')

avg_throughput_d = 1000/avg_latency_d
avg_throughput_c = 1000/avg_latency_c
avg_throughput_r = 1000/avg_latency_r
avg_throughput_c_c = 1000/avg_latency_c_c

print('average throughput for queries answered by resolver :')
print('\tdefault\t:',round(avg_throughput_d,2),'request/s')
print('\tcustom\t:',round(avg_throughput_c,2),'request/s')
print('\tcustom_RD\t:',round(avg_throughput_r,2),'request/s')
print('\tcustom_Cache\t:',round(avg_throughput_c_c,2),'request/s')

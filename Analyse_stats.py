import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
columns = "name,type,RD,Cache,sum_RTT,queries,total_time,cache_hits,cache_misses,num_answers"
columns = columns.split(',')
df = pd.read_csv('servers_stats.csv')
RD = df['RD'].astype(bool)
Cache = df['Cache'].astype(bool)

size = 10
alpha = 0.4
custom = df.where(~(RD|Cache) ).dropna(how='all').head(size)
custom_RD = df.where(RD & (~Cache)).dropna(how='all').head(size)
custom_Cache = df.where((~RD) & Cache).dropna(how='all').head(size)

names = custom['name']
d_L = custom['total_time']
q_L = custom['queries']
plt.scatter(d_L,q_L,c ='blue',alpha=alpha,label='custom')

names = custom_RD['name']
d_L = custom_RD['total_time']
q_L = custom_RD['queries']
plt.scatter(d_L,q_L,c ='red',alpha=alpha,label='custom_RD')

names = custom_Cache['name']
d_L = custom_Cache['total_time']
q_L = custom_Cache['queries']
plt.scatter(d_L,q_L,c ='green',alpha=alpha,label='custom_Cache')

plt.legend()
plt.xlabel('total time (s)')
plt.ylabel('queries')
plt.title('total latency vs number of queries')

plt.savefig('latency_vs_queries.png',format='PNG')

plt.figure()

names = custom['name']
d_L = custom['sum_RTT']
q_L = custom['queries']
d_L = d_L/q_L
plt.scatter(d_L,q_L,c ='blue',alpha=alpha,label='custom')

names = custom_RD['name']
d_L = custom_RD['sum_RTT']
q_L = custom_RD['queries']
d_L = d_L/q_L
plt.scatter(d_L,q_L,c ='red',alpha=alpha,label='custom_RD')

names = custom_Cache['name']
d_L = custom_Cache['sum_RTT']
q_L = custom_Cache['queries']
d_L = d_L/q_L
plt.scatter(d_L,q_L,c ='green',alpha=alpha,label='custom_Cache')

plt.legend()
plt.xlabel('avg RTT (s)')
plt.ylabel('queries')
plt.title('avg RTT vs number of queries')
plt.savefig('avg_RTT_vs_queries.png',format='PNG')

alpha = 0.1
custom = df.where(~(RD|Cache) ).dropna(how='all')
custom_RD = df.where(RD & (~Cache)).dropna(how='all')
custom_Cache = df.where((~RD) & Cache).dropna(how='all')


plt.figure()

names = custom['name']
d_L = custom['total_time']
q_L = custom['sum_RTT']
plt.scatter(q_L,d_L,c ='blue',alpha=alpha,label='custom')

names = custom_RD['name']
d_L = custom_RD['total_time']
q_L = custom_RD['sum_RTT']
plt.scatter(q_L,d_L,c ='red',alpha=alpha,label='custom_RD')

names = custom_Cache['name']
d_L = custom_Cache['total_time']
q_L = custom_Cache['sum_RTT']
plt.scatter(q_L,d_L,c ='green',alpha=alpha,label='custom_Cache')

plt.plot(df['sum_RTT'],df['sum_RTT'],color='black',label='$y=x$')

plt.legend()
plt.xlabel('sum of RTTs (s)')
plt.ylabel('total time (s)')
plt.title('total latency vs sum of RTTs')
plt.savefig('latency_vs_sum_RTT.png',format='PNG')

# for name,d,q in zip(names,d_L,q_L):
#     plt.annotate(name,(d,q),size=5,rotation=-30,ha='center')


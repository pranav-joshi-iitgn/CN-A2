import pandas as pd
df = pd.read_csv('H1.csv')
answered = ( df['num_ans_RR_default'] > 0 )
success,failed,total = sum(answered),sum(~answered),len(df)
avg_latency_ans = (df['lookup_time_default']).where(answered).mean().round(2) #ms
avg_throughput_ans = round(1000/avg_latency_ans,2) # requests/s
avg_latency = (df['lookup_time_default']).mean().round(2) # ms
avg_throughput = round(1000/avg_latency,2) # requests/s
print(success,'/',total,'=',round(100*success/total,2),'% queries were answered')
print(failed,'/',total,'=',round(100*failed/total,2),'% queries were not answered')
print('average latency is',avg_latency,'ms')
print('average throughput is',avg_throughput,'requests/s')
print('average latency for only answered queries is',avg_latency_ans,'ms')
print('average throughput for only answered queries is',avg_throughput_ans,'requests/s')
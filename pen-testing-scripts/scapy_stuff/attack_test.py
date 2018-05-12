import time
previous_attack_val=[73.8313,-12.0675,0.0]
previous_meas=[0.0,0.0,0.0]
def ramp(attack_value,t,ramp_factor=0.0024):
	# Implement ramp attack,check what the unit of 't' is
	max_time=3600.0 # The ramp resets every hour
	return ramp_factor*(t%max_time)+attack_value
initial_time=time.time()

attack_val=1
scheduled_tie=[73.8,-12.0]
del_P_load=(previous_attack_val[0]-scheduled_tie[0]+previous_attack_val[1]-scheduled_tie[1])/1000
previous_attack_val[2]= 60 -del_P_load*60/((3/5.0))
print str(previous_attack_val[2])		

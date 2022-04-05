import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from pylab import cm
NumSbox = 0
a,b = np.loadtxt('S'+str(NumSbox)+'.csv',unpack=True,delimiter=',',skiprows=0);
fig = plt.figure();

plt.plot(a,b,label = "line 1",marker='o',ms=2,mfc='r',mec='r',linewidth=0.5);
plt.xlabel('The number of infection-based ciphertexts',fontsize=16)
plt.ylabel('The rank of candidate key',fontsize=16)

plt.savefig("Alg4_Simulation_fault_S"+str(NumSbox)+".eps");

plt.show()

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from pylab import cm
a,b = np.loadtxt('FindFault_Alg4_firstTest.csv',unpack=True,delimiter=',',skiprows=1);
fig = plt.figure();
plt.scatter(a,b,color= "green",marker= ".", s=0.5);
plt.xlabel('The number of infection-based ciphertexts (N)',fontsize=16)
plt.ylabel('The number of Sboxes',fontsize=16)


plt.savefig("Alg4_Simulation_part1_1.png");

plt.show()


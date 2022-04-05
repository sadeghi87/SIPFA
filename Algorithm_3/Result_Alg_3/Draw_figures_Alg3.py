import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from pylab import cm
a,b = np.loadtxt('Alg3_Reult.csv',unpack=True,delimiter=',',skiprows=0);

fig = plt.figure();


plt.ylim(400,550)


plt.scatter(a,b,color= "green",marker= ".", s=0.3);

plt.xlabel('The key number (10,000 random keys selected in total)')
plt.ylabel('The number of infection-based ciphertexts (N)')

plt.savefig("Alg3_Simulation_DES.eps");

plt.show()
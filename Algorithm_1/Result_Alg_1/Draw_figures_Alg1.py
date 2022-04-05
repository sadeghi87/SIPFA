import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from pylab import cm
a,b = np.loadtxt('Result_Alg1.csv',unpack=True,delimiter=',',skiprows=1);

fig = plt.figure();


plt.ylim(450,490)


plt.scatter(a,b,color= "green",marker= ".", s=0.3);

plt.xlabel('The key number (10,000 random keys selected in total)')
plt.ylabel('The number of ineffective ciphertexts (N)')

plt.savefig("Alg1_Simulation_DES.eps");

plt.show()

#colors = cm.get_cmap('tab10',2);
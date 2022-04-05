import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from pylab import cm
NumSbox = 0 # Enter the Number of Sbox
a,b = np.loadtxt('Result_Alg2_'+ str(NumSbox) +'.csv',unpack=True,delimiter=',')

fig = plt.figure();
plt.ylim(-16,b[0]+(b[0]*0.25))
plt.plot(a,b,label = "line 1",marker='o',ms=1,mfc='r',mec='r',linewidth=0.9);

plt.scatter(a[0], b[0], color="black")
plt.annotate(r"$(N_0,nk_0)$=({},{})".format(int(a[0]),int(b[0])),
              xy=(a[0], b[0]), xytext=(+10, -5), annotation_clip=False,
              textcoords="offset points", fontsize=16)
              # arrowprops=dict(arrowstyle="<-", connectionstyle="arc3,rad=.3"))
for i in range(0,len(b)):
    if (b[i] == 1):
        plt.scatter(a[i], b[i], color="black")
        plt.annotate(r"$(N,nk)$=({},{})".format(int(a[i]),int(b[i])),
            xy=(a[i], b[i]), xytext=(-20, +12), annotation_clip=False,
            textcoords="offset points", fontsize=16)
        break
plt.xlabel('The number of ineffective ciphertexts',fontsize=16)
plt.ylabel('The number of candidate keys',fontsize=16)
plt.savefig("Alg2_Simulation_fault_S"+ str(NumSbox)+".eps")
plt.show()

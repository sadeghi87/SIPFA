/* Simulation of Algorithm 1
In this algorithm, it is assumed the fault location is known 
and the aim is recovering all candidates key $sk_16,\cdots,sk_1$ of DES cipher
in a detection-based countermeasure assumption.
In this code, about 10,000 random keys have been selected. 
Then for each of the selected keys, the average number of ineffective ciphertexts
needed to retrieve the key is calculated
(this average is taken for 100 different sets of random ineffective ciphertexts).
*/


#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <memory.h>
#include <string.h>

#include "DES.h"
// A function for building a 64-bit random number
uint64_t Random64()
{
	union {
		uint64_t R;
		uint8_t Ri[8];
	}rand64;
	rsize_t i;
	for (i = 0; i < 8; i++)
		rand64.Ri[i] = rand() % 255;
	return rand64.R;
}
int main(int argc, char ** argv)
{
	
	srand((unsigned)time(NULL));
	int const Num_ROUNDS = 16;
	DES_Alg_ctx ctx;
	Fault_DES_Alg Fault;
	Fault.row = rand()% 4;
	Fault.col = rand() % 16;
	int const N = 1500; // An estimate for N

	FILE *fprt;
	fprt = fopen("Result_Alg1.csv", "w"); 

	int Sbox;
	int RandomKeyNumber;
	int MaxOfRepetition = 100;
	int NumberOfRepetition;


	// master key of DES
	uint64_t key;
	//RequiredData for each repitation (Total Number Of Repetition is 100)
	int RequiredData[100]; 
	double	SUM=0;
	//An array to calculate an average of 10000 selected Random Key Number
	double Average[10000] = { 0 }; 

	// 10,000 random keys have been selected
	for (RandomKeyNumber = 0; RandomKeyNumber < 10000; RandomKeyNumber++)
	{
		int temp = 1;
		key = Random64(); // the master key is chosen randomly

		int SumOfRequiredData=0;
		 Average[RandomKeyNumber] = 0;
//############################################################################################
		// Simulation is performed on 100 different sets of random ineffective ciphertexts
		for (NumberOfRepetition = 0; NumberOfRepetition < MaxOfRepetition; NumberOfRepetition++)
		{
			uint64_t Data1, Data2;
			uint64_t Valu_before_addingKey;
			int count[16][8] = { 1 }; // counting the number of ciphertexts for each faulty sbox. //count[#rounds][#sboxes]

			int arr[64];
			int i;
// step 1
			for (Fault.Sbox = 0; Fault.Sbox < 8; Fault.Sbox++)
			{
				for (i = 0; i < 64; i++)
					arr[i] = 1;
				i = 0;
				int counter = 0, Num_of_CipherText = 0;

// step 4, 
				do { //while (Num_of_CipherText <= N)
					Data1 = Data2 = Random64();
			//#############################################################################################	
					//Encryption 
					DES_Alg_Enc(&Data1, key);
					//Encryption when a fault is occurred 
					DES_Alg_EncFaulty(&Fault, &Data2, key);

					//here Data1 and Data2 are ciphertexts
// step 5
					if (Data1 == Data2) //a detection based countermeasure
					{
						ctx.Ineffective_CipherText[Fault.Sbox][Num_of_CipherText] = Data1;

						Num_of_CipherText++;
						Valu_before_addingKey = 0;
// step 6
						DES_Expansion(&Fault, &Data1, &Valu_before_addingKey);

						if ((0 <= Valu_before_addingKey) && (Valu_before_addingKey < 64))
						{
							if (arr[Valu_before_addingKey])
							{
								counter++;
								arr[Valu_before_addingKey] = 0;
							};
						};

						if (counter < 63)
							count[Num_ROUNDS - 1][Fault.Sbox]++;
					}

				} while (Num_of_CipherText <= N);
				if (counter != 63)
					temp = 0;
				ctx.Num_of_InCipher[Fault.Sbox] = Num_of_CipherText;
				int X = 0, t1 = 0;
				for (i = 0; i < 64; i++)
					if (arr[i])
					{
						X = i;
						t1++;
					};
// step 8       $sk_n[i]    <---   X \oplus \delta_i
				ctx.rk[Fault.Sbox] = (X ^ ConvertRowCol_to_InputSbox(Fault.row, Fault.col));
			}     //for Fault.Sbox=0 to 7


// step 8
			Convert_rk_to_subkey(&ctx, Num_ROUNDS);  // Return sk_16
//step 9
			int r;
			for (r = Num_ROUNDS; r > 1; r--)
			{

				for (Fault.Sbox = 0; Fault.Sbox < 8; Fault.Sbox++)
					for (i = 0; i < ctx.Num_of_InCipher[Fault.Sbox]; i++)
					{
						if (r == Num_ROUNDS)
							DES_Alg_Dec_LastRound(&ctx.Ineffective_CipherText[Fault.Sbox][i], ctx.subkey[Num_ROUNDS - 1]);
						else
							DES_Alg_Dec_oneRound(&ctx.Ineffective_CipherText[Fault.Sbox][i], ctx.subkey[r - 1]);
					}


				for (Fault.Sbox = 0; Fault.Sbox < 8; Fault.Sbox++)
				{
					int arr[64];
					for (i = 0; i < 64; i++)
						arr[i] = 1;
					i = 0;
					int counter = 0;
// step 16
					do //while (i < ctx.Num_of_InCipher[Fault.Sbox]); 
					{
						Valu_before_addingKey = 0;

						DES_Expansion2(&Fault, &ctx.Ineffective_CipherText[Fault.Sbox][i], &Valu_before_addingKey);
						if ((0 <= Valu_before_addingKey) && (Valu_before_addingKey < 64))
						{
							if (arr[Valu_before_addingKey])
							{
								counter++;
								arr[Valu_before_addingKey] = 0;
							};
						};
						i++;
						if (counter < 63)
							count[r - 2][Fault.Sbox]++;

					} while (i < ctx.Num_of_InCipher[Fault.Sbox]);
					if (counter != 63)
						temp = 0;


					int X = 0, t2 = 0;
					for (i = 0; i < 64; i++)
						if (arr[i])
						{
							X = i;
							t2++;
						};
// step 19
					ctx.rk[Fault.Sbox] = (X ^ ConvertRowCol_to_InputSbox(Fault.row, Fault.col));
				}//for (Fault.Sbox = 0; Fault.Sbox < 8; Fault.Sbox++)

// Return sk_r
				Convert_rk_to_subkey(&ctx, r - 1);


			}    //for (r = Num_ROUNDS; r > 1; r--)
// End of Alg 1
/* In the following, for each of the selected keys, the average number of ineffective ciphertexts
needed to recover the key is calculated

The average is taken for 100 different sets of random ineffective ciphertexts.
*/
			if (temp) // If all subkeys have been recovered correctly
			{

				int max[8] = { 0 };
				RequiredData[NumberOfRepetition] = 0;

				for (Sbox = 0; Sbox < 8; Sbox++)
					for (i = 0; i < Num_ROUNDS; i++)
						if (count[i][Fault.Sbox] > max[Sbox])
							max[Fault.Sbox] = count[i][Sbox];

					RequiredData[NumberOfRepetition] += max[Sbox];
			
			}//if (temp)

			else
			{// There are no  enough ciphertext
				RequiredData[NumberOfRepetition] = 0;
			}
			
			SumOfRequiredData += RequiredData[NumberOfRepetition];
			

		}// for NumberOfRepetitions
		
		// Average number of ineffective ciphertexts required to recover the chosen key
		Average[RandomKeyNumber] = (double)((double)SumOfRequiredData / NumberOfRepetition);
		// Calculating the total Mean.
		SUM += Average[RandomKeyNumber];
		
		printf("On average, %f ineffective ciphertexts is needed to recover Random Key Number %d(%016llx)\n", Average[RandomKeyNumber], RandomKeyNumber, key);
		printf("------------------------\n");

		fprintf(fprt,"%d,%f\n", RandomKeyNumber,Average[RandomKeyNumber]);
	} // for RandomKeyNumber
	  
			printf("\n\n\n Mean: %f \n", (double)((double)SUM / (RandomKeyNumber)));
		fclose(fprt);
		return 0;
	}










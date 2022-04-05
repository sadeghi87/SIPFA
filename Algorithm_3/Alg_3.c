/*
Algorithm 3 is based on the infection-based countermeasure assumption 
when the fault location and its value are known and its purpose is to
recover the keys $sk_n,\cdots,sk_1$ on DES block cipher.
To simulate Algorithm 3,  about 10,000 random keys are been selected.
Then for each of the selected keys, the average number of infection
ciphertexts needed to recover the key is calculated (this average is
taken for 100 different sets of random infection-based ciphertexts).
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
	time_t start, finish;
	int Passed_time;
	int rr;
	
	int const Num_ROUNDS = 16;
	DES_Alg_ctx ctx;
	Fault_DES_Alg Fault;
	Fault.Sbox = rand() % 8;
	Fault.row = rand() % 4;
	Fault.col = rand() % 16;



	FILE *fprt;
	fprt = fopen("Alg3_Reult.csv", "w");

		//#############################################################################################
	uint64_t key;
	int RandomKeyNumber;
	int NumberOfRepetition;
	int MaxOfRepetition = 100;
	double Average = 0; 
	// 10,000 random keys have been selected
	for (RandomKeyNumber = 0; RandomKeyNumber < 10000; RandomKeyNumber++)
	{
		int temp, k;
		double sum = 0;
		// 64-bit master key
		key = Random64();
		// Key schedual
		uint64_t a_key[16];
		a_key[0] = key;
		uint64_t next_key = 0;
		for (int ii = 0; ii < 16; ii++)
		{
			key_schedule(&a_key[ii], &next_key, ii);
			if (ii != 15)
				a_key[ii + 1] = next_key;
		}
		// Simulation is performed on 100 different sets of random infection ciphertexts
		for (NumberOfRepetition = 0; NumberOfRepetition < MaxOfRepetition; NumberOfRepetition++)
		{

			int  N = 400;// An estimate for N

			do
			{
				temp = 1;
				//############################################################################################
				uint64_t Data1, Data2, MData;
				uint64_t Valu_before_addingKey;




				int count[16][8] = { 1 }; // counting the number of ciphertexts for each faulty sbox. //count[#rounds][#sboxes]

				int arr[64];
				int i;
//step 2, 3
				for (Fault.Sbox = 0; Fault.Sbox < 8; Fault.Sbox++)
				{
					for (i = 0; i < 64; i++)
						ctx.counter[Fault.Sbox][i] = 0;

					int Num_of_CipherText = 0;

					do {			//while (Num_of_CipherText <= N);
						Data1 = Data2 = Random64();// 0x123456ABCD132536;// Random64();
	//#############################################################################################	
						//Encryption 
						DES_Alg_Enc(&Data1, key);
						//Encryption when a fault is occurred 
						DES_Alg_EncFaulty(&Fault, &Data2, key);
// step 4 ,5
						//here Data is ciphertext
						if (Data1 == Data2)
							MData = Data1;
						else
							MData = Random64(); ////a infection based countermeasure

						{

							ctx.Ineffective_CipherText[Fault.Sbox][Num_of_CipherText] = MData;

							Num_of_CipherText++;

							Valu_before_addingKey = 0;
//step 6
							DES_Expansion(&Fault, &MData, &Valu_before_addingKey);

							if ((0 <= Valu_before_addingKey) && (Valu_before_addingKey < 64))
								ctx.counter[Fault.Sbox][Valu_before_addingKey]++;

						}

					} while (Num_of_CipherText <= N);
					ctx.Num_of_InCipher[Fault.Sbox] = Num_of_CipherText;
// step 8
					int Min = 0, MinValu_before_addingKey = 0;

					Min = ctx.counter[Fault.Sbox][0];
					for (i = 1; i < 64; i++) {
						if (ctx.counter[Fault.Sbox][i] < Min) {
							Min = ctx.counter[Fault.Sbox][i];
							MinValu_before_addingKey = i;
						}

					}
//
					ctx.rk[Fault.Sbox] = (MinValu_before_addingKey ^ ConvertRowCol_to_InputSbox(Fault.row, Fault.col));
				}////for Fault.Sbox = 0; Fault.Sbox < 8; Fault.Sbox++

				// ctx.subkey[Num_ROUNDS - 1] <---- ctx.rk[0] || ... || ctx.rk[7]
				Convert_rk_to_subkey(&ctx, Num_ROUNDS);
//steps 9 to 13
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
// step 16
						for (i = 0; i < 64; i++)
							ctx.counter[Fault.Sbox][i] = 0;
						do
						{
							Valu_before_addingKey = 0;

							DES_Expansion2(&Fault, &ctx.Ineffective_CipherText[Fault.Sbox][i], &Valu_before_addingKey);
							if ((0 <= Valu_before_addingKey) && (Valu_before_addingKey < 64))
							{
								ctx.counter[Fault.Sbox][Valu_before_addingKey]++;
							};
							i++;

						} while (i < ctx.Num_of_InCipher[Fault.Sbox]);

// step 20
						int Min = 0, MinValu_before_addingKey = 0;

						Min = ctx.counter[Fault.Sbox][0];
						for (i = 1; i < 64; i++)
							if (ctx.counter[Fault.Sbox][i] < Min)
							{
								Min = ctx.counter[Fault.Sbox][i];
								MinValu_before_addingKey = i;
							}

						ctx.rk[Fault.Sbox] = (MinValu_before_addingKey ^ ConvertRowCol_to_InputSbox(Fault.row, Fault.col));

					} // for fault
// step 20
					Convert_rk_to_subkey(&ctx, r - 1);


				} //for r


				// to estimate the best value of N
				for (i = 0; i < 16; i++)
					if (ctx.subkey[i] != a_key[i])
						temp = 1;
					else
						temp = 0;

				N++;
			} while (temp);

			sum = (sum + N);

		}//for NumberOfRepetition// 


		printf("On average, %f infection ciphertexts is needed to recover Random Key Number %d(%016llx)\n", (double)((double)sum / MaxOfRepetition), RandomKeyNumber, key);
		printf("------------------------\n");
		fprintf(fprt, "%d,%f\n", RandomKeyNumber,(double)((double)sum / MaxOfRepetition));

	}//for RandomKeyNumber = 0; RandomKeyNumber < 10000; RandomKeyNumber++

		fclose(fprt);

		return 0;
	}










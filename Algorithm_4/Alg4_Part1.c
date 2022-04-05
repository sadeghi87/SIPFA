/*
This code is a simulation of Alg 4 steps 1 to 14.
The aim of first part of Alg4 is finding  the fault location 
*/
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <memory.h>
#include "getopt.h"
#include <string.h>
#include <math.h>
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
	Fault.Sbox = 0;
	Fault.row = rand() % 4;
	Fault.col = rand() % 16;

	int N;// Number Of Infection_Based Ciphertexts
	printf("The fulty Sbox ---> %d \n", Fault.Sbox);

	FILE *fprt;

	//#############################################################################################

	uint64_t key;

	int Sbox;
	//############################################################################################
	uint64_t Data_1, Data_2, Data;
	uint64_t Valu_before_addingKey;


	int i, j, h;
	int kk = 0, ll = 0, mm = 0;
	double SEI[8];
	double q[8][64];
	int cnt[8][64];
	int Num_of_CipherText;
	int temmp, temmp2;
	double Max = 0;
	int max_index = 0;

	int CountTests = 0;
	int Num_of_repeatedTest = 100; // the number of repeated
	int Index_Key[100] = { 0 };

	fprt = fopen("Result_Alg4.csv", "w");

	while (CountTests < Num_of_repeatedTest) 										
	{
		CountTests++;
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
		for (N = 1; N < 10000; N++) {
			temmp = 1;
			uint64_t * infection_CipherText = (uint64_t *)malloc(sizeof(uint64_t) * N);
			//step 1 to 4
			//************************************************
			for (i = 0; i < 8; i++)
				SEI[i] = 0;
			for (i = 0; i < 8; i++)
				for (j = 0; j < 64; j++)
				{
					cnt[i][j] = 0;
					q[i][j] = 0;
				}
			//************************************************
			Num_of_CipherText = 0;
			do {  // while (Num_of_CipherText < N)
				Data_1 = Data_2 = Random64();//

											 //Encryption 
				DES_Alg_Enc(&Data_1, key);
				DES_Alg_EncFaulty(&Fault, &Data_2, key);

				//here Data is ciphertext
				// step 6
				if (Data_1 == Data_2)
					Data = Data_1;
				else
					Data = Random64();
				{
					infection_CipherText[Num_of_CipherText] = Data;
					Num_of_CipherText++;

					Valu_before_addingKey = 0;
					// step 7
					DES_Expansion_for_lastRound(&Data, &Valu_before_addingKey);
					uint64_t Data = Valu_before_addingKey;
					// steps 8, 9
					for (Sbox = 0; Sbox < 8; Sbox++) // for all Sboxes
					{
						Valu_before_addingKey = ((Data >> (64 - 6 * (Sbox + 1))) & 0x3F);
						if ((0 <= Valu_before_addingKey) && (Valu_before_addingKey < 64))
						{
							cnt[Sbox][Valu_before_addingKey]++;
						}
					}// for (sbox=0 ...
				}// if
			} while (Num_of_CipherText < N);

			// steps 9 to 13
			double temp;
			for (Sbox = 0; Sbox < 8; Sbox++)
				for (h = 0; h < 64; h++)
				{
					q[Sbox][h] = ((double)cnt[Sbox][h] / N);

					temp = (q[Sbox][h] - (double)(1 / 64));
					SEI[Sbox] = (SEI[Sbox] + pow((double)temp, 2));
				}
			// step 14
			Max = 0;
			max_index = 0;
			for (i = 0; i < 8; i++)
			{
				if (SEI[i] > Max)
				{
					Max = SEI[i];
					max_index = i;
				}
			}

			fprintf(fprt, "%d,%d\n", N, max_index);
			printf( "The number of infection-based ciphertexts (N): %d, The number of Sboxes: %d\n", N, max_index);





			if (Fault.Sbox != max_index)
				temmp = 0;

		}// while (CountTests < Num_of_repeatedTest);// for N = ... // do

	}// for N




	fclose(fprt);
	//	free(infection_CipherText);
	system("pause");
	return 0;
}
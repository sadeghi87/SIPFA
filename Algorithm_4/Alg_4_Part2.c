/*
In the second partof Algorithm 4, we generate $N$ infection-based ciphertexts
all of which were obtained using the same master key and a faulty Sbox. 
Note that due to time constraints, we assumed only 12 bits of the related keys $k_{16}$ 
to be unknown. Given $N$ ($N=3000,3500,\cdots,20000)$, we repeated this test for 100 
random secret keys and counted the average number of the ranks of the candidate keys. 
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
	Fault.Sbox = rand() % 8;
	Fault.row = rand() % 4;
	Fault.col = rand() % 16;

	int N;// Number Of Infection_Based Ciphertexts

	
	FILE *fprt;
	fprt = fopen("Result_Alg4_secondPart.csv", "w");
//#############################################################################################
// master key
	uint64_t key;

	int Sbox;
//############################################################################################
	uint64_t Data_1, Data_2, Data;
	uint64_t Valu_before_addingKey;
	

//	 $N$($N = 3000, 3500, \cdots, 20000)$
	for (N = 3000; N <= 20000; N=N+500)
	{
		printf("For N = %d : \n", N);
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
		int Num_of_repeatedTest = 3; // the number of repeated
		int Index_Key[100] = { 0 };





		while (CountTests < Num_of_repeatedTest) //
		{
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
			temmp = 1;
			uint64_t * infection_CipherText = (uint64_t *)malloc(sizeof(uint64_t) * N);
//step 1 to 4

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
				//Encryption when a fault is occurred 
				DES_Alg_EncFaulty(&Fault, &Data_2, key);

				//here Data is ciphertext
// step 6
				if (Data_1 == Data_2)
					Data = Data_1;
				else
					Data = Random64(); //an Infection based countermeasure
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

			if (Fault.Sbox != max_index)
				temmp = 0;

			if (temmp)
			{
				Fault.Sbox = max_index;
// to Step 14
				/*
				a_key[15] = ctx.rk[0] || ... || ctx.rk[7] so:
				if the faulty_Sbox_number =0:
				the subkeys ctx.rk[i], i= 1, 3, 4, 5, 6, and 7 should be guessed.
				and for i= 0,2, we do not need subkeys ctx.rk[i]
				if the faulty_Sbox_number =1:
				the subkeys ctx.rk[i], i= 0, 2, 4, 5, 6, and 7 should be guessed.
				and for i= 1,3, we do not need subkeys ctx.rk[i]
				if the faulty_Sbox_number =2:
				the subkeys ctx.rk[i], i= 0, 1, 3, 4, 5, and 6 should be guessed.
				and for i= 2,7, we do not need subkeys ctx.rk[i]
				if the faulty_Sbox_number =3:
				the subkeys ctx.rk[i], i= 0, 1, 2, 4, 6, and 7 should be guessed.
				and for i= 3,5, we do not need subkeys ctx.rk[i]
				if the faulty_Sbox_number =4:
				the subkeys ctx.rk[i], i= 0, 1, 2, 3, 5, and 7 should be guessed.
				and for i= 4,6, we do not need subkeys ctx.rk[i]
				if the faulty_Sbox_number =5:
				the subkeys ctx.rk[i], i= 0, 2, 3, 4, 6, and 7 should be guessed.
				and for i= 5,1, we do not need subkeys ctx.rk[i]
				if the faulty_Sbox_number =6:
				the subkeys ctx.rk[i], i= 1, 2, 3, 4, 5, and 7 should be guessed.
				and for i= 6,0, we do not need subkeys ctx.rk[i]
				if the faulty_Sbox_number =7:
				the subkeys ctx.rk[i], i= 0, 1, 2, 3, 5, and 6 should be guessed.
				and for i= 7,4, we do not need subkeys ctx.rk[i]

				Note that since we do not need to know 12 bits of ctx.rk[i] so,
				In this test, we assume 24-bit of subkeys are known and
				guess just 12 bits of subkeys.
				*/
				// we do not need to know 12 bits of ctx.rk[i] so:
				ctx.rk[Fault.Sbox] = ((a_key[15] >> (64 - 6 * (Fault.Sbox + 1))) & 0x3F);
				if (Fault.Sbox == 0)
					ctx.rk[2] = ((a_key[15] >> (64 - 6 * (2 + 1))) & 0x3F);
				else if (Fault.Sbox == 1)
					ctx.rk[3] = ((a_key[15] >> (64 - 6 * (3 + 1))) & 0x3F);
				else if (Fault.Sbox == 2)
					ctx.rk[7] = ((a_key[15] >> (64 - 6 * (7 + 1))) & 0x3F);
				else if (Fault.Sbox == 3)
					ctx.rk[5] = ((a_key[15] >> (64 - 6 * (5 + 1))) & 0x3F);
				else if (Fault.Sbox == 4)
					ctx.rk[6] = ((a_key[15] >> (64 - 6 * (6 + 1))) & 0x3F);
				else if (Fault.Sbox == 5)
					ctx.rk[1] = ((a_key[15] >> (64 - 6 * (1 + 1))) & 0x3F);
				else if (Fault.Sbox == 6)
					ctx.rk[0] = ((a_key[15] >> (64 - 6 * (0 + 1))) & 0x3F);
				else if (Fault.Sbox == 7)
					ctx.rk[4] = ((a_key[15] >> (64 - 6 * (4 + 1))) & 0x3F);

				if (Fault.Sbox == 0)
				{
					//we assume 24-bit of subkeys are known:
					ctx.rk[1] = Extract_rth_6bit_from_64bit(a_key[15], 1);
					ctx.rk[3] = Extract_rth_6bit_from_64bit(a_key[15], 3);
					ctx.rk[4] = Extract_rth_6bit_from_64bit(a_key[15], 4);
					ctx.rk[5] = Extract_rth_6bit_from_64bit(a_key[15], 5);
					//we guess 12-bit of subkeys:
					//	ctx.rk[6] = Extract_rth_6bit_from_64bit(a_key[15], 6);
					//	ctx.rk[7] = Extract_rth_6bit_from_64bit(a_key[15], 7);
				}
				else if (Fault.Sbox == 1)
				{
					//we assume 24-bit of subkeys are known:
					ctx.rk[0] = Extract_rth_6bit_from_64bit(a_key[15], 0);
					ctx.rk[2] = Extract_rth_6bit_from_64bit(a_key[15], 2);
					ctx.rk[4] = Extract_rth_6bit_from_64bit(a_key[15], 4);
					ctx.rk[5] = Extract_rth_6bit_from_64bit(a_key[15], 5);
					//we guess 12-bit of subkeys:
					//ctx.rk[6] = Extract_rth_6bit_from_64bit(a_key[15], 6);
					//ctx.rk[7] = Extract_rth_6bit_from_64bit(a_key[15], 7);
				}
				else if (Fault.Sbox == 2)
				{
					//we assume 24-bit of subkeys are known:
					ctx.rk[0] = Extract_rth_6bit_from_64bit(a_key[15], 0);
					ctx.rk[1] = Extract_rth_6bit_from_64bit(a_key[15], 1);
					ctx.rk[3] = Extract_rth_6bit_from_64bit(a_key[15], 3);
					ctx.rk[4] = Extract_rth_6bit_from_64bit(a_key[15], 4);
					//we guess 12-bit of subkeys:
					//ctx.rk[5] = Extract_rth_6bit_from_64bit(a_key[15], 5);
					//ctx.rk[6] = Extract_rth_6bit_from_64bit(a_key[15], 6);
				}
				else if (Fault.Sbox == 3)
				{
					//we assume 24-bit of subkeys are known:
					ctx.rk[0] = Extract_rth_6bit_from_64bit(a_key[15], 0);
					ctx.rk[1] = Extract_rth_6bit_from_64bit(a_key[15], 1);
					ctx.rk[2] = Extract_rth_6bit_from_64bit(a_key[15], 2);
					ctx.rk[4] = Extract_rth_6bit_from_64bit(a_key[15], 4);
					//we guess 12-bit of subkeys:
					//ctx.rk[6] = Extract_rth_6bit_from_64bit(a_key[15], 6);
					//ctx.rk[7] = Extract_rth_6bit_from_64bit(a_key[15], 7);
				}
				else if (Fault.Sbox == 4)
				{
					//we assume 24-bit of subkeys are known:
					ctx.rk[0] = Extract_rth_6bit_from_64bit(a_key[15], 0);
					ctx.rk[1] = Extract_rth_6bit_from_64bit(a_key[15], 1);
					ctx.rk[2] = Extract_rth_6bit_from_64bit(a_key[15], 2);
					ctx.rk[3] = Extract_rth_6bit_from_64bit(a_key[15], 3);
					//we guess 12-bit of subkeys:
					//ctx.rk[5] = Extract_rth_6bit_from_64bit(a_key[15], 5);
					//ctx.rk[7] = Extract_rth_6bit_from_64bit(a_key[15], 7);
				}
				else if (Fault.Sbox == 5)
				{
					//we assume 24-bit of subkeys are known:
					ctx.rk[0] = Extract_rth_6bit_from_64bit(a_key[15], 0);
					ctx.rk[2] = Extract_rth_6bit_from_64bit(a_key[15], 2);
					ctx.rk[3] = Extract_rth_6bit_from_64bit(a_key[15], 3);
					ctx.rk[4] = Extract_rth_6bit_from_64bit(a_key[15], 4);
					//we guess 12-bit of subkeys:
					//ctx.rk[6] = Extract_rth_6bit_from_64bit(a_key[15], 6);
					//ctx.rk[7] = Extract_rth_6bit_from_64bit(a_key[15], 7);
				}
				else if (Fault.Sbox == 6)
				{
					//we assume 24-bit of subkeys are known:
					ctx.rk[1] = Extract_rth_6bit_from_64bit(a_key[15], 1);
					ctx.rk[2] = Extract_rth_6bit_from_64bit(a_key[15], 2);
					ctx.rk[3] = Extract_rth_6bit_from_64bit(a_key[15], 3);
					ctx.rk[4] = Extract_rth_6bit_from_64bit(a_key[15], 4);
					//we guess 12-bit of subkeys:
					//ctx.rk[5] = Extract_rth_6bit_from_64bit(a_key[15], 5);
					//ctx.rk[7] = Extract_rth_6bit_from_64bit(a_key[15], 7);
				}
				else if (Fault.Sbox == 7)
				{
					//we assume 12-bit of subkeys are known:
					ctx.rk[0] = Extract_rth_6bit_from_64bit(a_key[15], 0);
					ctx.rk[1] = Extract_rth_6bit_from_64bit(a_key[15], 1);
					ctx.rk[2] = Extract_rth_6bit_from_64bit(a_key[15], 2);
					ctx.rk[3] = Extract_rth_6bit_from_64bit(a_key[15], 3);
					//we guess 12-bit of subkeys:
					//ctx.rk[5] = Extract_rth_6bit_from_64bit(a_key[15], 5);
					//ctx.rk[6] = Extract_rth_6bit_from_64bit(a_key[15], 6);
				}


				//infection_CipherText
				uint64_t * infection_CipherText_ = (uint64_t *)malloc(sizeof(uint64_t) * N);
				//building SEI_k[64][64][64] = { 0 };
				int cnt_sort = 0;
				int n1, n2, n3;
				int  k = 64, l = 64, m = 64;
				double  ***SEI_k = (int ***)malloc(sizeof(int *) * k);



				for (n1 = 0; n1 < k; n1++)
					SEI_k[n1] = (int **)malloc(sizeof(int *) * l);


				for (n1 = 0; n1 < k; n1++)
					for (n2 = 0; n2 < l; n2++)
						SEI_k[n1][n2] = (int *)malloc(sizeof(int *) * m);

// step 15, 16
				for (n1 = 0; n1 < k; n1++)
					for (n2 = 0; n2 < l; n2++)
						for (n3 = 0; n3 < m; n3++)
							SEI_k[n1][n2][n3] = 0;


				//		do {// continiue to #candidate =1
				Max = 0;
				max_index = 0;
				int t2 = 0;
				double sort_temp;
				double * Sort_SEI_k = (double *)malloc(sizeof(double) * pow(2.0, 12));

				for (i = 0; i < pow(2.0, 12); i++)
					Sort_SEI_k[i] = 0;

				for (k = 0; k <= 0; k++)
					for (l = 0; l < 64; l++)
						for (m = 0; m < 64; m++)
						{
							if (Fault.Sbox == 0)
							{
								//ctx.rk[5] = k;
								ctx.rk[6] = l;
								ctx.rk[7] = m;
							}
							else if (Fault.Sbox == 1)
							{
								//ctx.rk[5] = k;
								ctx.rk[6] = l;
								ctx.rk[7] = m;
							}
							else if (Fault.Sbox == 2)
							{
								//ctx.rk[4] = k;
								ctx.rk[5] = l;
								ctx.rk[6] = m;
							}
							else if (Fault.Sbox == 3)
							{
								//ctx.rk[4] = k;
								ctx.rk[6] = l;
								ctx.rk[7] = m;
							}
							else if (Fault.Sbox == 4)
							{
								//	ctx.rk[3] = k;
								ctx.rk[5] = l;
								ctx.rk[7] = m;
							}
							else if (Fault.Sbox == 5)
							{
								//	ctx.rk[4] = k;
								ctx.rk[6] = l;
								ctx.rk[7] = m;
							}
							else if (Fault.Sbox == 6)
							{
								//	ctx.rk[4] = k;
								ctx.rk[5] = l;
								ctx.rk[7] = m;
							}
							else if (Fault.Sbox == 7)
							{
								//	ctx.rk[3] = k;
								ctx.rk[5] = l;
								ctx.rk[6] = m;
							}


							for (i = 0; i < Num_of_CipherText; i++)
								infection_CipherText_[i] = infection_CipherText[i];


							Convert_rk_to_subkey(&ctx, Num_ROUNDS);

//step 20
							for (i = 0; i < Num_of_CipherText; i++)
								DES_Alg_Dec_LastRound(&infection_CipherText_[i], ctx.subkey[Num_ROUNDS - 1]);



							int cnt_[64];
							for (i = 0; i < 64; i++)
								cnt_[i] = 0;
							i = 0;
							do
							{
								Valu_before_addingKey = 0;
//step 21
								DES_Expansion(&Fault, &infection_CipherText_[i], &Valu_before_addingKey);
								if ((0 <= Valu_before_addingKey) && (Valu_before_addingKey < 64))
								{
									cnt_[Valu_before_addingKey]++;
								}
								i++;
							} while (i < Num_of_CipherText);
//steps 22 to 24
							double p[64] = { 0 };
							double temp_;
							for (h = 0; h < 64; h++)
							{
								p[h] = ((double)cnt_[h] / N);

								temp_ = (p[h] - (double)(1 / 64));
								SEI_k[k][l][m] = (SEI_k[k][l][m] + pow((double)temp_, 2));
							}
							// Sort SEI_k from Max to Min to find the rank of keys
							Sort_SEI_k[cnt_sort] = SEI_k[k][l][m];

							for (j = 0; j < cnt_sort; j++)
								if (Sort_SEI_k[cnt_sort] >= Sort_SEI_k[j])
								{
									sort_temp = Sort_SEI_k[cnt_sort];
									for (i = cnt_sort; i > j; i--)
										Sort_SEI_k[i] = Sort_SEI_k[i - 1];
									Sort_SEI_k[i] = sort_temp;
									break;
								}
							cnt_sort++;

							if (ctx.subkey[Num_ROUNDS - 1] == a_key[15])
							{
								kk = k;
								ll = l;
								mm = m;
							}
						} // for k,l,m ...
				int u = 0;
				for (j = 0; j < 63; j++)
					if (Sort_SEI_k[j] == SEI_k[kk][ll][mm])
					{
						u++;
						if (u == 1)
							Index_Key[CountTests] = j;

					}
			//	if (u >= 2)
			//		printf("u >= 2\n");

				printf("The number of repetitions: %d\n", CountTests);

				CountTests++;

			}// if (temp)  
		}// while (CountTests < Num_of_repeatedTest);

		int Sum = 0;
		for (j = 0; j < Num_of_repeatedTest; j++) {
			Sum = (Sum + Index_Key[j]);
		}
		fprintf(fprt, "%d,%f\n", N, (double)Sum / Num_of_repeatedTest);
		printf("The number of infection-based ciphertexts: %d, The rank of candidate key:\t %f \n", N, (double)Sum / Num_of_repeatedTest);
	}

	fclose(fprt);
	//	free(infection_CipherText);
	system("pause");
	return 0;
}










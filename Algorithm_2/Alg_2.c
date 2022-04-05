/*
In Algorithm 2, we assume that the fault location and also its value are unknown 
for the adversary and the purpose is  to recover the $\kappa$ bits of $sk_n$ for 
a detection-based countermeasure.
To simulate Algorithm 2, we assume only 12 bits of the related keys $k_{16}$ 
are unknown and we generate $N$ detection-based countermeasure ciphertexts all
of which are obtain using the same master key and a faulty Sbox. 
For each $N$, we repeated the tests 100 times to obtain an average of the number
of key candidates. 
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
	int N; 
//#############################################################################################
	// master key of DES
	uint64_t key;
//############################################################################################
	uint64_t Data1, Data2;
	uint64_t Valu_before_addingKey;
	int count[16][8] = { 1 }; // counting the number of ciphertexts for each faulty sbox. //count[#rounds][#sboxes]
	int i, j, f=0;
	int arr[8][64];
		for (i = 0; i < 8; i++)
			for (j = 0; j < 64; j++)
				arr[i][j] = 1;

		FILE *fprt;
		fprt = fopen("Result_Alg2.csv", "w");

		// The fault location and its value are unknown
		Fault.Sbox =  rand() % 8;
		Fault.row = rand() % 3;
		Fault.col = rand() % 16;

		i = 0;

		int	Num_of_CipherText;
		int Sbox;

		int NumberOfRepetition;
		int MaxOfRepetition = 100; // the number of repeated
		int SumCandidateKey[100];

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
		printf("\n The key sk_n is:\t  %016llx \n", a_key[15]);
		uint64_t  Ineffective_CipherText__[3000] = { 0 };
		Num_of_CipherText = 0;
		for (N = 1; N < 3000; N++)
		{
			
			for (NumberOfRepetition = 0; NumberOfRepetition < MaxOfRepetition; NumberOfRepetition++)
			{
				
				do { //while (Num_of_CipherText < N)

					Data1 = Data2 = Random64();
			//#############################################################################################	
					//Encryption 
					DES_Alg_Enc(&Data1, key);
					//Encryption when a fault is occurred 
					DES_Alg_EncFaulty(&Fault, &Data2, key);

					//here Data is ciphertext
					if (Data1 == Data2) //detection-based countermeasure
					{
// step 4 (Get a correct ciphertex)
						ctx.Ineffective_CipherText_[Num_of_CipherText] = Data1;

						Num_of_CipherText++;
// Step 5
						DES_Expansion_for_lastRound(&Data1, &Valu_before_addingKey);
						//ctx.Ineffective_CipherText_[Num_of_CipherText] = Data1;
						
						uint64_t Xn = Valu_before_addingKey;
// step 6,7
						for (Sbox = 0; Sbox < 8; Sbox++) // for all Sboxes
						{
							Valu_before_addingKey = ((Xn >> (64 - 6 * (Sbox + 1))) & 0x3F);
							if ((0 <= Valu_before_addingKey) && (Valu_before_addingKey < 64))
							{
								if (arr[Sbox][Valu_before_addingKey])
								{
									arr[Sbox][Valu_before_addingKey] = 0;
								};
							};
						}// for (sbox=0 ...
					}

				} while (Num_of_CipherText < N);
// step 8
				int faulty_Sbox_number = 0, t = 0,e; 

				for (e = 0; e < 8; e++) // for all Sboxes
				{
					for (i = 0; i < 64; i++)
						if (arr[e][i])
						{
// step 9 (e gives the faulty Sboxs numbe)				
							faulty_Sbox_number = e; 
						//	OutputExpansion_Value = i;
							t++;
						};
				}
				int err = 1;
				if (t >= 2) // There are no  enough ciphertext
				{
					printf("%d \n", N);
					NumberOfRepetition = MaxOfRepetition -1;
					err = 0;
				}
				
			if (err) // There are  enough ciphertext
				{
					f = 1;
					
					Fault.Sbox = faulty_Sbox_number;

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


					int value = 0, t2 = 0;
					SumCandidateKey[NumberOfRepetition] = 0;
					int k, l, m;

// Step 11 
//we guess 12-bit of subkeys:
				//	for (k = 0; k <=0; k++)
						for (l = 0; l < 64; l++) // guess 6-bit
							for (m = 0; m < 64; m++) // guess 6-bit
							{
								if (Fault.Sbox == 0)
								{
									//ctx.rk[5] = k;
									ctx.rk[6] = l;
									ctx.rk[7] = m;
								}
								else if (Fault.Sbox == 1)
								{
									//		ctx.rk[5] = k;
									ctx.rk[6] = l;
									ctx.rk[7] = m;
								}
								else if (Fault.Sbox == 2)
								{
									//		ctx.rk[4] = k;
									ctx.rk[5] = l;
									ctx.rk[6] = m;
								}
								else if (Fault.Sbox == 3)
								{
									//		ctx.rk[4] = k;
									ctx.rk[6] = l;
									ctx.rk[7] = m;
								}
								else if (Fault.Sbox == 4)
								{
									//			ctx.rk[3] = k;
									ctx.rk[5] = l;
									ctx.rk[7] = m;
								}
								else if (Fault.Sbox == 5)
								{
									//		ctx.rk[4] = k;
									ctx.rk[6] = l;
									ctx.rk[7] = m;
								}
								else if (Fault.Sbox == 6)
								{
									//			ctx.rk[4] = k;
									ctx.rk[5] = l;
									ctx.rk[7] = m;
								}
								else if (Fault.Sbox == 7)
								{
									//			ctx.rk[3] = k;
									ctx.rk[5] = l;
									ctx.rk[6] = m;
								}

								// ctx.subkey[Num_ROUNDS - 1]  <----  ctx.rk[0]||...||ctx.rk[7]
								Convert_rk_to_subkey(&ctx, Num_ROUNDS); 
// Step 12
								for (i = 0; i < Num_of_CipherText; i++)
								{
									Ineffective_CipherText__[i] = ctx.Ineffective_CipherText_[i];
									DES_Alg_Dec_LastRound(&Ineffective_CipherText__[i], ctx.subkey[Num_ROUNDS - 1]);
								}

								int arrr[64];
								for (i = 0; i < 64; i++)
									arrr[i] = 1;
								i = 0;

								do
								{
									Valu_before_addingKey = 0; // Valu_before_addingKey <----  X_{n-1}[i]
// Step 13 , 14
									
									DES_Expansion(&Fault, &Ineffective_CipherText__[i], &Valu_before_addingKey);
									if ((0 <= Valu_before_addingKey) && (Valu_before_addingKey < 64))
									{
										if (arrr[Valu_before_addingKey])
										{
											arrr[Valu_before_addingKey] = 0;
										};
									};
									i++;


								} while (i < Num_of_CipherText);
// Step 14
								for (i = 0; i < 64; i++)
									if (arrr[i]) // it determines a Candidate Key
									{
										//value = i;
										//	t2++;
										SumCandidateKey[NumberOfRepetition]++; 
								//		printf("\n obtained key sk_n is:\t  %016llx \n", ctx.subkey[15]);
									};

							} // for m,k,l..
// step 16
				if (SumCandidateKey[NumberOfRepetition]==1)
				{
						printf("\n The expected key is:\t  %016llx \n", ctx.subkey[15]);
				}
							if (MaxOfRepetition > 1)
								printf("The number of Test:\t %d\t", NumberOfRepetition);

						printf("N =  %d  \t  \#Candidate keys:\t %d\n", N, SumCandidateKey[NumberOfRepetition]);//t2
					
				}// if err
				
			}// for NumberOfRepetition=1,...,100.
			
			int Sum = 0;
			for (j = 0; j < MaxOfRepetition; j++)
			{
				Sum = (Sum + SumCandidateKey[j]);
			}

			if (f == 1 && MaxOfRepetition > 1) {
				fprintf(fprt, "%d,%f\n", N, (double)Sum / MaxOfRepetition);

				printf("N %d \t Mean:\t %f\n", N, (double)Sum / MaxOfRepetition);
				printf("--------------------------------\n");
			}

		} //for N

		fclose(fprt);
		return 0;
	}











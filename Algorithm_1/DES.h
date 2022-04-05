// 
// Implementation of DES coded by:
//     - David Wong, moi@davidwong.fr
//     - Jacques Monin, jacques.monin@u-bordeaux.fr
//     - Hugo Bonnin, hugo.bonnin@u-bordeaux.fr
//

#include <string.h>

#ifndef DES_H
#define DES_H





#ifndef contex
typedef struct Fault_DES {
	int Sbox;
	int row;
	int col;

}Fault_DES_Alg;

typedef struct DES_Alg
{
	uint64_t rk[8];
	uint64_t subkey[16];
	uint64_t  Ineffective_CipherText[8][10000]; // an array for saving all Ineffective Ciphertexts related with 8 faulted sboxes
	int Num_of_InCipher[8]; // the number of each Ineffective Ciphertext for 8 faulted sboxes
}DES_Alg_ctx;
#endif

//////////////////////////////////////////////////////
//               USEFUL DEFINES                    //
////////////////////////////////////////////////////

#define FIRSTBIT 0x8000000000000000 // 1000000000...

//////////////////////////////////////////////////////
//                 PROTOTYPES                      //
////////////////////////////////////////////////////

// Addbit helper
// Takes the bit number "position_from" from "from"
// adds it to "block" in position "position_to"
void addbit(uint64_t *block, uint64_t from,
            int position_from, int position_to);

// Initial and Final Permutations
void Permutation(uint64_t* data, bool initial);

// Verify if the parity bits are okay
bool key_parity_verify(uint64_t key);

// Key Schedule ( http://en.wikipedia.org/wiki/File:DES-key-schedule.png )
// input :
//   * encrypt : false if decryption
//   * next_key : uint64_t next_key 0
//   * round : [[0, 15]]
// changes :
//   * [key] is good to be used in the XOR in the rounds
//   * [next_key] is the combined leftkey+rightkey to be used
//     in the key_schedule for next round
void key_schedule(uint64_t* key, uint64_t* next_key, int round);

void rounds(uint64_t *data, uint64_t key);

void Last_rounds(uint64_t *data, uint64_t key, int i, int j, int k);

void Convert_rk_to_subkey(DES_Alg_ctx* ctx, int round);

void DES_Alg_EncFaulty(Fault_DES_Alg* Fault, uint64_t *data, uint64_t key);

void DES_Alg_Enc(uint64_t *data, uint64_t key);

void DES_Expansion(Fault_DES_Alg *Fault, uint64_t *data, uint64_t *OutputExpansion);

int ConvertRowCol_to_InputSbox(int row, int col);

void DES_Alg_Dec_LastRound(uint64_t *data, uint64_t key);

void DES_Alg_Dec_oneRound(uint64_t *data, uint64_t key);

void DES_Expansion2(Fault_DES_Alg *Fault, uint64_t *data, uint64_t *OutputExpansion);
#endif

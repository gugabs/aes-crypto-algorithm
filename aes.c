#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// S-Box Initialization Dependency

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

#define ROUNDS 10 

typedef unsigned char BYTE;

const BYTE round_constants[] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

void initialize_aes_sbox(uint8_t sbox[256]);
void read_line(FILE* credentials, BYTE** target);
void create_block(BYTE** block, BYTE* key);
void key_expansion(uint8_t* sbox, BYTE** key_block, BYTE* round_keys);
void add_round_key(BYTE** block, BYTE* round_key);
void sub_bytes(uint8_t* sbox, BYTE** block);
void shift_rows(BYTE** block);
void mix_columns(BYTE** block);
void aes_encrypt(uint8_t* sbox, BYTE** block, BYTE* round_keys);

int main(int argc, char *argv[]) {
  uint8_t* sbox = malloc(sizeof(uint8_t) * 256);

  BYTE** key_block = (BYTE**) malloc(sizeof(BYTE*) * 4);
  BYTE** cipher_block = (BYTE**) malloc(sizeof(BYTE*) * 4);

  for (int i = 0; i < 4; i++) {
    key_block[i] = (BYTE*) malloc(sizeof(BYTE) * 4);
    cipher_block[i] = (BYTE*) malloc(sizeof(BYTE) * 4);
  }

  BYTE* round_keys = malloc(sizeof(BYTE) * 4 * 44);

  FILE* credentials;

  BYTE* key = NULL;
  BYTE* plain_text = NULL;

  credentials = fopen("credentials.txt", "r");

  if (credentials == NULL) {
    perror("File can't be opened\n");

    return 1;
  }

  read_line(credentials, &key);
  read_line(credentials, &plain_text);

  fclose(credentials);

  initialize_aes_sbox(sbox);

  create_block(key_block, key);
  key_expansion(sbox, key_block, round_keys);

  create_block(cipher_block, plain_text);
  aes_encrypt(sbox, cipher_block, round_keys);

  printf("\n");
  printf("Encoded Text:\n");
  printf("\n");

  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      printf("%02hhX", cipher_block[j][i]);

  printf("\n");

  for (int i = 0; i < 4; i++) {
    free(key_block[i]);
    free(cipher_block[i]);
  }

  free(sbox);
  free(key_block);
  free(cipher_block);
  free(round_keys);

  return 0;
}

void read_line(FILE* credentials, BYTE** target) {
  char* line;

  char ch_buffer;

  int line_size = 1;
  int ch_index = 0;

  line = malloc(sizeof(char));

  while ((ch_buffer = getc(credentials)) != '\n' && ch_buffer != EOF) {
    line = realloc(line, line_size + 1);
    line[ch_index] = ch_buffer;

    line_size++;
    ch_index++;
  }

  line[ch_index] = '\0';

  *target = realloc(*target, line_size);
  strcpy(*target, line);

  free(line);
}

// Wikipedia AES S-Box Implementation

void initialize_aes_sbox(uint8_t sbox[256]) {
  uint8_t p = 1, q = 1;

  /* loop invariant: p * q == 1 in the Galois field */
  do {
    /* multiply p by 3 */
    p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

    /* divide q by 3 (equals multiplication by 0xf6) */
    q ^= q << 1;
    q ^= q << 2;
    q ^= q << 4;
    q ^= q & 0x80 ? 0x09 : 0;

    /* compute the affine transformation */
    uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

    sbox[p] = xformed ^ 0x63;
  } while (p != 1);

  /* 0 is a special case since it has no inverse */
  sbox[0] = 0x63;
}

void create_block(BYTE** block, BYTE* key) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      block[i][j] = key[j * 4 + i];
    }
  }
}

void key_expansion(uint8_t* sbox, BYTE** key_block, BYTE* round_keys) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      round_keys[i * 4 + j] = key_block[j][i];
    }
  }

  for (int i = 4; i < 44; i++) {
    BYTE shift_aux[4];

    memcpy(shift_aux, round_keys + (i - 1) * 4, 4);

    if (i % 4 == 0) {
      BYTE circular_byte = shift_aux[0];

      for (int j = 0; j < 4; j++) {
        if (j == 3) {
          shift_aux[j] = circular_byte;
          break;
        }

        shift_aux[j] = shift_aux[j + 1];
      }

      for (int k = 0; k < 4; k++) {
        shift_aux[k] = sbox[shift_aux[k]];
      }

      shift_aux[0] ^= round_constants[(i / 4) - 1];
    }

    for (int j = 0; j < 4; j++) {
      round_keys[i * 4 + j] = round_keys[(i - 4) * 4 + j] ^ shift_aux[j];
    }
  }
}

void add_round_key(BYTE** block, BYTE* round_key) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      block[j][i] ^= round_key[i * 4 + j];
    }
  }
}

void sub_bytes(uint8_t* sbox, BYTE** block) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      block[i][j] = sbox[block[i][j]];
    }
  } 
}

void shift_rows(BYTE** block) {
  BYTE circular_byte;

  circular_byte = block[1][0];

  for (int i = 0; i < 3; i++) 
    block[1][i] = block[1][i + 1];
  
  block[1][3] = circular_byte;

  for (int i = 0; i < 2; i++) {
    circular_byte = block[2][i];
    block[2][i] = block[2][i + 2];
    block[2][i + 2] = circular_byte;
  }
  
  circular_byte = block[3][3];

  for (int i = 3; i > 0; i--) 
    block[3][i] = block[3][i - 1];

  block[3][0] = circular_byte;
}

// ChatGPT gmul Implementation

unsigned char gmul(unsigned char a, unsigned char b) {
  unsigned char p = 0;
  unsigned char carry;

  for (int i = 0; i < 8; i++) {
    if (b & 1)
      p ^= a;

    carry = a & 0x80;
    a <<= 1;

    if (carry) 
      a ^= 0x1b;

    b >>= 1;
  }

  return p;
}

void mix_columns(BYTE** block) {
  BYTE mix_aux[4];

  for (int i = 0; i < 4; i++) {
    mix_aux[0] = gmul(0x02, block[0][i]) ^ gmul(0x03, block[1][i]) ^ block[2][i] ^ block[3][i];
    mix_aux[1] = block[0][i] ^ gmul(0x02, block[1][i]) ^ gmul(0x03, block[2][i]) ^ block[3][i];
    mix_aux[2] = block[0][i] ^ block[1][i] ^ gmul(0x02, block[2][i]) ^ gmul(0x03, block[3][i]);
    mix_aux[3] = gmul(0x03, block[0][i]) ^ block[1][i] ^ block[2][i] ^ gmul(0x02, block[3][i]);

    for (int j = 0; j < 4; j++)
      block[j][i] = mix_aux[j];
  }
}

void aes_encrypt(uint8_t* sbox, BYTE** block, BYTE* round_keys) {
  add_round_key(block, round_keys);

  for (int i = 1; i <= ROUNDS; i++) {
    sub_bytes(sbox, block);
    shift_rows(block);

    if (i < ROUNDS)
      mix_columns(block);

    add_round_key(block, (round_keys + i * 16));

    printf("\n");
    printf("Round %d Encryption:\n", i);
    printf("\n");

    for (int i = 0; i < 4; i++)
      for (int j = 0; j < 4; j++)
        printf("%02hhX", block[j][i]);

    printf("\n");
  }
}
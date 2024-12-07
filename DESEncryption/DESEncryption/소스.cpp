#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 초기 치환 테이블 (IP)
int IP[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

// 최종 치환 테이블 (FP)
int FP[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

// S-박스: DES에서 6비트를 4비트로 줄이는 핵심 변환 테이블
// S-박스 정의 (8개의 4x16 S-박스)
int S_BOX[8][4][16] = {
    // S1
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    // S2
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    // S3
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    // S4
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    // S5
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    // S6
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    // S7
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    // S8
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

// 확장 함수 E (32비트 -> 48비트 확장)
int E[] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};

// S-박스 변환 함수
// 입력된 48비트를 32비트로 압축하는 과정
void sbox(int* input, int* output) {
    for (int i = 0; i < 8; i++) {
        // 각 6비트 블록을 사용해 S-박스에서 값을 찾아서 4비트로 변환
        int row = (input[i * 6] << 1) | input[i * 6 + 5];  // 행: 첫 비트와 마지막 비트로 계산
        int col = (input[i * 6 + 1] << 3) | (input[i * 6 + 2] << 2) | (input[i * 6 + 3] << 1) | input[i * 6 + 4];  // 열: 중간 4비트로 계산
        int sbox_value = S_BOX[i][row][col];
        // 4비트 결과를 다시 배열에 저장
        for (int j = 0; j < 4; j++) {
            output[i * 4 + j] = (sbox_value >> (3 - j)) & 0x01;  // S-박스 결과를 4비트로 변환
        }
    }
}

// Feistel 함수: DES의 핵심 부분. 우측 32비트를 확장하고 S-박스를 통과시켜 좌측 32비트와 XOR.
void feistel(int* left, int* right, int* round_key) {
    int expanded_right[48];  // 우측 32비트를 48비트로 확장
    int sbox_output[32];    // S-박스를 거친 후 32비트 출력

    // 확장 함수 E, 32비트를 48비트로 확장
    for (int i = 0; i < 48; i++) {
        expanded_right[i] = right[E[i] - 1];
    }

    // 확장된 우측 48비트를 라운드 키와 XOR
    for (int i = 0; i < 48; i++) {
        expanded_right[i] ^= round_key[i];
    }

    // S-박스를 통과하여 48비트를 32비트로 압축
    sbox(expanded_right, sbox_output);

    // 좌측 32비트와 XOR하여 결과 반영
    for (int i = 0; i < 32; i++) {
        left[i] ^= sbox_output[i];
    }
}

// 라운드 키 생성 함수
void generate_round_key(int* master_key, int* round_key, int round) {
    // 키를 복사하여 사용
    for (int i = 0; i < 48; i++) {
        round_key[i] = master_key[i];  //48비트만 사용
    }
}

// 초기 치환 함수 (IP 테이블을 사용)
void initial_permutation(int* data) {
    int temp[64];
    for (int i = 0; i < 64; i++) {
        temp[i] = data[IP[i] - 1];
    }
    for (int i = 0; i < 64; i++) {
        data[i] = temp[i];
    }
}

// 최종 치환 함수 (FP 테이블을 사용)
void final_permutation(int* data) {
    int temp[64];
    for (int i = 0; i < 64; i++) {
        temp[i] = data[FP[i] - 1];
    }
    for (int i = 0; i < 64; i++) {
        data[i] = temp[i];
    }
}


// DES 암호화 함수
// 평문(64비트)을 암호문(64비트)으로 변환
void des_encrypt(int* plaintext, int* ciphertext, int* key) {
    // 초기 치환
    initial_permutation(plaintext);

    // 16 라운드 Feistel 네트워크
    int left[32], right[32];
    for (int i = 0; i < 32; i++) {
        left[i] = plaintext[i];
        right[i] = plaintext[i + 32];
    }

    // 16 라운드 Feistel 구조
    for (int round = 0; round < 16; round++) {
        int round_key[48];
        generate_round_key(key, round_key, round); // 매 라운드마다 키 생성
        feistel(left, right, round_key); // Feistel 함수 적용

        // 마지막 라운드를 제외하고 좌우 스왑
        if (round != 15) {
            int temp[32];
            memcpy(temp, left, sizeof(temp));
            memcpy(left, right, sizeof(left));
            memcpy(right, temp, sizeof(right));
        }
    }

    // 좌우 결합 후 최종 치환
    for (int i = 0; i < 32; i++) {
        plaintext[i] = left[i];
        plaintext[i + 32] = right[i];
    }

    // 최종 치환
    final_permutation(plaintext);

    // 암호문을 출력 배열로 복사
    memcpy(ciphertext, plaintext, 64 * sizeof(int));
}

// DES 복호화 함수 (암호화의 반대 과정)
void des_decrypt(int* ciphertext, int* plaintext, int* key) {
    // 초기 치환
    initial_permutation(ciphertext);

    int left[32], right[32];
    for (int i = 0; i < 32; i++) {
        left[i] = ciphertext[i];
        right[i] = ciphertext[i + 32];
    }

    // 16 라운드를 역순으로 수행 (복호화)
    for (int round = 15; round >= 0; round--) {
        int round_key[48];
        generate_round_key(key, round_key, round); // 라운드 키 생성
        feistel(left, right, round_key); // Feistel 함수 적용

        // 마지막 라운드를 제외하고 좌우 스왑
        if (round != 0) {
            int temp[32];
            memcpy(temp, left, sizeof(temp));
            memcpy(left, right, sizeof(left));
            memcpy(right, temp, sizeof(right));
        }
    }

    // 좌우 결합 후 최종 치환
    for (int i = 0; i < 32; i++) {
        ciphertext[i] = left[i];
        ciphertext[i + 32] = right[i];
    }

    // 최종 치환
    final_permutation(ciphertext);

    // 평문을 출력 배열로 복사
    memcpy(plaintext, ciphertext, 64 * sizeof(int));
}

// 패딩 추가 함수 (PKCS5/7)
int add_padding(unsigned char* buffer, int length) {
    int pad_value = 8 - (length % 8); // 남은 바이트를 채울 값
    for (int i = length; i < length + pad_value; i++) {
        buffer[i] = pad_value;
    }
    return length + pad_value; // 새로 패딩된 전체 길이 반환
}

// 패딩 제거 함수 (PKCS5/7)
int remove_padding(unsigned char* buffer, int length) {
    int pad_value = buffer[length - 1];
    return length - pad_value; // 패딩 제거 후 실제 데이터 길이 반환
}

// 파일 암호화 함수
void encrypt_file(const char* input_file, const char* output_file, int* key) {
    FILE* in = fopen(input_file, "rb");
    FILE* out = fopen(output_file, "wb");

    if (!in || !out) {
        printf("파일을 열 수 없습니다.\n");
        return;
    }

    unsigned char buffer[8]; // 8바이트(64비트) 단위로 읽기
    int ciphertext[64]; // 64비트 암호문
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, 8, in)) > 0) {
        if (bytes_read < 8) {
            bytes_read = add_padding(buffer, bytes_read); // 패딩 처리
        }

        // 64비트(8바이트)를 64개의 비트 배열로 변환
        int plaintext[64];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                plaintext[i * 8 + j] = (buffer[i] >> (7 - j)) & 0x01;
            }
        }

        des_encrypt(plaintext, ciphertext, key);

        // 암호화된 64비트 배열을 다시 8바이트로 변환하여 파일에 기록
        for (int i = 0; i < 8; i++) {
            buffer[i] = 0;
            for (int j = 0; j < 8; j++) {
                buffer[i] |= (ciphertext[i * 8 + j] << (7 - j));
            }
        }

        fwrite(buffer, 1, 8, out);
    }

    fclose(in);
    fclose(out);
}


// 파일 복호화 함수 (패딩 처리 수정)
void decrypt_file(const char* input_file, const char* output_file, int* key) {
    FILE* in = fopen(input_file, "rb");
    FILE* out = fopen(output_file, "wb");

    if (!in || !out) {
        printf("파일을 열 수 없습니다.\n");
        return;
    }

    unsigned char buffer[8];
    int plaintext[64];
    size_t bytes_read;
    size_t file_size;

    // 파일 크기 확인
    fseek(in, 0, SEEK_END);
    file_size = ftell(in);
    fseek(in, 0, SEEK_SET);

    size_t total_bytes_read = 0;

    while ((bytes_read = fread(buffer, 1, 8, in)) > 0) {
        total_bytes_read += bytes_read;

        // 64비트(8바이트)를 64개의 비트 배열로 변환
        int ciphertext[64];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                ciphertext[i * 8 + j] = (buffer[i] >> (7 - j)) & 0x01;
            }
        }

        des_decrypt(ciphertext, plaintext, key);

        // 복호화된 64비트 배열을 다시 8바이트로 변환
        for (int i = 0; i < 8; i++) {
            buffer[i] = 0;
            for (int j = 0; j < 8; j++) {
                buffer[i] |= (plaintext[i * 8 + j] << (7 - j));
            }
        }

        // 마지막 블록일 경우 패딩 제거
        if (total_bytes_read == file_size) {
            bytes_read = remove_padding(buffer, 8);
        }

        fwrite(buffer, 1, bytes_read, out);
    }

    fclose(in);
    fclose(out);
}


int main() {
    int key[64] = {
    0,1,1,0, 0,1,1,0,  // 1바이트 (패리티 비트 포함)
    1,0,1,0, 1,0,1,0,  // 2바이트
    0,1,1,0, 0,1,1,0,  // 3바이트
    1,0,1,0, 1,0,1,0,  // 4바이트
    0,1,1,0, 0,1,1,0,  // 5바이트
    1,0,1,0, 1,0,1,0,  // 6바이트
    0,1,1,0, 0,1,1,0,  // 7바이트
    1,0,1,0, 1,0,1,0   // 8바이트 (패리티 비트 포함)
    };

    // 평문 파일을 암호화
    encrypt_file("plaintext.txt", "ciphertext.dat", key);

    // 암호문 파일을 복호화
    decrypt_file("ciphertext.dat", "decrypted.txt", key);

    // 파일이 일치하는지 확인
    printf("암호화 및 복호화 완료.\n");

    return 0;
}
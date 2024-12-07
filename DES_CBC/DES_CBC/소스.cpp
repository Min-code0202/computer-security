#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

// IV 생성 함수 추가
void generate_iv(int* iv) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 64; i++) {
        iv[i] = rand() % 2;  // 0 또는 1의 무작위 비트 생성
    }
}

// IV를 파일에 저장하는 함수
void save_iv(FILE* file, int* iv) {
    unsigned char iv_bytes[8];
    for (int i = 0; i < 8; i++) {
        iv_bytes[i] = 0;
        for (int j = 0; j < 8; j++) {
            iv_bytes[i] |= (iv[i * 8 + j] << (7 - j));
        }
    }
    fwrite(iv_bytes, 1, 8, file);
}

// IV를 파일에서 읽는 함수
void read_iv(FILE* file, int* iv) {
    unsigned char iv_bytes[8];
    fread(iv_bytes, 1, 8, file);
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            iv[i * 8 + j] = (iv_bytes[i] >> (7 - j)) & 0x01;
        }
    }
}

// XOR 연산 함수 (64비트)
void xor_blocks(int* block1, int* block2, int* result) {
    for (int i = 0; i < 64; i++) {
        result[i] = block1[i] ^ block2[i];
    }
}

// CBC 모드로 수정된 파일 암호화 함수
void encrypt_file(const char* input_file, const char* output_file, int* key) {
    FILE* in = fopen(input_file, "rb");
    FILE* out = fopen(output_file, "wb");

    if (!in || !out) {
        printf("파일을 열 수 없습니다.\n");
        return;
    }

    // IV 생성 및 저장
    int iv[64];
    generate_iv(iv);
    save_iv(out, iv);

    unsigned char buffer[8];
    int previous_block[64];  // 이전 암호문 블록
    memcpy(previous_block, iv, sizeof(iv));  // 처음에는 IV를 사용

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, 8, in)) > 0) {
        if (bytes_read < 8) {
            bytes_read = add_padding(buffer, bytes_read);
        }

        // 평문 블록을 비트 배열로 변환
        int plaintext[64];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                plaintext[i * 8 + j] = (buffer[i] >> (7 - j)) & 0x01;
            }
        }

        // CBC 모드: 이전 암호문 블록과 XOR
        int xored_block[64];
        xor_blocks(plaintext, previous_block, xored_block);

        // DES 암호화
        int ciphertext[64];
        des_encrypt(xored_block, ciphertext, key);

        // 현재 암호문을 다음 라운드를 위해 저장
        memcpy(previous_block, ciphertext, sizeof(ciphertext));

        // 암호문을 바이트로 변환하여 파일에 저장
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

// CBC 모드로 수정된 파일 복호화 함수
void decrypt_file(const char* input_file, const char* output_file, int* key) {
    FILE* in = fopen(input_file, "rb");
    FILE* out = fopen(output_file, "wb");

    if (!in || !out) {
        printf("파일을 열 수 없습니다.\n");
        return;
    }

    // IV 읽기
    int iv[64];
    read_iv(in, iv);

    unsigned char buffer[8];
    int previous_block[64];  // 이전 암호문 블록
    memcpy(previous_block, iv, sizeof(iv));  // 처음에는 IV를 사용

    // 파일 크기 확인 (IV 제외)
    fseek(in, 0, SEEK_END);
    size_t file_size = ftell(in) - 8;  // IV 크기(8바이트) 제외
    fseek(in, 8, SEEK_SET);  // IV 다음부터 읽기 시작

    size_t total_bytes_read = 0;

    while ((fread(buffer, 1, 8, in)) > 0) {
        total_bytes_read += 8;

        // 현재 암호문 블록을 비트 배열로 변환
        int current_ciphertext[64];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                current_ciphertext[i * 8 + j] = (buffer[i] >> (7 - j)) & 0x01;
            }
        }

        // DES 복호화
        int decrypted_block[64];
        des_decrypt(current_ciphertext, decrypted_block, key);

        // CBC 모드: 이전 블록과 XOR
        int plaintext[64];
        xor_blocks(decrypted_block, previous_block, plaintext);

        // 현재 암호문을 다음 라운드를 위해 저장
        memcpy(previous_block, current_ciphertext, sizeof(current_ciphertext));

        // 평문을 바이트로 변환
        for (int i = 0; i < 8; i++) {
            buffer[i] = 0;
            for (int j = 0; j < 8; j++) {
                buffer[i] |= (plaintext[i * 8 + j] << (7 - j));
            }
        }

        // 마지막 블록이면 패딩 제거
        size_t write_size = 8;
        if (total_bytes_read == file_size) {
            write_size = remove_padding(buffer, 8);
        }

        fwrite(buffer, 1, write_size, out);
    }

    fclose(in);
    fclose(out);
}

// 파일 비교 함수
int compare_files(const char* file1, const char* file2) {
    FILE* f1 = fopen(file1, "rb");
    FILE* f2 = fopen(file2, "rb");

    if (!f1 || !f2) {
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        printf("파일을 열 수 없습니다.\n");
        return -1;
    }

    // 파일 크기 비교
    fseek(f1, 0, SEEK_END);
    fseek(f2, 0, SEEK_END);
    long size1 = ftell(f1);
    long size2 = ftell(f2);

    if (size1 != size2) {
        printf("파일 크기가 다릅니다.\n");
        printf("원본 파일 크기: %ld bytes\n", size1);
        printf("복호화된 파일 크기: %ld bytes\n", size2);
        fclose(f1);
        fclose(f2);
        return 0;
    }

    // 파일 포인터를 처음으로 되돌림
    fseek(f1, 0, SEEK_SET);
    fseek(f2, 0, SEEK_SET);

    // 버퍼 크기 정의 (64KB)
    const size_t BUFFER_SIZE = 65536;
    unsigned char* buffer1 = (unsigned char*)malloc(BUFFER_SIZE);
    unsigned char* buffer2 = (unsigned char*)malloc(BUFFER_SIZE);

    if (!buffer1 || !buffer2) {
        printf("메모리 할당 실패\n");
        if (buffer1) free(buffer1);
        if (buffer2) free(buffer2);
        fclose(f1);
        fclose(f2);
        return -1;
    }

    int is_identical = 1;
    size_t total_bytes = 0;
    size_t bytes_read1, bytes_read2;

    // 버퍼 단위로 파일 내용 비교
    while (1) {
        bytes_read1 = fread(buffer1, 1, BUFFER_SIZE, f1);
        bytes_read2 = fread(buffer2, 1, BUFFER_SIZE, f2);

        if (bytes_read1 != bytes_read2) {
            is_identical = 0;
            break;
        }

        if (bytes_read1 == 0) {
            break;
        }

        if (memcmp(buffer1, buffer2, bytes_read1) != 0) {
            is_identical = 0;
            // 불일치하는 위치 찾기
            for (size_t i = 0; i < bytes_read1; i++) {
                if (buffer1[i] != buffer2[i]) {
                    printf("첫 번째 불일치 위치: %zu byte\n", total_bytes + i);
                    printf("원본 파일 값: 0x%02X\n", buffer1[i]);
                    printf("복호화된 파일 값: 0x%02X\n", buffer2[i]);
                    break;
                }
            }
            break;
        }

        total_bytes += bytes_read1;
    }

    free(buffer1);
    free(buffer2);
    fclose(f1);
    fclose(f2);

    return is_identical;
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

    // 사용자로부터 텍스트 입력 받기
    printf("암호화할 텍스트를 입력하세요 (입력 완료 후 새 줄에서 Ctrl+Z (Windows)를 눌러주세요):\n");

    // plaintext.txt 파일 생성 또는 열기
    FILE* plain_file = fopen("plaintext.txt", "w");
    if (!plain_file) {
        printf("plaintext.txt 파일을 생성할 수 없습니다.\n");
        return 1;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        fputs(buffer, plain_file);
    }
    fclose(plain_file);

    printf("\nDES CBC 모드 암호화/복호화 시작\n");

    // 평문 파일을 암호화
    printf("파일 암호화 중...\n");
    encrypt_file("plaintext.txt", "ciphertext.dat", key);
    printf("암호화 완료\n");

    // 암호문 파일을 복호화
    printf("파일 복호화 중...\n");
    decrypt_file("ciphertext.dat", "decrypted.txt", key);
    printf("복호화 완료\n");

    // 파일 비교
    printf("\n파일 비교 검증 시작...\n");
    int result = compare_files("plaintext.txt", "decrypted.txt");

    if (result == 1) {
        printf("검증 성공: 원본 파일과 복호화된 파일이 완전히 일치합니다.\n");
    }
    else if (result == 0) {
        printf("검증 실패: 파일이 일치하지 않습니다.\n");
    }
    else {
        printf("검증 오류: 파일 비교 중 오류가 발생했습니다.\n");
    }

    return 0;
}
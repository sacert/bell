// LZ4 streaming API example : line-by-line logfile compression
// by Takayuki Matsuoka


// going to have many compressed files - don't worry about optimizing right now
// build some kind of index/directory which stores these compressed files
// 
//
//  SHA - name - BASE


#if defined(_MSC_VER) && (_MSC_VER <= 1800)  /* Visual Studio <= 2013 */
#  define _CRT_SECURE_NO_WARNINGS
#  define snprintf sprintf_s
#endif
#include "lz4.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BELL_FILE_EXTENSION ".bell"

static size_t write_uint16(FILE* fp, uint16_t i)
{
    return fwrite(&i, sizeof(i), 1, fp);
}

static size_t write_bin(FILE* fp, const void* array, int arrayBytes)
{
    return fwrite(array, 1, arrayBytes, fp);
}

static size_t read_uint16(FILE* fp, uint16_t* i)
{
    return fread(i, sizeof(*i), 1, fp);
}

static size_t read_bin(FILE* fp, void* array, int arrayBytes)
{
    return fread(array, 1, arrayBytes, fp);
}


static void test_compress(
    FILE* outFp,
    FILE* inpFp,
    size_t messageMaxBytes,
    size_t ringBufferBytes)
{
    LZ4_stream_t* const lz4Stream = LZ4_createStream();
    const size_t cmpBufBytes = LZ4_COMPRESSBOUND(messageMaxBytes);
    char* const cmpBuf = (char*) malloc(cmpBufBytes);
    char* const inpBuf = (char*) malloc(ringBufferBytes);
    int inpOffset = 0;

    for ( ; ; )
    {
        char* const inpPtr = &inpBuf[inpOffset];

#if 0
        // Read random length data to the ring buffer.
        const int randomLength = (rand() % messageMaxBytes) + 1;
        const int inpBytes = (int) read_bin(inpFp, inpPtr, randomLength);
        if (0 == inpBytes) break;
#else
        // Read line to the ring buffer.
        int inpBytes = 0;
        if (!fgets(inpPtr, (int) messageMaxBytes, inpFp))
            break;
        inpBytes = (int) strlen(inpPtr);
#endif

        {
            const int cmpBytes = LZ4_compress_fast_continue(
                lz4Stream, inpPtr, cmpBuf, inpBytes, cmpBufBytes, 1);
            if (cmpBytes <= 0) break;
            write_uint16(outFp, (uint16_t) cmpBytes);
            write_bin(outFp, cmpBuf, cmpBytes);

            // Add and wraparound the ringbuffer offset
            inpOffset += inpBytes;
            if ((size_t)inpOffset >= ringBufferBytes - messageMaxBytes) inpOffset = 0;
        }
    }
    write_uint16(outFp, 0);

    free(inpBuf);
    free(cmpBuf);
    LZ4_freeStream(lz4Stream);
}


static void test_decompress(
    FILE* outFp,
    FILE* inpFp,
    size_t messageMaxBytes,
    size_t ringBufferBytes)
{
    LZ4_streamDecode_t* const lz4StreamDecode = LZ4_createStreamDecode();
    char* const cmpBuf = (char*) malloc(LZ4_COMPRESSBOUND(messageMaxBytes));
    char* const decBuf = (char*) malloc(ringBufferBytes);
    int decOffset = 0;

    for ( ; ; )
    {
        uint16_t cmpBytes = 0;

        if (read_uint16(inpFp, &cmpBytes) != 1) break;
        if (cmpBytes == 0) break;
        if (read_bin(inpFp, cmpBuf, cmpBytes) != cmpBytes) break;

        {
            char* const decPtr = &decBuf[decOffset];
            const int decBytes = LZ4_decompress_safe_continue(
                lz4StreamDecode, cmpBuf, decPtr, cmpBytes, (int) messageMaxBytes);
            if (decBytes <= 0) break;
            write_bin(outFp, decPtr, decBytes);

            // Add and wraparound the ringbuffer offset
            decOffset += decBytes;
            if ((size_t)decOffset >= ringBufferBytes - messageMaxBytes) decOffset = 0;
        }
    }

    free(decBuf);
    free(cmpBuf);
    LZ4_freeStreamDecode(lz4StreamDecode);
}


static int compare(FILE* f0, FILE* f1)
{
    int result = 0;
    const size_t tempBufferBytes = 65536;
    char* const b0 = (char*) malloc(tempBufferBytes);
    char* const b1 = (char*) malloc(tempBufferBytes);

    while(0 == result)
    {
        const size_t r0 = fread(b0, 1, tempBufferBytes, f0);
        const size_t r1 = fread(b1, 1, tempBufferBytes, f1);

        result = (int) r0 - (int) r1;

        if (0 == r0 || 0 == r1) break;
        if (0 == result) result = memcmp(b0, b1, r0);
    }

    free(b1);
    free(b0);
    return result;
}

void get_index_file(void) {
  // this file should be hashed / compressed
  // 
  // if the file doesn't exist, create it
  //
}

void build_index_file(void) {
  // this will be a bit special as it will also have to create the BASE file
  // for later though
}

// create has for file - save it within hashes folde

// basic hashing for compressed_file name
// file names themselves don't work since need to save the same filename for different points in time
char* hash(char *s) {
  char* hashed_s = malloc(65);
	unsigned char *d = SHA256(s, strlen(s), 0);

	int i;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(hashed_s + (i* 2 ), "%02x", d[i]);
  return hashed_s;
}


char * stringMerge(const char *s1, const char *s2) {
    size_t n = strlen(s1);

    char *p = (char *)malloc(n + strlen(s2) + 1);

    if (p)
    {
        strcpy(p, s1);
        strcpy(p + n, s2);
    }

    return p;
}

char* integer_to_string(int x)
{
    char* buffer = malloc(sizeof(char) * sizeof(int) * 4 + 1);
    if (buffer)
    {
         sprintf(buffer, "%d", x);
    }
    return buffer; // caller is expected to invoke free() on this buffer to release memory
}

int main(int argc, char* argv[]) {

  struct stat fileStat;
  stat("README.md",&fileStat);

  // should be in it's own function - calculating SHA
  // should be this string + the sha name
  char* f_mode = integer_to_string(fileStat.st_mode);
  char* f_uid = integer_to_string(fileStat.st_uid);
  char* temp = stringMerge(f_mode, f_uid);
  char* f_gid = integer_to_string(fileStat.st_gid);
  temp = stringMerge(temp, f_gid);
  char* f_size = integer_to_string(fileStat.st_size);
  temp = stringMerge(temp, f_size);
  char* f_mtime = integer_to_string(fileStat.st_mtime);
  temp = stringMerge(temp, f_mtime);
  char* f_ctime = integer_to_string(fileStat.st_ctime);
  temp = stringMerge(temp, f_ctime);
  printf("%s\n",temp);
  char* file_stats = temp;
  
  enum {
      MESSAGE_MAX_BYTES   = 1024,
      RING_BUFFER_BYTES   = 1024 * 256 + MESSAGE_MAX_BYTES,
  };

  char* sha_file = stringMerge(argv[1], file_stats);
  // use file name to create the sha
  char* sha = hash(sha_file);
  char *sha_encrypted_filename = stringMerge(sha, BELL_FILE_EXTENSION);

  //free(sha_encrypted_filename);
  free(sha);

  char inpFilename[256] = { 0 };
  char lz4Filename[256] = { 0 };
  //char decFilename[256] = { 0 };

  if (argc < 2)
  {
      printf("Please specify input filename\n");
      return 0;
  }


  snprintf(inpFilename, 256, "%s", argv[1]);
  snprintf(lz4Filename, 256, "%s", sha_encrypted_filename);
  //snprintf(decFilename, 256, "%s", dencrpyted_sha_file);

  printf("inp = [%s]\n", inpFilename);
  printf("lz4 = [%s]\n", lz4Filename);
  //printf("dec = [%s]\n", decFilename);

  // compress
  {
      FILE* inpFp = fopen(inpFilename, "rb");
      FILE* outFp = fopen(lz4Filename, "wb");

      test_compress(outFp, inpFp, MESSAGE_MAX_BYTES, RING_BUFFER_BYTES);

      fclose(outFp);
      fclose(inpFp);
  }

  // decompress
  /*
  {
      FILE* inpFp = fopen(lz4Filename, "rb");
      FILE* outFp = fopen(decFilename, "wb");

      test_decompress(outFp, inpFp, MESSAGE_MAX_BYTES, RING_BUFFER_BYTES);

      fclose(outFp);
      fclose(inpFp);
  }
  */

  // verify
  /*
  {
      FILE* inpFp = fopen(inpFilename, "rb");
      FILE* decFp = fopen(decFilename, "rb");

      const int cmp = compare(inpFp, decFp);
      if (0 == cmp)
          printf("Verify : OK\n");
      else
          printf("Verify : NG\n");

      fclose(decFp);
      fclose(inpFp);
  }
  */

  return 0;
}

// compress file - essentially done ( just clean up required )
// create index of file - save file as a SHA which uses the filename so it'll be easy to retrieve
// if a file has been modified -- how to check if it has been modified?
//  // well create a tree like structure are run a depth/or breadth first search to figure out which files have been 
//  // modified since the BASE date
// when a make a change to the file, I want to look at the previous version of the file
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
#include <dirent.h>
#include <stdbool.h>
#include <limits.h>
#include <regex.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BELL_FILE_EXTENSION ".bell"

//#define RED   "\e[0;31m"
//#define GREEN "\e[0;32m"
#define NRM  "\x1B[0m"
#define RED  "\x1B[31m"
#define GRN  "\x1B[32m"
#define YEL  "\x1B[33m"
#define BLU  "\x1B[34m"
#define MAG  "\x1B[35m"
#define CYN  "\x1B[36m"
#define WHT  "\x1B[37m"
#define RESET "\e[0m"

#define SET_COLOR(x) printf("%s", x)

// regex matcher -- a helper
int match(const char *string, const char *pattern) {
  regex_t re;
  if (regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB) != 0) return 0;
  int status = regexec(&re, string, 0, NULL, 0);
  regfree(&re);
  if (status != 0) return 0;
  return 1;
}

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

char* bell_dir() {

  DIR *d;
  struct dirent *dir;
  char *current_dir = ".";

  d = opendir(current_dir);
  if (d) {
    char* path = realpath(current_dir, NULL);
    while (strcmp(path, "/") != 0 ) {
      while ((dir = readdir(d)) != NULL) {
        // HEAD will be changed to '.bell'
        if (strcmp(dir->d_name, ".bell") == 0) {
          return path;
        }
      }
      //preppend "../" to current_dir
      char *tmp = malloc(strlen("../") + strlen(current_dir) +1);
      strcat(tmp, "../");
      strcat(tmp, current_dir);
      current_dir = tmp;
      d = opendir(current_dir);
      free(path);
      path = realpath(current_dir, NULL);
      free(dir);
    }
    return 1;
    free(current_dir);
    free(dir);
    free(d);
  }
  return 1;
}

bool allNewFilesInDir(char *dirname, time_t after_timestamp) {
  DIR *dir;
  struct dirent *dirp;
  dir=opendir(dirname);
  chdir(dirname);
  while((dirp=readdir(dir))!=NULL) {
    if(strcmp(dirp->d_name, ".")==0 || strcmp(dirp->d_name, "..")==0){
      continue;
    } else if (dirp->d_type == DT_DIR || dirp->d_type == DT_REG) {
      struct stat dirStat;
      stat(dirp->d_name,&dirStat);
      if (after_timestamp > dirStat.st_mtime) {
        chdir("..");
        closedir(dir);
        return false;
      }
    }
  }
  chdir("..");
  closedir(dir);
  return true;
}


void searchInDirectory(char *dirname, time_t after_timestamp, char* path, char** ignore_types, int ignore_types_count) {
    DIR *dir;
    struct dirent *dirp;
    dir=opendir(dirname);
    chdir(dirname);
    while((dirp=readdir(dir))!=NULL) {
      if(strcmp(dirp->d_name, ".")==0 || strcmp(dirp->d_name, "..")==0){
              continue;
      } else if (dirp->d_type == DT_DIR || dirp->d_type == DT_REG) {
        
        struct stat dirStat;
        stat(dirp->d_name,&dirStat);

        char *path_from_root = malloc(strlen(path) + 1 + strlen(dirp->d_name) + 1);
        strcpy(path_from_root, path);
        strcat(path_from_root, dirp->d_name);
        // if a folder, check if it is new and all files within it are new and print it
        if (dirp->d_type == DT_DIR) {

          strcpy(path_from_root, path);
          strcat(path_from_root, dirp->d_name);
          strcat(path_from_root, "/");

          int skip = 0;
          int i;
          for (i = 0; i < ignore_types_count; i++) {

            if (match(path_from_root, ignore_types[i])) {
              skip = 1;
              continue;
            }
          }

          if (skip)
            continue;

          if (allNewFilesInDir(dirp->d_name, after_timestamp)) {
            SET_COLOR(BLU);
            printf("\t%s\n", path_from_root);
            continue;
            SET_COLOR(RESET);
          } else {
            searchInDirectory(dirp->d_name, after_timestamp, path_from_root, ignore_types, ignore_types_count);
          }
        } else {
          int skip = 0;
          int i;
          for (i = 0; i < ignore_types_count; i++) {
            if (match(dirp->d_name, ignore_types[i])) {
              skip = 1;
              continue;
            }
          }

          if (skip)
            continue;

          // if a file, any file that was modified AFTER setting the head
          if (after_timestamp < dirStat.st_mtime) {

            SET_COLOR(RED);
            if (strlen(path) == 0) {
              printf("\t%s\n", dirp->d_name);
            } else {
              printf(" \t%s\n", path_from_root);
            }
            SET_COLOR(RESET);
          }
        }
      }
    }
    chdir("..");
    closedir(dir);
}

int main(int argc, char* argv[]) {

  struct stat fileStat;
  // need add commands
  // if 'status' == give all files within the directory that have been modified
  // if 'add' == compress that file
  // if 'goto' == pass in sha and decrypt that file

  // status, we have to store somewhere the current 'root' SHA (timestamp we can get from the file itself)
  // within a file called HEAD
  //
  //

  if(!strcmp(argv[2],"status")) {

    // locate the .bell directory
    char *repo_dir = bell_dir();
    char *head_file = malloc(strlen(repo_dir) + strlen("/.bell/HEAD") + 1);
    strcpy(head_file, repo_dir);
    strcat(head_file, "/.bell/HEAD");
    stat(head_file,&fileStat);

    //get all files that were modified after this time
    time_t after_timestamp = fileStat.st_mtime;


    char *ignore_file = malloc(strlen(repo_dir) + strlen("/.bellignore") + 1);
    strcpy(ignore_file, repo_dir);
    strcat(ignore_file, "/.bellignore");
    FILE* file = fopen(ignore_file, "r");
    char line[256];

    int line_counter = 0;
    while (fgets(line, sizeof(line), file)) {
      line_counter += 1;
    }

    char *ignore_file_regex[line_counter];

    line_counter = 0;
    rewind(file);
    while (fgets(line, sizeof(line), file)) {

      // dont include newline character
      size_t ln = strlen(line)-1;
      if (line[ln] == '\n')
        line[ln] = '\0';

      ignore_file_regex[line_counter] = strdup (line);
      line_counter+=1;
    }
    fclose(file);


    printf("Files changed:\n");
    searchInDirectory(".", after_timestamp, "", ignore_file_regex, line_counter);
  } else {
    printf("fook");
  }

  return 0;
  stat("README.md",&fileStat);

  /*
  char head_sha[64];
  FILE *fp = fopen("HEAD", "r");
  if (!fp) {
      perror ("HEAD could not be located.\n");
      return 1;
  }
  fgets (head_sha, 64, fp);
  */

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

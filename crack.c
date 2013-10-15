/*
* Joe Mayer
*
* Oct. 1, 2013
*
* Brute force password cracker
* using threads.
*
* usage: crack threads keysize target
*/

#define _GNU_SOURCE

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<string.h>
#include<crypt.h>
#include<math.h>
#include<pthread.h>

//Global Variables
int threads, keysize;
char salt[3];
char *target;

//Structure to hold start and finish char arrays.
typedef struct{
   char s[9];
   char f[9];   
}bounds;
/*
*The function takes a number and converts it
* to the corresponding string base 26, and 
* with compensation considerations to accumulates.
*Stores the result in char array pointed to by p.
*/
void num_to_string(double num, char *p){
   /*With known max size of 8 characters all
     char arrays are 9 chars long and intially made 
     of all NULL chars. This is for ease of use with
     c string functions.
   */
   char temp[]="\0\0\0\0\0\0\0\0\0";
   int num_chars;
   double accum = 1;
   int power = 0;
   while(floor(num/accum)!=0){
      if(accum == 1){
         accum = 0;
      }
      ++power; 
      accum+=pow(26,power);
   }
   accum-=pow(26,power);
   num-=accum;
   int i;
   int backward = 8;
   while(floor(num/26)!=0){
      i = fmod(num,26) + 97;
      temp[backward] = (char) i;
      --backward;
      num = floor(num/26);
   }
   i = fmod(num,26) + 97;
   temp[backward] = (char) i;
   //don't reset backward.
   int forward = 0;
   while(backward<9){
      *(p+forward) = temp[backward];
      ++backward;
      ++forward;
   }
   while(forward<9){
      *(p+forward)= '\0';
      ++forward;
   }
}
/*
*Takes pointer to bounds array as input.
*Balances the amount of string to enumerate
* evenly among the threads. With several calls
* num_to_string.
*/
void balance(bounds *b){
   double total=0;
   int i = 1; //i keeps track of the power
   while(i<=keysize){
      total+=pow(26,i);
      ++i;
   }
   double quo = total/threads;
   quo = floor(quo);
   int remainder = fmod(total,threads);
   quo--; //Decrement so that additon below works out.
   i = 0; //i is repurposed for index counting
   double start;
   double finish = -1;
   while(i<(threads-1)){
      start = finish+1;
      num_to_string(start,b[i].s);
      finish = start + quo;
      num_to_string(finish,b[i].f);
      ++i;
   }
   //For the final thread.
   start = finish+1;
   num_to_string(start,b[i].s);
   finish = start + quo + remainder;
   num_to_string(finish,b[i].f);
}
/*
*The function that each thread calls.
*Uses strenum to enumerate through a given
* set of strings.
*If the string needs to be lengthen in resets
* the string adds an 'a' and again calls strenum.
*/
void *bruteforce(bounds *b){
   char *sp = (*b).s;
   struct crypt_data data;
   data.initialized = 0;
   while(strenum((*b).s,sp,(*b).f,data) != 1){
      //SP is @ same pos. as S.
      while(*sp != '\0'){
         *sp = 'a';
         ++sp;
      }
      *(sp) = 'a';
      sp = (*b).s;
   }
   pthread_exit(NULL);
}
/*
*This function recursively enumerates through a char array
* of a given length.
*It compares each enumeration with both its final goal and
* the cryptographic hash. If one is a match the function
* returns or exits respectively.
*/
int strenum(char *s,char *sp, char *f,struct crypt_data data){
   int r;
   while( ((*sp)%97) < 26){
      char *hash;
      hash = crypt_r(s,salt,&data); 
      //You have found the hash.
      if (strcmp(hash,target) == 0){
         printf("%s\n",s);   
         exit(1);
      }
      //Check if its equal to final.
      if (strcmp(s,f) == 0){
         return 1; 
      }
      //Uses the NULL char to find end of current string.
      if (*(sp+1) != '\0'){
         r = strenum(s,sp+1,f,data);
         if(r==1){
            return 1;
         }
	 *(sp+1)='a'; //Reset the value of the last changed char.
      }
      (*sp)++;
   }
   return 0;
}
/*
*The main function. With intial error checking,
* obtaining input parameters, calling auxilliary
* functions and thread creation.
*/
int main(int argc, char *argv[]){
   //Check valid number of arguments.
   if (argc != 4){
      fprintf(stderr,"Usage Error: %s threads keysize target\n",argv[0]);
      exit(1);
   }
   threads = atoi(argv[1]);
   keysize = atoi(argv[2]);
   //Check valid thread input.
   if (threads < 0 || threads > 10){
      fprintf(stderr,"Threads argument invalid.\n");
   }
   //Check valid keysize input.
   if (keysize < 0 || keysize > 10){
      fprintf(stderr,"Keysize argument invalid.\n");
   }
   target = argv[3];
   salt[0] = *(target);
   salt[1] = *(target+1);
   salt[2] = '\0';
   pthread_t t_id[threads];
   bounds b[threads];
   balance(b);
   int i = 0;
   int success;
   //create threads here.
   while(i < threads){
      success = pthread_create(&t_id[i], NULL, bruteforce, (void *)&b[i]);
      if (success != 0){
         fprintf(stderr,"Thread creation error\n");
         exit(1);
      }
      ++i; 
   }   
   i = 0;
   while(i < threads){
      success = pthread_join(t_id[i],NULL);
      if (success != 0){
         fprintf(stderr,"Thread join error.\n");
         exit(1);
      }
      ++i;
   }
  // printf("No Match Found.\n");
return 0;}

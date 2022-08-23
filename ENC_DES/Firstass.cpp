

/**************************************************************************
 *  $Id$
 *  Release $Name:-cs6500$
 *
 *  File:	Sourcefile first.cpp Openssl Symmetric Encryption and decryption and performance analyisis .
 *
 *  Purpose:The objective is to obtain the relevant key from the user input passphrase and call 
            the associated OpenSSL API routines for encryption and decryption. The data from the input 
            file is either encrypted or decrypted (based on the command line operation specified) and 
            stored in the output file. Base64 encoding can also be used.
 *
 *  Author:	
 *
 *  Created:    wed 02-feb-2022 12:22:49
 *
 *  Last modified:  Sun 13-feb-2022 17:38:13
 *
 *  Bugs:	
 *
 *  Change Log:	<Date> <Author>
 *  		<Changes>
 *
 **************************************************************************/



 /*-------------------------------------------------------------------------
 *   Title: Header Files  
 *   Uses: Include Header File from C++ libraries and openssl libraries.
 *.  Args: 
 *   Returns:;
 *   Bugs:
 * -------------------------------------------------------------------------*/
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include<bits/stdc++.h>

//defining standard input ouput for program
using namespace std;


/*-------------------------------------------------------------------------
 *   Title: Errorhandling
 *   Uses: This function is used to check if the encryption or decryption program contains 
          any error if its contain any error than it abort.
 *.  Args:void.
 *   Returns:;
 *   Bugs:No Bug detected
 * -------------------------------------------------------------------------*/


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
 /*-------------------------------------------------------------------------
 *   Title: Mean block time calculation 
 *   Uses: Calculate time taken to calculate the mean block time.
 *.  Args:time,filesize,alg.
 *   Returns:No;
 *   Bugs:No Bug detected
 * -------------------------------------------------------------------------*/
 
 void Mean_block_time_encryption(long long int time,int file_size,int alg)
 {
        switch(alg)
               {
	        case 1:  
		    cout<<"Total Blocks = "<<(file_size/16)<<endl;
		    cout<<"Mean Block Encryption time = "<<time/(file_size/16)<<endl;
		    break;
               case 0:
                   cout<<"Total Blocks = "<<file_size/8<<endl;
		    cout<<"Mean Block Encryption time = "<<time/(file_size/8)<<" ns "<<endl;
		    break;
		 }   

 }
  /*-------------------------------------------------------------------------
 *   Title: encryption 
 *   Uses: calculate time taken to calu.
 *.  Args:plaintext,plaintext_len,key,iv,plaintext.
 *   Returns:No;
 *   Bugs:No Bug detected
 * -------------------------------------------------------------------------*/
 void Mean_block_time_decryption(long long int time,int file_size,int alg)
 {
        switch(alg)
                {
	        case 1:  
		    cout<<"Total Blocks = "<<(file_size/16)<<endl;
		    cout<<"Mean Block decryption time = "<<time/(file_size/16)<<endl;
		    break;
               case 0:
                   cout<<"Total Number of Blocks = "<<file_size/8<<endl;
		    cout<<"Mean Block decryption time = "<<time/(file_size/8)<<" ns "<<endl;
		    break;
		}    

 }
 /*-------------------------------------------------------------------------
 *   Title: encryption 
 *   Uses: This command is used to take the inputfile and encrypt it and return the ciphertext length.
 *.  Args:plaintext,plaintext_len,key,iv,plaintext.
 *   Returns:plaintext length;
 *   Bugs:No Bug detected
 * -------------------------------------------------------------------------*/
int encrypt(int alg,int mode,int keysize,int file_size,unsigned char *plain_text, int plain_text_length, unsigned char *key,unsigned char *iv, unsigned char *cipher_text)
{
    EVP_CIPHER_CTX *cipher_text_x;

    

    int cipher_text_length,length;

    //creation and the intilization of the context.
    cipher_text_x = EVP_CIPHER_CTX_new();
    if(!(cipher_text_x))
        handleErrors();
        
        
     EVP_CIPHER_CTX_set_padding(cipher_text_x, 0);

     auto start_timing = chrono::high_resolution_clock::now();
     
     
       switch(alg)
      {
         case 1:
         {
              switch(keysize)
              {
                   case 128:
                    if(EVP_EncryptInit_ex(cipher_text_x,EVP_aes_128_cbc(), NULL, key, iv)!=1)
                    handleErrors();
                    break;
                   case 256:
                   if( EVP_EncryptInit_ex(cipher_text_x, EVP_aes_256_cbc(), NULL, key, iv)!=1)
                    handleErrors();
                    break;
                     
              }
              break;
         }
         case 2:
         {
           
              if( EVP_EncryptInit_ex(cipher_text_x, EVP_des_ede3() , NULL,  key , iv)!=1)
                    handleErrors();
                    break;
         }
    }
    
     
    
    

   //Give the meassage to be encrypted and print the desired output.
    if( EVP_EncryptUpdate(cipher_text_x, cipher_text, &length, plain_text, plain_text_length)!=1)
        handleErrors();
    cipher_text_length = length;
    //Finilization the encryption.
    if(1 != EVP_EncryptFinal_ex(cipher_text_x, cipher_text + length, &length))
        handleErrors();
        
       //calculate the time taken for the encryption process
	long long int time = chrono::duration_cast<chrono::nanoseconds>( chrono::high_resolution_clock::now() - start_timing).count();
	cout << "\nTotal time taken to encrypt the File: " ;
	cout<< time <<" ns" << endl;
	
  	Mean_block_time_encryption(time, file_size, alg);
       
    cipher_text_length = cipher_text_length+length;

    /*free the EVP or Cleaning up the EVP */
    EVP_CIPHER_CTX_free(cipher_text_x);
     //return the ciper text length which is the required ouptup.
    return cipher_text_length;
}



 /*-------------------------------------------------------------------------
 *   Title: decryption  
 *   Uses: This command is used to take the encrypt file and decrypt to the plaintext and return it.
 *.  Args:ciphertext,ciphertext_len,key,iv,plaintext.
 *   Returns:plaintext length;
 *   Bugs:No Bug detected
 * -------------------------------------------------------------------------*/
 
 
int decrypt(int alg,int mode,int keysize,int file_size,unsigned char *cipher_text, int cipher_text_length, unsigned char *key,unsigned char *iv, unsigned char *plain_text)
{
    EVP_CIPHER_CTX *cipher_text_x;

    

    int plain_text_length,length;

     //creation and the intilization of the context.
    cipher_text_x = EVP_CIPHER_CTX_new();
    if(!(cipher_text_x))
      handleErrors();

   
   //Calcuate the starttime of the decryption  
     auto start_timing = chrono::high_resolution_clock::now();

        
        
   switch(alg)
    {
         case 1:
         {
              switch(keysize)
              {
                   case 128:
                   if( EVP_DecryptInit_ex(cipher_text_x, EVP_aes_128_cbc(), NULL, key, iv)!=1)
                   handleErrors();
                   break;
                   case 256:
                   if( EVP_DecryptInit_ex(cipher_text_x, EVP_aes_256_cbc(), NULL, key, iv)!=1)
                    handleErrors();
                    break;
              }
              break;
         }
         case 2:
         {
              if( EVP_DecryptInit_ex(cipher_text_x, EVP_des_ede3(), NULL, key, iv)!=1)
                    handleErrors();
                    break;
         }
    }
        
      
     
        
        

    //Give the encrypt ciher text convert it in to plain text.
    if( EVP_DecryptUpdate(cipher_text_x, plain_text, &length, cipher_text, cipher_text_length)!=1)
        handleErrors();
    plain_text_length = length;

    //Here the finalize the decrypt file.
    if( EVP_DecryptFinal_ex(cipher_text_x, plain_text + length, &length)!=1)
        handleErrors();
        
        //calculate the time taken for the encryption process
	long long int time = chrono::duration_cast<chrono::nanoseconds>( chrono::high_resolution_clock::now() - start_timing).count();
	cout << "\nTotal time taken to decypt the file: ";
	cout << time<<" ns" << endl;
	
	Mean_block_time_decryption(time,file_size, alg);
	
        
        
    plain_text_length = plain_text_length+ length;

    /* free the EVP*/
    EVP_CIPHER_CTX_free(cipher_text_x);
    
     //return the plaintext length.
    return plain_text_length;
}


 /*-------------------------------------------------------------------------
 *   Title: main   
 *   Uses: This is the main of the program it takes the command line input 
           the opretion,algorathim ,mode and key we pass and call encrypt 
           and decrypt function based on the command.
 *.  Args:argc, argv
 *   Returns:0;
 *   Bugs:No Bug detected
 * -------------------------------------------------------------------------*/

int main (int argc, char** argv)
{
  
  int oper=-1;
  int alg=-1;
  int mode=-1;
  int keysize=-1;
  string inpfile="";
  string outfile="";
  int index=1;
  //intilization of the key of 32 Byte.
  unsigned char key[32] ;  
  // Taking the salt iv of 128 bit.
  unsigned char *iv = (unsigned char *)"012345678901234567890123456789";  
  unsigned char *plain_text ;
  unsigned char chr;
  unsigned char text[100001];
  unsigned char cipher_text[100001];
  unsigned char de_crypted_text[100001];
  ofstream out;
  ifstream in;
  int id=0;
  int de_length=0;
  int ci_length=0;
  
         while (index< argc )
         {
             
               string s = argv[index++];
               if(s.compare("-p") == 0)
               {
                    string str = argv[index++];
                    
                    if(str.compare("ENC") == 0)
                    {
                         oper = 1;
                    }
                    else
                    {
                         oper = 0;
                    }            
                           
               }
               else if(s.compare("-a") == 0)
               {
                    string str = argv[index++];
                    
                    if(str.compare("AES") == 0)
                    {
                         alg = 1;
                    }
                    else
                    {
                         alg = 0;
                    }            
                      
               }
               else if(s.compare("-m") == 0)
               {
                    string str = argv[index++];
                    
                    if(str.compare("CBC") == 0)
                    {
                         mode = 1;
                    }
                    else
                    {
                         mode = 0;
                    }            
                       
               }
               else if(s.compare("-k") == 0)
               {
                    string str = argv[index++];
                    
                    if(str.compare("128") == 0)
                    {
                         keysize = 128;
                    }
                    else if(str.compare("256") == 0)
                    {
                         keysize = 256;
                    }
                    else 
                    {
                         keysize = 168;
                    }            
                       
               }   
               else if(s.compare("-i") == 0)
               {
                  
                    inpfile = argv[index++]; 
                                      
               } 
                else if(s.compare("-o") == 0)
               {
                  
                    outfile = argv[index++];     
                                  
               }           
         }
         
      
      
      ifstream in_file(inpfile, ios::binary);
      in_file.seekg(0, ios::end);
      int file_size = in_file.tellg();
       cout<<file_size<<endl;
     cout<<"\nEnter the user passpashrase :- ";
     cin>>key;
     
     
   

   
    in.open(inpfile);
    for(int i=0; in >> std::noskipws >> chr;i++ ) {
      
       text[i] = chr;
        
    }
    
    
    in.close();
    
    plain_text = text;
    
    
    
   
   
    

  




    /* Encrypt the plaintext */
    if(oper==1)
    {
     
          ci_length = encrypt(alg,mode,keysize,file_size,plain_text, strlen ((char *)plain_text), key,  iv,cipher_text);
      out.open(outfile);
      index=0;
      while(index<ci_length)
      {
	
	out << cipher_text[index];
	index++;
      }
    out.close();
   }
else
{

    
 
     

    de_length = decrypt(alg,mode,keysize,file_size,plain_text, file_size, key,  iv,de_crypted_text);  
    

   
  
   
    
      out.open(outfile);
      index=0;
      while(index<de_length)
      {
	
	out << de_crypted_text[index];
	index++;
      }
    out.close();

}


    return 0;
}

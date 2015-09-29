/*
 * sig_client.c
 *
 * Author: Alec Guertin
 * University of California, Berkeley
 * CS 161 - Computer Security
 * Fall 2014 Semester
 * Project 1
 */
#include "client.h"


#define SIZE_128 16

/* The file descriptor for the socket connected to the server. */
static int sockfd;

static void perform_rsa(mpz_t result, mpz_t message, mpz_t d, mpz_t n);
static int hex_to_ascii(char a, char b);
static int hex_to_int(char a);
static void usage();
static void kill_handler(int signum);
static int random_int();
static void cleanup();


void getCiphertext(unsigned char*, unsigned char*);

int main(int argc, char **argv) {
  int err, option_index, c, clientlen, counter;
  unsigned char rcv_plaintext[AES_BLOCK_SIZE];
  unsigned char rcv_ciphertext[AES_BLOCK_SIZE];
  unsigned char send_plaintext[AES_BLOCK_SIZE];
  unsigned char send_ciphertext[AES_BLOCK_SIZE];
  aes_context enc_ctx, dec_ctx;
  in_addr_t ip_addr;
  struct sockaddr_in server_addr;
  FILE *c_file, *d_file, *m_file;
  ssize_t read_size, write_size;
  struct sockaddr_in client_addr;
  tls_msg err_msg, send_msg, rcv_msg;
  mpz_t client_exp, client_mod;
  fd_set readfds;
  struct timeval tv;

  c_file = d_file = m_file = NULL;

  /*
   * This section is networking code that you don't need to worry about.
   * Look further down in the function for your part.
   */

  memset(&ip_addr, 0, sizeof(in_addr_t));

  option_index = 0;
  err = 0;

  static struct option long_options[] = {
    {"ip", required_argument, 0, 'i'},
    {"cert", required_argument, 0, 'c'},
    {"exponent", required_argument, 0, 'd'},
    {"modulus", required_argument, 0, 'm'},
    {0, 0, 0, 0},
  };

  while (1) {
    c = getopt_long(argc, argv, "c:i:d:m:", long_options, &option_index);
    if (c < 0) {
      break;
    }
    switch(c) {
    case 0:
      usage();
      break;
    case 'c':
      c_file = fopen(optarg, "r");
      if (c_file == NULL) {
  perror("Certificate file error");
  exit(1);
      }
      break;
    case 'd':
      d_file = fopen(optarg, "r");
      if (d_file == NULL) {
  perror("Exponent file error");
  exit(1);
      }
      break;
    case 'i':
      ip_addr = inet_addr(optarg);
      break;
    case 'm':
      m_file = fopen(optarg, "r");
      if (m_file == NULL) {
  perror("Modulus file error");
  exit(1);
      }
      break;
    case '?':
      usage();
      break;
    default:
      usage();
      break;
    }
  }

  if (d_file == NULL || c_file == NULL || m_file == NULL) {
    usage();
  }
  if (argc != 9) {
    usage();
  }

  mpz_init(client_exp);
  mpz_init(client_mod);


  size_t bytes_read;
  bytes_read = mpz_inp_str(client_exp, d_file, 0);
  if (bytes_read <= 0) {
    err = 1;
  }
  bytes_read = mpz_inp_str(client_mod, m_file, 0);
  if (bytes_read <= 0) {
    err = 1;
  }
  if (err == 1) {
    printf("%s\n", "Error: cannot read one or more files. See spec for usage.");
    exit(1);
  }

  char *client_exp_str, *client_mod_str;
  client_exp_str = mpz_get_str(NULL, 16, client_exp);
  client_mod_str = mpz_get_str(NULL, 16, client_mod);

  mpz_clear(client_exp);
  mpz_clear(client_mod);


  signal(SIGTERM, kill_handler);

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Could not open socket");
    exit(1);
  }

  memset(&server_addr, 0, sizeof(struct sockaddr_in));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = ip_addr;
  server_addr.sin_port = htons(HANDSHAKE_PORT);
  err = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
  if (err < 0) {
    perror("Could not bind socket");
    cleanup();
  }

  // YOUR CODE HERE
  // IMPLEMENT THE TLS HANDSHAKE

  /*
   * START ENCRYPTED MESSAGES
   */

  /***************** send hello *****************/
  int output;
  hello_message client_hello = {CLIENT_HELLO, random_int(), TLS_RSA_WITH_AES_128_ECB_SHA256};
  output = send_tls_message(sockfd, &client_hello, HELLO_MSG_SIZE);
  if(output != ERR_OK) {
    perror("Could not send hello message");
    exit(1);
  }


  /***************** recieve server hello *****************/ 
  hello_message server_hello;
  output = receive_tls_message(sockfd, &server_hello, HELLO_MSG_SIZE, SERVER_HELLO);
  while (output != ERR_OK) { // if fail keep going until succeed
    output = receive_tls_message(sockfd, &server_hello, HELLO_MSG_SIZE, SERVER_HELLO);
  }


  /***************** send client cert *****************/ 
  char c_cert[CERT_MSG_SIZE];
  fread(c_cert, CERT_MSG_SIZE, 1, c_file);
  cert_message *client_cert = malloc(sizeof(cert_message));
  client_cert->type = CLIENT_CERTIFICATE;
  strncpy(client_cert->cert, c_cert, CERT_MSG_SIZE);
  output = send_tls_message(sockfd, client_cert, CERT_MSG_SIZE);
  if(output != ERR_OK) {
    perror("Could not send client cert");
    exit(1);
  }
  free(client_cert);


  /***************** recieve server cert *****************/ 
  cert_message server_cert;
  output = receive_tls_message(sockfd, &server_cert, CERT_MSG_SIZE, SERVER_CERTIFICATE);
  while (output != ERR_OK) { // if fail keep going until succeed
    output = receive_tls_message(sockfd, &server_cert, CERT_MSG_SIZE, SERVER_CERTIFICATE);
  }

  mpz_t decrypted_cert, ca_mod, ca_exp;
  mpz_init(decrypted_cert);
  mpz_init(ca_mod);
  mpz_init(ca_exp);
  mpz_set_str(ca_mod, CA_MODULUS, 0);
  mpz_set_str(ca_exp, CA_EXPONENT, 0);
  decrypt_cert(decrypted_cert, &server_cert, ca_exp, ca_mod);
  
  //Get he server cert string (from the mpz output) that represent the "server certificate"
  char *result_str, buffer[RSA_MAX_LEN];
  result_str = mpz_get_str(NULL, 16, decrypted_cert);
  int i = 0;
  int j = 0;
  while(result_str[i] != '\0') {
    buffer[j] = hex_to_ascii(result_str[i], result_str[i+1]);
    j++;
    i+=2;
  }

  mpz_clear(decrypted_cert);
  mpz_clear(ca_mod);
  mpz_clear(ca_exp);

  //Parse the server cert and get its information: server modulus --> tokens[4].  server_exp --> tokens[6]
  char *pch;
  char *tokens[8];
  pch = strtok(buffer, " \n");
  for (i = 0; pch != NULL; i++) {
    tokens[i] = pch;
    pch = strtok (NULL, " \n");
  }



  /***************** send encrypted premaster key using server public key *****************/ 
  mpz_t premaster, server_mod, server_exp, encrypted_premaster;
  mpz_init(premaster);
  mpz_init(server_mod);
  mpz_init(server_exp);
  mpz_init(encrypted_premaster);

  int premaster_int = rand();

  mpz_set_ui(premaster, premaster_int);
  mpz_set_str(server_mod, tokens[4], 0);
  mpz_set_str(server_exp, tokens[6], 0);
  perform_rsa(encrypted_premaster, premaster, server_exp, server_mod);


  ps_msg *premaster_secret = malloc(sizeof(ps_msg));
  premaster_secret->type = PREMASTER_SECRET;
  strncpy(premaster_secret->ps, mpz_get_str(NULL, 16, encrypted_premaster), RSA_MAX_LEN);
  output = send_tls_message(sockfd, premaster_secret, PS_MSG_SIZE);
  if(output != ERR_OK) {
    perror("Could not send encrypted premaster");
    exit(1);
  }
  free(premaster_secret);
  mpz_clear(premaster);
  mpz_clear(server_mod);
  mpz_clear(server_exp);
  mpz_clear(encrypted_premaster);
  


  /***************** recieve encrypted master secret using client public key *****************/ 
  ps_msg server_master_secret_msg;
  output = receive_tls_message(sockfd, &server_master_secret_msg, PS_MSG_SIZE, VERIFY_MASTER_SECRET);
  while (output != ERR_OK) {
    output = receive_tls_message(sockfd, &server_master_secret_msg, PS_MSG_SIZE, VERIFY_MASTER_SECRET);
  }
  
  mpz_t new_client_mod, new_client_exp, local_master_secret;
  mpz_init(new_client_mod);
  mpz_init(new_client_exp);
  mpz_init(local_master_secret);
  mpz_set_str(new_client_mod, client_mod_str, 16);
  mpz_set_str(new_client_exp, client_exp_str, 16);

  mpz_t server_master_secret;
  mpz_init(server_master_secret);
  decrypt_verify_master_secret(server_master_secret, &server_master_secret_msg, new_client_exp, new_client_mod);

  unsigned char local_master_secret_str[SIZE_128];
  compute_master_secret(premaster_int, client_hello.random, server_hello.random, local_master_secret_str);
  char *computed_ms;
  computed_ms = hex_to_str(local_master_secret_str, SIZE_128);

  //compare if client's master secret and server's master secret are equal
  mpz_set_str(local_master_secret, computed_ms, 16);
  if (mpz_cmp(local_master_secret, server_master_secret) != 0) {
    perror("Master secrets don't match");
    exit(1);
  } 
  mpz_clear(new_client_exp);
  mpz_clear(new_client_mod);
  mpz_clear(local_master_secret);

  char *master_secret_buffer;
  master_secret_buffer = mpz_get_str(NULL, 16, server_master_secret);
  mpz_clear(server_master_secret);

  //printf("Successful Handshake!!!!\n");

  ////////////////////////////////////////////////////////////
  memset(send_plaintext, 0, AES_BLOCK_SIZE);
  memset(send_ciphertext, 0, AES_BLOCK_SIZE);
  memset(rcv_plaintext, 0, AES_BLOCK_SIZE);
  memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);

  memset(&rcv_msg, 0, TLS_MSG_SIZE);

  aes_init(&enc_ctx);
  aes_init(&dec_ctx);
  
  // YOUR CODE HERE
  // SET AES KEYS
  unsigned char master_key[SIZE_128];
  getCiphertext(master_secret_buffer, master_key);

  aes_setkey_enc(&enc_ctx, master_key, 128);
  aes_setkey_dec(&dec_ctx, master_key, 128);

  fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
  /* Send and receive data. */
  while (1) {
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sockfd, &readfds);
    tv.tv_sec = 2;
    tv.tv_usec = 10;

    select(sockfd+1, &readfds, NULL, NULL, &tv);
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      counter = 0;
      memset(&send_msg, 0, TLS_MSG_SIZE);
      send_msg.type = ENCRYPTED_MESSAGE;
      memset(send_plaintext, 0, AES_BLOCK_SIZE);
      read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      while (read_size > 0 && counter + AES_BLOCK_SIZE < TLS_MSG_SIZE - INT_SIZE) {
  if (read_size > 0) {
    err = aes_crypt_ecb(&enc_ctx, AES_ENCRYPT, send_plaintext, send_ciphertext);
    memcpy(send_msg.msg + counter, send_ciphertext, AES_BLOCK_SIZE);
    counter += AES_BLOCK_SIZE;
  }
  memset(send_plaintext, 0, AES_BLOCK_SIZE);
  read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      }
      write_size = write(sockfd, &send_msg, INT_SIZE+counter+AES_BLOCK_SIZE);
      if (write_size < 0) {
  perror("Could not write to socket");
  cleanup();
      }
    } else if (FD_ISSET(sockfd, &readfds)) {
      memset(&rcv_msg, 0, TLS_MSG_SIZE);
      memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);
      read_size = read(sockfd, &rcv_msg, TLS_MSG_SIZE);
      if (read_size > 0) {
  if (rcv_msg.type != ENCRYPTED_MESSAGE) {
    goto out;
  }
  memcpy(rcv_ciphertext, rcv_msg.msg, AES_BLOCK_SIZE);
  counter = 0;
  while (counter < read_size - INT_SIZE - AES_BLOCK_SIZE) {
    aes_crypt_ecb(&dec_ctx, AES_DECRYPT, rcv_ciphertext, rcv_plaintext);
    printf("%s", rcv_plaintext);
    counter += AES_BLOCK_SIZE;
    memcpy(rcv_ciphertext, rcv_msg.msg+counter, AES_BLOCK_SIZE);
  }
  printf("\n");
      }
    }

  }

 out:
  close(sockfd);
  return 0;
}

/*
 * \brief                  Decrypts the certificate in the message cert.
 *
 * \param decrypted_cert   This mpz_t stores the final value of the binary
 *                         for the decrypted certificate. Write the end
 *                         result here.
 * \param cert             The message containing the encrypted certificate.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the certificate.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the certificate.
 */
void
decrypt_cert(mpz_t decrypted_cert, cert_message *cert, mpz_t key_exp, mpz_t key_mod)
{
  // YOUR CODE HERE
  mpz_t s_cert;
  mpz_init(s_cert);
  mpz_set_str(s_cert, cert->cert, 0);
  perform_rsa(decrypted_cert, s_cert, key_exp, key_mod);
  mpz_clear(s_cert);
}


/*
 * \brief                  Decrypts the master secret in the message ms_ver.
 *
 * \param decrypted_ms     This mpz_t stores the final value of the binary
 *                         for the decrypted master secret. Write the end
 *                         result here.
 * \param ms_ver           The message containing the encrypted master secret.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the master secret.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the master secret.
 */
void
decrypt_verify_master_secret(mpz_t decrypted_ms, ps_msg *ms_ver, mpz_t key_exp, mpz_t key_mod)
{
  // YOUR CODE HERE
  mpz_t ms_message;
  mpz_init(ms_message);
  mpz_set_str(ms_message, ms_ver->ps, 16);
  perform_rsa(decrypted_ms, ms_message, key_exp, key_mod);
  mpz_clear(ms_message);
}


/*
 * \brief                  Computes the master secret.
 *
 * \param ps               The premaster secret.
 * \param client_random    The random value from the client hello.
 * \param server_random    The random value from the server hello.
 * \param master_secret    A pointer to the final value of the master secret.
 *                         Write the end result here.
 */
void
compute_master_secret(int ps, int client_random, int server_random, unsigned char *master_secret)
{
  // YOUR CODE HERE
  // Master secret = H(PS||clienthello.random||serverhello.random||PS)

  void *ptr_ps = &ps;
  void *ptr_client_random = &client_random;
  void *ptr_server_random = &server_random;

  SHA256_CTX ctx;

  // Hash the key
  sha256_init(&ctx);
  sha256_update(&ctx, ptr_ps, sizeof(int));
  sha256_update(&ctx, ptr_client_random, sizeof(int));
  sha256_update(&ctx, ptr_server_random, sizeof(int));
  sha256_update(&ctx, ptr_ps, sizeof(int));
  sha256_final(&ctx, master_secret);  
}




/*
 * \brief                  Sends a message to the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to send
 *                         the message on.
 * \param msg              A pointer to the message to send.
 * \param msg_len          The length of the message in bytes.
 */
int
send_tls_message(int socketno, void *msg, int msg_len)
{
  // YOUR CODE HERE
  ssize_t write_size;
  int *msg_array;
  msg_array = (int *) msg;
  int msg_array_type = msg_array[0];

  switch (msg_array_type) {
    case CLIENT_HELLO: {
      hello_message *client_hello = (hello_message*) msg;
      write_size = write(socketno, client_hello, msg_len);
      break; }
    case CLIENT_CERTIFICATE: {
      cert_message *client_cert = (cert_message*) msg;
      write_size = write(socketno, client_cert, msg_len);
      break; }
    case PREMASTER_SECRET: {
      ps_msg *premaster_secret = (ps_msg*) msg;
      write_size = write(socketno, premaster_secret, msg_len);
      break;
    }
    case ENCRYPTED_MESSAGE: {
      tls_msg *encrypted_msg = (tls_msg*) msg;
      write_size = write(socketno, encrypted_msg, msg_len);
      break;
    }
  }

  if (write_size == -1) {
    perror("could not write to socket\n");
    exit(1);
    return ERR_FAILURE;
  }
  return ERR_OK;
}


/*
 * \brief                  Receieves a message from the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to receive
 *                         the message on.
 * \param msg              A pointer to where to store the received message.
 * \param msg_len          The length of the message in bytes.
 * \param msg_type         The expected type of the message to receive.
 */
int
receive_tls_message(int socketno, void *msg, int msg_len, int msg_type)
{
  // YOUR CODE HERE
  //read msg
  ssize_t bytes_read;
  bytes_read = read(socketno, msg, msg_len);
  if (bytes_read <= 0) {
    perror("could not receive message\n");
    exit(1);
    return ERR_FAILURE;
  }
  
  //cast msg into an integer array and then read byte 0 of the array.
  int *msg_array;
  msg_array = (int *) msg;
  int msg_array_type = msg_array[0];

  if( bytes_read == -1 || bytes_read == 0 || (msg_array_type == ERROR_MESSAGE) || (msg_array_type != msg_type) )
    return ERR_FAILURE;
  else
    return ERR_OK;
}


/*
 * \brief                Encrypts/decrypts a message using the RSA algorithm.
 *
 * \param result         a field to populate with the result of your RSA calculation.
 * \param message        the message to perform RSA on. (probably a cert in this case)
 * \param e              the encryption key from the key_file passed in through the
 *                       command-line arguments
 * \param n              the modulus for RSA from the modulus_file passed in through
 *                       the command-line arguments
 *
 * Fill in this function with your proj0 solution or see staff solutions.
 */
static void
perform_rsa(mpz_t result, mpz_t message, mpz_t d, mpz_t n)
{
    /* YOUR CODE HERE */      
    mpz_set_ui(result, 1);
      
    mpz_t odd;
    mpz_init(odd);  //variable used to know if d is odd or even
    
    //each iteration divide d by two until d reach zero
    for(;mpz_cmp_ui(d, 0) > 0; mpz_div_ui(d, d, 2)) {
    mpz_mod_ui(odd, d, 2);    //calculate if d is odd or even   
    
    //If in this iteration d is odd (d mod 2 != 0), then result = result * message mod n
    //The reason is because the final result can be calculated by taking products according to the binary expansion of d.
    //then if it is odd then is part of the binary expansion of d.
    if(mpz_cmp_ui(odd, 0) != 0) {
      mpz_mul(result, result, message);
      mpz_mod(result, result, n);
    }
    
    //In each iteration square the message mod n
    mpz_mul(message, message, message);
    mpz_mod(message, message, n);   
  }
}


/* Returns a pseudo-random integer. */
static int
random_int()
{
  srand(time(NULL));
  return rand();
}

/*
 * \brief                 Returns ascii string from a number in mpz_t form.
 *
 * \param output_str      A pointer to the output string.
 * \param input           The number to convert to ascii.
 */
void
mpz_get_ascii(char *output_str, mpz_t input)
{
  int i,j;
  char *result_str;
  result_str = mpz_get_str(NULL, HEX_BASE, input);
  i = 0;
  j = 0;
  while (result_str[i] != '\0') {
    output_str[j] = hex_to_ascii(result_str[i], result_str[i+1]);
    j += 1;
    i += 2;
  }
}

/*
 * \brief                  Returns a pointer to a string containing the
 *                         characters representing the input hex value.
 *
 * \param data             The input hex value.
 * \param data_len         The length of the data in bytes.
 */
char
*hex_to_str(char *data, int data_len)
{
  int i;
  char *output_str = calloc(1+2*data_len, sizeof(char));
  for (i = 0; i < data_len; i += 1) {
    snprintf(output_str+2*i, 3, "%02X", (unsigned int) (data[i] & 0xFF));
  }
  return output_str;
}

/* Return the public key exponent given the decrypted certificate as string. */
int
get_cert_exponent(mpz_t result, char *cert)
{
  int err;
  char *srch, *srch2;
  char exponent[RSA_MAX_LEN/2];
  memset(exponent, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, ':');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 2;
  srch2 = strchr(srch, '\n');
  if (srch2 == NULL) {
    return ERR_FAILURE;
  }
  strncpy(exponent, srch, srch2-srch);
  err = mpz_set_str(result, exponent, 0);
  if (err == -1) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}

/* Return the public key modulus given the decrypted certificate as string. */
int
get_cert_modulus(mpz_t result, char *cert)
{
  char *srch, *srch2;
  char modulus[RSA_MAX_LEN/2];
  memset(modulus, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, ':');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 2;
  srch2 = strchr(srch, '\n');
  if (srch2 == NULL) {
    return ERR_FAILURE;
  }
  strncpy(modulus, srch, srch2-srch);
  int err = mpz_set_str(result, modulus, 0);
  if (err == -1) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}

/* Prints the usage string for this program and exits. */
static void
usage()
{
    printf("./client -i <server_ip_address> -c <certificate_file> -m <modulus_file> -d <exponent_file>\n");
    exit(1);
}

/* Catches the signal from C-c and closes connection with server. */
static void
kill_handler(int signum)
{
  if (signum == SIGTERM) {
    cleanup();
  }
}

/* Converts the two input hex characters into an ascii char. */
static int
hex_to_ascii(char a, char b)
{
    int high = hex_to_int(a) * 16;
    int low = hex_to_int(b);
    return high + low;
}

/* Converts a hex value into an int. */
static int
hex_to_int(char a)
{
    if (a >= 97) {
  a -= 32;
    }
    int first = a / 16 - 3;
    int second = a % 16;
    int result = first*10 + second;
    if (result > 9) {
  result -= 1;
    }
    return result;
}

/* Closes files and exits the program. */
static void
cleanup()
{
  close(sockfd);
  exit(1);
}

//Receives a char array string and return an unsigend char array with the Ciphertext value
void getCiphertext(unsigned char *input, unsigned char *ciphertext) {
    int value;
    unsigned char buff[2];
    strcpy (buff, "");
    unsigned char character1, character2;
    int i,j;
    for(i=0, j=0; i<(int)strlen(input); i+=2, j++) {
        sprintf(buff,"%c", input[i]);
        sscanf(buff, "%X", &value);
        character1 = (char) value;
        character1 <<= 4;
            
        sprintf(buff,"%c", input[i+1]);
        sscanf(buff, "%X", &value);
        character2 = (char) value;
            
        character1 |= character2;
        ciphertext[j] = character1;    
    }    
}
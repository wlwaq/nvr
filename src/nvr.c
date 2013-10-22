/*
 ============================================================================
 Name        : nvr.c
 Author      : lsc
 Version     :
 Copyright   : R & D Center of Internet of Things Security
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include "nvr.h"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }


static char *ASU_ip_addr;
pid_t pid;

static annotation = 1;  //1-lvshichao,2-yaoyao

typedef struct user
{
    int user_ID;
    int client_socket;
    //client_socket==NOT_LOGIN,表示没有用户登录,
    //client_socket==NOT_IN_USE,表示没有用户注册,
}user;

//多线程共享user_table
static user user_table[USER_AMOUNT_MAX];
//访问user_table时要使用的信号量
pthread_mutex_t user_table_mutex;

void init_user_table()
{
    int i=0;
    for(i=0;i<USER_AMOUNT_MAX;i++)
    {
        user_table[i].client_socket = NOT_IN_USE;
        user_table[i].user_ID = 255;
    }
}

int init_server_socket()
{
    struct sockaddr_in server_addr;

    // 接收缓冲区
    int nRecvBuf = 32*1024; //设置为32K
    //发送缓冲区
    int nSendBuf = 32*1024; //设置为32K

    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(CHAT_LISTEN_PORT);

    int server_socket = socket(AF_INET,SOCK_STREAM,0);

    setsockopt(server_socket,SOL_SOCKET,SO_RCVBUF,(const BYTE *)&nRecvBuf,sizeof(int));
    setsockopt(server_socket,SOL_SOCKET,SO_SNDBUF,(const BYTE *)&nSendBuf,sizeof(int));

    if( server_socket < 0)
    {
        perror("socket error!");
        exit(1);
    }

    if( bind(server_socket,(struct sockaddr*)&server_addr,sizeof(server_addr)))
    {
        perror("server bind error Failed!");
        exit(1);
    }

    if ( listen(server_socket, 5) )
    {
        printf("Server Listen Failed!");
        exit(1);
    }
    return server_socket;
}


int connect_to_asu()
{
	int client_socket;
    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;
    socklen_t server_addr_length;

    int nRecvBuf = 32*1024; //设置为32K
    int nSendBuf = 32*1024; //设置为32K

    //设置一个socket地址结构client_addr,代表客户端internet地址, 端口
    bzero(&client_addr,sizeof(client_addr)); //把一段内存区的内容全部设置为0
    client_addr.sin_family = AF_INET;    //internet协议族
    client_addr.sin_addr.s_addr = htons(INADDR_ANY);//INADDR_ANY表示自动获取本机地址
    client_addr.sin_port = htons(0);    //0表示让系统自动分配一个空闲端口
    //创建用于internet的流协议(TCP)socket,用client_socket代表客户端socket

    if( (client_socket = socket(AF_INET,SOCK_STREAM,0)) < 0){
        printf("Create Socket Failed!\n");
        return FALSE;
    }
    //把客户端的socket和客户端的socket地址结构联系起来
    if( bind(client_socket,(struct sockaddr*)&client_addr,sizeof(client_addr))){
        printf("Client Bind Port Failed!\n");
        return FALSE;
    }

    //设置一个socket地址结构server_addr,代表服务器的internet地址, 端口
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    if(inet_aton(ASU_ip_addr,&server_addr.sin_addr) == 0) //服务器的IP地址来自程序的参数
    {
        printf("Server IP Address Error!\n");
        return FALSE;
    }
    server_addr.sin_port = htons(CHAT_SERVER_PORT);
    server_addr_length = sizeof(server_addr);

    setsockopt(client_socket,SOL_SOCKET,SO_RCVBUF,(const BYTE *)&nRecvBuf,sizeof(int));
    setsockopt(client_socket,SOL_SOCKET,SO_SNDBUF,(const BYTE *)&nSendBuf,sizeof(int));

    //客户端向服务器发起连接,连接成功后client_socket代表了客户端和服务器的一个socket连接
    if(connect(client_socket,(struct sockaddr*)&server_addr, server_addr_length) < 0)
    {
        printf("AE Can Not Connect To ASU %s!\n",ASU_ip_addr);
        return FALSE;
    }
    return client_socket;

}

int send_to_peer(int new_server_socket, BYTE *send_buffer, int send_len)
{

	int length = send(new_server_socket,send_buffer,send_len,0);
	//printf("--- send %d bytes ---\n",length);
	printf("---------发送 %d 字节数据！---------\n",length);

    if(length <0){
        printf("Socket Send Data Failed Or Closed\n");
        close(new_server_socket);
        return FALSE;
    }
	else
		return TRUE;
}


int recv_from_peer(int new_server_socket, BYTE *recv_buffer, int recv_len)
{
	int length = 0;
	length = recv(new_server_socket,recv_buffer, recv_len,MSG_WAITALL);//MSG_WAITALL

	if (length < 0)
	{
		printf("Receive Data From Server Failed\n");
		return FALSE;
	}else if(length < recv_len)
	{
		printf("Receive data from server less than required, %d bytes.\n",length);
		return FALSE;
	}else if(length > recv_len)
	{
		printf("Receive data from server more than required.\n");
		return FALSE;
	}
	else
	{
		//printf("--- receive data succeed, %d bytes. ---\n",length);
		printf("---------接收数据成功, 接收 %d 字节数据！---------\n",length);
		return TRUE;
	}

}


BOOL getCertData(int userID, BYTE buf[], int *len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中

	if (userID == 0)
		sprintf(certname, "./cacert/cacert.pem");
	else
		sprintf(certname, "./cert/usercert%d.pem", userID);


	if(annotation == 2)
		printf("  cert file name: %s\n", certname);

	fp = fopen(certname, "rb");
	if (fp == NULL)
	{
		printf("reading the cert file failed!\n");
		return FALSE;
	}
	*len = fread(buf, 1, 5000, fp);
	if(annotation == 2)
		printf("  cert's length is %d\n", *len);
	fclose(fp);
	if(annotation == 2)
		printf("  将证书保存到缓存buffer成功!\n");

	return TRUE;
}

BOOL writeCertFile(int userID, BYTE buf[], int len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中

	if (userID == 0)
		sprintf(certname, "./cacert/cacert.pem");
	else
		//sprintf(certname, "./cert/usercert%d.pem", userID);
		sprintf(certname, "./cert/camerareceive.pem");
	if(annotation == 2)
		printf("  cert file name: %s\n", certname);

	fp = fopen(certname, "w");
	if (fp == NULL)
	{
		printf("open cert file failed!\n");
		return FALSE;
	}
	int res = fwrite(buf, 1, len, fp);
	if(annotation == 2)
		printf("  cert's length is %d\n", len);
	fclose(fp);
	if(annotation == 2)
		printf("  write cert complete!\n");

	return TRUE;
}

/*************************************************

Function:    // getprivkeyfromprivkeyfile
Description: // CA(驻留在ASU中)从cakey.pem中提取CA的私钥，以便后续进行ASU的签名
Calls:       // openssl读取私钥PEM文件相关函数
Called By:   // 待添加！！！
Input:	     //	无
Output:      //	CA(驻留在ASU中)的私钥
Return:      // EVP_PKEY *privKey
Others:      // 该函数只是在本工程中为asu.c专用，即提取CA(驻留在ASU中)的私钥，如需提取其他私钥，还有待于将打开文件的目录及文件名做点修改

*************************************************/
EVP_PKEY * getprivkeyfromprivkeyfile(int userID)
{
	EVP_PKEY * privKey;
	FILE* fp;
	//RSA rsa_struct;
	RSA* rsa;
	char keyname[40];

	if (userID == 0)
		sprintf(keyname, "./private/cakey.pem");
	else
		sprintf(keyname, "./private/userkey%d.pem", userID);
	fp = fopen(keyname, "r");

	if(annotation == 2)
		printf("  key file name: %s\n", keyname);
	if (fp == NULL)
	{
		fprintf(stderr, "Unable to open %s for RSA priv params\n", keyname);
		return NULL;
	}

	rsa = RSA_new();
	if ((rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL)) == NULL)
	{
		fprintf(stderr, "Unable to read private key parameters\n");
		return NULL;
	}
	fclose(fp);

	// print
	//printf("Content of Private key PEM file\n");
	//RSA_print_fp(stdout, rsa, 0);
	//printf("\n");

	privKey = EVP_PKEY_new();
	if (EVP_PKEY_set1_RSA(privKey, rsa) != 1) //保存RSA结构体到EVP_PKEY结构体
	{
		printf("EVP_PKEY_set1_RSA err\n");
		RSA_free (rsa);
		return NULL;
	}
	else
	{
		RSA_free (rsa);
		return privKey;
	}
}

/*************************************************

Function:    // getpubkeyfromcert
Description: // 从数字证书(PEM文件)中读取公钥
Calls:       // openssl中读PEM文件的API
Called By:   // 待添加！！！
Input:	     //	用户证书的用户名certnum
Output:      //	数字证书公钥
Return:      // EVP_PKEY *pubKey
Others:      // 用户证书的用户名certnum最好是用字符串形式，但是目前是int值，有待改进

*************************************************/
EVP_PKEY *getpubkeyfromcert(int certnum)
{
	EVP_PKEY *pubKey;

	BIO * key = NULL;
	X509 * Cert = NULL; //X509证书结构体，保存CA证书
	key = BIO_new(BIO_s_file());

	char certname[60];
	memset(certname, '\0', sizeof(certname)); //初始化certname,以免后面写如乱码到文件中
	if (certnum == 0)
		sprintf(certname, "./cacert/cacert.pem"); //./demoCA/
	else
		sprintf(certname, "./cert/usercert%d.pem", certnum);

	BIO_read_filename(key,certname);
	if (!PEM_read_bio_X509(key, &Cert, 0, NULL))
	{
		/* Error 读取证书失败！*/
		printf("读取证书失败!\n");
		return NULL;
	}

	pubKey = EVP_PKEY_new();
	//获取证书公钥
	pubKey = X509_get_pubkey(Cert);
	return pubKey;
}

/*************************************************

Function:    // verify_sign
Description: // 验证数字签名
Calls:       // openssl验证签名的API
Called By:   // 待添加！！！
Input:	     //	input---待验证签名的整个数据包
                sign_input_len---待验证签名的有效数据字段的长度，并非整个input长度
                sign_value---签名字段
                sign_output_len---签名字段的长度
                pubKey---验证签名所使用的公钥
Output:      //	验证签名结果，TRUE or FALSE
Return:      // TRUE or FALSE
Others:      // 注意sign_input_len字段并非整个input长度，这一点今后如果感觉不合适再修改

*************************************************/

BOOL verify_sign(BYTE *input,int sign_input_len,BYTE * sign_value, unsigned int sign_output_len,EVP_PKEY * pubKey)
{
	EVP_MD_CTX mdctx;		 //摘要算法上下文变量

	EVP_MD_CTX_init(&mdctx); //初始化摘要上下文

	BYTE sign_input_buffer[10000];

	memcpy(sign_input_buffer,input,sign_input_len);    //sign_inputLength为签名算法输入长度，为所传入分组的除签名字段外的所有字段

	if (!EVP_VerifyInit_ex(&mdctx, EVP_md5(), NULL))	//验证初始化，设置摘要算法，一定要和签名一致。
	{
		printf("EVP_VerifyInit_ex err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_VerifyUpdate(&mdctx, sign_input_buffer, sign_input_len))	//验证签名（摘要）Update
	{
		printf("err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_VerifyFinal(&mdctx, sign_value,sign_output_len, pubKey))		//验证签名（摘要）Update
	{
		printf("EVP_Verify err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}
//	else
//	{
//		printf("  验证签名正确!!!\n");
//	}
	//释放内存
//	EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}


/*************************************************

Function:    // SHA256
Description: // SHA256散列函数
Calls:       // openssl SHA256的API函数
Called By:   //
Input:	     //	input---待计算摘要的输入数据
                input_len---待计算摘要的输入数据长度
                output---摘要结果输出
Output:      //	摘要值
Return:      // 256bit(32Byte)摘要
Others:      // 本处注释只是为了大家理解，待理解后，本处注释可删除

*************************************************/
//SHA256(input, input_len, output);


/*************************************************

Function:    // hmac_sha256
Description: // WAPI消息认证MAC算法
Calls:       // openssl SHA256的API函数
Called By:   // 待添加！！！
Input:	     //	text---待计算MAC的输入数据
                text_len---待计算MAC的输入数据长度
                key---hmac密钥
                key_len---hmac密钥长度
                digest---输出MAC值
Output:      //	MAC值
Return:      // 256bit(32Byte)MAC
Others:      // 如果想设定输出MAC的长度，可考虑添加一个输出MAC长度的形参

*************************************************/

void hmac_sha256(
		const BYTE *text,      /* pointer to data stream        */
		int        text_len,   /* length of data stream         */
		const BYTE *key,       /* pointer to authentication key */
		int        key_len,    /* length of authentication key  */
		void       *digest)    /* caller digest to be filled in */
{
	BYTE k_ipad[65]; /* inner padding -
	                  * key XORd with ipad
	                  */
	BYTE k_opad[65]; /* outer padding -
	                  * key XORd with opad
	                  */
	BYTE tk[SHA256_DIGEST_LENGTH];
	BYTE tk2[SHA256_DIGEST_LENGTH];
	BYTE bufferIn[1024];
	BYTE bufferOut[1024];
	int i;
	/* if key is longer than 64 bytes reset it to key=sha256(key) */
	if (key_len > 64)
	{
		SHA256(key, key_len, tk);
		key = tk;
		key_len = SHA256_DIGEST_LENGTH;
	}
	/*
	 * the HMAC_SHA256 transform looks like:
	 *
	 * SHA256(K XOR opad, SHA256(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected
	 */
	/* start out by storing key in pads */
	memset(k_ipad, 0, sizeof k_ipad);
	memset(k_opad, 0, sizeof k_opad);
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++)
	{
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
	/*
	 * perform inner SHA256
	 */
	memset(bufferIn, 0x00, 1024);
	memcpy(bufferIn, k_ipad, 64);
	memcpy(bufferIn + 64, text, text_len);
	SHA256(bufferIn, 64 + text_len, tk2);
	/*
	 * perform outer SHA256
	 */
	memset(bufferOut, 0x00, 1024);
	memcpy(bufferOut, k_opad, 64);
	memcpy(bufferOut + 64, tk2, SHA256_DIGEST_LENGTH);
	SHA256(bufferOut, 64 + SHA256_DIGEST_LENGTH, digest);
}
/*************************************************

Function:    // gen_randnum
Description: // 生成随机数
Calls:       // openssl SHA256的API函数以及RAND_bytes函数
Called By:   // 待添加！！！
Input:	     //	randnum---保存生成的随机数
                randnum_len---随机数长度
Output:      //	随机数
Return:      // 256bit(32Byte)MAC
Others:      //

*************************************************/
void gen_randnum(BYTE *randnum,int randnum_len)
{
	int ret;
	BYTE randnum_seed[randnum_len];

	ret = RAND_bytes(randnum_seed, randnum_len);
	if(ret!=1)
	{
		printf("生成随机数种子失败！\n");
	}
	//参考WAPI实施指南P49 SHA-256(挑战种子)--->挑战，随机数生成算法：SHA-256(随机数种子)--->随机数
	SHA256(randnum_seed, randnum_len, randnum);
}




int getECDHparam(ecdh_param *ecdhparam, const char *oid)
{
	unsigned char  *buf;
	int oidlen = 0;

	oidlen=a2d_ASN1_OBJECT(NULL,0,oid,-1);
	if (oidlen <= 0){
		printf("oid encode failed.\n");
		return FALSE;
	}
	buf=(unsigned char *)malloc(sizeof(unsigned char)*oidlen);
	oidlen=a2d_ASN1_OBJECT(buf,oidlen,oid,-1);

	ecdhparam->param_identify = 1;
	ecdhparam->param_length = oidlen;
	memcpy(ecdhparam->oid.oid_code, buf, oidlen);
	free(buf);

	return TRUE;
}

int getLocalIdentity(identity *localIdentity, int localUserID)
{
	BIO *b=NULL;    //bio\u63a5\u53e3
	X509 *local_cert=NULL;  //X509\u683c\u5f0f\u670d\u52a1\u7aef\u8bc1\u4e66
	X509_NAME *issuer_name=NULL;   //\u8bc1\u4e66\u9881\u53d1\u8005\u540d\u5b57
	X509_NAME *subject_name=NULL;   //\u8bc1\u4e66\u6240\u6709\u8005\u540d\u5b57
	char issuer_str[256] = {0};          //\u9881\u53d1\u8005\u540d\u5b57\u5b58\u50a8\u5b57\u7b26\u4e32
	char subject_str[256] = {0};         //\u6240\u6709\u8005\u540d\u5b57\u5b58\u50a8\u5b57\u7b26\u4e32
	long serialnum;
	int offset;
	//\u5c06PEM\u683c\u5f0f\u7684\u8bc1\u4e66\u5b58\u4e3aX509\u8bc1\u4e66\u683c\u5f0f
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中

	if (localUserID == 0)
		//sprintf(certname, "./demoCA/cacert.pem");//./demoCA/
		sprintf(certname, "./cacert/cacert.pem");//./demoCA/
	else
		//sprintf(certname, "./demoCA/newcerts/usercert%d.pem", certnum);  //终端运行./client
		sprintf(certname, "./cert/usercert%d.pem", localUserID);                //eclipse调试或运行

	if(annotation == 2)
		printf("  cert file name: %s\n", certname);

	SSLeay_add_all_algorithms();   //\u52a0\u8f7d\u76f8\u5173\u7b97\u6cd5

	b=BIO_new_file(certname,"r");
	local_cert=PEM_read_bio_X509(b,NULL,NULL,NULL);
	BIO_free(b);
	if(local_cert==NULL)
	{
		printf("open local cert failed.\n");
		X509_free(local_cert);
		return FALSE;
	}

	issuer_name=X509_get_issuer_name(local_cert);
	X509_NAME_oneline(issuer_name,issuer_str,256);

	subject_name=X509_get_subject_name(local_cert);
	X509_NAME_oneline(subject_name,subject_str,256);

	serialnum = ASN1_INTEGER_get(X509_get_serialNumber(local_cert));
	X509_free(local_cert);

	localIdentity->identity_identify = 1; //X.509 cert

	offset = 0;
	memcpy(localIdentity->cer_der.data + offset, (BYTE*)subject_str, strlen(subject_str));
	offset += strlen(subject_str);
	memcpy(localIdentity->cer_der.data + offset, (BYTE*)issuer_str, strlen(issuer_str));
	offset += strlen(issuer_str);
	memcpy(localIdentity->cer_der.data + offset, (BYTE*)&serialnum, sizeof(serialnum)/sizeof(BYTE));
	offset += sizeof(serialnum);

	localIdentity->identity_length = offset;

	return TRUE;

}

/*************************************************

Function:    // gen_sign
Description: // 生成数字签名
Calls:       // openssl生成签名的API
Called By:   // fill_certificate_auth_resp_packet
Input:	     //	input---待生成签名的整个数据包(分组)
                sign_input_len---待生成签名的有效数据字段的长度，并非整个input长度
                sign_value---保存生成的字段
                sign_output_len---生成的签名字段的长度
                privKey---生成签名所使用的私钥
Output:      //	生成签名操作结果，TRUE or FALSE
Return:      // TRUE or FALSE
Others:      // 注意sign_input_len字段并非整个input长度，这一点今后如果感觉不合适再修改

*************************************************/

BOOL gen_sign(BYTE * input,int sign_input_len,BYTE * sign_value, unsigned int *sign_output_len,EVP_PKEY * privKey)
{
	EVP_MD_CTX mdctx;						//摘要算法上下文变量

	unsigned int temp_sign_len;
	unsigned int i;
	BYTE sign_input_buffer[10000];


	memset(sign_input_buffer,0,sizeof(sign_input_buffer));
	memcpy(sign_input_buffer,input,sign_input_len);    //sign_inputLength为签名算法输入长度，为所传入分组的除签名字段外的所有字段

	//以下是计算签名代码
	EVP_MD_CTX_init(&mdctx);				//初始化摘要上下文

	if (!EVP_SignInit_ex(&mdctx, EVP_md5(), NULL))	//签名初始化，设置摘要算法，本例为MD5
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_SignUpdate(&mdctx, sign_input_buffer, sign_input_len))	//计算签名（摘要）Update
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同;
		return FALSE;
	}

	if (!EVP_SignFinal(&mdctx, sign_value, & temp_sign_len, privKey))	//签名输出
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	* sign_output_len = temp_sign_len;
/*
	printf("签名值是: \n");
	for (i = 0; i < * sign_output_len; i++)
	{
		if (i % 16 == 0)
			printf("\n%08xH: ", i);
		printf("%02x ", sign_value[i]);
	}
	printf("\n");
*/
	//清理内存
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}

//1) ProcessWAPIProtocolAuthActive
int fill_auth_active_packet(int user_ID,auth_active *auth_active_packet)
{
	//fill WAI packet head
	if(annotation == 2)
		printf("fill WAI packet head:\n");
	auth_active_packet->wai_packet_head.version = 1;
	auth_active_packet->wai_packet_head.type = 1;
	auth_active_packet->wai_packet_head.subtype = AUTH_ACTIVE;
	auth_active_packet->wai_packet_head.reserved = 0;
	auth_active_packet->wai_packet_head.packetnumber = 1;
	auth_active_packet->wai_packet_head.fragmentnumber = 0;
	auth_active_packet->wai_packet_head.identify = 0;

	//fill flag
	if(annotation == 2)
		printf("fill flag:\n");
	auth_active_packet->flag = 0x00;

	//fill auth identify, first time random number
	if(annotation == 2)
		printf("fill auth identify:\n");
	gen_randnum((BYTE *)&auth_active_packet->authidentify, sizeof(auth_active_packet->authidentify));

	//fill ae rand number
	if(annotation == 2)
		printf("fill ae rand number:\n");
	gen_randnum((BYTE *)&auth_active_packet->aechallenge, sizeof(auth_active_packet->aechallenge));

	//fill local ASU identity
	if(annotation == 2)
		printf("fill local ASU identity:\n");
	int asu_ID = 0;
	getLocalIdentity(&auth_active_packet->localasuidentity, asu_ID);

	//fill ecdh param
	if(annotation == 2)
		printf("fill ecdh param:\n");
	const  char  oid[]={"1.2.156.11235.1.1.2.1"};

	getECDHparam(&auth_active_packet->ecdhparam, oid);

	//fill ae certificate
	if(annotation == 2)
		printf("fill ae certificate:\n");
	auth_active_packet->certificatestaae.cer_identify = 1; //X.509 cert

	BYTE cert_buffer[5000];
	int cert_len = 0;

	if (!getCertData(user_ID, cert_buffer, &cert_len))    //先读取ASUE证书，"demoCA/newcerts/usercert2.pem"
	{
		printf("将证书保存到缓存buffer失败!");
		return FALSE;
	}

	auth_active_packet->certificatestaae.cer_length = cert_len;   //证书长度字段
	memcpy((auth_active_packet->certificatestaae.cer_X509),(BYTE*)cert_buffer,strlen((char*)cert_buffer));

	//fill packet length
	auth_active_packet->wai_packet_head.length = sizeof(auth_active);

	//fill ae signature
	if(annotation == 2)
		printf("fill ae signature:\n");
	//AE\u4f7f\u7528AE\u7684\u79c1\u94a5(userkey2.pem)\u6765\u751f\u6210AE\u7b7e\u540d
	EVP_PKEY * privKey;
	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	privKey = getprivkeyfromprivkeyfile(user_ID);
	if(privKey == NULL)
	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}

	if(!gen_sign((BYTE *)auth_active_packet,(auth_active_packet->wai_packet_head.length-sizeof(auth_active_packet->aesign)),sign_value, &sign_len,privKey))
	{
		printf("generate signature failed.\n");
		return FALSE;
	}

	auth_active_packet->aesign.sign.length = sign_len;
	memcpy(auth_active_packet->aesign.sign.data,sign_value,sign_len);

	return TRUE;

}

int ProcessWAPIProtocolAuthActive(int user_ID, auth_active *auth_active_packet)
{
	if (!fill_auth_active_packet(user_ID, auth_active_packet))
	{
		printf("fill auth active packet failed!\n");
	}
	else
		printf("网络硬盘录像机封装【认证激活分组】成功！准备发往摄像机！\n");

	return TRUE;

}

//2) ProcessWAPIProtocolAccessAuthRequest
/*
int fill_access_auth_requ_packet(int user_ID,access_auth_requ *access_auth_requ_packet)
{
	//fill WAI packet head
	access_auth_requ_packet->wai_packet_head.version = 1;
	access_auth_requ_packet->wai_packet_head.type = 1;
	access_auth_requ_packet->wai_packet_head.subtype = AUTH_ACTIVE;
	access_auth_requ_packet->wai_packet_head.reserved = 0;
	access_auth_requ_packet->wai_packet_head.packetnumber = 2;
	access_auth_requ_packet->wai_packet_head.fragmentnumber = 0;
	access_auth_requ_packet->wai_packet_head.identify = 0;

	//fill flag
	access_auth_requ_packet->flag = 0x04;

	//fill auth identify
	memset((BYTE *)&access_auth_requ_packet->authidentify, 0, sizeof(access_auth_requ_packet->authidentify));

	//fill asue rand number
	memset((BYTE *)&access_auth_requ_packet->asuechallenge, 0, sizeof(access_auth_requ_packet->aechallenge));

	//fill asue cipher data
	memset((BYTE *)&access_auth_requ_packet->asuekeydata, 0, sizeof(access_auth_requ_packet->asuekeydata));

	//fill ae rand number
	memset((BYTE *)&access_auth_requ_packet->aechallenge, 0, sizeof(access_auth_requ_packet->aechallenge));


	//fill local ae identity
	getLocalIdentity(&access_auth_requ_packet->staaeidentity, user_ID);

	//fill ecdh param
	const  char  oid[]={"1.2.156.11235.1.1.2.1"};
	getECDHparam(&access_auth_requ_packet->ecdhparam, oid);

	//fill asue certificate
	access_auth_requ_packet->certificatestaasue.cer_identify = 1; //X.509 cert

	BYTE cert_buffer[5000];
	int cert_len = 0;

	if (!getCertData(user_ID, cert_buffer, &cert_len))	  //先读取ASUE证书，"demoCA/newcerts/usercert2.pem"
	{
		printf("将证书保存到缓存buffer失败!");
		return FALSE;
	}

	access_auth_requ_packet->certificatestaasue.cer_length = cert_len;   //证书长度字段
	memcpy((access_auth_requ_packet->certificatestaasue.cer_X509),(BYTE*)cert_buffer,strlen((char*)cert_buffer));


	//fill packet length
	access_auth_requ_packet->wai_packet_head.length = sizeof(access_auth_requ);


	//fill asue signature
	//AE\u4f7f\u7528AE\u7684\u79c1\u94a5(userkey2.pem)\u6765\u751f\u6210AE\u7b7e\u540d
	EVP_PKEY * privKey;
	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	privKey = getprivkeyfromprivkeyfile(user_ID);
	if(privKey == NULL)
	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}

	if(!gen_sign((BYTE *)access_auth_requ_packet,(access_auth_requ_packet->wai_packet_head.length-sizeof(access_auth_requ_packet->asuesign)),sign_value, &sign_len,privKey))
	{
		printf("generate signature failed.\n");
		return FALSE;
	}

	access_auth_requ_packet->asuesign.sign.length = sign_len;
	memcpy(access_auth_requ_packet->asuesign.sign.data,sign_value,sign_len);

	return TRUE;

}

int ProcessWAPIProtocolAccessAuthRequest(int user_ID, access_auth_requ *access_auth_requ_packet)
{

	memset((BYTE *)access_auth_requ_packet, 0, sizeof(access_auth_requ));
	if (!fill_access_auth_requ_packet(user_ID, access_auth_requ_packet)){
		printf("fill access auth request packet failed!\n");
	}

	return TRUE;
}
*/
int HandleWAPIProtocolAccessAuthRequest(int user_ID, auth_active *auth_active_packet, access_auth_requ *access_auth_requ_packet)
{

	//write asue cert into cert file
	if(annotation == 2)
		printf("write asue cert into cert file:\n");
	int asue_ID = 1;
	//writeCertFile(asue_ID, (BYTE *)access_auth_requ_packet->certificatestaasue.cer_X509, (int)access_auth_requ_packet->certificatestaasue.cer_length);

	//verify sign of ASUE
	if(annotation == 2)
		printf("verify sign of ASUE:\n");
	//read ae certificate get ae pubkey(公钥)
	EVP_PKEY *asuepubKey = NULL;
	BYTE *pTmp = NULL;
	BYTE derasuepubkey[1024];
	int asuepubkeyLen, i;
	asuepubKey = getpubkeyfromcert(asue_ID);
	if(asuepubKey == NULL)
	{
		printf("get asue's public key failed.\n");
		return FALSE;
	}

	pTmp = derasuepubkey;
	//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
	asuepubkeyLen = i2d_PublicKey(asuepubKey, &pTmp);

	//verify the sign
	if (verify_sign((BYTE *) access_auth_requ_packet,
			sizeof(access_auth_requ) - sizeof(sign_attribute),
			access_auth_requ_packet->asuesign.sign.data,
			access_auth_requ_packet->asuesign.sign.length, asuepubKey))
	{
		printf("网络硬盘录像机验证摄像机签名正确!!!\n");
		EVP_PKEY_free(asuepubKey);
	}
	else
	{
		printf("asue's sign verify failed.\n");
		return FALSE;
	}

	//verify FLAG
	if(annotation == 2)
		printf("verify FLAG:\n");
	if(access_auth_requ_packet->flag != 0x04){
		printf("verify flag failed.\n");
		return FALSE;
	}

	//verify auth identity, is same auth active packet
	if(annotation == 2)
		printf("verify auth identity:\n");
	if (memcmp(access_auth_requ_packet->authidentify,
			auth_active_packet->authidentify,
			sizeof(access_auth_requ_packet->authidentify)) != 0)
		printf("verify auth identity failed!\n");

	//verify AE identity
	if(annotation == 2)
		printf("verify AE identity, unfinished!!!\n");
	identity localaeidentity;
	getLocalIdentity(&localaeidentity, user_ID);

	if( memcmp(access_auth_requ_packet->staaeidentity.cer_der.data,
		localaeidentity.cer_der.data,
		localaeidentity.identity_length) != 0)
	{
		printf("verify AE identity failed.\n");
		printf("length:%d, %d\n", localaeidentity.identity_length, access_auth_requ_packet->staaeidentity.identity_length);
		printf("data[:20]: %20s, %20s\n", localaeidentity.cer_der.data, access_auth_requ_packet->staaeidentity.cer_der.data);
		return FALSE;
	}else
	{
		if(annotation == 2)
			printf("verify AE identity succeed.\n");
	}

	//verify AE rand number, is same auth active packet
	if(annotation == 2)
		printf("verify AE rand number:\n");
	if(memcmp(access_auth_requ_packet->aechallenge,
		auth_active_packet->aechallenge,
		sizeof(access_auth_requ_packet->aechallenge)) != 0)
		printf("verify AE rand number failed!\n");


	return TRUE;
}




//3)

int fill_certificate_auth_requ_packet(int user_ID,access_auth_requ *access_auth_requ_packet,certificate_auth_requ *certificate_auth_requ_packet)
{
	//fill WAI packet head
	certificate_auth_requ_packet->wai_packet_head.version = 1;
	certificate_auth_requ_packet->wai_packet_head.type = 1;
	certificate_auth_requ_packet->wai_packet_head.subtype = CERTIFICATE_AUTH_REQU;
	certificate_auth_requ_packet->wai_packet_head.reserved = 0;
	certificate_auth_requ_packet->wai_packet_head.length = sizeof(certificate_auth_requ);
	certificate_auth_requ_packet->wai_packet_head.packetnumber = 3;
	certificate_auth_requ_packet->wai_packet_head.fragmentnumber = 0;
	certificate_auth_requ_packet->wai_packet_head.identify = 0;

	//fill addid
	memset((BYTE *)&(certificate_auth_requ_packet->addid.mac1),0,sizeof(certificate_auth_requ_packet->addid.mac1));
	memset((BYTE *)&(certificate_auth_requ_packet->addid.mac2),0,sizeof(certificate_auth_requ_packet->addid.mac2));

	//fill ae and asue rand number
	gen_randnum((BYTE *)&(certificate_auth_requ_packet->aechallenge),32);
	memcpy((BYTE *)&(certificate_auth_requ_packet->asuechallenge), (BYTE *)&(access_auth_requ_packet->asuechallenge), sizeof(certificate_auth_requ_packet->asuechallenge));

	//fill asue certificate

	memcpy(&(certificate_auth_requ_packet->staasuecer),&(access_auth_requ_packet->certificatestaasue),sizeof(certificate));
	//memset((BYTE *)&(certificate_auth_requ_packet->staasuecer),0,sizeof(certificate));

	//fill ae certificate
	BYTE cert_buffer[5000];
	int cert_len = 0;

	memset(cert_buffer,0,sizeof(cert_buffer));
	cert_len = 0;

	if (!getCertData(user_ID, cert_buffer, &cert_len)) //读取AE证书，"usercert2.pem",uesrID=2
	{
		printf("将证书保存到缓存buffer失败!");
		return FALSE;
	}

	certificate_auth_requ_packet->staaecer.cer_length = cert_len;   //证书长度字段
	memcpy((certificate_auth_requ_packet->staaecer.cer_X509),cert_buffer, cert_len);

	//fill ae signature
	EVP_PKEY * privKey;
	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	privKey = getprivkeyfromprivkeyfile(user_ID);
	if(privKey == NULL)
	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}

	if(!gen_sign((BYTE *)certificate_auth_requ_packet,(certificate_auth_requ_packet->wai_packet_head.length-sizeof(certificate_auth_requ_packet->aesign)),sign_value, &sign_len,privKey))
	{
		printf("generate signature failed.\n");
		return FALSE;
	}

	certificate_auth_requ_packet->aesign.sign.length = sign_len;
	memcpy(certificate_auth_requ_packet->aesign.sign.data,sign_value,sign_len);

	return TRUE;

}


int ProcessWAPIProtocolCertAuthRequest(int user_ID,access_auth_requ *access_auth_requ_packet,certificate_auth_requ *certificate_auth_requ_packet)
{
	memset((BYTE *)certificate_auth_requ_packet, 0, sizeof(certificate_auth_requ));
	if (!fill_certificate_auth_requ_packet(user_ID,access_auth_requ_packet,certificate_auth_requ_packet))
	{
		printf("fill certificate auth requ packet failed!\n");
	}
	else
		printf("网络硬盘录像机封装证书认证请求分组成功!准备发往认证服务器！\n");
	return TRUE;
}


//4)

int HandleProcessWAPIProtocolCertAuthResp(int user_ID, certificate_auth_requ *certificate_auth_requ_packet,certificate_auth_resp *certificate_auth_resp_packet,access_auth_resp *access_auth_resp_packet)
{
	//读取CA(驻留在ASU)中的公钥证书获取CA公钥
	EVP_PKEY *asupubKey = NULL;
	BYTE *pTmp = NULL;
	BYTE derasupubkey[1024];
	int asupubkeyLen, i;
	asupubKey = getpubkeyfromcert(0);
	if(asupubKey == NULL){
		printf("get asu's public key failed.\n");
		return FALSE;
		}

	pTmp = derasupubkey;
	//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
	asupubkeyLen = i2d_PublicKey(asupubKey, &pTmp);

	//验证ASU服务器对整个证书认证响应分组(除本字段外)的签名，检验该分组的完整性、验证该份组的发送源身份
	if (verify_sign((BYTE *) certificate_auth_resp_packet,
			sizeof(certificate_auth_resp) - sizeof(sign_attribute),
			certificate_auth_resp_packet->cerauthrespasusign.sign.data,
			certificate_auth_resp_packet->cerauthrespasusign.sign.length, asupubKey))
	{
		printf("验证认证服务器对整个证书认证响应分组(除本字段外)的签名正确!!!\n");
		EVP_PKEY_free(asupubKey);
	}



//	//验证ASU服务器对证书验证结果字段的签名
//	if (verify_sign((BYTE *) &(certificate_auth_resp_packet->cervalidresult),
//			sizeof(certificate_valid_result),
//			certificate_auth_resp_packet->cervalresasusign.sign.data,
//			certificate_auth_resp_packet->cervalresasusign.sign.length, asupubKey))
//	{
//		printf("验证ASU服务器对证书验证结果字段的签名正确！！！......\n");
//		EVP_PKEY_free(asupubKey);
//	}


	//验证ASUE随机数是否一致(证书认证请求分组vs证书认证响应分组)
	if(annotation == 2)
		printf("verify AE rand number between certificate_auth_requ vs certificate_auth_resp_packet:\n");
	if (memcmp(certificate_auth_resp_packet->cervalidresult.random1,
			certificate_auth_requ_packet->aechallenge,
			sizeof(certificate_auth_requ_packet->aechallenge)) != 0)
	{
		printf("verify ASUE random number failed between certificate_auth_requ vs certificate_auth_resp_packet!\n");
		return FALSE;
	}

	//检查ASU对ASUE证书的验证结果字段(certificate_auth_resp_packet->cervalidresult.cerresult1)
	if(annotation == 2)
		printf("verify cert valid result of ASUE:\n");
	if (certificate_auth_resp_packet->cervalidresult.cerresult1!= 0)
	{
		//printf("asu verify asue cert valid result failed.\n");

		printf("*******************************************************************\n");
		printf("*                                                                 *\n");
		printf("* 警告：网络硬盘录像机验证摄像机失败，不允许该摄像机接入!!!            *\n");
		printf("*                                                                 *\n");
		printf("*******************************************************************\n");
//		printf("警告：网络硬盘录像机验证摄像机失败！不允许该摄像机接入！.\n");
//		return FALSE;
	}
	else if(annotation == 2)
		printf("Authentication succeed!!\n");       //asu verify asue cert valid result succeed
	else if(annotation == 1)
	{
		printf("********************************************************************\n");
		printf("*                                                                  *\n");
		printf("* 网络硬盘录像机验证摄像机身份成功,允许该摄像机接入!!!             *\n");
		printf("*                                                                  *\n");
		printf("********************************************************************\n");
	}
//		printf("网络硬盘录像机验证摄像机成功！允许该摄像机接入！\n");       //asu verify asue cert valid result succeed

	//读取证书认证响应分组中的证书验证结果字段，将该字段拷贝到接入认证响应分组中的复合证书验证结果的证书验证结果字段中
	memcpy(&(access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result),&(certificate_auth_resp_packet->cervalidresult),sizeof(certificate_valid_result));

	//读取证书认证响应分组中的ASU服务器对证书验证结果字段的签名字段，将该字段拷贝到接入认证响应分组中的复合证书验证结果的签名字段中
	memcpy(&(access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result_asu_sign),&(certificate_auth_resp_packet->cervalresasusign),sizeof(certificate_valid_result));

	return TRUE;

}


int ProcessWAPIProtocolCertAuthResp(int user_ID, certificate_auth_requ *certificate_auth_requ_packet,certificate_auth_resp *certificate_auth_resp_packet,access_auth_resp *access_auth_resp_packet)//该函数的主要工作是查看证书验证结果，并填充接入认证响应分组
{
	memset((BYTE *)access_auth_resp_packet, 0, sizeof(access_auth_resp));
	if (!HandleProcessWAPIProtocolCertAuthResp(user_ID,certificate_auth_requ_packet,certificate_auth_resp_packet,access_auth_resp_packet))
	{
		printf("handle certificate auth resp packet failed!\n");
		return FALSE;
	}
	else
		printf("网络硬盘录像机解析证书认证响应分组结束！\n");

	return TRUE;
}

//5 ProcessWAPIProtocolAccessAuthResp
int fill_access_auth_resp_packet(int user_ID, access_auth_requ *access_auth_requ_packet, access_auth_resp *access_auth_resp_packet)
{

	//fill WAI packet head
	if(annotation == 2)
		printf("fill WAI packet head:\n");
	access_auth_resp_packet->wai_packet_head.version = 1;
	access_auth_resp_packet->wai_packet_head.type = 1;
	access_auth_resp_packet->wai_packet_head.subtype = ACCESS_AUTH_RESP;
	access_auth_resp_packet->wai_packet_head.reserved = 0;
	access_auth_resp_packet->wai_packet_head.packetnumber = 5;
	access_auth_resp_packet->wai_packet_head.fragmentnumber = 0;
	access_auth_resp_packet->wai_packet_head.identify = 0;

	//fill flag, same as access auth requ packet
	if(annotation == 2)
		printf("fill flag:\n");
	access_auth_resp_packet->flag = access_auth_requ_packet->flag;

	//fill auth identify, same as access auth requ packet
	if(annotation == 2)
		printf("fill auth identify:\n");
	memcpy((BYTE *)&access_auth_resp_packet->authidentify,(BYTE *)&access_auth_requ_packet->authidentify, sizeof(access_auth_resp_packet->authidentify));

	//fill asue rand number
	if(annotation == 2)
		printf("fill asue rand number:\n");
	memcpy((BYTE *)&access_auth_resp_packet->asuechallenge, (BYTE *)&access_auth_requ_packet->asuechallenge, sizeof(access_auth_resp_packet->aechallenge));

	//fill ae rand number
	if(annotation == 2)
		printf("fill ae rand number:\n");
	memcpy((BYTE *)&access_auth_resp_packet->aechallenge, (BYTE *)&access_auth_requ_packet->aechallenge, sizeof(access_auth_resp_packet->aechallenge));

	//fill ae cipher data
	if(annotation == 2)
		printf("fill ae cipher data, unfinished!!!\n");
	memset((BYTE *)&access_auth_resp_packet->aekeydata, 0, sizeof(access_auth_resp_packet->aekeydata));

	//fill certificate valid result
	if(annotation == 2)
		printf("fill certificate valid result complete.\n");
	//almost same type and content as certificate_auth_resp_packet, except addid segment
	//access_auth_resp_packet->cervalidresult is filled in "HandleProcessWAPIProtocolCertAuthResp" function called before
	//So skip this step.

	//fill asue access result, depend on "fill certificate valid result" step
	if(annotation == 2)
		printf("fill access result:\n");
	if(access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result.cerresult1 == 0)
	{
		access_auth_resp_packet->accessresult = 0; // by means of asu's asue cerresult1,ae set asue's access result(0-succeed,1-failed)
	}
	else
		access_auth_resp_packet->accessresult = 1;


	//fill packet length
	access_auth_resp_packet->wai_packet_head.length = sizeof(access_auth_resp);

	//fill ae signature
	if(annotation == 2)
		printf("fill ae signature:\n");
	//AE\u4f7f\u7528AE\u7684\u79c1\u94a5(userkey2.pem)\u6765\u751f\u6210AE\u7b7e\u540d
	EVP_PKEY * privKey;
	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	privKey = getprivkeyfromprivkeyfile(user_ID);
	if(privKey == NULL)
	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}

	if(!gen_sign((BYTE *)access_auth_resp_packet,(access_auth_resp_packet->wai_packet_head.length-sizeof(access_auth_resp_packet->aesign)),sign_value, &sign_len,privKey))
	{
		printf("generate signature failed.\n");
		return FALSE;
	}

	access_auth_resp_packet->aesign.sign.length = sign_len;
	memcpy(access_auth_resp_packet->aesign.sign.data,sign_value,sign_len);

	return TRUE;
}

int ProcessWAPIProtocolAccessAuthResp(int user_ID, access_auth_requ *access_auth_requ_packet, access_auth_resp *access_auth_resp_packet)
{
	if (!fill_access_auth_resp_packet(user_ID, access_auth_requ_packet, access_auth_resp_packet)){
		printf("fill access auth responce packet failed!\n");
	}
	else
		printf("网络硬盘录像机封装接入认证响应分组成功！\n");

	return TRUE;
}
/*
void runffmpeg(pid_t *ffmpegpid, int res)
{

}
*/
void ProcessWAPIProtocol(int new_asue_socket)
{
	int user_ID = 2;
	int asu_socket;
	int auth_result=FALSE;
	int run_ffmpeg_flag=FALSE;
	auth_active auth_active_packet;
	access_auth_requ access_auth_requ_packet;
	certificate_auth_requ certificate_auth_requ_packet;
	certificate_auth_resp certificate_auth_resp_packet;
	access_auth_resp access_auth_resp_packet;


	struct timeval tv;
	gettimeofday(&tv, NULL);
	long start = tv.tv_sec * 1000 + tv.tv_usec / 1000;

	//1) ProcessWAPIProtocolAuthActive
	if(annotation == 1)
		printf("\n*************\n 1) 认证激活分组(网络硬盘录像机->摄像机): \n");
	else if(annotation == 2)
		printf("\n***\n 1) ProcessWAPIProtocolAuthActive: \n");
	//stop for keyboard
	getchar();
	memset((BYTE *)&auth_active_packet, 0, sizeof(auth_active));
	ProcessWAPIProtocolAuthActive(user_ID, &auth_active_packet);
	send_to_peer(new_asue_socket, (BYTE *)&auth_active_packet, sizeof(auth_active_packet));

	//2) ProcessWAPIProtocolAccessAuthRequest
	if (annotation == 1)
		printf("\n*************\n 2) 接入认证请求分组(摄像机->网络硬盘录像机): \n");
	else if (annotation == 2)
		printf("\n***\n 2) HandleWAPIProtocolAccessAuthRequest: \n");
	memset((BYTE *)&access_auth_requ_packet, 0, sizeof(access_auth_requ));
	if (annotation == 2)
		printf("recv auth active packet from ASUE...\n");
	recv_from_peer(new_asue_socket, (BYTE *)&access_auth_requ_packet, sizeof(access_auth_requ_packet));

	//verify access_auth_requ_packet
	HandleWAPIProtocolAccessAuthRequest(user_ID, &auth_active_packet, &access_auth_requ_packet);

	//3) ProcessWAPIProtocolCertAuthRequest
	if (annotation == 1)
		printf("\n*************\n 网络硬盘录像机开始连接认证服务器: \n");
	else if (annotation == 2)
		printf("\n***\n Connect to asu.\n");
    asu_socket = connect_to_asu();
	if (annotation == 1)
		printf("\n*************\n 网络硬盘录像机连接认证服务器成功！ \n");

	if (annotation == 1)
		printf("\n*************\n 3) 证书认证请求分组(网络硬盘录像机->认证服务器): \n");
	else if (annotation == 2)
		printf("\n***\n 3) ProcessWAPIProtocolCertAuthRequest: \n");
	//stop for keyboard
	getchar();
	ProcessWAPIProtocolCertAuthRequest(user_ID, &access_auth_requ_packet,&certificate_auth_requ_packet);
	send_to_peer(asu_socket,(BYTE *)&certificate_auth_requ_packet, sizeof(certificate_auth_requ_packet));

	//4) ProcessWAPIProtocolCertAuthResp
	if (annotation == 1)
		printf("\n*************\n 4) 证书认证响应分组(认证服务器->网络硬盘录像机): \n");
	else if (annotation == 2)
	{
		printf("\n***\n 4) HandleWAPIProtocolCertAuthResp: \n");
		printf("recv Cert Auth Resp packet from ASU...\n");
	}

	recv_from_peer(asu_socket, (BYTE *)&certificate_auth_resp_packet, sizeof(certificate_auth_resp));

	//pid_t pid;
//	auth_result = ProcessWAPIProtocolCertAuthResp(user_ID,&certificate_auth_requ_packet, &certificate_auth_resp_packet,&access_auth_resp_packet);//该函数的主要工作是查看证书验证结果，并填充接入认证响应分组
	ProcessWAPIProtocolCertAuthResp(user_ID,&certificate_auth_requ_packet, &certificate_auth_resp_packet,&access_auth_resp_packet);
	//5) ProcessWAPIProtocolAccessAuthResp
	if (annotation == 1)
		printf("\n*************\n 5) 接入认证响应分组(网络硬盘录像机->摄像机): \n");
	else if (annotation == 2)
		printf("\n***\n 5) ProcessWAPIProtocolAccessAuthResp: \n");
	//stop for keyboard
	getchar();
	ProcessWAPIProtocolAccessAuthResp(user_ID, &access_auth_requ_packet, &access_auth_resp_packet);
	send_to_peer(new_asue_socket, (BYTE *)&access_auth_resp_packet, sizeof(access_auth_resp_packet));

	gettimeofday(&tv, NULL);
	long end = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	printf("三元对等身份认证过程运行时间为：%d毫秒\n", end - start);


	auth_result = access_auth_resp_packet.accessresult;
	if (!auth_result) // accessresult:0---接入认证成功，1---接入认证失败
		run_ffmpeg_flag = TRUE;
	else
		run_ffmpeg_flag = FALSE;


	//run ffmpeg
	if(run_ffmpeg_flag)        //run_ffmpeg_flag:0---不启动，1---启动
	{
		char abuf[INET_ADDRSTRLEN];
		struct sockaddr_in asueaddr;
		socklen_t length = sizeof(asueaddr);
		getpeername(new_asue_socket, (struct sockaddr*) &asueaddr, &length);
		inet_ntop(AF_INET, &asueaddr.sin_addr, abuf, INET_ADDRSTRLEN);
		printf("\n");
		char *ffmpeg_prog_dir="";//"/home/yaoyao/ffmpeg_sources/ffmpeg/";
		char ffmpeg_cmd[256];
		//snprintf(ffmpeg_cmd,255,"%sffmpeg -debug ts -i rtsp://%s:8557/PSIA/Streaming/channels/2?videoCodecType=H.264 -vcodec copy -an http://localhost:8090/feed1.ffm",ffmpeg_prog_dir, abuf);
		snprintf(ffmpeg_cmd,255,"%sffmpeg -debug ts -i rtsp://192.168.115.40:8557/PSIA/Streaming/channels/2?videoCodecType=H.264 -vcodec copy -an http://localhost:8090/feed1.ffm >/dev/null 2>/dev/null",ffmpeg_prog_dir);
		printf(ffmpeg_cmd);
		printf("\n");

		if((pid = fork()) < 0){
			perror("fork()");
		}else if(pid == 0){
			if(execl("/bin/sh", "sh", "-c", ffmpeg_cmd, (char *)0) < 0){
				perror("execl failed");
			}
			pid++;
		}else{}
	}
	else{
		//int status;
		printf("kill %d\n",pid);
		kill(pid,SIGABRT);
		wait(NULL);
		pid++;
		printf("kill %d\n",pid);
		kill(pid,SIGABRT);
		wait(NULL);
	}


}

void * serve_each_asue(void * new_server_socket_to_client)
{
	int new_asue_socket = (int)new_server_socket_to_client;

	//printf("start serve asue...\n");

	printf("网络硬盘录像机开启“三元对等”身份认证过程!!!\n");
	ProcessWAPIProtocol(new_asue_socket);

	close(new_asue_socket);

	printf("pthread exit\n");
	pthread_exit(NULL);

}


void listen_from_asue()
{

	int threadnum = 1;
	init_user_table();
	pthread_mutex_init(&user_table_mutex, NULL);
	int server_socket = init_server_socket();

	pthread_t child_thread;
	pthread_attr_t child_thread_attr;
	pthread_attr_init(&child_thread_attr);
	pthread_attr_setdetachstate(&child_thread_attr, PTHREAD_CREATE_DETACHED);

    if (pthread_attr_init(&child_thread_attr) != 0)
    	perror("pthread_attr_init");

	pthread_attr_setdetachstate(&child_thread_attr,PTHREAD_CREATE_DETACHED);

	//  accept connection from each ASUE
	while (1)
	{
		struct sockaddr_in client_addr;
		socklen_t length = sizeof(client_addr);

		int new_asue_socket = accept(server_socket, (struct sockaddr*) &client_addr, &length);
		if (new_asue_socket < 0){
			perror("AE Accept Failed\n");
			//break;
		}

		//printf("going to create thread %d ...\n", threadnum);
		if (pthread_create(&child_thread, &child_thread_attr, serve_each_asue,(void *) new_asue_socket) < 0)
		//if (pthread_create(&child_thread, NULL, serve_each_asue,(void *) new_asue_socket) < 0)
			perror("pthread_create Failed");
		//serve_each_asue((void *)new_asue_socket);

		threadnum++;
	}
}



int main(int argc, char **argv)
{
	OpenSSL_add_all_algorithms();

    if (argc != 2)
    {
		printf("Usage: %s ASU_ip_addr\n", argv[0]);
		exit(1);
	}

	ASU_ip_addr = argv[1];

	//printf("listen from asue.\n");
	printf("网络硬盘录像机监听摄像机的接入!!!\n");
	listen_from_asue();

	return 0;

}

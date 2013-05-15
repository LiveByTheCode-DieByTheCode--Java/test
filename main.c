/** 
 * Michael Zaruba
 * 110468851
 *
 * Partner:
 * Daniel Freundel
 *
 * Used code from CBitCoin:
 * https://github.com/cmsc417/cbitcoin/blob/master/examples/pingpong.c
 */
 
 /*
  *   TODOs!!
  * For detecting dropped nodes: have data structure containing each address,
  *		mapped to an integer, increase this integer every second.
  *		Once it reaches 60, we know we have lost them
  *   Or do we use the fields within CBPeer?
  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <CBPeer.h>
#include <CBMessage.h>
#include <CBVersion.h>
#include <CBNetworkAddress.h>
 
//Start node
#define KALE "kale.umd.edu"
//Ports
#define MY_PORT 7777
#define UMDNET_PORT 28333
#define TESTNET_PORT 18333
#define MAINNET_PORT 8333
//Netmagic codes
#define UMDNET_NETMAGIC 0xd0b4bef9	//0xf9beb4d0
#define TESTNET_NETMAGIC 0x0b110907	//0x0709110B
#define MAINNET_NETMAGIC 0xd9b4bef9	//0xf9beb4d9
//Header offsets
#define CB_MESSAGE_HEADER_NETWORK_ID 0
#define CB_MESSAGE_HEADER_TYPE 4
#define CB_MESSAGE_HEADER_LENGTH 16
#define CB_MESSAGE_HEADER_CHECKSUM 20
//Payload offsets
#define VERSION_OFF 0
#define SERVICES_OFF 4
#define TIMESTAMP_OFF 12
#define ADDR_RECV_OFF 20
#define ADDR_FROM_OFF 46
#define NONCE_OFF 72
#define USER_AGENT_OFF 80
//Constant Strings
#define VERSION "version\0\0\0\0\0"
#define VERACK "verack\0\0\0\0\0\0"
#define PING "ping\0\0\0\0\0\0\0\0"
#define PONG "pong\0\0\0\0\0\0\0\0"
#define INV "inv\0\0\0\0\0\0\0\0\0"
#define GETDATA "getdata\0\0\0\0\0"
#define NOTFOUND "notfound\0\0\0\0"
#define GETBLOCKS "getblocks\0\0\0"
#define ADDR "addr\0\0\0\0\0\0\0\0"
#define GETADDR "getaddr\0\0\0\0\0"
#define BLOCK "block\0\0\0\0\0\0\0"
#define HEADERS "headers\0\0\0\0\0"
#define CHECKORDER "checkorder\0\0"
#define SUBMITORDER "submitorder\0"
#define REPLY "reply\0\0\0\0\0\0\0"
#define ALERT "alert\0\0\0\0\0\0\0"
#define TX "tx\0\0\0\0\0\0\0\0\0\0"
#define USER_AGENT "cmsc417versiona"
//Macros
#define NETMAGIC network == 3 ? UMDNET_NETMAGIC : (network == 2 ? TESTNET_NETMAGIC : MAINNET_NETMAGIC)
#define NETPORT network == 3 ? UMDNET_PORT : (network == 2 ? TESTNET_PORT : MAINNET_PORT)
//Limits
#define MAX_CONNS 255	//Max connections to keep open
#define MAX_PENDING 10	//Max pending connections for server socket to listen
#define BUFFER_SIZE 4096
#define TIMEOUT 1000	//Should be low enough to not delay user input

/*
 * Function prototypes
 */
void print_hex(CBByteArray);
void handle_command();
void send_packet(int, char *, char *);
int connect_to_kale();
void send_version_msg();
int recv_kale_version();
int recv_kale_verack();
int recv_packet(int);
void exit_program(int);

/*
 * Global Variables
 */
//1 = UMDNET, 2 = TESTNET, 3 = MAINNET
//Defaults to UMDNET
int network = 1;

//Array of connections(socket descriptors)
struct pollfd descriptors[MAX_CONNS]; 

//Array of CBPeers, for now
//peers[index] returns CBPeer with socket descriptor descriptors[index] 
//Index 0 and 1 should never be used, 2 is only for kale connection
CBPeer peers[MAX_CONNS];
int curPeers = 2;
CBAssociativeArray chain;


/* 
 * Begin actual code
 */
 
/**
 * Prints the hex representation of a CBByteArray
 * This method was copied entirely from:
 * https://github.com/cmsc417/cbitcoin/blob/master/examples/pingpong.c
 */
void print_hex(CBByteArray *str) {
    int i = 0;
    uint8_t *ptr = str->sharedData->data;
    for (; i < str->length; i++) printf("%02x", ptr[str->offset + i]);
    printf("\n");
}


/**
 * Reads a command from stdin and calls
 * the appropriate method to handle it
 * Supported commands are:
 * help - Displays list of commands
 * quit - Exits the program safely
 * ping - Sends a ping message to all connections
 * peers - Displays a list of all the peers connected to
 * audit - Shows how many coins the user has
 * buy - Sends a specified number of bitcoins to the specified address
 */
void handle_command(){
	//Read a line
	char * line = 0;
	unsigned int len = 0;
	getline(&line, &len, stdin);
	char cmd[255] = {0},
		arg1[255] = {0},
		arg2[255] = {0};
	sscanf(line, "%s %s %s", cmd, arg1, arg1);
	
	if (!strcmp(cmd, "help")){
		printf("Commands: [cmd] [argument] ...\n");
		printf("\taudit\t- Displays how many coins you have\n");
		printf("\tbuy [coins] [public key]\t- Gives [coins] coins to use with account [public key]\n");
		printf("\thelp\t- Shows this message\n");
		printf("\tpeers\t- Displays a list of currently connected peers");
		printf("\tping\t- Sends a ping message to all connected clients\n");
		printf("\tquit\t- Safely exits the program\n");
	} else if (!strcmp(cmd, "quit")){
		exit_program(0);
	} else if (!strcmp(cmd, "ping")){
		//Ping all peers
		int i;
		printf("Sending ping to all connected peers\n");
		for (i = 2; i < curPeers; i++){
			if (peers[i]){
				send_packet(i, PING, "");
			}
		}
	} else if (!strcmp(cmd, "audit")){
		//Call audit
	} else if (!strcmp(cmd, "buy")){
		//Call buy
	} else if (!strcmp(cmd, "peers")){
		int i;
		printf("Sending ping to all connected peers\n");
		for (i = 2; i < curPeers; i++){
			if (peers[i]){
				printf ("Peer Number : %d\n", (i-2));
				printf ("Port : %lu\n", peers[i]->socketID);
			}
		}
	} else {
		printf("Error: Command not recognized.\nType 'help' for a list of commands\n");
	}
	return;
}


/**
 * Constructs a header of the specified type
 * (and payload, depending on message type)
 * and sends to the specified peer
 * Parameters:
 *  index - Index in peers[] of CBPeer to send to
 * 	cmd - Non-null-terminated string of command type, eg. 'version'
 * 	payload - The actual message to be sent (MUST be 
 * 		properly formatted and null-terminated.
 * 		No payload is needed for a VERSION msg)
 */
void send_packet(int index, char * cmd, char * payload){
	char header[24] = {0};
	int msg_length = 0;
	CBMessage * message;
	
	char * command = malloc(12 * sizeof(char));
	if (command == NULL){
		perror("ERROR: malloc() failed. Exiting");
		exit_program(1);
	}
	
	//Set command to all null
	memset(command, '\0', 12 * sizeof(char));
	
	//Ensure cmd not too long
	if (strlen(cmd) > 12){
		perror("Invalid argument 'cmd'; greater than 12 bytes");
		exit_program(0);
	}
	
	//Copy input string onto NULL-terminated string of length 12
	strcpy(command, cmd);
	
	//Construct the header section, except for length and checksum
	memcpy(header + CB_MESSAGE_HEADER_TYPE, command, 12);
	CBInt32ToArray(header, CB_MESSAGE_HEADER_NETWORK_ID, NETMAGIC);
	
	//Different steps for different packet types
	if (!strcmp(command, VERSION, 12)){
		//Version packet
		CBByteArray * ip = CBNewByteArrayWithDataCopy((uint_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}, 16);
		CBByteArray * ua = CBNewByteArrayFromString(USER_AGENT, '\00');
		CBNetworkAddress *srcAddr = CBNewNetworkAddress(0, ip, 0, CB_SERVICE_FULL_BLOCKS, false);
		int32_t vers = 70001;
		int nonce = rand();
		CBVersion * version = CBNewVersion(vers, CB_SERVICE_FULL_BLOCKS, time(NULL), peers[inedx].base, srcAddr, nonce, ua, 0);
		message = CBGetMessage(version);
		msg_length = CBVersionCalculateLength(version);
		message->bytes = CBNewByteArrayOfSize(len);
		msg_length = CBVersionSerialize(version, false);
		if (!msg_length){
			perror("Failed to send version - Serialization Failed");
			//Free structures
			CBFreeByteArray(ip);
			CBFreeByteArray(ua);
			CBFreeNetworkAddress(srcAddr);
			CBFreeVersion(version);
			exit_program(1);
		}
	} 
	else if (!strcmp(command, VERACK, 12) || !strcmp(command, GETADDR, 12) || !strcmp(command, PING, 12)){
		//Packet with no payload
		msg_length = 0;
		CBByteArray * bytes = CBNewByteArrayFromString("", '\00');
		message = CBNewMessageByObject();
		if (!CBInitMessageByObject(message, bytes)){
			perror("Failed to init message");
			CBFreeByteArray(bytes);
		}
	}
	else if (!strcmp(command, ADDR, 12)){
		//ADDR Packet
		CBAddressBroadcast *addr = CBNewAddressBroadcast(true);
		int i = 0; int max = 30;
		if (max > curPeers)max = curPeers;
		
		for (i; i < max; i++){
			CPPosition *tmp = 
			CBAddressBroadcastAddNetworkAddress (addr, tmp);
		}
		
		CBMessage *message = CBGetMessage(addr);
		msg_length = CBAddressBroadcastCalculateLength(addr);
		message->bytes = CBNewByteArrayOfSize(msg_length);
		msg_length = CBAddressBroadcastSerialize(addr, true);
		if (!msg_length){
			perror("Failed to send addr - Serialization Failed");
			CBFreeAddressBroadcast(addr);
		}
	}
	else if (!strcmp(command, GETBLOCKS, 12)){
		CBChainDescriptor chainDescriptor = CBNewChainDescriptor(void);
		CBPosition *cur; CBAssociativeArrayGetLast(blockArr, cur);
		CBPosition *gen; CBAssociativeArrayGetFirst(blockArr, gen);
		CBByteArray *stopAtHash = new CBByteArrayFromString ("", "\00");
		int i = 0; int step = 1; int y = 0;
		
		CBChainDescriptorAddHash(chainDescriptor, ((CBBlock *)cur->node->elements[1])->hash);
		while (cur != gen){
			for (y = 0; y < step; y++){
				cur = cur->node->parent;
			}
			if (cur == NULL) break;
			if (i >= 10) step *=2;
			CBChainDescriptorAddHash(chainDescriptor, ((CBBlock*)cur->node->elements[1])->hash);
		}
		CBChainDescriptorAddHash(chainDescriptor, ((CBBlock *)cur->node->elements[1])->hash);
		CBGetBlocks * getBlocks = CBNewGetBlocks(VERSION, chainDescriptor, stopAtHash);
		
		CBMessage *message = CBGetMessage(getblocks);
		msg_length = CBInventoryBroadcastCalculateLength(addr);
		message->bytes = CBNewByteArrayOfSize(msg_length);
		msg_length = CBInventoryBroadcastSerialize(addr, true);
		if (!msg_length){
			perror("Failed to send addr - Serialization Failed");
			CBFreeChainDescriptor(chainDescriptor);
			CBFreeByteArray (stopAtHash);
			CBFreeGetBlocks(getBlocks);
		}
	}
	else if (!strcmp(command, INV, 12)){
		CBInventoryBroadcast * inv = CBNewInventoryBroadcast(void);
	
		CBGetBlocks * msg = CBNewGetBlocksFromData(bytes);
		CBByteArray * lastHash = msg->chainDescriptor->stopAtHash;
		CBByteArray * firstHash = msg->chainDescriptor->hashes[0];
		CBFindResult *res = CBAssociativeArrayFind(blockArr, firstHash);
		CBPosition *st = res->position; int i = 0; int y = 0;
		
		while (CBAssociativeArrayIterate(blockArr, st)){
			if ((CBBlock *)st->node->element[1]->hash == lastHash){y = -1; break;}
			CBInventoryItem *tmp = CBNewInventoryItem(CB_INVENTORY_ITEM_BLOCK, ((block *)st->node->element[1])->hash);
			inv->items[i++] = tmp;
			CBFreeInventoryItem(tmp);
		}
	
		if (y != -1){
			for (i = 0; i < txCt; i++){
				CBInventoryItem * tmp = CBNewInventoryItem(CB_INVENTORY_ITEM_TRANSACTION, t->hash)
				inv->items[i++] = tmp;
			}
		}
		inv->itemNum = --i;
		CBMessage *message = CBGetMessage(inv);
		msg_length = CBInventoryBroadcastCalculateLength(inv);
		message->bytes = CBNewByteArrayOfSize(msg_length);
		msg_length = CBInventoryBroadcastSerialize(inv, true);
		if (!msg_length){
			perror("Failed to send addr - Serialization Failed");
			CBFreeInventoryBroadcast(inv);
			CBFreeGetBlocks(msg);
		}
	}
	else if (!strcmp(command, GETDATA, 12)){
		CBInventoryBroadcast * getdata = CBNewInventoryBroadcast(void);
		CBInventoryBroadcast * inv = CBNewInventoryBroadcastFromData(bytes);
		int i = 0;
		for (i = 0; i < inv->itemNum; i++){
			CBFindResult * res = CBAssociativeArrayFind(blockArr, inv->items[i]);
			if (!res->found)items[getdata->itemNum++] = inv->items[i];
		}
		CBMessage *message = CBGetMessage(getdata);
		msg_length = CBInventoryBroadcastCalculateLength(getdata);
		message->bytes = CBNewByteArrayOfSize(msg_length);
		msg_length = CBInventoryBroadcastSerialize(getdata, true);
		if (!msg_length){
			perror("Failed to send addr - Serialization Failed");
			CBFreeInventoryBroadcast(getdata);
			CBFreeInventoryBroadcast(inv);
		}
	}
	else if (!strcmp(command, BLOCK, 12)){
		CBFindResult * res = CBAssociativeArrayFind(blockArr, bytes);
		if (res->found){CBBlock block * = (CBBlock *)res->position->node->elements[1]}
		CBMessage *message = CBGetMessage(block);
		msg_length = CBBlockCalculateLength(block);
		message->bytes = CBNewByteArrayOfSize(msg_length);
		len = CBBlockSerialize(block, false);
		if (!msg_length){
			perror("Failed To Send Block");
		}
		
	}
	else if (!strcmp(command,  TX, 12)){
		CBFindResult * res = CBAssociativeArrayFind(txArr, bytes);
		if (res->found){CBTransaction tx * = (CBTransaction *)res->position->node->elements[1]};
		msg_length = CBTransactionCalculateLength(tx);
		message->bytes = CBNewByteArrayOfSize(msg_length);
		len = CBTransactionSerialize(block, false);
		if (msg_length){
			perror ("Failed To Send Transaction");
		}
	}
	else{
		CBByteArray * bytes = CBNewByteArrayFromString(payload, '\00');
		message = CBNewMessageByObject();
		if (!CBInitMessageByObject(message, bytes)){
			perror("Failed to init message");
		}
	}
	//Compute Checksum
	if (message->bytes){
		//Create checksum
		uint8_t hash[32], hash2[32];
		CBSha256(CBByteArrayGetData(message->bytes), message->bytes->length, hash);
		CBSha256(hash, 32, hash2);
		for (int i = 0; i < 4; i++){
			message->checksum[i] = hash2[i];
		}
	}
	//Put last two fields into header
	CBInt32ToArray(header, CB_MESSAGE_HEADER_LENGTH, message->bytes->length);
	memcpy(header + CB_MESSAGE_HEADER_CHECKSUM, message->checksum, 4);
	
	//Send header
	send(descriptors[2].fd, header, 24, 0);
	
	//Send message
	send(descriptors[2].fd, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length);
	printf("Message length: %d\n", message->bytes->length);
	printf("Checksum: %x\n", *((uint32_t *) message->checksum));
	print_hex(message->bytes);
	
	//Free structures
	if (!strcmp(command, VERSION, 12)){
		CBFreeByteArray(ip);
		CBFreeByteArray(ua);
		CBFreeNetworkAddress(srcAddr);
		CBFreeVersion(version);
	} 
	else if (!strcmp(command, VERACK, 12) || !strcmp(command, GETADDR, 12) || !strcmp(command, PING, 12)){
		CBFreeByteArray(bytes);
	}
	else if (!strcmp(command, ADDR, 12)){
		CBFreeAddressBroadcast(addr);
	}
	else if (!strcmp(command, GETBLOCKS, 12)){
		CBFreeChainDescriptor(chainDescriptor);
		CBFreeByteArray (stopAtHash);
		CBFreeGetBlocks(getBlocks);
	}
	else if (!strcmp(command, INV, 12)){
		CBFreeInventoryBroadcast(inv);
		CBFreeGetBlocks(msg);
	}
	else if (!strcmp(command, GETDATA, 12)){
		CBFreeInventoryBroadcast(getdata);
		CBFreeInventoryBroadcast(inv);
	}
}
	return;
}


/**
 * Initializes a connection to the kale.cs.umd.edu server
 * The 'network' global variable should be a value 1-3 specifying which
 * defined network (port) to use:
 * 3 - mainnet - 28333
 * 2 - testnet - 18333
 * 1 - umdnet - 8333
 * The global variable 'descriptors' holds the socket for this connection
 * always at index 2 (descriptors[2].fd)
 * Likewise, the CBPeer structure for this connection is always at peers[2]
 * The socket is set to a negative value if no connection could be made
 */
void connect_to_kale(){
	printf("Attempting to connect to kale...\n");
	
	//Create a CBPeer for kale
	CBByteArray * ip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 128, 8, 126, 25}, 16);
	CBNetworkAddress * peerAddr = CBNewNetworkAddress(0, ip, NET_PORT, CB_SERVICE_FULL_BLOCKS, false);
	peers[2] = CBNewPeerByTakingNetworkAddress(peerAddr);
	if (!CBInitPeerByTakingNetworkAddress(peers[2])){
		perror("ERROR: Failed to init kale's CBPeer");
	}
	
	//Now create the socket
	struct sockaddr_in addr;
	int addr_len = sizeof(addr);
	if ((descriptors[2].fd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
		perror("Could not connect - Socket Error");
		return -1;
	}
	memset(&addr, sizeof(addr), 0);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(NET_PORT);
	addr.sin_addr.s_addr = (((((25 << 8) | 126) << 8) | 8) << 8) | 128;
	if (connect(descriptors[2].fd, (struct sockaddr *)&addr, sizeof(addr)) < 0){
		perror("Could not connect - Connect Error");
		return;
	}
	printf("Connection Successful!\n");
	return;
}


/**
 * Sends the version message to kale
 * The file descriptor for the socket connection
 * to Kale is always descriptors[2].fd
 */
void send_version_msg(){
	CBByteArray * ip = CBNewByteArrayWithDataCopy((uint_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}, 16);
	CBByteArray * ua = CBNewByteArrayFromString(USER_AGENT/*"cmsc417versiona"*/, '\00');
	CBNetworkAddress *srcAddr = CBNewNetworkAddress(0, ip, 0, CB_SERVICE_FULL_BLOCKS, false);
	int32_t vers = 70001;
	int nonce = rand();
	CBVersion * version = CBNewVersion(vers, CB_SERVICE_FULL_BLOCKS, time(NULL), peers[2]base, srcAddr, nonce, ua, 0);
	CBMessage * message = CBGetMessage(version);
	char header[24];
	memcpy(header + CB_MESSAGE_HEADER_TYPE, VERSION/*"version\0\0\0\0\0"*/, 12);
	
	//Compute length, serialized, checksum
	message->bytes = CBNewByteArrayOfSize(CBVersionCalculateLength(version));
	if (CBVersionSerialise(version, false) == 0){
		perror("Failed to send version - Serialization Failed");
		//Free structures
		CBFreeByteArray(ip);
		CBFreeByteArray(ua);
		CBFreeNetworkAddress(srcAddr);
		CBFreeVersion(version);
		exit_program(1);
	}
	if (message->bytes){
		//Create checksum
		uint8_t hash[32], hash2[32];
		CBSha256(CBByteArrayGetData(message->bytes), message->bytes->length, hash);
		CBSha256(hash, 32, hash2);
		for (int i = 0; i < 4; i++){
			message->checksum[i] = hash2[i];
		}
	}
	CBInt32ToArray(header, CB_MESSAGE_HEADER_NETWORK_ID, NETMAGIC);
	CBInt32ToArray(header, CB_MESSAGE_HEADER_LENGTH, message->bytes->length);
	memcpy(header + CB_MESSAGE_HEADER_CHECKSUM, message->checksum, 4);
	
	//Send header
	send(descriptors[2].fd, header, 24, 0);
	
	//Send message
	send(descriptors[2].fd, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length);
	printf("Message length: %d\n", message->bytes->length);
	printf("Checksum: %x\n", *((uint32_t *) message->checksum));
	print_hex(message->bytes);
	peers[2].versionSent = true;	
	
	//Free structures
	CBFreeByteArray(ip);
	CBFreeByteArray(ua);
	CBFreeNetworkAddress(srcAddr);
	CBFreeVersion(version);
	return;
}


/**
 * Gets kale's response version message
 * Returns 1 on success, -1 on failure
 */
int recv_kale_version(){
	CBByteArray bytes;
	//Read header
	char header[24];
	recv(descriptors[2].fd, header, 24, 0);
	printf("Received a header in response\n");
	if (*((uint32_t *)(header + CB_MESSAGE_HEADER_NETWORK_ID)) != NETMAGIC) {
        printf("The header does not contain the correct Netmagic\n");
        return -1;
    }
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, VERSION, 12)){
		printf("Received VERSION from kale\n");
		//Receive payload and check version is correct
		unsigned int length = *((uint32_t *)(header + CB_MESSAGE_HEADER_LENGTH));
		char * payload = (char *)malloc(length * sizeof(char));
		socklen_t nread = 0;
		if (length){
			nread = recv(sock, payload, length, 0);
		}
		if (nread != length){
			printf("ERROR: Incomplete read: %u out of %u bytes\n", nread, length);
			return -1;
		} else {
			printf("Read payload of %u bytes\n", nread);
			bytes = CBNewByteArrayFromString(payload);
			int ua_end = length - 5; //4 for start_height, 1 for relay
			int ua_length = ua_end - USER_AGENT_OFF;
			char agent[length];
			memset(agent, '\0', length * sizeof(char));
			strcpy(agent, payload + USER_AGENT_OFF, ua_length);
			//check user agent matches
			if (!strncmp(agent, USER_AGENT)){
				perror("User agent does not match. Version refused.");
				return -1;
			}
			return 1;
		}
	}
	return -1;
}


/**
 * Gets the verack from kale
 * Returns 1 if successful, -1 otherwise
 */
int recv_kale_verack(){
	// Read header
    char header[24];
    recv(descriptors[2].fd, header, 24, 0);
    printf("Received a header\n");
    if (*((uint32_t *)(header + CB_MESSAGE_HEADER_NETWORK_ID)) != NETMAGIC) {
        printf("The header does not contain the correct Netmagic\n");
        return -1;
    }
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, VERACK, 12)) {
        printf("Received VERACK from kale\n");
		return 1;
    }
	return -1;
}


/**
 * Generic method for receving a header 
 * Takes as a parameter the index in 'descriptors' array
 * of the socket descriptor to listen to:
 *  0 - Stdin, but we shouldn't get this here
 * 	1 - Listener for incoming connections
 *  2 - Kale connection
 *  3+ - Other open connections
 * This index also doubles as the index in the 'peers'
 * array to the corresponding CBPeer for this connection
 * Forwards to the appropriate method based on the header type
 * 
 * Ensures NETMAGIC matches before forwarding
 * As of now does not check checksum
 */
int recv_packet(int index){
	CBByteArray bytes;
	char header[24];
	recv(descriptors[index], header, 24, 0);
	printf("Received Header\n");
	if (*((uint32_t *)(header + CB_MESSAGE_HEADER_NETWORK_ID)) != NETMAGIC){
		printf("NETMAGIC does not match\n");
		return -1;		
	}

	//Read payload
	unsigned int length = *((uint32_t *)(header + CB_MESSAGE_HEADER_LENGTH));
	char * payload = (char *)malloc(length * sizeof(char));
	socklen_t nread = 0;
	if (length){
		nread = recv(descriptors[index], payload, length, 0);
	}
	if (nread != length){
		printf("ERROR: Incomplete read: %u out of %u bytes\n", nread, length);
	} else {
		printf("Read payload of %u bytes\n", nread);
	}
	
	//Byte array of entire payload
	bytes = CBNewByteArrayFromString(payload);
	
	//Dispatch
	//The first argument is the index of the CBPeer in array 'peers',
	// which is also the index of the socket descriptor in the 'descriptors' array
	//The second argument is the entire payload, expressed as a CBByteArray
	//TODO:Uncomment the method calls
	if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, VERSION, 12)){
		printf("Received a VERSION header\n");
		send_packet(index, VERSION, bytes);
		send_packet(index, VERACK, bytes);
	} else if (!strncmp(header + CB_MESSAGE_HEADER_TYPE, VERACK, 12)){
		printf("Received a VERACK header\n");
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, PING, 12)){
		printf("Received a PING header\n");
		send_packet(index, PONG, bytes);
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, PONG, 12)){
		printf("Received a PONG header\n");
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, INV, 12)){
		printf("Received an INV header\n");
		send_packet(index, GETDATA, bytes);
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, GETDATA, 12)){
		printf("Received a GETDATA header\n");
		int i = 0; CBInventoryBroadcast * get = CBNewInventoryBroadcastFromData(bytes);
		for (i; i < tmp->itemNum; i++){
			CBInventoryItem * inv = get->items[i];
			if (get->items[i]->type == CB_INVENTORY_ITEM_TRANSACTION){
				send_packet(index, TX, get->items[i]->hash);
			}
			else if (get->items[i]->type == CB_INVENTORY_ITEM_BLOCK){
				send_packet(index, BLOCK, get->items[i]->hash);
			}
			else{
				perror ("Invalid Transaction Item");
			}		
		}
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, NOTFOUND, 12)){
		printf("Received a NOTFOUND header\n");
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, GETBLOCKS, 12)){
		printf("Received a GETBLOCKS header\n");
		send_packet(index, INV, bytes);
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, ADDR, 12)){
		CBBroadcastAddress * tmp; int i = 0;
		CBInitAddressBroadcastFromData(tmp, true, bytes);
		for (i = 0; i < tmp-> addrNum; i++){
			//Process Address
		}
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, GETADDR, 12)){
		printf("Received a GETADDR header\n");
		send_packet(index, GETADDR, bytes);
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, BLOCK, 12)){
		printf("Received a BLOCK header\n");
		CBBlock * tmp = CBNewBlockFromData(bytes);
		processBlock(itm);
		for (i = 2; i < curPeers; i++){
			send_packet(i, INV, bytes);
		}
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, HEADERS, 12)){
		printf("Received a HEADERS header\n");
		//handle_headers(index, bytes);
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, CHECKORDER, 12)){
		printf("Received a CHECKORDER header\n");
		//handle_checkorder(index, bytes);
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, SUBMITORDER, 12)){
		printf("Received a SUBMITORDER header\n");
		//handle_submitorder(index, bytes);
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, REPLY, 12)){
		printf("Received a REPLY header\n");
		//handle_reply(index, bytes);
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, ALERT, 12)){
		printf("Received an ALERT header\n");
		//handle_alert(index, bytes);
	} else if (!strcmp(header + CB_MESSAGE_HEADER_TYPE, TRANSACTION, 12)) {
		printf("Received a TRANSACTION header\n");
		CBTransaction *tmp = CBNewBlockFromData(bytes);
		CBAssociativeArrayInsert(txArr, tmp, txCt++, NULL);
		for (i = 2; i < curPeers; i++){
			send_packet(i, INV, bytes);
		}
	} else {
		printf("ERROR: Received an invalid header\n");
	}
	
	//TODO:Should this be here or in helper methods?
	free(payload);
}
 
 
/**
 * Exits the program gracefully
 * Closes all opened socket connections
 * Attempts to free all data structures
 */
void exit_program(int exit_code){
	int i = 0;
	//First close all connections
	//Skip index 0 because that is stdin
	for (i = 1; i < MAX_CONNS; i++){
		if (descriptors[i].fd != 1){
			close(descriptors[i]);
		}
	}
	//Now free CBPeers
	for (i = 1; i < MAX_CONNS; i++){
		if (peers[i]){
			//Not sure if this is correct
			CBFreeObject(peers[i]);
		}
	}
	//TODO: Free anything else?
	
	//Finally exit with the given exit code
	exit(exit_code);
}


/**
 * Main
 * First set up file descriptors:
 *	0 - stdin
 *	1 - listen for new connections
 *	2 - connection to kale
 *	3+ - open connections to others
 * Create the socket which will listen for incoming 
 *  connections and bind it
 * Loop until the "quit" command is executed
 */
int main(int argc, char * argv[]) {
	printf("BitCoin client - Daniel Freundel and Michael Zaruba");

	//The first descriptor will be for stdin
	descriptors[0].fd = fileno(stdin);
	
	//The rest of the descriptors will be set to -1 for now
	int a;
	for (a = 1; a < MAX_CONNS; a++){
		descriptors[a].fd = -1;
	}
	
	//Initialize CBPeers array
	peers = {0};
	
	//Create and bind a local socket for listening for incoming connections
	int server_sock;
	if ((server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
		perror("Failed to create server socket");
		exit_program(1);
	}
	struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(MY_PORT);
	//Bind to local address
    if (bind(server_sock, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0){
      perror("Failed to bind server socket");
      exit_program(1);
    }
    //Mark socket for listening
    if (listen(server_sock, MAX_PENDING) < 0){
      printf("Listen() for socket failed\n");
      exit_program(1);
    }
	
	//Initialize the connection to kale
	connect_to_kale();
	//Ensure connection worked
	if (descriptors[2].fd < 0){
		perror("ERROR: Could not connect to kale.");
		exit_program(1);
	}
	
	//Send a version message
	send_version_msg();
	//Make sure receive version message back from kale
	if (recv_kale_version() != 1){
		exit_program(1);
	}
	//Make sure receive verack message from kale
	if (recv_kale_verack() != 1){
		exit_program(1);
	}
	
	//Query kale getaddr to learn of new peers
	send_packet(2, GETADDR, "");
	
	int x = 0, i = 0;
	int changed = 0;
	
	// TODO:
	// MAKE THIS INFINITE!
	while (x < 32000){
		//descriptors[0].fd = fileno(stdin);
		//descriptors[0].events = POLLIN;
		//Is this for loop necessary inside while?
		//Should it be moved outside?
		for (i = 0; i < MAX_CONNS; i++){
			descriptors[i].events = POLLIN;
		}
		
		changed = poll(descriptors, MAX_CONNS, TIMEOUT);
		if (changed < 0){
			perror("An error occurred in poll()");
			exit_program(1);
		}else {
			//Loop through descriptors to find events
			for (i = 0; i < MAX_CONNS; i++){
				if (descriptors[i].revents & POLLIN){
					//Have an event; see what it is
					if (i == 0){ 
						//Command was entered into stdin
						handle_command();
					} else if (i == 1) {
						//Incoming request for a new connection
						//from a node we are not yet peers with
						
						/* NOT YET IMPLEMENTED
						printf("Incoming connection\n");
						//Find out if we have space
						int flag = -1;
						for (int j = 3; j < MAX_CONNS; j++){
							if (descriptor[j].fd < 0){
								flag = j;
								break;
							}
						}
						if (flag < 3){ //Invalid value; did not find empty space
							perror("ERROR: Could not accept request - MAX_CONNS reached");
						} else {
							struct sockaddr_storage client;
							socklen_t client_addr_length = sizeof(client);						
							int new_sock = accept(descriptors[1].fd, (struct sockaddr *) &client, &client_addr_length);
							if (new_sock < 0){
								perror("Failed to accept incoming connection\n");
							}
							
							//Make sure we get version before adding it
							
						}
						*/
					} else {
						//Send index of file descriptor to the method
						//which handles packets
						recv_packet(i);
					}			
				} else if (descriptors[i].revents & (POLLERR | POLLHUP | POLLNVAL)){
					//An error occurred
					//Should probably close this connection
					close(descriptors[i].fd);
					CBFreeObject(peers[i]);
					peers[i] = NULL;
				}
			}
		}
		
		//Send pings
		for (i = 2; i < curPeers; i++){
			send_packet(i, PING, "");
		}
		
	}//end while
	return 0;
}




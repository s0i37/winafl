#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib") //Winsock Library
#pragma comment(lib, "wininet")

namespace windows {
    #include <Windows.h>
    #include <winsock.h>
    HANDLE pipe_sync;
    OVERLAPPED pipe_overlapped;
}


enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};

short is_init = 0;


namespace windows {
	char read_from_pipe(unsigned int timeout) /* ! timeout needed */
    {
        DWORD num_read;
        char result;

        if(ReadFile(pipe_sync, &result, 1, &num_read, &pipe_overlapped) || GetLastError() == ERROR_IO_PENDING)
        {
            if(WaitForSingleObject(pipe_overlapped.hEvent, timeout) != WAIT_OBJECT_0)
            {
                CancelIo(pipe_sync);
                WaitForSingleObject(pipe_overlapped.hEvent, INFINITE);
                result = 0;
            }
        }
        return result;
    }
	void setup_pipe()
    {
        /* create new pipe */
        pipe_sync = CreateNamedPipe(
            "\\\\.\\pipe\\afl_sync",   // pipe name
            PIPE_ACCESS_DUPLEX |              // read/write access
            FILE_FLAG_OVERLAPPED,             // overlapped mode
            PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
            1,                        // max. instances
            512,                      // output buffer size
            512,                      // input buffer size
            0,                        // client time-out
            NULL);

        memset(&pipe_overlapped, 0, sizeof(pipe_overlapped));
        pipe_overlapped.hEvent = CreateEvent(
            NULL,           // default security attribute
            TRUE,           // manual-reset event
            TRUE,           // initial state = signaled
            NULL);          // unnamed event object

        printf("[*] waiting an opening pipe\n");
        ConnectNamedPipe(pipe_sync, NULL);
        printf("[+] pipe has opened\n");
        Sleep(1000);
        is_init = 1;
    }

    static void send_data_tcp(void *data, long size, unsigned int fuzz_iterations)
    {
    	static struct sockaddr_in si_other;
        static int slen = sizeof(si_other);
        static WSADATA wsa;
        int s;
        char * target_ip_address = "127.0.0.1";
        short target_port = 8888;

        if (fuzz_iterations == 0) {
            /* wait while the target process open the socket */

            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
                printf("WSAStartup failed. Error Code : %d", WSAGetLastError());

            // setup address structure
            memset((char *)&si_other, 0, sizeof(si_other));
            si_other.sin_family = AF_INET;
            si_other.sin_port = htons(target_port);
            si_other.sin_addr.S_un.S_addr = inet_addr(target_ip_address);
        }

        /* In case of TCP we need to open a socket each time we want to establish
        * connection. In theory we can keep connections always open but it might
        * cause our target behave differently (probably there are a bunch of
        * applications where we should apply such scheme to trigger interesting
        * behavior).
        */
        if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == SOCKET_ERROR)
            printf("socket() failed with error code : %d", WSAGetLastError());

        // Connect to server.
        if (connect(s, (SOCKADDR *)& si_other, slen) == SOCKET_ERROR)
            printf("connect() failed with error code : %d", WSAGetLastError());

        // Send our buffer
        if (send(s, (const char *)data, size, 0) == SOCKET_ERROR)
            printf("send() failed with error code : %d", WSAGetLastError());

        // shutdown the connection since no more data will be sent
        if (shutdown(s, 0x1/*SD_SEND*/) == SOCKET_ERROR)
            printf("shutdown failed with error: %d\n", WSAGetLastError());
        // close the socket to avoid consuming much resources
        if (closesocket(s) == SOCKET_ERROR)
            printf("closesocket failed with error: %d\n", WSAGetLastError());
    }
}

__declspec(dllexport) void APIENTRY dll_write_to_testcase(char* out_file, int out_fd, const void* mem, unsigned int len)
{
	return;
}

__declspec(dllexport) int APIENTRY dll_run_target(char **argv, unsigned int timeout, char *trace_bits, unsigned int map_size, char *data, long size, unsigned int fuzz_iterations)
{
    char result;
    if(!is_init)
        windows::setup_pipe();
	windows::send_data_tcp(data, size, fuzz_iterations);
    result = windows::read_from_pipe(timeout);
	switch(result)
	{
		case 'K':
			return FAULT_NONE;
		case 'C':
			return FAULT_CRASH;
		default:
			return FAULT_TMOUT;
	}
}

/*
__declspec(dllexport) int APIENTRY dll_run(char *data, long size, int fuzz_iterations)
{
	return 1;
}
*/

__declspec(dllexport) int APIENTRY dll_init()
{
	return 1;
}

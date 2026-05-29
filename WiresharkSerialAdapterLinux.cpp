/*
Wireshark Serial Adapter - Linux Port
Original Copyright (C) 2025 Joel Z.
Linux port by usage of Claude (Anthropic), 2025

This software is licensed under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

Build:
  g++ -std=c++17 -O2 -o wireshark_serial_adapter wireshark_serial_adapter_linux.cpp -lpthread

Install:
  Copy the binary to .../wireshark/extcap/
  and make it executable: chmod +x wireshark_serial_adapter
*/
#include <string>
#include <vector>
#include <queue>
#include <chrono>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <cstdlib>

// POSIX / Linux headers
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <dirent.h>
#include <pthread.h>
#include <poll.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

using namespace std;

// ---------------------------------------------------------------------------
// Type aliases replacing Windows-specific types
// ---------------------------------------------------------------------------
typedef uint8_t  BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
#define INVALID_HANDLE_VALUE (-1)

// ---------------------------------------------------------------------------
// Global configuration (mirrors the Windows original)
// ---------------------------------------------------------------------------
const double ProgramVersion = 2.0;
const std::string WireSharkAdapterName = "Serial Port Adapter";
const bool GuiMenu = true;

std::string FileName            = "";
std::string Port                = "/dev/ttyUSB0";
std::string BaudRate            = "19200";
std::string ByteSize            = "8";
std::string StopBits            = "1";
std::string Parity              = "NONE";
std::string FrameTiming         = "event";
std::string FrameTimebase       = "modbus_multi";
std::string FrameMulti          = "2.0";
std::string FrameDelay          = "0.0";
std::string FrameCorrect        = "none";
std::string WiresharkDLT        = "250";
std::string CaptureOutputPipeName = "";
std::string ControlInPipeName   = "";
std::string ControlOutPipeName  = "";

#define DLT_RTAC_SERIAL 250

// ---------------------------------------------------------------------------
// Handles (file descriptors on Linux)
// ---------------------------------------------------------------------------
static int hComSerial          = INVALID_HANDLE_VALUE;
static int hCaptureOutputPipe  = INVALID_HANDLE_VALUE;
static int hControlInPipe      = INVALID_HANDLE_VALUE;
static int hControlOutPipe     = INVALID_HANDLE_VALUE;

static pthread_t hCommReadThread;
static pthread_t hControlInThread;

// ---------------------------------------------------------------------------
// Inter-thread signalling: replaces Windows manual-reset events.
// Two condition variable / mutex pairs:
//   frameReady  – set by COM thread when a frame is assembled,
//                 waited on by the ProcessFrames thread.
//   frameQueued – set by ProcessFrames after it has consumed the frame,
//                 waited on by the COM thread before clearing the buffer.
// ---------------------------------------------------------------------------
static pthread_mutex_t frameReadyMutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  frameReadyCond   = PTHREAD_COND_INITIALIZER;
static bool            frameReadyFlag   = false;

static pthread_mutex_t frameQueuedMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  frameQueuedCond  = PTHREAD_COND_INITIALIZER;
static bool            frameQueuedFlag  = false;

// Protects SerialFrameVector when it is handed between threads
static pthread_mutex_t serialFrameMutex = PTHREAD_MUTEX_INITIALIZER;

// ---------------------------------------------------------------------------
// Frame types
// ---------------------------------------------------------------------------
typedef unsigned char typeFrameByte;
typedef std::vector<typeFrameByte> typeFrameVector;
typedef std::queue<typeFrameVector> typeFrameQueue;

typeFrameQueue  InputQueue;
typeFrameVector FragmentVector;
typeFrameVector SerialFrameVector;

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
void SendWireSharkControl(BYTE bControlNumber, BYTE bCommand, std::string sPayload);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Write an entire buffer to a file descriptor.
// Retries on EINTR (signal interrupted the syscall).
// Returns false on EPIPE / other errors so callers can react cleanly
// without crashing.  SIGPIPE itself is ignored in main().
static bool write_all(int fd, const void* buf, size_t len)
{
    if (fd < 0 || buf == nullptr || len == 0) return false;
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;   // interrupted — retry same position
            return false;                   // EPIPE, EBADF, etc.
        }
        if (n == 0) return false;           // shouldn't happen on a pipe
        p   += static_cast<size_t>(n);
        len -= static_cast<size_t>(n);
    }
    return true;
}

// Signal "frame ready": wake ProcessFrames thread.
static void event_frameReady_set()
{
    pthread_mutex_lock(&frameReadyMutex);
    frameReadyFlag = true;
    pthread_cond_signal(&frameReadyCond);
    pthread_mutex_unlock(&frameReadyMutex);
}

// Wait for "frame ready": called from ProcessFrames thread.
static void event_frameReady_wait()
{
    pthread_mutex_lock(&frameReadyMutex);
    while (!frameReadyFlag)
        pthread_cond_wait(&frameReadyCond, &frameReadyMutex);
    frameReadyFlag = false;
    pthread_mutex_unlock(&frameReadyMutex);
}

// Signal "frame queued": wake COM thread after frame has been consumed.
static void event_frameQueued_set()
{
    pthread_mutex_lock(&frameQueuedMutex);
    frameQueuedFlag = true;
    pthread_cond_signal(&frameQueuedCond);
    pthread_mutex_unlock(&frameQueuedMutex);
}

// Wait for "frame queued": called from COM read thread.
static void event_frameQueued_wait()
{
    pthread_mutex_lock(&frameQueuedMutex);
    while (!frameQueuedFlag)
        pthread_cond_wait(&frameQueuedCond, &frameQueuedMutex);
    frameQueuedFlag = false;
    pthread_mutex_unlock(&frameQueuedMutex);
}

// Return elapsed microseconds between two CLOCK_MONOTONIC timestamps.
static double elapsed_us(const struct timespec& start, const struct timespec& end)
{
    return (double)(end.tv_sec  - start.tv_sec ) * 1e6
         + (double)(end.tv_nsec - start.tv_nsec) / 1e3;
}

// Map an integer baud rate to the POSIX speed_t constant.
static speed_t baud_to_speed(int baud)
{
    switch (baud) {
        case 1200:   return B1200;
        case 2400:   return B2400;
        case 4800:   return B4800;
        case 9600:   return B9600;
        case 14400:  return B9600;   // no B14400 on Linux; fall back
        case 19200:  return B19200;
        case 38400:  return B38400;
        case 57600:  return B57600;
        case 115200: return B115200;
        case 230400: return B230400;
#ifdef B460800
        case 460800: return B460800;
#endif
#ifdef B921600
        case 921600: return B921600;
#endif
        default:     return B9600;
    }
}

// ---------------------------------------------------------------------------
// Debug helper (unchanged logic)
// ---------------------------------------------------------------------------
void print_hex(typeFrameByte frame[], int len, bool space = false)
{
    for (int pos = 0; pos < len; pos++) {
        unsigned int v = (unsigned char)frame[pos];
        fprintf(stderr, "%s%02x", space ? " " : "", v & 0xFF);
    }
}

// ---------------------------------------------------------------------------
// COM port reader thread
// Replaces: ComReadThreadFunc (DWORD WINAPI ...)
// ---------------------------------------------------------------------------
void* ComReadThreadFunc(void* /*lpParam*/)
{
    // Accept bare names like "ttyS0" or "/dev/ttyUSB0"
    std::string mPORT = Port;
    if (mPORT.find('/') == std::string::npos) {
        mPORT = "/dev/" + mPORT;
    }

    int mBaudRate = std::stoi(BaudRate);
    int mByteSize = std::stoi(ByteSize);

    // Open serial port: read/write, no controlling terminal, sync
    hComSerial = open(mPORT.c_str(), O_RDWR | O_NOCTTY | O_SYNC);
    if (hComSerial < 0) {
        fprintf(stderr, "Cannot open %s: %s\n", mPORT.c_str(), strerror(errno));
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // Configure termios (replaces DCB + SetCommState)
    // -----------------------------------------------------------------------
    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    if (tcgetattr(hComSerial, &tty) != 0) {
        fprintf(stderr, "tcgetattr: %s\n", strerror(errno));
        close(hComSerial);
        hComSerial = INVALID_HANDLE_VALUE;
        return nullptr;
    }

    cfmakeraw(&tty);  // Sets 8N1, no flow control, raw I/O as baseline

    cfsetispeed(&tty, baud_to_speed(mBaudRate));
    cfsetospeed(&tty, baud_to_speed(mBaudRate));

    // Byte size
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= (mByteSize == 7) ? CS7 : CS8;

    // Stop bits
    if (StopBits == "2") tty.c_cflag |=  CSTOPB;
    else                  tty.c_cflag &= ~CSTOPB;

    // Parity
    if      (Parity == "ODD")  { tty.c_cflag |= PARENB; tty.c_cflag |=  PARODD; }
    else if (Parity == "EVEN") { tty.c_cflag |= PARENB; tty.c_cflag &= ~PARODD; }
    else                       { tty.c_cflag &= ~PARENB; }

    // No hardware flow control
    tty.c_cflag &= ~CRTSCTS;
    tty.c_cflag |=  CREAD | CLOCAL;

    // Non-blocking reads: return immediately with whatever is in the buffer
    tty.c_cc[VMIN]  = 0;
    tty.c_cc[VTIME] = 0;

    if (tcsetattr(hComSerial, TCSANOW, &tty) != 0) {
        fprintf(stderr, "tcsetattr: %s\n", strerror(errno));
    }

    // -----------------------------------------------------------------------
    // Recalculate inter-frame timeout (same logic as original)
    // -----------------------------------------------------------------------
    struct termios actual_tty;
    tcgetattr(hComSerial, &actual_tty);

    int actual_bytesize = 8;
    switch (actual_tty.c_cflag & CSIZE) {
        case CS5: actual_bytesize = 5; break;
        case CS6: actual_bytesize = 6; break;
        case CS7: actual_bytesize = 7; break;
        case CS8: actual_bytesize = 8; break;
    }
    int actual_stopbits = (actual_tty.c_cflag & CSTOPB) ? 2 : 1;
    int actual_parity   = (actual_tty.c_cflag & PARENB) ? 1 : 0;

    double dblBitsPerByte = 1 + actual_bytesize + actual_stopbits + actual_parity;
    double Serial_1_Char  = dblBitsPerByte / (double)mBaudRate * 1000000.0; // µs

    if (mBaudRate > 19200 && FrameTimebase == "modbus_multi")
        Serial_1_Char = 500.0;

    double ReadFrameDelay = std::stod(FrameDelay);
    double ReadFrameMulti = std::stod(FrameMulti);
    double ReadTimeOut    = (ReadFrameMulti * Serial_1_Char) + ReadFrameDelay;
    if (FrameTimebase == "char_delay")
        ReadTimeOut = ReadFrameDelay;

    bool is_polling = (FrameTiming == "polling");

    // Flush stale data (replaces PurgeComm)
    tcflush(hComSerial, TCIOFLUSH);
    {
        char buf[1024];
        (void)read(hComSerial, buf, sizeof(buf)); // discard any queued bytes
    }

    if (is_polling)
        SendWireSharkControl(4, 2, "Frame Timing Polling\n");
    else
        SendWireSharkControl(4, 2, "Frame Timing Event\n");

    typeFrameByte RX_CHAR[1024];

    // -----------------------------------------------------------------------
    // Main receive loop
    // Replaces: WaitCommEvent → select(), ReadFile → read()
    // -----------------------------------------------------------------------
    while (hComSerial != INVALID_HANDLE_VALUE)
    {
        // --- Wait for at least one byte (replaces WaitCommEvent EV_RXCHAR) ---
        if (!is_polling) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(hComSerial, &rfds);
            int r = select(hComSerial + 1, &rfds, nullptr, nullptr, nullptr);
            if (r <= 0) continue;
        }

        // --- Collect bytes until the inter-frame gap exceeds ReadTimeOut ---
        double      EV_Timeout = 0.0;
        struct timespec ts_start, ts_end;
        clock_gettime(CLOCK_MONOTONIC, &ts_start);

        do {
            ssize_t n = read(hComSerial, RX_CHAR, sizeof(RX_CHAR));
            if (n > 0) {
                pthread_mutex_lock(&serialFrameMutex);
                SerialFrameVector.insert(SerialFrameVector.end(),
                                         RX_CHAR, RX_CHAR + n);
                pthread_mutex_unlock(&serialFrameMutex);
                clock_gettime(CLOCK_MONOTONIC, &ts_start); // reset idle timer
                EV_Timeout = 0.0;
            } else {
                if (!is_polling) {
                    // Sleep half the timeout to avoid burning CPU, then check elapsed.
                    useconds_t wait_us = static_cast<useconds_t>(ReadTimeOut / 2.0);
                    if (wait_us > 0) usleep(wait_us);
                }
                clock_gettime(CLOCK_MONOTONIC, &ts_end);
                EV_Timeout = elapsed_us(ts_start, ts_end);
            }
        } while (EV_Timeout < ReadTimeOut);

        if (!SerialFrameVector.empty()) {
            // Signal ProcessFrames that a complete frame is ready,
            // then wait for it to acknowledge (replaces SetEvent / WaitForSingleObject).
            event_frameReady_set();
            event_frameQueued_wait();
            pthread_mutex_lock(&serialFrameMutex);
            SerialFrameVector.clear();
            pthread_mutex_unlock(&serialFrameMutex);
        }
    }
    return nullptr;
}

int CreateComThread()
{
    int ret = pthread_create(&hCommReadThread, nullptr, ComReadThreadFunc, nullptr);
    if (ret != 0) {
        fprintf(stderr, "pthread_create (COM): %s\n", strerror(ret));
        return 0;
    }
    pthread_detach(hCommReadThread);
    return 1;
}

// ---------------------------------------------------------------------------
// CRC helpers (unchanged logic)
// ---------------------------------------------------------------------------
int CRC16_2(typeFrameByte frame[], int len)
{
    int crc = 0xFFFF;
    for (int pos = 0; pos < len; pos++) {
        crc ^= (int)frame[pos];
        for (int i = 8; i != 0; i--) {
            if ((crc & 0x0001) != 0) { crc >>= 1; crc &= 0x7FFF; crc ^= 0xA001; }
            else                     { crc >>= 1; }
        }
    }
    crc = ((crc << 8) | (crc >> 8)) & 0xFFFF;
    return crc;
}

bool CRC_OK(typeFrameByte frame[], int len)
{
    if (len <= 2) return false;
    unsigned int CALC_CRC  = (unsigned int)CRC16_2(frame, len - 2);
    unsigned int FRAME_CRC = ((unsigned int)frame[len - 2] << 8) | (unsigned int)frame[len - 1];
    return (CALC_CRC == FRAME_CRC);
}

// ---------------------------------------------------------------------------
// FindModbusFrameEnd (unchanged logic)
// ---------------------------------------------------------------------------
int FindModbusFrameEnd(typeFrameByte frame[], int len)
{
    int ReturnVal = 0;
    int QueryCrcLoc = 0;
    int ResponseCrcLoc = 0;
    int cur_len;
    typeFrameByte* cur_frame;
    int frame_start = 0;

    for (; (frame_start < len - 2) && ReturnVal == 0; frame_start++) {
        bool ResponseSizeOK = false, QuerySizeOK = false;
        bool ResponseCrcOK  = false, QueryCrcOK  = false;
        QueryCrcLoc = 0; ResponseCrcLoc = 0;

        cur_len   = len - frame_start;
        cur_frame = frame + frame_start;

        if (cur_len >= 3) {
            typeFrameByte ModbusFunction = cur_frame[1];
            switch (ModbusFunction) {
                case 1: case 2: case 3: case 4:
                    QueryCrcLoc = 6;
                    if (cur_len - 1 > 2) ResponseCrcLoc = (int)cur_frame[2] + 3;
                    break;
                case 5: case 6:
                    QueryCrcLoc = ResponseCrcLoc = 6;
                    break;
                case 11:
                    QueryCrcLoc = 2; ResponseCrcLoc = 6;
                    break;
                case 12: case 17:
                    QueryCrcLoc = 2;
                    if (cur_len - 1 > 2) ResponseCrcLoc = (int)cur_frame[2] + 3;
                    break;
                case 15: case 16:
                    if (cur_len - 1 > 6) QueryCrcLoc = (int)cur_frame[6] + 7;
                    ResponseCrcLoc = 6;
                    break;
                case 20: case 21:
                    if (cur_len - 1 > 3) QueryCrcLoc = ResponseCrcLoc = (int)cur_frame[2] + 3;
                    break;
                case 22:
                    QueryCrcLoc = ResponseCrcLoc = 8;
                    break;
                case 23:
                    if (cur_len - 1 > 10) QueryCrcLoc    = (int)cur_frame[10] + 11;
                    if (cur_len - 1 >  3) ResponseCrcLoc = (int)cur_frame[ 2] +  3;
                    break;
                case 24:
                    QueryCrcLoc = 4;
                    if (cur_len - 1 > 4) ResponseCrcLoc = (int)cur_frame[4] + 4;
                    break;
                default:
                    if ((0x80 & cur_frame[1]) > 0) {
                        QueryCrcLoc = ResponseCrcLoc = 3;
                    } else {
                        for (int i = 3; (i < cur_len - 2) && ReturnVal == 0; i++) {
                            if (CRC_OK(cur_frame, i)) ReturnVal = i;
                        }
                    }
                    break;
            }
        }

        ResponseSizeOK = (ResponseCrcLoc > 0 && ResponseCrcLoc + 2 <= cur_len);
        QuerySizeOK    = (QueryCrcLoc    > 0 && QueryCrcLoc    + 2 <= cur_len);

        if (ResponseSizeOK) {
            ResponseCrcOK = CRC_OK(cur_frame, ResponseCrcLoc + 2);
            if (ResponseCrcOK) ReturnVal = ResponseCrcLoc + 2;
        }
        if (QuerySizeOK) {
            QueryCrcOK = CRC_OK(cur_frame, QueryCrcLoc + 2);
            if (QueryCrcOK) ReturnVal = QueryCrcLoc + 2;
        }
    }

    if (frame_start != 1 && ReturnVal > 0)
        ReturnVal = -1 * (frame_start - 1);
    return ReturnVal;
}

// ---------------------------------------------------------------------------
// Wireshark control pipe message sender
// Replaces: WriteFile → write_all()
// The byte-swap logic is the same; on Linux we can also use htons() directly.
// ---------------------------------------------------------------------------
void SendWireSharkControl(BYTE bControlNumber, BYTE bCommand, std::string sPayload)
{
    if (hControlOutPipe == INVALID_HANDLE_VALUE) return;

    typeFrameVector OutVector;
    typeFrameByte*  ptr;

    char  cSyncPipeIndication = 'T';
    ptr = (typeFrameByte*)&cSyncPipeIndication;
    OutVector.insert(OutVector.end(), ptr, ptr + 1);

    BYTE bZero = 0;
    OutVector.push_back(bZero);

    // Message length in network (big-endian) byte order
    WORD wMessageLength = (WORD)(sPayload.length() + 2);
    WORD wML_BE = (WORD)((wMessageLength >> 8) | ((wMessageLength & 0xFF) << 8));
    ptr = (typeFrameByte*)&wML_BE;
    OutVector.insert(OutVector.end(), ptr, ptr + sizeof(wML_BE));

    OutVector.push_back(bControlNumber);
    OutVector.push_back(bCommand);

    if (!sPayload.empty()) {
        ptr = (typeFrameByte*)sPayload.data();
        OutVector.insert(OutVector.end(), ptr, ptr + sPayload.size());
    }

    write_all(hControlOutPipe, OutVector.data(), OutVector.size());
}

// ---------------------------------------------------------------------------
// Build a pcap packet (unchanged logic; WriteFile replaced by write_all)
// ---------------------------------------------------------------------------
typeFrameVector WireSharkPacket(typeFrameByte frame[], int len)
{
    static bool xHeaderWritten = false;
    typeFrameVector OutVector;
    typeFrameByte*  ptr;
    DWORD network = (DWORD)std::stoul(WiresharkDLT);

    if (!xHeaderWritten) {
        xHeaderWritten = true;
        DWORD  magic_number   = 0xa1b2c3d4;
        WORD   version_major  = 2;
        WORD   version_minor  = 4;
        DWORD  thiszone       = 0;
        DWORD  sigfigs        = 0;
        DWORD  snaplen        = 65535;

        ptr = (typeFrameByte*)&magic_number;  OutVector.insert(OutVector.end(), ptr, ptr + 4);
        ptr = (typeFrameByte*)&version_major; OutVector.insert(OutVector.end(), ptr, ptr + 2);
        ptr = (typeFrameByte*)&version_minor; OutVector.insert(OutVector.end(), ptr, ptr + 2);
        ptr = (typeFrameByte*)&thiszone;      OutVector.insert(OutVector.end(), ptr, ptr + 4);
        ptr = (typeFrameByte*)&sigfigs;       OutVector.insert(OutVector.end(), ptr, ptr + 4);
        ptr = (typeFrameByte*)&snaplen;       OutVector.insert(OutVector.end(), ptr, ptr + 4);
        ptr = (typeFrameByte*)&network;       OutVector.insert(OutVector.end(), ptr, ptr + 4);
    }

    // Timestamp via std::chrono (same as original)
    auto time_now  = chrono::system_clock::now();
    auto epoch_now = chrono::duration_cast<chrono::seconds>(time_now.time_since_epoch()).count();
    auto us_now    = chrono::duration_cast<chrono::microseconds>(time_now.time_since_epoch()).count();
    us_now -= epoch_now * 1000000;

    DWORD dwEPOCH      = (DWORD)epoch_now;
    DWORD dwMicroSec   = (DWORD)us_now;
    DWORD dwPacketLen1 = (DWORD)len;
    DWORD dwPacketLen2 = (DWORD)len;

    if (network == DLT_RTAC_SERIAL) {
        dwPacketLen1 = (DWORD)(len + 12);
        dwPacketLen2 = (DWORD)(len + 12);
    }

    ptr = (typeFrameByte*)&dwEPOCH;      OutVector.insert(OutVector.end(), ptr, ptr + 4);
    ptr = (typeFrameByte*)&dwMicroSec;   OutVector.insert(OutVector.end(), ptr, ptr + 4);
    ptr = (typeFrameByte*)&dwPacketLen1; OutVector.insert(OutVector.end(), ptr, ptr + 4);
    ptr = (typeFrameByte*)&dwPacketLen2; OutVector.insert(OutVector.end(), ptr, ptr + 4);

    if (network == DLT_RTAC_SERIAL) {
        DWORD dwRTAC_RelativeTimeStampL = 0;
        DWORD dwDuration = 0;
        // Reverse byte order
        dwDuration = ((dwDuration & 0x000000FFU) << 24) |
                     ((dwDuration & 0x0000FF00U) <<  8) |
                     ((dwDuration & 0x00FF0000U) >>  8) |
                     ((dwDuration & 0xFF000000U) >> 24);
        DWORD dwRTAC_RelativeTimeStampR = dwDuration;
        BYTE  bRTAC_SerialEventType = 0x06; // CAPTURE_COMPLETE
        BYTE  bRTAC_UARTState = 0;
        WORD  wRTAC_Footer = 0;

        ptr = (typeFrameByte*)&dwRTAC_RelativeTimeStampL; OutVector.insert(OutVector.end(), ptr, ptr + 4);
        ptr = (typeFrameByte*)&dwRTAC_RelativeTimeStampR; OutVector.insert(OutVector.end(), ptr, ptr + 4);
        OutVector.push_back(bRTAC_SerialEventType);
        OutVector.push_back(bRTAC_UARTState);
        ptr = (typeFrameByte*)&wRTAC_Footer; OutVector.insert(OutVector.end(), ptr, ptr + 2);
    }

    OutVector.insert(OutVector.end(), frame, frame + len);
    return OutVector;
}

// ---------------------------------------------------------------------------
// Output_Frame: guard against an invalid fd; write_all handles EINTR/EPIPE.
// ---------------------------------------------------------------------------
void Output_Frame(typeFrameByte frame[], int len)
{
    if (hCaptureOutputPipe < 0) return;   // pipe not open yet — drop silently
    typeFrameVector OutVector = WireSharkPacket(frame, len);
    write_all(hCaptureOutputPipe, OutVector.data(), OutVector.size());
}

// ---------------------------------------------------------------------------
// Modbus fragment reassembly (unchanged logic)
// ---------------------------------------------------------------------------
void ProcessModbusFragmentFrames()
{
    while (!InputQueue.empty()) {
        if (CRC_OK(InputQueue.front().data(), (int)InputQueue.front().size())) {
            if (!FragmentVector.empty()) {
                Output_Frame(FragmentVector.data(), (int)FragmentVector.size());
                FragmentVector.clear();
            }
            Output_Frame(InputQueue.front().data(), (int)InputQueue.front().size());
        } else {
            int frame_len = (int)InputQueue.front().size();
            typeFrameByte* frame = InputQueue.front().data();
            FragmentVector.insert(FragmentVector.end(), frame, frame + frame_len);
            int FrameEndLoc = 0;

            do {
                frame_len   = (int)FragmentVector.size();
                frame       = FragmentVector.data();
                FrameEndLoc = FindModbusFrameEnd(frame, frame_len);

                if (FrameEndLoc > 0) {
                    Output_Frame(frame, FrameEndLoc);
                    FragmentVector.erase(FragmentVector.begin(),
                                         FragmentVector.begin() + FrameEndLoc);
                }
                if (FrameEndLoc < 0) {
                    FrameEndLoc = -1 * FrameEndLoc;
                    Output_Frame(frame, FrameEndLoc);
                    FragmentVector.erase(FragmentVector.begin(),
                                         FragmentVector.begin() + FrameEndLoc);
                }
            } while (FrameEndLoc != 0 && !FragmentVector.empty());
        }
        InputQueue.pop();
    }
}

// ---------------------------------------------------------------------------
// ProcessFrames: main loop waiting for frames from the COM thread.
// Replaces WaitForSingleObject with the condition-variable pair.
// ---------------------------------------------------------------------------
void ProcessFrames()
{
    while (true) {
        event_frameReady_wait();          // Wait until COM thread has a frame

        // Snapshot SerialFrameVector under the mutex so the COM thread cannot
        // clear it while we are copying. We release before signalling so the
        // COM thread is not forced to wait for us to finish processing.
        pthread_mutex_lock(&serialFrameMutex);
        typeFrameVector FrameVector = SerialFrameVector;
        pthread_mutex_unlock(&serialFrameMutex);

        event_frameQueued_set();          // Tell COM thread it can clear the buffer

        if (FrameCorrect == "modbus_crc") {
            InputQueue.push(FrameVector);
            ProcessModbusFragmentFrames();
        } else {
            Output_Frame(FrameVector.data(), (int)FrameVector.size());
        }
    }
}

// ---------------------------------------------------------------------------
// Utility: strip path component from argv[0]
// ---------------------------------------------------------------------------
char* filename_remove_path(const char* filename_in)
{
    const char* filename_out = filename_in;
    if (filename_in) {
        filename_out = strrchr(filename_in, '/');
        if (filename_out) filename_out++;
        else filename_out = filename_in;
    }
    return const_cast<char*>(filename_out);
}

// ---------------------------------------------------------------------------
// Open an extcap FIFO created by Wireshark.
//
// WHY O_RDWR:
//   Wireshark creates these FIFOs before launching the extcap. Opening a
//   FIFO with O_WRONLY blocks until the reader connects, and opening with
//   O_RDONLY blocks until the writer connects.  If the two sequential opens
//   in main() happen in a different order than Wireshark expects, both sides
//   stall forever (Wireshark then times out and crashes).
//
//   On Linux, opening a FIFO with O_RDWR is non-blocking: it returns
//   immediately regardless of whether the other end is ready. Subsequent
//   read()/write() calls still block normally, so data flow is unaffected.
//   This is the standard workaround used by many extcap implementations.
int OpenExtcapPipe(const std::string& pipe_name)
{
    int fd = open(pipe_name.c_str(), O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Cannot open extcap pipe %s: %s\n",
                pipe_name.c_str(), strerror(errno));
    }
    return fd;
}

// ---------------------------------------------------------------------------
// Extcap config: list serial ports
// Replaces Windows COM1-255 enumeration with /dev/ttyS*, ttyUSB*, ttyACM*
// ---------------------------------------------------------------------------
void print_extcap_config_comport()
{
    std::string argString = "arg {number=0}{call=--port}{display=Port}{type=selector}\n";

    // Patterns to probe
    const char* prefixes[] = {
        "/dev/ttyUSB", "/dev/ttyACM", "/dev/ttyXRUSB", nullptr
    };

    for (int pi = 0; prefixes[pi]; pi++) {
        for (int i = 0; i < 32; i++) {
            std::string portPath = std::string(prefixes[pi]) + std::to_string(i);
            int fd = open(portPath.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
            if (fd >= 0) {
                close(fd);
                argString += "value {arg=0}{value=" + portPath +
                             "}{display=" + portPath + "}{default=false}\n";
            } else if (errno == EACCES || errno == EBUSY) {
                argString += "value {arg=0}{value=" + portPath +
                             "}{display=" + portPath + " (IN USE)}{default=false}\n";
            }
        }
    }
    printf("%s", argString.c_str());
}

void print_extcap_config_baud()
{
    std::string argString = "arg {number=1}{call=--baud}{display=Baud Rate}{type=selector}\n";
    ifstream file("./baud.ini");
    if (file.is_open()) {
        string line;
        while (getline(file, line))
            argString += "value {arg=1}{value=" + line + "}{display=" + line + "}{default=false}\n";
        file.close();
    } else {
        const char* bauds[] = {
            "1200","2400","4800","9600","14400","19200","38400",
            "57600","115200","230400","460800","921600", nullptr
        };
        for (int i = 0; bauds[i]; i++) {
            bool def = (std::string(bauds[i]) == "19200");
            argString += std::string("value {arg=1}{value=") + bauds[i] +
                         "}{display=" + bauds[i] + "}{default=" +
                         (def ? "true" : "false") + "}\n";
        }
    }
    printf("%s", argString.c_str());
}

void print_extcap_config_bytesize()
{
    printf("arg {number=2}{call=--byte}{display=Byte Size}{type=selector}\n"
           "value {arg=2}{value=8}{display=8}{default=true}\n"
           "value {arg=2}{value=7}{display=7}{default=false}\n");
}

void print_extcap_config_parity()
{
    printf("arg {number=3}{call=--parity}{display=Parity}{type=selector}\n"
           "value {arg=3}{value=NONE}{display=NONE}{default=true}\n"
           "value {arg=3}{value=ODD}{display=ODD}{default=false}\n"
           "value {arg=3}{value=EVEN}{display=EVEN}{default=false}\n");
}

void print_extcap_config_stopbits()
{
    printf("arg {number=4}{call=--stop}{display=Stop Bits}{type=selector}\n"
           "value {arg=4}{value=1}{display=1}{default=true}\n"
           "value {arg=4}{value=2}{display=2}{default=false}\n");
}

void print_extcap_config_interframe()
{
    printf(
        "arg {number=5}{call=--frame_timing}{display=Interframe Timing Detection}{type=selector}\n"
        "value {arg=5}{value=event}{display=Event}{default=true}\n"
        "value {arg=5}{value=polling}{display=Polling}{default=false}\n"
        "arg {number=6}{call=--frame_timebase}{display=Interframe Timebase}{type=selector}\n"
        "value {arg=6}{value=modbus_multi}{display=Multipler :1X Modbus Character}{default=true}\n"
        "value {arg=6}{value=char_multi}{display=Multipler: 1X Character}{default=false}\n"
        "value {arg=6}{value=char_delay}{display=Delay Only}{default=false}\n"
        "arg {number=7}{call=--frame_multi}{display=Interframe Multipler}{type=double}{range=1,15}{default=3.0}\n"
        "arg {number=8}{call=--frame_delay}{display=Interframe Delay(us)}{type=double}{range=0,15}{default=0.0}\n"
        "arg {number=9}{call=--frame_correct}{display=Interframe Correction}{type=selector}\n"
        "value {arg=9}{value=none}{display=None}{default=true}\n"
        "value {arg=9}{value=modbus_crc}{display=Modbus CRC}{default=false}\n"
    );
}

void print_extcap_config_dlt()
{
    std::string argString = "arg {number=10}{call=--dlt}{display=Wireshark DLT}{type=selector}\n";
    argString += "value {arg=10}{value=250}{display=250:  RTAC Serial}{default=true}\n";
    for (int v = 147; v <= 162; v++) {
        char buf[128];
        snprintf(buf, sizeof(buf),
                 "value {arg=10}{value=%d}{display=%d:  User DLT}{default=false}\n", v, v);
        argString += buf;
    }
    printf("%s", argString.c_str());
}

void print_extcap_config()
{
    print_extcap_config_comport();
    print_extcap_config_baud();
    print_extcap_config_bytesize();
    print_extcap_config_parity();
    print_extcap_config_stopbits();
    print_extcap_config_interframe();
    print_extcap_config_dlt();
}

static void print_help(const std::string& filename)
{
    printf(
        "Created by Joel Zupancic (Windows version)\n"
        "This is free software! The Source is free! There is NO warranty!\n\n"
        "This program captures packets from a serial interface and\n"
        "saves them to a named pipe for Wireshark.\n\n"
        "Copy the binary to ~/.config/wireshark/extcap/ and chmod +x it.\n\n"
        "*****Command Line Options*****\n"
        "--port     e.g. /dev/ttyUSB0, /dev/ttyS0\n"
        "--baud     e.g. 9600, 19200, 115200\n"
        "--byte     7 or 8\n"
        "--parity   NONE, ODD, EVEN\n"
        "--stop     1 or 2\n"
        "--fifo     Output FIFO path (provided by Wireshark)\n\n"
        "*****Wireshark Extcap Options*****\n"
        "--capture                 Start capture\n"
        "--extcap-interfaces       List interfaces\n"
        "--extcap-interface <ifc>  Select interface\n"
        "--extcap-dlts             List DLTs for interface\n"
        "--extcap-config           List configuration options\n"
        "--fifo <path>             Output FIFO\n"
        "--extcap-control-in       Control pipe (Wireshark → extcap)\n"
        "--extcap-control-out      Control pipe (extcap → Wireshark)\n"
        "--extcap-version          Show version\n"
    );
}

void print_extcap_interfaces()
{
    std::string argString =
        "interface {value=" + WireSharkAdapterName + "_" + FileName +
        "}{display=" + WireSharkAdapterName + " (" + FileName + ")}\n";

    if (GuiMenu) {
        argString +=
            "extcap {version=1.0}{display=Example extcap interface}\n"
            "control {number=0}{type=string}{display=Message}\n"
            "control {number=1}{type=selector}{display=Time delay}"
                "{tooltip=Time delay between packages}\n"
            "control {number=2}{type=boolean}{display=Verify}"
                "{default=true}{tooltip=Verify package content}\n"
            "control {number=3}{type=button}{display=Turn on}{tooltip=Turn on or off}\n"
            "control {number=4}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}\n"
            "value {control=1}{value=1}{display=1 sec}\n"
            "value {control=1}{value=2}{display=2 sec}{default=true}\n";
    }
    printf("%s", argString.c_str());
}

void print_extcap_dlt(const std::string& /*sInterface*/)
{
    printf("dlt {number=147}{name=%s_%s}{display=%s (%s)}\n",
           WireSharkAdapterName.c_str(), FileName.c_str(),
           WireSharkAdapterName.c_str(), FileName.c_str());
}

// ---------------------------------------------------------------------------
// Control-in pipe reader thread
// Replaces DWORD WINAPI ControlInThreadFunc (OVERLAPPED I/O) with blocking read
// ---------------------------------------------------------------------------
void* ControlInThreadFunc(void* /*lpParam*/)
{
    // Open with O_RDWR (non-blocking open) — see OpenExtcapPipe comment.
    int hPipe = OpenExtcapPipe(ControlInPipeName);
    if (hPipe < 0) return nullptr;
    hControlInPipe = hPipe;

    typeFrameVector FrameVector;
    typeFrameByte   RX_CHAR[1024];
    ssize_t         RX_LEN = 0;

    while (true) {
        RX_LEN = read(hPipe, RX_CHAR, sizeof(RX_CHAR));
        if (RX_LEN <= 0) {
            if (errno == EINTR) continue;
            break; // EOF or error
        }
        FrameVector.insert(FrameVector.end(), RX_CHAR, RX_CHAR + RX_LEN);

        if (FrameVector.size() >= 6) {
            char  SyncPipeChar    = (char)FrameVector[0];
            WORD  wMessageLength  = (WORD)(((WORD)FrameVector[2] << 8) | (WORD)FrameVector[3]);
            BYTE  ControlNumber   = FrameVector[4];
            BYTE  Command         = FrameVector[5];

            if (FrameVector.size() >= (size_t)(wMessageLength + 4)) {
                std::string sPayload(
                    (const char*)&FrameVector[6],
                    (size_t)(wMessageLength - 2));

                std::string sOutput =
                    "SyncPipeChar: "   + std::to_string((int)SyncPipeChar)  +
                    " wMessageLength: " + std::to_string(wMessageLength)    +
                    " ControlNumber: "  + std::to_string(ControlNumber)     +
                    " FrameVectorSize: "+ std::to_string(FrameVector.size())+
                    " Command: "        + std::to_string(Command)           +
                    "\nPayload: "       + sPayload + "\n\n";

                SendWireSharkControl(4, 2, sOutput);
                FrameVector.clear();
            }
        }
    }
    close(hPipe);
    hControlInPipe = INVALID_HANDLE_VALUE;
    return nullptr;
}

int CreateControlInThread()
{
    int ret = pthread_create(&hControlInThread, nullptr, ControlInThreadFunc, nullptr);
    if (ret != 0) {
        fprintf(stderr, "pthread_create (control-in): %s\n", strerror(ret));
        return 0;
    }
    pthread_detach(hControlInThread);
    return 1;
}

// ---------------------------------------------------------------------------
// Cleanup on exit
// ---------------------------------------------------------------------------
void on_main_exit()
{
    if (hComSerial         != INVALID_HANDLE_VALUE) close(hComSerial);
    if (hCaptureOutputPipe != INVALID_HANDLE_VALUE) close(hCaptureOutputPipe);
    if (hControlOutPipe    != INVALID_HANDLE_VALUE) close(hControlOutPipe);
    if (hControlInPipe     != INVALID_HANDLE_VALUE) close(hControlInPipe);
}

// ---------------------------------------------------------------------------
// Argument parser (logic unchanged; file path handling updated for Linux)
// ---------------------------------------------------------------------------
bool ParseMainArg(int argc, char* argv[])
{
    int  argi = 0;
    bool Wireshark_Capture = false;
    bool PrintArgExit      = false;
    std::string sExtcapInterface = "";
    std::string sArgMainOpt = "";

    FileName = filename_remove_path(argv[0]);

    for (argi = 1; argi < argc && !PrintArgExit; argi++) {
        if (strcmp(argv[argi], "--help")             == 0) { print_help(FileName);          PrintArgExit = true; }
        if (strcmp(argv[argi], "--version")          == 0) { printf("%.1f", ProgramVersion); PrintArgExit = true; }
        if (strcmp(argv[argi], "--extcap-interfaces")== 0) { print_extcap_interfaces();      PrintArgExit = true; }
        if (strcmp(argv[argi], "--extcap-config")    == 0) { print_extcap_config();           PrintArgExit = true; }
        if (strcmp(argv[argi], "--extcap-dlts")      == 0) { sArgMainOpt = "--extcap-dlts";   PrintArgExit = true; }
        if (strcmp(argv[argi], "--capture")          == 0)   Wireshark_Capture = true;

        // Key-value pairs
        struct { const char* flag; std::string* target; } opts[] = {
            { "--fifo",               &CaptureOutputPipeName },
            { "--extcap-control-in",  &ControlInPipeName     },
            { "--extcap-control-out", &ControlOutPipeName    },
            { "--extcap-interface",   &sExtcapInterface      },
            { "--port",               &Port                  },
            { "--baud",               &BaudRate              },
            { "--byte",               &ByteSize              },
            { "--parity",             &Parity                },
            { "--stop",               &StopBits              },
            { "--frame_timing",       &FrameTiming           },
            { "--frame_timebase",     &FrameTimebase         },
            { "--frame_multi",        &FrameMulti            },
            { "--frame_delay",        &FrameDelay            },
            { "--frame_correct",      &FrameCorrect          },
            { "--dlt",                &WiresharkDLT          },
            { nullptr, nullptr }
        };

        for (int k = 0; opts[k].flag && !PrintArgExit; k++) {
            if (strcmp(argv[argi], opts[k].flag) == 0) {
                argi++;
                if (argi >= argc) {
                    fprintf(stderr, "%s requires a value\n", opts[k].flag);
                    PrintArgExit = true;
                } else {
                    *opts[k].target = argv[argi];
                }
                break;
            }
        }
    }

    if (sArgMainOpt == "--extcap-dlts") {
        if (sExtcapInterface.empty())
            fprintf(stderr, "--extcap-dlts requires --extcap-interface\n");
        else
            print_extcap_dlt(sExtcapInterface);
    }

    return (Wireshark_Capture && !PrintArgExit);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    if (!ParseMainArg(argc, argv))
        return 0;

    // Ignore SIGPIPE so that a write() to a closed pipe returns EPIPE instead
    // of killing this process.  write_all() treats EPIPE as a non-fatal error.
    signal(SIGPIPE, SIG_IGN);

    atexit(on_main_exit);

    // Open all extcap FIFOs with O_RDWR (non-blocking open — see OpenExtcapPipe).
    // This avoids the deadlock that results from two sequential O_WRONLY opens
    // when Wireshark has not yet opened the read end of the second pipe.
    hCaptureOutputPipe = OpenExtcapPipe(CaptureOutputPipeName);

    // Control-in thread (Wireshark → extcap button presses etc.)
    CreateControlInThread();

    // Control-out pipe: extcap sends status/log messages → Wireshark toolbar
    hControlOutPipe = OpenExtcapPipe(ControlOutPipeName);

    // Start the serial reader thread
    CreateComThread();

    // Block forever processing frames
    ProcessFrames();

    return 0;
}

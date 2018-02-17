#ifndef SECLIB_H

//////////////////////////////////////////////////////////////////////////
// Global macro switches

#ifndef _DEBUG
#define SECLIB_SPEED
#endif // _DEBUG

#ifdef SECLIB_SPEED
#define	DONT_USE_KERNEL_STATUS			// Do not update the kernel status
#define	WIN32_USE_HEAP_API_FOR_MEMORY	// Use the heap API to allocate memory
#define	WIN32_NO_DEBUG_HELP_DLL			// Do not call the DLL for debugging
#define	DONT_CHECK_HEAP					// Do not check the status of the heap
#define	DONT_ALLOW_RUN_ON_DEBUGGER		// Do not allow running on the debugger
#endif // SECLIB_SPEED


//////////////////////////////////////////////////////////////////////////
// Global consts

//// Brand
// (Define it if building SoftEther VPN Project.)
#define	GC_SOFTETHER_VPN
#define	GC_SOFTETHER_OSS

//// Basic Variables

#define	CEDAR_PRODUCT_STR			"SoftEther"
#define	CEDAR_PRODUCT_STR_W			L"SoftEther"
#define	CEDAR_SERVER_STR			"SoftEther VPN Server"
#define	CEDAR_BRIDGE_STR			"SoftEther VPN Bridge"
#define	CEDAR_BETA_SERVER			"SoftEther VPN Server Pre Release"
#define	CEDAR_MANAGER_STR			"SoftEther VPN Server Manager"
#define	CEDAR_CUI_STR				"SoftEther VPN Command-Line Admin Tool"
#define CEDAR_ELOG					"SoftEther EtherLogger"
#define	CEDAR_CLIENT_STR			"SoftEther VPN Client"
#define CEDAR_CLIENT_MANAGER_STR	"SoftEther VPN Client Connection Manager"
#define	CEDAR_ROUTER_STR			"SoftEther VPN User-mode Router"
#define	CEDAR_SERVER_LINK_STR		"SoftEther VPN Server (Cascade Mode)"
#define	CEDAR_BRIDGE_LINK_STR		"SoftEther VPN Bridge (Cascade Mode)"
#define	CEDAR_SERVER_FARM_STR		"SoftEther VPN Server (Cluster RPC Mode)"



//// Default Port Number

#define	GC_DEFAULT_PORT		5555
#define	GC_CLIENT_CONFIG_PORT	9930
#define	GC_CLIENT_NOTIFY_PORT	9983


//// Software Name

#define	GC_SVC_NAME_VPNSERVER		"SEVPNSERVER"
#define	GC_SVC_NAME_VPNCLIENT		"SEVPNCLIENT"
#define	GC_SVC_NAME_VPNBRIDGE		"SEVPNBRIDGE"



//// Registry

#define	GC_REG_COMPANY_NAME			"SoftEther Project"




//// Setup Wizard

#define	GC_SW_UIHELPER_REGVALUE		"SoftEther VPN Client UI Helper"
#define	GC_SW_SOFTETHER_PREFIX		"se"
#define	GC_SW_SOFTETHER_PREFIX_W	L"se"



//// VPN UI Components

#define	GC_UI_APPID_CM				L"SoftEther.SoftEther VPN Client"



//////////////////////////////////////////////////////////////////////////
// Mayaqua


// Constant
#define	PENCORE_DLL_NAME		"|PenCore.dll"

#define	DEFAULT_TABLE_FILE_NAME		"|strtable.stb"		// Default string table
//#define	DEFAULT_TABLE_FILE_NAME		"@hamcore_zh/strtable.stb"		// Test for Chinese

#define	STRTABLE_ID					"SEC_TABLE_180217"	// String table identifier

// Determining the OS
#ifdef	WIN32
#define	OS_WIN32		// Microsoft Windows
#else
#define	OS_UNIX			// UNIX
#endif	// WIN32

// Directory separator
#ifdef	OS_WIN32
#define	PATH_BACKSLASH	// Backslash (\)
#else	// WIN32
#define	PATH_SLASH		// Slash (/)
#endif	// WIN32

// Character code
#ifdef	OS_WIN32
#define	CODE_SHIFTJIS	// Shift_JIS code
#else	// WIN32
#define	CODE_EUC		// euc-jp code
#endif	// WIN32

// Endian
#define	IsBigEndian()		(g_little_endian ? false : true)
#define	IsLittleEndian()	(g_little_endian)

#ifdef	OS_WIN32
// Replace the snprintf function
#define	snprintf	_snprintf
#endif	// OS_WIN32
// Compiler dependent
#ifndef	OS_WIN32
// Gcc compiler
#define	GCC_PACKED		__attribute__ ((__packed__))
#else	// OS_WIN32
// VC++ compiler
#define	GCC_PACKED
#endif	// OS_WIN32

// Macro that displays the current file name and line number
#define	WHERE			if (IsDebug()){printf("%s: %u\n", __FILE__, __LINE__); SleepThread(10);}
#define	WHERE32			if (IsDebug()){	\
	char tmp[128]; sprintf(tmp, "%s: %u", __FILE__, __LINE__); Win32DebugAlert(tmp);	\
	}
#define TIMECHECK		if (IsDebug()){printf("%-12s:%5u", __FILE__, __LINE__);TimeCheck();}

// Probe related
#ifdef	USE_PROBE
#define	PROBE_WHERE						WriteProbe(__FILE__, __LINE__, "");
#define	PROBE_STR(str)					WriteProbe(__FILE__, __LINE__, (str));
#define	PROBE_DATA2(str, data, size)	WriteProbeData(__FILE__, __LINE__, (str), (data), (size));
#define	PROBE_DATA(data, size)			WriteProbeData(__FILE__, __LINE__, "", (data), (size));
#else	// USE_PROBE
#define	PROBE_WHERE
#define	PROBE_STR(str)
#define	PROBE_DATA2(str, data, size)
#define	PROBE_DATA(data, size)
#endif	// USE_PROBE

// Determine the performance / memory strategy
#if	(defined(CPU_X86) || defined(CPU_X64) || defined(CPU_X86_X64) || defined(CPU_SPARC) || defined(CPU_SPARC64) || defined(OS_WIN32) || defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64) || defined(i386) || defined(__i386) || defined(__i386__) || defined(__ia64__) || defined(__IA64__) || defined(_IA64))
#define	USE_STRATEGY_PERFORMACE
#else
#define	USE_STRATEGY_LOW_MEMORY
#endif


// Macro that displays the current time
#ifdef	WIN32
#define	WHEN			if (IsDebug()){WHERE; MsPrintTick();}
#else	// WIN32
#define	WHEN
#endif	// WIN32

#ifdef	OS_UNIX
#ifndef	UNIX_SOLARIS
#ifndef	CPU_SH4
// Getifaddrs system call is supported on UNIX other than Solaris.
// However, it is not supported also by the Linux on SH4 CPU
#define	MAYAQUA_SUPPORTS_GETIFADDRS
#endif	// CPU_SH4
#endif	// UNIX_SOLARIS
#endif	// OS_UNIX

#ifdef	OS_UNIX
// Header only needed in UNIX OS
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>
#include <dirent.h>
#ifdef	UNIX_LINUX
#include <sys/vfs.h>
#elif	UNIX_BSD
#include <sys/param.h>
#include <sys/mount.h>
#endif
#ifdef	UNIX_SOLARIS
#include <sys/statvfs.h>
#define	USE_STATVFS
#endif	// UNIX_SOLARIS
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#ifdef	UNIX_SOLARIS
#include <sys/filio.h>
#endif	// UNIX_SOLARIS
#include <sys/poll.h>
#include <sys/resource.h>
#include <pthread.h>
#ifdef	UNIX_LINUX
#include <sys/prctl.h>
#endif	// UNIX_LINUX
#include <signal.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
//#include <netinet/ip.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <readline/readline.h>
#include <readline/history.h>
//#include <curses.h>
#ifdef	MAYAQUA_SUPPORTS_GETIFADDRS
#include <ifaddrs.h>
#endif	// MAYAQUA_SUPPORTS_GETIFADDRS

#ifdef	UNIX_LINUX
typedef void *iconv_t;
iconv_t iconv_open(__const char *__tocode, __const char *__fromcode);
size_t iconv(iconv_t __cd, char **__restrict __inbuf,
	size_t *__restrict __inbytesleft,
	char **__restrict __outbuf,
	size_t *__restrict __outbytesleft);
int iconv_close(iconv_t __cd);
#else	// UNIX_LINUX
#include <iconv.h>
#endif	// UNIX_LINUX



#ifdef	UNIX_LINUX
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#endif	// UNIX_LINUX

#ifdef	UNIX_SOLARIS
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#endif	// UNIX_SOLARIS

#ifdef	UNIX_MACOS
#include <sys/event.h>
#endif	// UNIX_MACOS

#ifndef	NO_VLAN


#ifdef	UNIX_LINUX

// -----------------------------------------------------------------
// Tap header for Linux
// -----------------------------------------------------------------
/*
*  Universal TUN/TAP device driver.
*  Copyright (C) 1999-2000 Maxim Krasnyansky <max_mk@yahoo.com>
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*  GNU General Public License for more details.
*
*  $Id: if_tun.h,v 1.2 2001/10/31 15:27:57 arjanv Exp $
*/

#ifndef __IF_TUN_H
#define __IF_TUN_H

/* Uncomment to enable debugging */
/* #define TUN_DEBUG 1 */



/* Read queue size */
#define TUN_READQ_SIZE  10

/* TUN device flags */
#define TUN_TUN_DEV     0x0001  
#define TUN_TAP_DEV     0x0002
#define TUN_TYPE_MASK   0x000f

#define TUN_FASYNC      0x0010
#define TUN_NOCHECKSUM  0x0020
#define TUN_NO_PI       0x0040
#define TUN_ONE_QUEUE   0x0080
#define TUN_PERSIST     0x0100  

/* Ioctl defines */
#define TUNSETNOCSUM  _IOW('T', 200, int) 
#define TUNSETDEBUG   _IOW('T', 201, int) 
#define TUNSETIFF     _IOW('T', 202, int) 
#define TUNSETPERSIST _IOW('T', 203, int) 
#define TUNSETOWNER   _IOW('T', 204, int)

/* TUNSETIFF ifr flags */
#define IFF_TUN         0x0001
#define IFF_TAP         0x0002
#define IFF_NO_PI       0x1000
#define IFF_ONE_QUEUE   0x2000

struct tun_pi {
	unsigned short flags;
	unsigned short proto;
};
#define TUN_PKT_STRIP   0x0001

#endif /* __IF_TUN_H */
#else	// UNIX_LINUX

#ifdef	UNIX_SOLARIS

// -----------------------------------------------------------------
// Tap header for Solaris
// -----------------------------------------------------------------
/*
*  Universal TUN/TAP device driver.
*
*  Multithreaded STREAMS tun pseudo device driver.
*
*  Copyright (C) 1999-2000 Maxim Krasnyansky <max_mk@yahoo.com>
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*  GNU General Public License for more details.
*
*  $Id: if_tun.h,v 1.4 2000/05/01 12:23:27 maxk Exp $
*/

#ifndef _SYS_IF_TUN_H
#define _SYS_IF_TUN_H

#ifdef _KERNEL
/* Uncomment to enable debuging */
/* #define TUN_DEBUG 1 */

#ifdef TUN_DEBUG
#define DBG      cmn_err
#else
#define DBG( a... )
#endif

/* PPA structure, one per TUN iface */
struct tunppa {
	unsigned int id;              /* Iface number         */
	queue_t *rq;                  /* Control Stream RQ    */
	struct tunstr * p_str;        /* Protocol Streams     */
};
#define TUNMAXPPA       20

/* Stream structure, one per Stream */
struct tunstr {
	struct tunstr *s_next;        /* next in streams list */
	struct tunstr *p_next;        /* next in ppa list */
	queue_t *rq;                  /* pointer to rq */

	struct tunppa *ppa;           /* assigned PPA */
	u_long flags;                 /* flags */
	u_long state;                 /* DL state */
	u_long sap;                   /* bound sap */
	u_long minor;                 /* minor device number */
};

/* Flags */
#define TUN_CONTROL     0x0001

#define TUN_RAW         0x0100
#define TUN_FAST        0x0200

#define TUN_ALL_PHY     0x0010
#define TUN_ALL_SAP     0x0020
#define TUN_ALL_MUL     0x0040

#define SNIFFER(a) ( (a & TUN_ALL_SAP) || (a & TUN_ALL_PHY) )

struct tundladdr {
	u_short sap;
};
#define TUN_ADDR_LEN    (sizeof(struct tundladdr))

#define TUN_QUEUE       0
#define TUN_DROP        1

#endif /* _KERNEL */

/* IOCTL defines */
#define TUNNEWPPA       (('T'<<16) | 0x0001)
#define TUNSETPPA       (('T'<<16) | 0x0002)

#endif  /* _SYS_IF_TUN_H */

#else	// UNIX_SOLARIS

#if	defined(UNIX_BSD) || (!defined(NO_VLAN) && defined(UNIX_MACOS))

// -----------------------------------------------------------------
// Tap header for FreeBSD
// -----------------------------------------------------------------
// -----------------------------------------------------------------
// Tap header For MacOS
// -----------------------------------------------------------------
/*      $NetBSD: if_tun.h,v 1.5 1994/06/29 06:36:27 cgd Exp $   */

/*
* Copyright (c) 1988, Julian Onions <jpo@cs.nott.ac.uk>
* Nottingham University 1987.
*
* This source may be freely distributed, however I would be interested
* in any changes that are made.
*
* This driver takes packets off the IP i/f and hands them up to a
* user process to have its wicked way with. This driver has it's
* roots in a similar driver written by Phil Cockcroft (formerly) at
* UCL. This driver is based much more on read/write/select mode of
* operation though.
*
* $FreeBSD: src/sys/net/if_tun.h,v 1.17 2000/01/23 01:47:12 brian Exp $
*/

#ifndef _NET_IF_TUN_H_
#define _NET_IF_TUN_H_

/* Refer to if_tunvar.h for the softc stuff */

/* Maximum transmit packet size (default) */
#define TUNMTU          1500

/* Maximum receive packet size (hard limit) */
#define TUNMRU          16384

struct tuninfo {
	int     baudrate;               /* linespeed */
	short   mtu;                    /* maximum transmission unit */
	u_char  type;                   /* ethernet, tokenring, etc. */
	u_char  dummy;                  /* place holder */
};

/* ioctl's for get/set debug */
#define TUNSDEBUG       _IOW('t', 90, int)
#define TUNGDEBUG       _IOR('t', 89, int)
#define TUNSIFINFO      _IOW('t', 91, struct tuninfo)
#define TUNGIFINFO      _IOR('t', 92, struct tuninfo)
#define TUNSLMODE       _IOW('t', 93, int)
#define TUNSIFMODE      _IOW('t', 94, int)
#define TUNSIFPID       _IO('t', 95)
#define TUNSIFHEAD      _IOW('t', 96, int)
#define TUNGIFHEAD      _IOR('t', 97, int)

#endif /* !_NET_IF_TUN_H_ */

#else	// UNIX_BSD

#endif	// defined(UNIX_BSD) || (!defined(NO_VLAN) && defined(UNIX_MACOS))

#endif	// UNIX_SOLARIS

#endif	// UNIX_LINUX



#endif	// NO_VLAN

#define	closesocket(s)		close(s)

#else	// Win32 only

#include <conio.h>

#endif	// OS_UNIX

// IPv6 support flag
#ifndef	WIN32
#ifndef	AF_INET6
#define	NO_IPV6
#endif	// AF_INET6
#endif	// WIN32

//////////////////////////////////////////////////////////////////////////
// MayaType

// Check whether the windows.h header is included
#ifndef	WINDOWS_H
#ifdef	_WINDOWS_
#define	WINDOWS_H
#endif	// _WINDOWS_
#endif	// WINDOWS_H

#if	!defined(SECLIB_INTERNAL)
// Structure which is used by OpenSSL
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct X509_req_st X509_REQ;
typedef struct PKCS12 PKCS12;
typedef struct bignum_st BIGNUM;
typedef struct x509_crl_st X509_CRL;
#endif	// ENCRYPT_C


// 
// Constant
// 

// Standard buffer size
#define	STD_SIZE			512
#define	MAX_SIZE			512
#define	BUF_SIZE			512

// Support Windows OS list
#define	SUPPORTED_WINDOWS_LIST		"Windows 98 / 98 SE / ME / NT 4.0 SP6a / 2000 SP4 / XP SP2, SP3 / Vista SP1, SP2 / 7 SP1 / 8 / 8.1 / 10 / Server 2003 SP2 / Server 2008 SP1, SP2 / Hyper-V Server 2008 / Server 2008 R2 SP1 / Hyper-V Server 2008 R2 / Server 2012 / Hyper-V Server 2012 / Server 2012 R2 / Hyper-V Server 2012 R2 / Server 2016"

// Infinite
#ifndef	WINDOWS_H
#define	INFINITE			(0xFFFFFFFF)
#endif


#define	SRC_NAME			__FILE__	// File name of the source code
#define	SRC_LINE			__LINE__	// Line number in the source code

// Maximum path size
#ifndef	WINDOWS_H
#define	MAX_PATH			260
#endif	// WINDOWS_H

// Types of seek
#ifndef	FILE_BEGIN
#define	FILE_BEGIN	SEEK_SET
#endif	// FILE_BEGIN
#ifndef	FILE_END
#define	FILE_END	SEEK_END
#endif	// FILE_END
#ifndef	FILE_CURRENT
#define	FILE_CURRENT	SEEK_CUR
#endif	// FILE_CURRENT

#ifndef	INVALID_SOCKET
#define	INVALID_SOCKET		(-1)
#endif	// INVALID_SOCKET

#ifndef	SOCKET_ERROR
#define	SOCKET_ERROR		(-1)
#endif	//SOCKET_ERROR

// Comparison function
typedef int (COMPARE)(void *p1, void *p2);


// 
// Macro


#ifdef	MAX
#undef	MAX
#endif	// MAX

#ifdef	MIN
#undef	MIN
#endif	// MIN

// Minimum value of a and b
#define	MIN(a, b)			((a) >= (b) ? (b) : (a))
// Maximum value of a and b
#define	MAX(a, b)			((a) >= (b) ? (a) : (b))

// Convert an int value to bool
#define	INT_TO_BOOL(i)		(((i) == 0) ? false : true)
#define	MAKEBOOL(i)			INT_TO_BOOL(i)
#define	BOOL_TO_INT(i)		(((i) == false) ? 0 : 1)

// Invert the bool type value
#define	NEGATIVE_BOOL(i)	(((i) == false) ? true : false)

// Return 'a' less than max_value
#define	LESS(a, max_value)	((a) <= (max_value) ? (a) : (max_value))
// Return 'a' greater than min_value
#define	MORE(a, min_value)	((a) >= (min_value) ? (a) : (min_value))
// Examine whether the value a is between the b and c
#define	INNER(a, b, c)		(((b) <= (c) && (a) >= (b) && (a) <= (c)) || ((b) >= (c) && (a) >= (c) && (a) <= (b)))
// Examine whether the value a is outbound of b and c
#define	OUTER(a, b, c)		(!INNER((a), (b), (c)))
// Adjust value 'a' to be between b and c
#define	MAKESURE(a, b, c)		(((b) <= (c)) ? (MORE(LESS((a), (c)), (b))) : (MORE(LESS((a), (b)), (c))))
// Compare a and b
#define COMPARE_RET(a, b)	(((a) == (b)) ? 0 : (((a) > (b)) ? 1 : -1))
// Compare bool type values
#define	EQUAL_BOOL(a, b)	(((a) && (b)) || ((!(a)) && (!(b))))
// Get the absolute value
#define	GET_ABS(a)			((a) >= 0 ? (a) : -(a))

// Convert the pointer to UINT
#define	POINTER_TO_KEY(p)		((sizeof(void *) == sizeof(UINT)) ? (UINT)(p) : HashPtrToUINT(p))
// Compare the pointer and UINT
#define	COMPARE_POINTER_AND_KEY(p, i)	(POINTER_TO_KEY(p) == (i))
// Convert the pointer to UINT64
#define	POINTER_TO_UINT64(p)	(((sizeof(void *) == sizeof(UINT64)) ? (UINT64)(p) : (UINT64)((UINT)(p))))
// Convert a UINT64 to pointer
#define	UINT64_TO_POINTER(i)	((sizeof(void *) == sizeof(UINT64)) ? (void *)(i) : (void *)((UINT)(i)))

// Add the value
#define	UINT_ADD(i, j)		((i == INFINITE || i == 0x7fffffff) ? (i) : (i += j))

// Reading data that is not dependent on the boundary or the endian
#define	READ_USHORT(buf)		(USHORT)((((USHORT)((UCHAR *)(buf))[0]) << 8) | (((USHORT)((UCHAR *)(buf))[1])))
#define	READ_UINT(buf)			(UINT)((((UINT)((UCHAR *)(buf))[0]) << 24) | (((UINT)((UCHAR *)(buf))[1]) << 16) | (((UINT)((UCHAR *)(buf))[2]) << 8) | (((UINT)((UCHAR *)(buf))[3])))
#define	READ_UINT64(buf)		(UINT64)((((UINT64)((UCHAR *)(buf))[0]) << 56) | (((UINT64)((UCHAR *)(buf))[1]) << 48) | (((UINT64)((UCHAR *)(buf))[2]) << 40) | (((UINT64)((UCHAR *)(buf))[3]) << 32) | (((UINT64)((UCHAR *)(buf))[4]) << 24) | (((UINT64)((UCHAR *)(buf))[5]) << 16) | (((UINT64)((UCHAR *)(buf))[6]) << 8) | (((UINT64)((UCHAR *)(buf))[7])))

// Writing data that is not dependent on the boundary or endian
#define	WRITE_USHORT(buf, i)	(((UCHAR *)(buf))[0]) = ((((USHORT)(i)) >> 8) & 0xFF); (((UCHAR *)(buf))[1]) = ((((USHORT)(i))) & 0xFF)
#define	WRITE_UINT(buf, i)		(((UCHAR *)(buf))[0]) = ((((UINT)(i)) >> 24) & 0xFF); (((UCHAR *)(buf))[1]) = ((((UINT)(i)) >> 16) & 0xFF); (((UCHAR *)(buf))[2]) = ((((UINT)(i)) >> 8) & 0xFF); (((UCHAR *)(buf))[3]) = ((((UINT)(i))) & 0xFF)
#define	WRITE_UINT64(buf, i)	(((UCHAR *)(buf))[0]) = ((((UINT64)(i)) >> 56) & 0xFF); (((UCHAR *)(buf))[1]) = ((((UINT64)(i)) >> 48) & 0xFF); (((UCHAR *)(buf))[2]) = ((((UINT64)(i)) >> 40) & 0xFF); (((UCHAR *)(buf))[3]) = ((((UINT64)(i)) >> 32) & 0xFF); (((UCHAR *)(buf))[4]) = ((((UINT64)(i)) >> 24) & 0xFF); (((UCHAR *)(buf))[5]) = ((((UINT64)(i)) >> 16) & 0xFF); (((UCHAR *)(buf))[6]) = ((((UINT64)(i)) >> 8) & 0xFF); (((UCHAR *)(buf))[7]) = ((((UINT64)(i))) & 0xFF)



// 
// Type declaration
// 

// bool type
#ifndef	WINDOWS_H
typedef	unsigned int		BOOL;
#define	TRUE				1
#define	FALSE				0
#endif	// WINDOWS_H

// bool type
#ifndef	WIN32COM_CPP
typedef	unsigned int		bool;
#define	true				1
#define	false				0
#endif	// WIN32COM_CPP

// 32bit integer type
#ifndef	WINDOWS_H
typedef	unsigned int		UINT;
typedef	unsigned int		UINT32;
typedef	unsigned int		DWORD;
typedef	signed int			INT;
typedef	signed int			INT32;

typedef	int					UINT_PTR;
typedef	long				LONG_PTR;

#endif

// 16bit integer type
typedef	unsigned short		WORD;
typedef	unsigned short		USHORT;
typedef	signed short		SHORT;

// 8bit integer type
typedef	unsigned char		BYTE;
typedef	unsigned char		UCHAR;

#ifndef	WIN32COM_CPP
typedef signed char			CHAR;
#endif	// WIN32COM_CPP


// 64-bit integer type
typedef	unsigned long long	UINT64;
typedef signed long long	INT64;

typedef signed long long	time_64t;

#ifdef	OS_UNIX
// Avoiding compile error
#define	__cdecl
#define	__declspec(x)
// socket type
typedef	int SOCKET;
#else	// OS_UNIX
#ifndef	_WINSOCK2API_
typedef UINT_PTR SOCKET;
#endif	// _WINSOCK2API_
#endif	// OS_UNIX

// OS type
#define	OSTYPE_WINDOWS_95						1100	// Windows 95
#define	OSTYPE_WINDOWS_98						1200	// Windows 98
#define	OSTYPE_WINDOWS_ME						1300	// Windows Me
#define	OSTYPE_WINDOWS_UNKNOWN					1400	// Windows (unknown)
#define	OSTYPE_WINDOWS_NT_4_WORKSTATION			2100	// Windows NT 4.0 Workstation
#define	OSTYPE_WINDOWS_NT_4_SERVER				2110	// Windows NT 4.0 Server
#define	OSTYPE_WINDOWS_NT_4_SERVER_ENTERPRISE	2111	// Windows NT 4.0 Server, Enterprise Edition
#define	OSTYPE_WINDOWS_NT_4_TERMINAL_SERVER		2112	// Windows NT 4.0 Terminal Server
#define	OSTYPE_WINDOWS_NT_4_BACKOFFICE			2113	// BackOffice Server 4.5
#define	OSTYPE_WINDOWS_NT_4_SMS					2114	// Small Business Server 4.5
#define	OSTYPE_WINDOWS_2000_PROFESSIONAL		2200	// Windows 2000 Professional
#define	OSTYPE_WINDOWS_2000_SERVER				2211	// Windows 2000 Server
#define	OSTYPE_WINDOWS_2000_ADVANCED_SERVER		2212	// Windows 2000 Advanced Server
#define	OSTYPE_WINDOWS_2000_DATACENTER_SERVER	2213	// Windows 2000 Datacenter Server
#define	OSTYPE_WINDOWS_2000_BACKOFFICE			2214	// BackOffice Server 2000
#define	OSTYPE_WINDOWS_2000_SBS					2215	// Small Business Server 2000
#define	OSTYPE_WINDOWS_XP_HOME					2300	// Windows XP Home Edition
#define	OSTYPE_WINDOWS_XP_PROFESSIONAL			2301	// Windows XP Professional
#define	OSTYPE_WINDOWS_2003_WEB					2410	// Windows Server 2003 Web Edition
#define	OSTYPE_WINDOWS_2003_STANDARD			2411	// Windows Server 2003 Standard Edition
#define	OSTYPE_WINDOWS_2003_ENTERPRISE			2412	// Windows Server 2003 Enterprise Edition
#define	OSTYPE_WINDOWS_2003_DATACENTER			2413	// Windows Server 2003 DataCenter Edition
#define	OSTYPE_WINDOWS_2003_BACKOFFICE			2414	// BackOffice Server 2003
#define	OSTYPE_WINDOWS_2003_SBS					2415	// Small Business Server 2003
#define	OSTYPE_WINDOWS_LONGHORN_PROFESSIONAL	2500	// Windows Vista
#define	OSTYPE_WINDOWS_LONGHORN_SERVER			2510	// Windows Server 2008
#define	OSTYPE_WINDOWS_7						2600	// Windows 7
#define	OSTYPE_WINDOWS_SERVER_2008_R2			2610	// Windows Server 2008 R2
#define	OSTYPE_WINDOWS_8						2700	// Windows 8
#define	OSTYPE_WINDOWS_SERVER_8					2710	// Windows Server 2012
#define	OSTYPE_WINDOWS_81						2701	// Windows 8.1
#define	OSTYPE_WINDOWS_SERVER_81				2711	// Windows Server 2012 R2
#define	OSTYPE_WINDOWS_10						2702	// Windows 10
#define	OSTYPE_WINDOWS_SERVER_10				2712	// Windows Server 10
#define	OSTYPE_WINDOWS_11						2800	// Windows 11 or later
#define	OSTYPE_WINDOWS_SERVER_11				2810	// Windows Server 11 or later
#define	OSTYPE_UNIX_UNKNOWN						3000	// Unknown UNIX
#define	OSTYPE_LINUX							3100	// Linux
#define	OSTYPE_SOLARIS							3200	// Solaris
#define	OSTYPE_CYGWIN							3300	// Cygwin
#define	OSTYPE_BSD								3400	// BSD
#define	OSTYPE_MACOS_X							3500	// MacOS X


// OS discrimination macro
#define	GET_KETA(t, i)			(((t) % (i * 10)) / i)
#define	OS_IS_WINDOWS_9X(t)		(GET_KETA(t, 1000) == 1)
#define	OS_IS_WINDOWS_NT(t)		(GET_KETA(t, 1000) == 2)
#define	OS_IS_WINDOWS(t)		(OS_IS_WINDOWS_9X(t) || OS_IS_WINDOWS_NT(t))
#define	OS_IS_SERVER(t)			(OS_IS_WINDOWS_NT(t) && GET_KETA(t, 10))
#define	OS_IS_WORKSTATION(t)	((OS_IS_WINDOWS_NT(t) && (!(GET_KETA(t, 10)))) || OS_IS_WINDOWS_9X(t))
#define	OS_IS_UNIX(t)			(GET_KETA(t, 1000) == 3)


// OS information
typedef struct OS_INFO
{
	UINT OsType;								// OS type
	UINT OsServicePack;							// Service pack number
	char *OsSystemName;							// OS system name
	char *OsProductName;						// OS product name
	char *OsVendorName;							// OS vendor name
	char *OsVersion;							// OS version
	char *KernelName;							// Kernel name
	char *KernelVersion;						// Kernel version
} OS_INFO;

// Time type
#ifndef	WINDOWS_H
typedef struct SYSTEMTIME
{
	WORD wYear;
	WORD wMonth;
	WORD wDayOfWeek;
	WORD wDay;
	WORD wHour;
	WORD wMinute;
	WORD wSecond;
	WORD wMilliseconds;
} SYSTEMTIME;
#endif	// WINDOWS_H


// Object.h
typedef struct LOCK LOCK;
typedef struct COUNTER COUNTER;
typedef struct REF REF;
typedef struct EVENT EVENT;
typedef struct DEADCHECK DEADCHECK;

// Tracking.h
typedef struct CALLSTACK_DATA CALLSTACK_DATA;
typedef struct TRACKING_OBJECT TRACKING_OBJECT;
typedef struct MEMORY_STATUS MEMORY_STATUS;
typedef struct TRACKING_LIST TRACKING_LIST;

// FileIO.h
typedef struct IO IO;

// Memory.h
typedef struct MEMTAG MEMTAG;
typedef struct BUF BUF;
typedef struct FIFO FIFO;
typedef struct LIST LIST;
typedef struct QUEUE QUEUE;
typedef struct SK SK;
typedef struct CANDIDATE CANDIDATE;
typedef struct STRMAP_ENTRY STRMAP_ENTRY;
typedef struct SHARED_BUFFER SHARED_BUFFER;
typedef struct HASH_LIST HASH_LIST;
typedef struct HASH_ENTRY HASH_ENTRY;
typedef struct PRAND PRAND;

// Str.h
typedef struct TOKEN_LIST TOKEN_LIST;
typedef struct INI_ENTRY INI_ENTRY;

// Internat.h
typedef struct UNI_TOKEN_LIST UNI_TOKEN_LIST;

// Encrypt.h
typedef struct CRYPT CRYPT;
typedef struct NAME NAME;
typedef struct X_SERIAL X_SERIAL;
typedef struct X X;
typedef struct K K;
typedef struct P12 P12;
typedef struct X_CRL X_CRL;
typedef struct DES_KEY_VALUE DES_KEY_VALUE;
typedef struct DES_KEY DES_KEY;
typedef struct DH_CTX DH_CTX;
typedef struct AES_KEY_VALUE AES_KEY_VALUE;
typedef struct CIPHER CIPHER;
typedef struct MD MD;

// Secure.h
typedef struct SECURE_DEVICE SECURE_DEVICE;
typedef struct SEC_INFO SEC_INFO;
typedef struct SECURE SECURE;
typedef struct SEC_OBJ SEC_OBJ;

// Kernel.h
typedef struct MEMINFO MEMINFO;
typedef struct LOCALE LOCALE;
typedef struct THREAD THREAD;
typedef struct THREAD_POOL_DATA THREAD_POOL_DATA;
typedef struct INSTANCE INSTANCE;

// Pack.h
typedef struct VALUE VALUE;
typedef struct ELEMENT ELEMENT;
typedef struct PACK PACK;

// Cfg.h
typedef struct FOLDER FOLDER;
typedef struct ITEM ITEM;
typedef struct CFG_RW CFG_RW;
typedef struct CFG_ENUM_PARAM CFG_ENUM_PARAM;

// Table.h
typedef struct TABLE TABLE;
typedef struct LANGLIST LANGLIST;

// Network.h
typedef struct IP IP;
typedef struct DNSCACHE DNSCACHE;
typedef struct SOCK_EVENT SOCK_EVENT;
typedef struct SOCK SOCK;
typedef struct SOCKSET SOCKSET;
typedef struct CANCEL CANCEL;
typedef struct ROUTE_ENTRY ROUTE_ENTRY;
typedef struct ROUTE_TABLE ROUTE_TABLE;
typedef struct IP_CLIENT IP_CLIENT;
typedef struct ROUTE_CHANGE ROUTE_CHANGE;
typedef struct ROUTE_CHANGE_DATA ROUTE_CHANGE_DATA;
typedef struct GETIP_THREAD_PARAM GETIP_THREAD_PARAM;
typedef struct WIN32_RELEASEADDRESS_THREAD_PARAM WIN32_RELEASEADDRESS_THREAD_PARAM;
typedef struct IPV6_ADDR IPV6_ADDR;
typedef struct TUBE TUBE;
typedef struct TUBEDATA TUBEDATA;
typedef struct PSEUDO PSEUDO;
typedef struct TUBEPAIR_DATA TUBEPAIR_DATA;
typedef struct UDPLISTENER UDPLISTENER;
typedef struct UDPLISTENER_SOCK UDPLISTENER_SOCK;
typedef struct UDPPACKET UDPPACKET;
typedef struct INTERRUPT_MANAGER INTERRUPT_MANAGER;
typedef struct TUBE_FLUSH_LIST TUBE_FLUSH_LIST;
typedef struct ICMP_RESULT ICMP_RESULT;
typedef struct SSL_PIPE SSL_PIPE;
typedef struct SSL_BIO SSL_BIO;
typedef struct RUDP_STACK RUDP_STACK;
typedef struct RUDP_SOURCE_IP RUDP_SOURCE_IP;
typedef struct RUDP_SESSION RUDP_SESSION;
typedef struct RUDP_SEGMENT RUDP_SEGMENT;
typedef struct CONNECT_TCP_RUDP_PARAM CONNECT_TCP_RUDP_PARAM;
typedef struct TCP_PAIR_HEADER TCP_PAIR_HEADER;
typedef struct NIC_ENTRY NIC_ENTRY;
typedef struct HTTP_VALUE HTTP_VALUE;
typedef struct HTTP_HEADER HTTP_HEADER;
typedef struct DNSPROXY_CLIENT DNSPROXY_CLIENT;
typedef struct DNSPROXY_CACHE DNSPROXY_CACHE;
typedef struct QUERYIPTHREAD QUERYIPTHREAD;
typedef struct IPBLOCK IPBLOCK;
typedef struct SAFE_REQUEST SAFE_REQUEST;
typedef struct SAFE_LIST SAFE_LIST;
typedef struct SAFE_QUOTA SAFE_QUOTA;
typedef struct SAFE_QUOTA2 SAFE_QUOTA2;
typedef struct SAFE_BLOCK SAFE_BLOCK;
typedef struct SAFE_REQUEST_LOG SAFE_REQUEST_LOG;
typedef struct DYN_VALUE DYN_VALUE;
typedef struct RELAY_PARAMETER RELAY_PARAMETER;
typedef struct SSL_ACCEPT_SETTINGS SSL_ACCEPT_SETTINGS;

// Tick64.h
typedef struct ADJUST_TIME ADJUST_TIME;
typedef struct TICK64 TICK64;

// FileIO.h
typedef struct DIRENT DIRENT;
typedef struct DIRLIST DIRLIST;
typedef struct ZIP_DATA_HEADER ZIP_DATA_HEADER;
typedef struct ZIP_DATA_FOOTER ZIP_DATA_FOOTER;
typedef struct ZIP_DIR_HEADER ZIP_DIR_HEADER;
typedef struct ZIP_END_HEADER ZIP_END_HEADER;
typedef struct ZIP_FILE ZIP_FILE;
typedef struct ZIP_PACKER ZIP_PACKER;
typedef struct ENUM_DIR_WITH_SUB_DATA ENUM_DIR_WITH_SUB_DATA;

// TcpIp.h
typedef struct MAC_HEADER MAC_HEADER;
typedef struct ARPV4_HEADER ARPV4_HEADER;
typedef struct IPV4_HEADER IPV4_HEADER;
typedef struct TAGVLAN_HEADER TAGVLAN_HEADER;
typedef struct UDP_HEADER UDP_HEADER;
typedef struct UDPV4_PSEUDO_HEADER UDPV4_PSEUDO_HEADER;
typedef struct IPV4_PSEUDO_HEADER IPV4_PSEUDO_HEADER;
typedef struct TCP_HEADER TCP_HEADER;
typedef struct ICMP_HEADER ICMP_HEADER;
typedef struct ICMP_ECHO ICMP_ECHO;
typedef struct DHCPV4_HEADER DHCPV4_HEADER;
typedef struct DNSV4_HEADER DNSV4_HEADER;
typedef struct BPDU_HEADER BPDU_HEADER;
typedef struct LLC_HEADER LLC_HEADER;
typedef struct PKT PKT;
typedef struct IPV6_HEADER_PACKET_INFO IPV6_HEADER_PACKET_INFO;
typedef struct IPV6_HEADER IPV6_HEADER;
typedef struct IPV6_OPTION_HEADER IPV6_OPTION_HEADER;
typedef struct IPV6_FRAGMENT_HEADER IPV6_FRAGMENT_HEADER;
typedef struct IPV6_PSEUDO_HEADER IPV6_PSEUDO_HEADER;
typedef struct ICMPV6_ROUTER_SOLICIATION_HEADER ICMPV6_ROUTER_SOLICIATION_HEADER;
typedef struct ICMPV6_ROUTER_ADVERTISEMENT_HEADER ICMPV6_ROUTER_ADVERTISEMENT_HEADER;
typedef struct ICMPV6_NEIGHBOR_SOLICIATION_HEADER ICMPV6_NEIGHBOR_SOLICIATION_HEADER;
typedef struct ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER;
typedef struct ICMPV6_OPTION_LIST ICMPV6_OPTION_LIST;
typedef struct ICMPV6_OPTION ICMPV6_OPTION;
typedef struct ICMPV6_OPTION_LINK_LAYER ICMPV6_OPTION_LINK_LAYER;
typedef struct ICMPV6_OPTION_PREFIX ICMPV6_OPTION_PREFIX;
typedef struct ICMPV6_OPTION_MTU ICMPV6_OPTION_MTU;
typedef struct IPV6_HEADER_INFO IPV6_HEADER_INFO;
typedef struct ICMPV6_HEADER_INFO ICMPV6_HEADER_INFO;
typedef struct DHCPV4_DATA DHCPV4_DATA;
typedef struct DHCP_OPTION DHCP_OPTION;
typedef struct DHCP_OPTION_LIST DHCP_OPTION_LIST;
typedef struct DHCP_CLASSLESS_ROUTE DHCP_CLASSLESS_ROUTE;
typedef struct DHCP_CLASSLESS_ROUTE_TABLE DHCP_CLASSLESS_ROUTE_TABLE;
typedef struct HTTPLOG HTTPLOG;
typedef struct DHCP_MODIFY_OPTION DHCP_MODIFY_OPTION;
typedef struct NBTDG_HEADER NBTDG_HEADER;
typedef struct IKE_HEADER IKE_HEADER;

//////////////////////////////////////////////////////////////////////////
// Object
// Constants
#define	OBJECT_ALLOC_FAIL_SLEEP_TIME		150
#define	OBJECT_ALLOC__MAX_RETRY				30

// Lock object
struct LOCK
{
	void *pData;
	BOOL Ready;
#ifdef	OS_UNIX
	UINT thread_id;
	UINT locked_count;
#endif	// OS_UNIX
#ifdef	_DEBUG
	char *FileName;
	UINT Line;
	UINT ThreadId;
#endif	// _DEBUG
};

// Counter object
struct COUNTER
{
	LOCK *lock;
	UINT c;
	bool Ready;
};

// Reference counter
struct REF
{
	COUNTER *c;
};

// Event object
struct EVENT
{
	REF *ref;
	void *pData;
};

// Deadlock detection
struct DEADCHECK
{
	LOCK *Lock;
	UINT Timeout;
	bool Unlocked;
};


// Lock function
#ifndef	_DEBUG

#define	Lock(lock)		LockInner((lock))
#define	Unlock(lock)	UnlockInner((lock))

#else	// _DEBUG

#define	Lock(lock)			\
	{						\
		LockInner(lock);	\
		if (lock != NULL) { lock->FileName = __FILE__; lock->Line = __LINE__; lock->ThreadId = ThreadId();}	\
	}

#define	Unlock(lock)		\
	{						\
		if (lock != NULL) { lock->FileName = NULL; lock->Line = 0; lock->ThreadId = 0;}	\
		UnlockInner(lock);	\
	}

#endif	// _DEBUG


// Function prototype
LOCK *NewLock();
LOCK *NewLockMain();
void DeleteLock(LOCK *lock);
COUNTER *NewCounter();
void UnlockInner(LOCK *lock);
bool LockInner(LOCK *lock);
void DeleteCounter(COUNTER *c);
UINT Count(COUNTER *c);
UINT Inc(COUNTER *c);
UINT Dec(COUNTER *c);
UINT Release(REF *ref);
UINT AddRef(REF *ref);
REF *NewRef();
EVENT *NewEvent();
void ReleaseEvent(EVENT *e);
void CleanupEvent(EVENT *e);
void Set(EVENT *e);
bool Wait(EVENT *e, UINT timeout);
bool WaitEx(EVENT *e, UINT timeout, volatile bool *cancel);
void CheckDeadLock(LOCK *lock, UINT timeout, char *name);
void CheckDeadLockThread(THREAD *t, void *param);

//////////////////////////////////////////////////////////////////////////
// Tracking

// The number of array
#define	TRACKING_NUM_ARRAY	1048576

// Hash from an pointer to an array index
#define	TRACKING_HASH(p)	(UINT)(((((UINT64)(p)) / (UINT64)(sizeof(void *))) % ((UINT64)TRACKING_NUM_ARRAY)))

// Call stack
struct CALLSTACK_DATA
{
	bool symbol_cache;
	UINT64 offset, disp;
	char *name;
	struct CALLSTACK_DATA *next;
	char filename[MAX_PATH];
	UINT line;
};

// Object
struct TRACKING_OBJECT
{
	UINT Id;
	char *Name;
	UINT64 Address;
	UINT Size;
	UINT64 CreatedDate;
	CALLSTACK_DATA *CallStack;
	char FileName[MAX_PATH];
	UINT LineNumber;
};

// Usage of the memory
struct MEMORY_STATUS
{
	UINT MemoryBlocksNum;
	UINT MemorySize;
};

// Tracking list
struct TRACKING_LIST
{
	struct TRACKING_LIST *Next;
	struct TRACKING_OBJECT *Object;
};

CALLSTACK_DATA *GetCallStack();
bool GetCallStackSymbolInfo(CALLSTACK_DATA *s);
void FreeCallStack(CALLSTACK_DATA *s);
CALLSTACK_DATA *WalkDownCallStack(CALLSTACK_DATA *s, UINT num);
void GetCallStackStr(char *str, UINT size, CALLSTACK_DATA *s);
void PrintCallStack(CALLSTACK_DATA *s);
void InitTracking();
void FreeTracking();
int CompareTrackingObject(const void *p1, const void *p2);
void LockTrackingList();
void UnlockTrackingList();
void InsertTrackingList(TRACKING_OBJECT *o);
void DeleteTrackingList(TRACKING_OBJECT *o, bool free_object_memory);
TRACKING_OBJECT *SearchTrackingList(UINT64 Address);

void TrackNewObj(UINT64 addr, char *name, UINT size);
void TrackGetObjSymbolInfo(TRACKING_OBJECT *o);
void TrackDeleteObj(UINT64 addr);
void TrackChangeObjSize(UINT64 addr, UINT size, UINT64 new_addr);

void GetMemoryStatus(MEMORY_STATUS *status);
void PrintMemoryStatus();
void MemoryDebugMenu();
int SortObjectView(void *p1, void *p2);
void DebugPrintAllObjects();
void DebugPrintCommandList();
void PrintObjectList(TRACKING_OBJECT *o);
void PrintObjectInfo(TRACKING_OBJECT *o);
void DebugPrintObjectInfo(UINT id);

void TrackingEnable();
void TrackingDisable();
bool IsTrackingEnabled();

//////////////////////////////////////////////////////////////////////////
// FileIO

// Constant
#define	HAMCORE_DIR_NAME			"hamcore"
#define	HAMCORE_FILE_NAME			"hamcore.se2"
#define	HAMCORE_FILE_NAME_2			"_hamcore.se2"
#define	HAMCORE_TEXT_NAME			"hamcore.txt"
#define	HAMCORE_HEADER_DATA			"HamCore"
#define	HAMCORE_HEADER_SIZE			7
#define	HAMCORE_CACHE_EXPIRES		(5 * 60 * 1000)

// IO structure
struct IO
{
	char Name[MAX_SIZE];
	wchar_t NameW[MAX_SIZE];
	void *pData;
	bool WriteMode;
	bool HamMode;
	BUF *HamBuf;
	UINT64 SetUpdateTime, SetCreateTime;
	UINT64 GetUpdateTime, GetCreateTime, GetAccessTime;
};

// HC structure
typedef struct HC
{
	char *FileName;				// File name
	UINT Size;					// File size
	UINT SizeCompressed;		// Compressed file size
	UINT Offset;				// Offset
	void *Buffer;				// Buffer
	UINT64 LastAccess;			// Access Date
} HC;

// DIRENT structure
struct DIRENT
{
	bool Folder;				// Folder
	char *FileName;				// File name (ANSI)
	wchar_t *FileNameW;			// File name (Unicode)
	UINT64 FileSize;			// File size
	UINT64 CreateDate;			// Creation Date
	UINT64 UpdateDate;			// Updating date
};

// DIRLIST structure
struct DIRLIST
{
	UINT NumFiles;				// Number of files
	struct DIRENT **File;			// File array
};

// ZIP related structure
#ifdef	OS_WIN32
#pragma pack(push, 1)
#endif	// OS_WIN32

struct ZIP_DATA_HEADER
{
	UINT Signature;
	USHORT NeedVer;
	USHORT Option;
	USHORT CompType;
	USHORT FileTime;
	USHORT FileDate;
	UINT Crc32;
	UINT CompSize;
	UINT UncompSize;
	USHORT FileNameLen;
	USHORT ExtraLen;
} GCC_PACKED;

struct ZIP_DATA_FOOTER
{
	UINT Signature;
	UINT Crc32;
	UINT CompSize;
	UINT UncompSize;
} GCC_PACKED;

struct ZIP_DIR_HEADER
{
	UINT Signature;
	USHORT MadeVer;
	USHORT NeedVer;
	USHORT Option;
	USHORT CompType;
	USHORT FileTime;
	USHORT FileDate;
	UINT Crc32;
	UINT CompSize;
	UINT UncompSize;
	USHORT FileNameLen;
	USHORT ExtraLen;
	USHORT CommentLen;
	USHORT DiskNum;
	USHORT InAttr;
	UINT OutAttr;
	UINT HeaderPos;
} GCC_PACKED;

struct ZIP_END_HEADER
{
	UINT Signature;
	USHORT DiskNum;
	USHORT StartDiskNum;
	USHORT DiskDirEntry;
	USHORT DirEntry;
	UINT DirSize;
	UINT StartPos;
	USHORT CommentLen;
} GCC_PACKED;

#define	ZIP_SIGNATURE				0x04034B50
#define	ZIP_SIGNATURE_END			0x06054B50
#define	ZIP_VERSION					10
#define	ZIP_VERSION_WITH_COMPRESS	20

#ifdef	OS_WIN32
#pragma pack(pop)
#endif	// OS_WIN32

struct ZIP_FILE
{
	char Name[MAX_PATH];
	UINT Size;
	UINT64 DateTime;
	UINT Attributes;
	UINT CurrentSize;
	UINT CompressSize;
	UINT Crc32;
	UINT HeaderPos;
};

struct ZIP_PACKER
{
	FIFO *Fifo;
	LIST *FileList;
	ZIP_FILE *CurrentFile;
};

struct ENUM_DIR_WITH_SUB_DATA
{
	LIST *FileList;
};

void InitCrc32();
UINT Crc32(void *buf, UINT pos, UINT len);
UINT Crc32First(void *buf, UINT pos, UINT len);
UINT Crc32Next(void *buf, UINT pos, UINT len, UINT last_crc32);
UINT Crc32Finish(UINT last_crc32);
void WriteZipDataHeader(ZIP_FILE *f, ZIP_DATA_HEADER *h, bool write_sizes);
void WriteZipDataFooter(ZIP_FILE *f, ZIP_DATA_FOOTER *h);
ZIP_PACKER *NewZipPacker();
void FreeZipPacker(ZIP_PACKER *p);
void ZipAddFileSimple(ZIP_PACKER *p, char *name, UINT64 dt, UINT attribute, void *data, UINT size);
bool ZipAddRealFileW(ZIP_PACKER *p, char *name, UINT64 dt, UINT attribute, wchar_t *srcname);
bool ZipAddRealFile(ZIP_PACKER *p, char *name, UINT64 dt, UINT attribute, char *srcname);
void ZipAddFileStart(ZIP_PACKER *p, char *name, UINT size, UINT64 dt, UINT attribute);
UINT ZipAddFileData(ZIP_PACKER *p, void *data, UINT pos, UINT len);
void ZipAddFileFooter(ZIP_PACKER *p);
FIFO *ZipFinish(ZIP_PACKER *p);
bool ZipWriteW(ZIP_PACKER *p, wchar_t *name);

bool DeleteDirInner(char *name);
bool DeleteDirInnerW(wchar_t *name);
bool DeleteDir(char *name);
bool DeleteDirW(wchar_t *name);
bool MakeDirInner(char *name);
bool MakeDirInnerW(wchar_t *name);
bool MakeDir(char *name);
bool MakeDirW(wchar_t *name);
bool MakeDirEx(char *name);
bool MakeDirExW(wchar_t *name);
bool FileDeleteInner(char *name);
bool FileDeleteInnerW(wchar_t *name);
bool FileDelete(char *name);
bool FileDeleteW(wchar_t *name);
bool FileSeek(IO *o, UINT mode, int offset);
UINT FileSize(IO *o);
UINT64 FileSize64(IO *o);
UINT FileSizeEx(char *name);
UINT FileSizeExW(wchar_t *name);
bool FileRead(IO *o, void *buf, UINT size);
bool FileWrite(IO *o, void *buf, UINT size);
void FileFlush(IO *o);
void FileClose(IO *o);
void FileCloseEx(IO *o, bool no_flush);
void FileCloseAndDelete(IO *o);
IO *FileCreateInner(char *name);
IO *FileCreateInnerW(wchar_t *name);
IO *FileCreate(char *name);
IO *FileCreateW(wchar_t *name);
bool FileWriteAll(char *name, void *data, UINT size);
bool FileWriteAllW(wchar_t *name, void *data, UINT size);
IO *FileOpenInner(char *name, bool write_mode, bool read_lock);
IO *FileOpenInnerW(wchar_t *name, bool write_mode, bool read_lock);
IO *FileOpen(char *name, bool write_mode);
IO *FileOpenW(wchar_t *name, bool write_mode);
IO *FileOpenEx(char *name, bool write_mode, bool read_lock);
IO *FileOpenExW(wchar_t *name, bool write_mode, bool read_lock);
void ConvertPath(char *path);
void ConvertPathW(wchar_t *path);
bool FileRenameInner(char *old_name, char *new_name);
bool FileRenameInnerW(wchar_t *old_name, wchar_t *new_name);
bool FileRename(char *old_name, char *new_name);
bool FileRenameW(wchar_t *old_name, wchar_t *new_name);
void NormalizePath(char *dst, UINT size, char *src);
void NormalizePathW(wchar_t *dst, UINT size, wchar_t *src);
bool GetRelativePathW(wchar_t *dst, UINT size, wchar_t *fullpath, wchar_t *basepath);
bool GetRelativePath(char *dst, UINT size, char *fullpath, char *basepath);
TOKEN_LIST *ParseSplitedPath(char *path);
UNI_TOKEN_LIST *ParseSplitedPathW(wchar_t *path);
char *GetCurrentPathEnvStr();
bool IsFileExistsInner(char *name);
bool IsFileExistsInnerW(wchar_t *name);
bool IsFileExists(char *name);
bool IsFileExistsW(wchar_t *name);
void InnerFilePath(char *dst, UINT size, char *src);
void InnerFilePathW(wchar_t *dst, UINT size, wchar_t *src);
void ConbinePath(char *dst, UINT size, char *dirname, char *filename);
void ConbinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename);
void CombinePath(char *dst, UINT size, char *dirname, char *filename);
void CombinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename);
void GetDirNameFromFilePath(char *dst, UINT size, char *filepath);
void GetDirNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *filepath);
void GetFileNameFromFilePath(char *dst, UINT size, char *filepath);
void GetFileNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *filepath);
void MakeSafeFileName(char *dst, UINT size, char *src);
void MakeSafeFileNameW(wchar_t *dst, UINT size, wchar_t *src);
void InitGetExeName(char *arg);
void UnixGetExeNameW(wchar_t *name, UINT size, wchar_t *arg);
void GetExeName(char *name, UINT size);
void GetExeNameW(wchar_t *name, UINT size);
void GetExeDir(char *name, UINT size);
void GetExeDirW(wchar_t *name, UINT size);
void BuildHamcore(char *dst_filename, char *src_dir, bool unix_only);
int CompareHamcore(void *p1, void *p2);
void InitHamcore();
void FreeHamcore();
BUF *ReadHamcore(char *name);
BUF *ReadHamcoreW(wchar_t *filename);
void SafeFileName(char *name);
void SafeFileNameW(wchar_t *name);
void UniSafeFileName(wchar_t *name);
DIRLIST *EnumDir(char *dirname);
DIRLIST *EnumDirW(wchar_t *dirname);
DIRLIST *EnumDirEx(char *dirname, COMPARE *compare);
DIRLIST *EnumDirExW(wchar_t *dirname, COMPARE *compare);
UNI_TOKEN_LIST *EnumDirWithSubDirsW(wchar_t *dirname);
TOKEN_LIST *EnumDirWithSubDirs(char *dirname);
void EnumDirWithSubDirsMain(ENUM_DIR_WITH_SUB_DATA *d, wchar_t *dirname);
void FreeDir(DIRLIST *d);
int CompareDirListByName(void *p1, void *p2);
bool GetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
bool GetDiskFreeW(wchar_t *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
void ConvertSafeFileName(char *dst, UINT size, char *src);
void ConvertSafeFileNameW(wchar_t *dst, UINT size, wchar_t *src);
bool FileReplaceRename(char *old_name, char *new_name);
bool FileReplaceRenameW(wchar_t *old_name, wchar_t *new_name);
bool IsFile(char *name);
bool IsFileW(wchar_t *name);
void GetCurrentDirW(wchar_t *name, UINT size);
void GetCurrentDir(char *name, UINT size);
bool SaveFileW(wchar_t *name, void *data, UINT size);
bool SaveFile(char *name, void *data, UINT size);
bool IsFileWriteLockedW(wchar_t *name);
bool IsFileWriteLocked(char *name);
bool IsInLines(BUF *buf, char *str, bool instr);
bool IsInLinesFile(wchar_t *filename, char *str, bool instr);


//////////////////////////////////////////////////////////////////////////
// Memory


// MallocFast (not implemented)
#define	MallocFast		Malloc
#define	ZeroMallocFast	ZeroMalloc

// Memory size that can be passed to the kernel at a time
#define	MAX_SEND_BUF_MEM_SIZE				(10 * 1024 * 1024)

// The magic number for memory tag
#define	MEMTAG_MAGIC						0x49414449

#define	CALC_MALLOCSIZE(size)				((MAX(size, 1)) + sizeof(MEMTAG))
#define	MEMTAG_TO_POINTER(p)				((void *)(((UCHAR *)(p)) + sizeof(MEMTAG)))
#define	POINTER_TO_MEMTAG(p)				((MEMTAG *)(((UCHAR *)(p)) - sizeof(MEMTAG)))
#define	IS_NULL_POINTER(p)					(((p) == NULL) || ((POINTER_TO_UINT64(p) == (UINT64)sizeof(MEMTAG))))

// Fixed size of a block of memory pool
#define	MEMPOOL_MAX_SIZE					3000


// Memory tag
struct MEMTAG
{
	UINT Magic;
	UINT Size;
	bool ZeroFree;
	UINT Padding;
};

// Buffer
struct BUF
{
	void *Buf;
	UINT Size;
	UINT SizeReserved;
	UINT Current;
};

// FIFO
struct FIFO
{
	REF *ref;
	LOCK *lock;
	void *p;
	UINT pos, size, memsize;
	UINT64 total_read_size;
	UINT64 total_write_size;
	bool fixed;
};

// List
struct LIST
{
	REF *ref;
	UINT num_item, num_reserved;
	void **p;
	LOCK *lock;
	COMPARE *cmp;
	bool sorted;
	UINT64 Param1;
};

// Queue
struct QUEUE
{
	REF *ref;
	UINT num_item;
	FIFO *fifo;
	LOCK *lock;
};

// Stack
struct SK
{
	REF *ref;
	UINT num_item, num_reserved;
	void **p;
	LOCK *lock;
	bool no_compact;
};

// Candidate list
struct CANDIDATE
{
	wchar_t *Str;						// String
	UINT64 LastSelectedTime;			// Date and time last selected
};

struct STRMAP_ENTRY
{
	char *Name;
	void *Value;
};

// Shared buffer
struct SHARED_BUFFER
{
	REF *Ref;
	void *Data;
	UINT Size;
};

// Macro
#define	LIST_DATA(o, i)		(((o) != NULL) ? ((o)->p[(i)]) : NULL)
#define	LIST_NUM(o)			(((o) != NULL) ? (o)->num_item : 0)
#define	HASH_LIST_NUM(o)	(((o) != NULL) ? (o)->NumItems : 0)

// Function pointer type to get a hash function
typedef UINT(GET_HASH)(void *p);

// Hash list
struct HASH_LIST
{
	UINT Bits;
	UINT Size;
	GET_HASH *GetHashProc;
	COMPARE *CompareProc;
	LOCK *Lock;
	REF *Ref;
	LIST **Entries;
	UINT NumItems;
	LIST *AllList;
};

// PRAND
struct PRAND
{
	UCHAR Key[20];
	CRYPT *Rc4;
};

// Function prototype
HASH_LIST *NewHashList(GET_HASH *get_hash_proc, COMPARE *compare_proc, UINT bits, bool make_list);
void ReleaseHashList(HASH_LIST *h);
void CleanupHashList(HASH_LIST *h);
void AddHash(HASH_LIST *h, void *p);
bool DeleteHash(HASH_LIST *h, void *p);
void *SearchHash(HASH_LIST *h, void *t);
UINT CalcHashForHashList(HASH_LIST *h, void *p);
void **HashListToArray(HASH_LIST *h, UINT *num);
void LockHashList(HASH_LIST *h);
void UnlockHashList(HASH_LIST *h);
bool IsInHashListKey(HASH_LIST *h, UINT key);
void *HashListKeyToPointer(HASH_LIST *h, UINT key);

PRAND *NewPRand(void *key, UINT key_size);
void FreePRand(PRAND *r);
void PRand(PRAND *p, void *data, UINT size);
UINT PRandInt(PRAND *p);

LIST *NewCandidateList();
void FreeCandidateList(LIST *o);
int ComapreCandidate(void *p1, void *p2);
void AddCandidate(LIST *o, wchar_t *str, UINT num_max);
BUF *CandidateToBuf(LIST *o);
LIST *BufToCandidate(BUF *b);

void *Malloc(UINT size);
void *MallocEx(UINT size, bool zero_clear_when_free);
void *ZeroMalloc(UINT size);
void *ZeroMallocEx(UINT size, bool zero_clear_when_free);
void *ReAlloc(void *addr, UINT size);
void Free(void *addr);
void CheckMemTag(MEMTAG *tag);
UINT GetMemSize(void *addr);

void *InternalMalloc(UINT size);
void *InternalReAlloc(void *addr, UINT size);
void InternalFree(void *addr);

void Copy(void *dst, void *src, UINT size);
void Move(void *dst, void *src, UINT size);
int Cmp(void *p1, void *p2, UINT size);
int CmpCaseIgnore(void *p1, void *p2, UINT size);
void ZeroMem(void *addr, UINT size);
void Zero(void *addr, UINT size);
void *Clone(void *addr, UINT size);
void *CloneTail(void *src, UINT src_size, UINT dst_size);
void *AddHead(void *src, UINT src_size, void *head, UINT head_size);

char B64_CodeToChar(BYTE c);
char B64_CharToCode(char c);
int B64_Encode(char *set, char *source, int len);
int B64_Decode(char *set, char *source, int len);
UINT Encode64(char *dst, char *src);
UINT Decode64(char *dst, char *src);

void Swap(void *buf, UINT size);
USHORT Swap16(USHORT value);
UINT Swap32(UINT value);
UINT64 Swap64(UINT64 value);
USHORT Endian16(USHORT src);
UINT Endian32(UINT src);
UINT64 Endian64(UINT64 src);
void EndianUnicode(wchar_t *str);

BUF *NewBuf();
BUF *NewBufFromMemory(void *buf, UINT size);
void ClearBuf(BUF *b);
void WriteBuf(BUF *b, void *buf, UINT size);
void WriteBufBuf(BUF *b, BUF *bb);
UINT ReadBuf(BUF *b, void *buf, UINT size);
BUF *ReadBufFromBuf(BUF *b, UINT size);
void AdjustBufSize(BUF *b, UINT new_size);
void SeekBuf(BUF *b, UINT offset, int mode);
void SeekBufToEnd(BUF *b);
void SeekBufToBegin(BUF *b);
void FreeBuf(BUF *b);
bool BufToFile(IO *o, BUF *b);
BUF *FileToBuf(IO *o);
UINT ReadBufInt(BUF *b);
USHORT ReadBufShort(BUF *b);
UINT64 ReadBufInt64(BUF *b);
UCHAR ReadBufChar(BUF *b);
bool WriteBufInt(BUF *b, UINT value);
bool WriteBufInt64(BUF *b, UINT64 value);
bool WriteBufChar(BUF *b, UCHAR uc);
bool WriteBufShort(BUF *b, USHORT value);
bool ReadBufStr(BUF *b, char *str, UINT size);
bool WriteBufStr(BUF *b, char *str);
void WriteBufLine(BUF *b, char *str);
void AddBufStr(BUF *b, char *str);
bool DumpBuf(BUF *b, char *filename);
bool DumpBufW(BUF *b, wchar_t *filename);
bool DumpBufWIfNecessary(BUF *b, wchar_t *filename);
bool DumpData(void *data, UINT size, char *filename);
bool DumpDataW(void *data, UINT size, wchar_t *filename);
BUF *ReadDump(char *filename);
BUF *ReadDumpWithMaxSize(char *filename, UINT max_size);
BUF *ReadDumpW(wchar_t *filename);
BUF *ReadDumpExW(wchar_t *filename, bool read_lock);
BUF *CloneBuf(BUF *b);
BUF *MemToBuf(void *data, UINT size);
BUF *RandBuf(UINT size);
BUF *ReadRemainBuf(BUF *b);
UINT ReadBufRemainSize(BUF *b);
bool CompareBuf(BUF *b1, BUF *b2);

UINT PeekFifo(FIFO *f, void *p, UINT size);
UINT ReadFifo(FIFO *f, void *p, UINT size);
BUF *ReadFifoAll(FIFO *f);
void ShrinkFifoMemory(FIFO *f);
UCHAR *GetFifoPointer(FIFO *f);
UCHAR *FifoPtr(FIFO *f);
void WriteFifo(FIFO *f, void *p, UINT size);
void WriteFifoFront(FIFO *f, void *p, UINT size);
void PadFifoFront(FIFO *f, UINT size);
void ClearFifo(FIFO *f);
UINT FifoSize(FIFO *f);
void LockFifo(FIFO *f);
void UnlockFifo(FIFO *f);
void ReleaseFifo(FIFO *f);
void CleanupFifo(FIFO *f);
FIFO *NewFifo();
FIFO *NewFifoFast();
FIFO *NewFifoEx(bool fast);
FIFO *NewFifoEx2(bool fast, bool fixed);
void InitFifo();
UINT GetFifoCurrentReallocMemSize();
void SetFifoCurrentReallocMemSize(UINT size);

void *Search(LIST *o, void *target);
void Sort(LIST *o);
void SortEx(LIST *o, COMPARE *cmp);
void Add(LIST *o, void *p);
void AddDistinct(LIST *o, void *p);
void Insert(LIST *o, void *p);
void InsertDistinct(LIST *o, void *p);
bool Delete(LIST *o, void *p);
bool DeleteKey(LIST *o, UINT key);
void DeleteAll(LIST *o);
void LockList(LIST *o);
void UnlockList(LIST *o);
void ReleaseList(LIST *o);
void CleanupList(LIST *o);
LIST *NewList(COMPARE *cmp);
LIST *NewListFast(COMPARE *cmp);
LIST *NewListEx(COMPARE *cmp, bool fast);
LIST *NewListEx2(COMPARE *cmp, bool fast, bool fast_malloc);
LIST *NewListSingle(void *p);
void CopyToArray(LIST *o, void *p);
void *ToArray(LIST *o);
void *ToArrayEx(LIST *o, bool fast);
LIST *CloneList(LIST *o);
void SetCmp(LIST *o, COMPARE *cmp);
void SetSortFlag(LIST *o, bool sorted);
int CompareStr(void *p1, void *p2);
bool InsertStr(LIST *o, char *str);
int CompareUniStr(void *p1, void *p2);
bool IsInList(LIST *o, void *p);
bool IsInListKey(LIST *o, UINT key);
void *ListKeyToPointer(LIST *o, UINT key);
bool IsInListStr(LIST *o, char *str);
bool IsInListUniStr(LIST *o, wchar_t *str);
bool ReplaceListPointer(LIST *o, void *oldptr, void *newptr);
void AddInt(LIST *o, UINT i);
void AddInt64(LIST *o, UINT64 i);
void AddIntDistinct(LIST *o, UINT i);
void AddInt64Distinct(LIST *o, UINT64 i);
void DelInt(LIST *o, UINT i);
void DelInt64(LIST *o, UINT64 i);
void ReleaseIntList(LIST *o);
void ReleaseInt64List(LIST *o);
void DelAllInt(LIST *o);
bool IsIntInList(LIST *o, UINT i);
bool IsInt64InList(LIST *o, UINT64 i);
LIST *NewIntList(bool sorted);
LIST *NewInt64List(bool sorted);
int CompareInt(void *p1, void *p2);
int CompareInt64(void *p1, void *p2);
void InsertInt(LIST *o, UINT i);
void InsertInt64(LIST *o, UINT64 i);
void InsertIntDistinct(LIST *o, UINT i);
void InsertInt64Distinct(LIST *o, UINT64 i);
void RandomizeList(LIST *o);

void *GetNext(QUEUE *q);
void *GetNextWithLock(QUEUE *q);
void *PeekQueue(QUEUE *q);
void InsertQueue(QUEUE *q, void *p);
void InsertQueueWithLock(QUEUE *q, void *p);
void InsertQueueInt(QUEUE *q, UINT value);
void LockQueue(QUEUE *q);
void UnlockQueue(QUEUE *q);
void ReleaseQueue(QUEUE *q);
void CleanupQueue(QUEUE *q);
QUEUE *NewQueue();
QUEUE *NewQueueFast();
UINT GetQueueNum(QUEUE *q);

SK *NewSk();
SK *NewSkEx(bool no_compact);
void ReleaseSk(SK *s);
void CleanupSk(SK *s);
void LockSk(SK *s);
void UnlockSk(SK *s);
void Push(SK *s, void *p);
void *Pop(SK *s);

UINT Uncompress(void *dst, UINT dst_size, void *src, UINT src_size);
UINT Compress(void *dst, UINT dst_size, void *src, UINT src_size);
UINT CompressEx(void *dst, UINT dst_size, void *src, UINT src_size, UINT level);
UINT CalcCompress(UINT src_size);
BUF *CompressBuf(BUF *src_buf);
BUF *UncompressBuf(BUF *src_buf);

bool IsZero(void *data, UINT size);
void FillBytes(void *data, UINT size, UCHAR c);

LIST *NewStrMap();
void *StrMapSearch(LIST *map, char *key);

UINT SearchBin(void *data, UINT data_start, UINT data_size, void *key, UINT key_size);
void CrashNow();
UINT Power(UINT a, UINT b);

void XorData(void *dst, void *src1, void *src2, UINT size);

SHARED_BUFFER *NewSharedBuffer(void *data, UINT size);
void ReleaseSharedBuffer(SHARED_BUFFER *b);
void CleanupSharedBuffer(SHARED_BUFFER *b);

void AppendBufUtf8(BUF *b, wchar_t *str);
void AppendBufStr(BUF *b, char *str);


//////////////////////////////////////////////////////////////////////////
// String

// String token
struct TOKEN_LIST
{
	UINT NumTokens;
	char **Token;
};

// INI_ENTRY
struct INI_ENTRY
{
	char *Key;
	char *Value;
	wchar_t *UnicodeValue;
};

// Function prototype
UINT StrLen(char *str);
UINT StrSize(char *str);
bool StrCheckLen(char *str, UINT len);
bool StrCheckSize(char *str, UINT size);
UINT StrCpy(char *dst, UINT size, char *src);
UINT StrCpyAllowOverlap(char *dst, UINT size, char *src);
UINT StrCat(char *dst, UINT size, char *src);
UINT StrCatLeft(char *dst, UINT size, char *src);
char ToLower(char c);
char ToUpper(char c);
void StrUpper(char *str);
void StrLower(char *str);
int StrCmp(char *str1, char *str2);
int StrCmpi(char *str1, char *str2);
void FormatArgs(char *buf, UINT size, char *fmt, va_list args);
void Format(char *buf, UINT size, char *fmt, ...);
char *CopyFormat(char *fmt, ...);
void Print(char *fmt, ...);
void PrintArgs(char *fmt, va_list args);
void PrintStr(char *str);
void Debug(char *fmt, ...);
void DebugArgs(char *fmt, va_list args);
UINT ToInt(char *str);
bool ToBool(char *str);
int ToInti(char *str);
void ToStr(char *str, UINT i);
void ToStri(char *str, int i);
void ToStrx(char *str, UINT i);
void ToStrx8(char *str, UINT i);
void TrimCrlf(char *str);
void Trim(char *str);
void TrimRight(char *str);
void TrimLeft(char *str);
bool GetLine(char *str, UINT size);
void FreeToken(TOKEN_LIST *tokens);
bool IsInToken(TOKEN_LIST *t, char *str);
TOKEN_LIST *ParseToken(char *src, char *separator);
void InitStringLibrary();
void FreeStringLibrary();
bool CheckStringLibrary();
bool InChar(char *string, char c);
UINT SearchStrEx(char *string, char *keyword, UINT start, bool case_sensitive);
UINT SearchStri(char *string, char *keyword, UINT start);
UINT SearchStr(char *string, char *keyword, UINT start);
UINT CalcReplaceStrEx(char *string, char *old_keyword, char *new_keyword, bool case_sensitive);
UINT ReplaceStrEx(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword, bool case_sensitive);
UINT ReplaceStr(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword);
UINT ReplaceStri(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword);
bool IsPrintableAsciiChar(char c);
bool IsPrintableAsciiStr(char *str);
void EnPrintableAsciiStr(char *str, char replace);
bool IsSafeChar(char c);
bool IsSafeStr(char *str);
void EnSafeStr(char *str, char replace);
void TruncateCharFromStr(char *str, char replace);
char *CopyStr(char *str);
void BinToStr(char *str, UINT str_size, void *data, UINT data_size);
void BinToStrW(wchar_t *str, UINT str_size, void *data, UINT data_size);
void PrintBin(void *data, UINT size);
bool StartWith(char *str, char *key);
bool EndWith(char *str, char *key);
UINT64 ToInt64(char *str);
void ToStr64(char *str, UINT64 value);
char *ReplaceFormatStringFor64(char *fmt);
TOKEN_LIST *ParseCmdLine(char *str);
TOKEN_LIST *CopyToken(TOKEN_LIST *src);
TOKEN_LIST *NullToken();
bool IsNum(char *str);
LIST *StrToStrList(char *str, UINT size);
BUF *StrListToStr(LIST *o);
void FreeStrList(LIST *o);
TOKEN_LIST *ListToTokenList(LIST *o);
LIST *TokenListToList(TOKEN_LIST *t);
bool IsEmptyStr(char *str);
void BinToStrEx(char *str, UINT str_size, void *data, UINT data_size);
void BinToStrEx2(char *str, UINT str_size, void *data, UINT data_size, char padding_char);
char *CopyBinToStrEx(void *data, UINT data_size);
char *CopyBinToStr(void *data, UINT data_size);
BUF *StrToBin(char *str);
void MacToStr(char *str, UINT size, UCHAR *mac_address);
void ToStr3(char *str, UINT size, UINT64 v);
void ToStrByte(char *str, UINT size, UINT64 v);
void ToStrByte1000(char *str, UINT size, UINT64 v);
TOKEN_LIST *UniqueToken(TOKEN_LIST *t);
char *NormalizeCrlf(char *str);
bool IsAllUpperStr(char *str);
UINT StrWidth(char *str);
char *MakeCharArray(char c, UINT count);
void MakeCharArray2(char *str, char c, UINT count);
bool StrToMac(UCHAR *mac_address, char *str);
bool IsSplitChar(char c, char *split_str);
bool GetKeyAndValue(char *str, char *key, UINT key_size, char *value, UINT value_size, char *split_str);
LIST *ReadIni(BUF *b);
INI_ENTRY *GetIniEntry(LIST *o, char *key);
void FreeIni(LIST *o);
UINT IniIntValue(LIST *o, char *key);
UINT64 IniInt64Value(LIST *o, char *key);
char *IniStrValue(LIST *o, char *key);
wchar_t *IniUniStrValue(LIST *o, char *key);
bool IniHasValue(LIST *o, char *key);
bool InStr(char *str, char *keyword);
bool InStrEx(char *str, char *keyword, bool case_sensitive);
bool InStrList(char *target_str, char *tokens, char *splitter, bool case_sensitive);
TOKEN_LIST *ParseTokenWithoutNullStr(char *str, char *split_chars);
TOKEN_LIST *ParseTokenWithNullStr(char *str, char *split_chars);
char *DefaultTokenSplitChars();
bool IsCharInStr(char *str, char c);
UINT HexTo4Bit(char c);
char FourBitToHex(UINT value);
void ToHex(char *str, UINT value);
void ToHex64(char *str, UINT64 value);
UINT HexToInt(char *str);
UINT64 HexToInt64(char *str);
UINT SearchAsciiInBinary(void *data, UINT size, char *str, bool case_sensitive);
bool IsStrInStrTokenList(char *str_list, char *str, char *split_chars, bool case_sensitive);
void IntListToStr(char *str, UINT str_size, LIST *o, char *separate_str);
LIST *StrToIntList(char *str, bool sorted);
void NormalizeIntListStr(char *dst, UINT dst_size, char *src, bool sorted, char *separate_str);
void ClearStr(char *str, UINT str_size);
void SetStrCaseAccordingToBits(char *str, UINT bits);


//////////////////////////////////////////////////////////////////////////
// Internationalized string


// String token
struct UNI_TOKEN_LIST
{
	UINT NumTokens;
	wchar_t **Token;
};

UINT UniStrLen(wchar_t *str);
UINT UniStrSize(wchar_t *str);
UINT UniStrCpy(wchar_t *dst, UINT size, wchar_t *src);
bool UniCheckStrSize(wchar_t *str, UINT size);
bool UniCheckStrLen(wchar_t *str, UINT len);
UINT UniStrCat(wchar_t *dst, UINT size, wchar_t *src);
UINT UniStrCatLeft(wchar_t *dst, UINT size, wchar_t *src);
wchar_t UniToLower(wchar_t c);
wchar_t UniToUpper(wchar_t c);
void UniStrLower(wchar_t *str);
void UniStrUpper(wchar_t *str);
int UniStrCmp(wchar_t *str1, wchar_t *str2);
int UniStrCmpi(wchar_t *str1, wchar_t *str2);
int UniSoftStrCmp(wchar_t *str1, wchar_t *str2);
void UniFormat(wchar_t *buf, UINT size, wchar_t *fmt, ...);
wchar_t *CopyUniFormat(wchar_t *fmt, ...);
void UniFormatArgs(wchar_t *buf, UINT size, wchar_t *fmt, va_list args);
void UniDebugArgs(wchar_t *fmt, va_list args);
void UniDebug(wchar_t *fmt, ...);
void UniPrint(wchar_t *fmt, ...);
void UniPrintArgs(wchar_t *fmt, va_list args);
void UniPrintStr(wchar_t *string);
void UniToStrx8(wchar_t *str, UINT i);
void UniToStrx(wchar_t *str, UINT i);
void UniToStri(wchar_t *str, int i);
void UniToStru(wchar_t *str, UINT i);
int UniToInti(wchar_t *str);
UINT UniToInt(wchar_t *str);
void UniToStrForSingleChars(char *dst, UINT dst_size, wchar_t *src);
void UniTrim(wchar_t *str);
void UniTrimLeft(wchar_t *str);
void UniTrimRight(wchar_t *str);
void UniTrimCrlf(wchar_t *str);
bool UniGetLine(wchar_t *str, UINT size);
bool UniGetLineWin32(wchar_t *str, UINT size);
bool UniGetLineUnix(wchar_t *str, UINT size);
void UniFreeToken(UNI_TOKEN_LIST *tokens);
UNI_TOKEN_LIST *UniParseToken(wchar_t *src, wchar_t *separator);
UINT UniSearchStrEx(wchar_t *string, wchar_t *keyword, UINT start, bool case_sensitive);
UINT UniSearchStri(wchar_t *string, wchar_t *keyword, UINT start);
UINT UniSearchStr(wchar_t *string, wchar_t *keyword, UINT start);
UINT UniCalcReplaceStrEx(wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive);
UINT UniReplaceStrEx(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive);
UINT UniReplaceStri(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword);
UINT UniReplaceStr(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword);
UINT GetUniType(wchar_t c);
UINT GetUtf8Type(BYTE *s, UINT size, UINT offset);
UINT CalcUniToUtf8(wchar_t *s);
UINT UniToUtf8(BYTE *u, UINT size, wchar_t *s);
UINT Utf8Len(BYTE *u, UINT size);
UINT CalcUtf8ToUni(BYTE *u, UINT u_size);
UINT Utf8ToUni(wchar_t *s, UINT size, BYTE *u, UINT u_size);
UINT CalcStrToUni(char *str);
UINT StrToUni(wchar_t *s, UINT size, char *str);
UINT CalcUniToStr(wchar_t *s);
UINT UniToStr(char *str, UINT size, wchar_t *s);
UINT CalcStrToUtf8(char *str);
UINT StrToUtf8(BYTE *u, UINT size, char *str);
UINT CalcUtf8ToStr(BYTE *u, UINT size);
UINT Utf8ToStr(char *str, UINT str_size, BYTE *u, UINT size);
bool IsSafeUniStr(wchar_t *str);
bool IsSafeUniChar(wchar_t c);
wchar_t *CopyUniStr(wchar_t *str);
wchar_t *CopyStrToUni(char *str);
UINT StrToUtf(char *utfstr, UINT size, char *str);
UINT UtfToStr(char *str, UINT size, char *utfstr);
UINT UniToUtf(char *utfstr, UINT size, wchar_t *unistr);
UINT UtfToUni(wchar_t *unistr, UINT size, char *utfstr);
char *CopyUniToUtf(wchar_t *unistr);
char *CopyStrToUtf(char *str);
char *CopyUniToStr(wchar_t *unistr);
wchar_t *CopyUtfToUni(char *utfstr);
char *CopyUtfToStr(char *utfstr);
wchar_t *UniReplaceFormatStringFor64(wchar_t *fmt);
void UniToStr64(wchar_t *str, UINT64 value);
UINT64 UniToInt64(wchar_t *str);
UNI_TOKEN_LIST *UniParseCmdLine(wchar_t *str);
UNI_TOKEN_LIST *UniCopyToken(UNI_TOKEN_LIST *src);
wchar_t *UniCopyStr(wchar_t *str);
TOKEN_LIST *UniTokenListToTokenList(UNI_TOKEN_LIST *src);
UNI_TOKEN_LIST *TokenListToUniTokenList(TOKEN_LIST *src);
UNI_TOKEN_LIST *UniNullToken();
UNI_TOKEN_LIST *NullUniToken();
bool UniIsNum(wchar_t *str);
bool IsEmptyUniStr(wchar_t *str);
bool UniIsEmptyStr(wchar_t *str);
void InitInternational();
void FreeInternational();
USHORT *WideToUtf16(wchar_t *str);
wchar_t *Utf16ToWide(USHORT *str);
void DumpUniStr(wchar_t *str);
void DumpStr(char *str);
wchar_t *InternalFormatArgs(wchar_t *fmt, va_list args, bool ansi_mode);
UINT UniStrWidth(wchar_t *str);
UNI_TOKEN_LIST *UnixUniParseToken(wchar_t *src, wchar_t *separator);
void UniToStr3(wchar_t *str, UINT size, UINT64 value);
bool UniEndWith(wchar_t *str, wchar_t *key);
bool UniStartWith(wchar_t *str, wchar_t *key);
wchar_t *UniNormalizeCrlf(wchar_t *str);
LIST *UniStrToStrList(wchar_t *str, UINT size);
BUF *UniStrListToStr(LIST *o);
void UniFreeStrList(LIST *o);
UNI_TOKEN_LIST *UniListToTokenList(LIST *o);
LIST *UniTokenListToList(UNI_TOKEN_LIST *t);
bool UniIsSafeChar(wchar_t c);
wchar_t *UniMakeCharArray(wchar_t c, UINT count);
BUF *UniStrToBin(wchar_t *str);
bool UniInStr(wchar_t *str, wchar_t *keyword);
bool UniInStrEx(wchar_t *str, wchar_t *keyword, bool case_sensitive);
void ClearUniStr(wchar_t *str, UINT str_size);
bool UniInChar(wchar_t *string, wchar_t c);
UNI_TOKEN_LIST *UniGetLines(wchar_t *str);

#ifdef	OS_UNIX
void GetCurrentCharSet(char *name, UINT size);
UINT UnixCalcStrToUni(char *str);
UINT UnixStrToUni(wchar_t *s, UINT size, char *str);
UINT UnixCalcUniToStr(wchar_t *s);
UINT UnixUniToStr(char *str, UINT size, wchar_t *s);
void *IconvWideToStr();
void *IconvStrToWide();
int IconvFree(void *d);
void *IconvWideToStrInternal();
void *IconvStrToWideInternal();
int IconvFreeInternal(void *d);
#endif	// OS_UNIX


//////////////////////////////////////////////////////////////////////////
// Encrypt


// Function of OpenSSL
void RAND_Init_For_SoftEther();
void RAND_Free_For_SoftEther();



// Constant
#define	MIN_SIGN_HASH_SIZE		(15 + SHA1_SIZE)
#define	SIGN_HASH_SIZE			(MIN_SIGN_HASH_SIZE)

#define DES_KEY_SIZE				8			// DES key size
#define	DES_IV_SIZE					8			// DES IV size
#define DES_BLOCK_SIZE				8			// DES block size
#define DES3_KEY_SIZE				(8 * 3)		// 3DES key size
#define RSA_KEY_SIZE				128			// RSA key size
#define DH_KEY_SIZE					128			// DH key size
#define	RSA_MIN_SIGN_HASH_SIZE		(15 + SHA1_HASH_SIZE)	// Minimum RSA hash size
#define	RSA_SIGN_HASH_SIZE			(RSA_MIN_SIGN_HASH_SIZE)	// RSA hash size
#define MD5_HASH_SIZE				16			// MD5 hash size
#define SHA1_HASH_SIZE				20			// SHA-1 hash size
#define SHA1_BLOCK_SIZE				64			// SHA-1 block size
#define HMAC_SHA1_96_KEY_SIZE		20			// HMAC-SHA-1-96 key size
#define HMAC_SHA1_96_HASH_SIZE		12			// HMAC-SHA-1-96 hash size
#define HMAC_SHA1_SIZE				(SHA1_HASH_SIZE)	// HMAC-SHA-1 hash size
#define	AES_IV_SIZE					16			// AES IV size
#define	AES_MAX_KEY_SIZE			32			// Maximum AES key size

// IANA definitions taken from IKEv1 Phase 1
#define SHA1_160						2
#define SHA2_256						4
#define SHA2_384						5
#define SHA2_512						6

// HMAC block size
#define	HMAC_BLOCK_SIZE					64
// The block size for sha-384 and sha-512 as defined by rfc4868
#define HMAC_BLOCK_SIZE_1024			128
#define HMAC_BLOCK_SIZE_MAX				512

#define DH_GROUP1_PRIME_768 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"

#define DH_GROUP2_PRIME_1024 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" \
	"FFFFFFFFFFFFFFFF"

#define DH_GROUP5_PRIME_1536 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"

#define	DH_SIMPLE_160	"AEE7561459353C95DDA966AE1FD25D95CD46E935"

#define	DH_SET_2048 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

#define	DH_SET_3072	\
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"\
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"\
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"\
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"\
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"\
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"\
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"\
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"\
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"\
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"\
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"\
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"\
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"\
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"\
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"\
	"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

#define	DH_SET_4096 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" \
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" \
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" \
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" \
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" \
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" \
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" \
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" \
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" \
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" \
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" \
	"FFFFFFFFFFFFFFFF"

// Macro
#define	HASHED_DATA(p)			(((UCHAR *)p) + 15)

// OpenSSL <1.1 Shims
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#	define EVP_PKEY_get0_RSA(obj) ((obj)->pkey.rsa)
#	define EVP_PKEY_base_id(pkey) ((pkey)->type)
#	define X509_get0_notBefore(x509) ((x509)->cert_info->validity->notBefore)
#	define X509_get0_notAfter(x509) ((x509)->cert_info->validity->notAfter)
#	define X509_get_serialNumber(x509) ((x509)->cert_info->serialNumber)
#endif

// Crypt context
struct CRYPT
{
	struct rc4_key_st *Rc4Key;
};

// Name in the certificate
struct NAME
{
	wchar_t *CommonName;		// CN
	wchar_t *Organization;		// O
	wchar_t *Unit;				// OU
	wchar_t *Country;			// C
	wchar_t *State;				// ST
	wchar_t *Local;				// L
};

// Serial number
struct X_SERIAL
{
	UINT size;
	UCHAR *data;
};

// Certificate
struct X
{
	X509 *x509;
	NAME *issuer_name;
	NAME *subject_name;
	bool root_cert;
	UINT64 notBefore;
	UINT64 notAfter;
	X_SERIAL *serial;
	bool do_not_free;
	bool is_compatible_bit;
	UINT bits;
	bool has_basic_constraints;
	char issuer_url[256];
};

// Key
struct K
{
	EVP_PKEY *pkey;
	bool private_key;
};

// PKCS#12
struct P12
{
	PKCS12 *pkcs12;
};

// CEL
struct X_CRL
{
	X509_CRL *Crl;
};

// Constant
#define	MD5_SIZE	16
#define	SHA1_SIZE	20
#define	SHA256_SIZE	32
#define	SHA384_SIZE	48
#define	SHA512_SIZE	64

// Key element of DES
struct DES_KEY_VALUE
{
	struct DES_ks *KeySchedule;
	UCHAR KeyValue[DES_KEY_SIZE];
};

// DES key
struct DES_KEY
{
	DES_KEY_VALUE *k1, *k2, *k3;
};

// AES key
struct AES_KEY_VALUE
{
	struct aes_key_st *EncryptKey;
	struct aes_key_st *DecryptKey;
	UCHAR KeyValue[AES_MAX_KEY_SIZE];
	UINT KeySize;
};

// DH
struct DH_CTX
{
	struct dh_st *dh;
	BUF *MyPublicKey;
	BUF *MyPrivateKey;
	UINT Size;
};

// Cipher object
struct CIPHER
{
	char Name[MAX_PATH];
	bool IsNullCipher;
	const struct evp_cipher_st *Cipher;
	struct evp_cipher_ctx_st *Ctx;
	bool Encrypt;
	UINT BlockSize, IvSize, KeySize;
};

// Message digest object
struct MD
{
	char Name[MAX_PATH];
	const struct evp_md_st *Md;
	struct hmac_ctx_st *Ctx;
	UINT Size;
};


// Lock of the OpenSSL
extern LOCK **ssl_lock_obj;

// Function prototype
CRYPT *NewCrypt(void *key, UINT size);
void FreeCrypt(CRYPT *c);
void Encrypt(CRYPT *c, void *dst, void *src, UINT size);
void Hash(void *dst, void *src, UINT size, bool sha);
void HashSha1(void *dst, void *src, UINT size);
void HashSha256(void *dst, void *src, UINT size);
void HashMd4(void *dst, void *src, UINT size);
void HashMd4(void *dst, void *src, UINT size);
void InitCryptLibrary();
void Rand(void *buf, UINT size);
void Rand128(void *buf);
UINT HashToUINT(void *data, UINT size);
UINT64 Rand64();
UINT Rand32();
USHORT Rand16();
UCHAR Rand8();
bool Rand1();
UINT HashPtrToUINT(void *p);

void CertTest();
BIO *BufToBio(BUF *b);
BUF *BioToBuf(BIO *bio);
BIO *NewBio();
void FreeBio(BIO *bio);
X *BioToX(BIO *bio, bool text);
X *BufToX(BUF *b, bool text);
BUF *SkipBufBeforeString(BUF *b, char *str);
void FreeX509(X509 *x509);
void FreeX(X *x);
BIO *XToBio(X *x, bool text);
BUF *XToBuf(X *x, bool text);
K *BioToK(BIO *bio, bool private_key, bool text, char *password);
int PKeyPasswordCallbackFunction(char *buf, int bufsize, int verify, void *param);
void FreePKey(EVP_PKEY *pkey);
void FreeK(K *k);
K *BufToK(BUF *b, bool private_key, bool text, char *password);
bool IsEncryptedK(BUF *b, bool private_key);
bool IsBase64(BUF *b);
BIO *KToBio(K *k, bool text, char *password);
BUF *KToBuf(K *k, bool text, char *password);
X *FileToX(char *filename);
X *FileToXW(wchar_t *filename);
bool XToFile(X *x, char *filename, bool text);
bool XToFileW(X *x, wchar_t *filename, bool text);
K *FileToK(char *filename, bool private_key, char *password);
K *FileToKW(wchar_t *filename, bool private_key, char *password);
bool KToFile(K *k, char *filename, bool text, char *password);
bool KToFileW(K *k, wchar_t *filename, bool text, char *password);
bool CheckXandK(X *x, K *k);
bool CompareX(X *x1, X *x2);
NAME *X509NameToName(void *xn);
wchar_t *GetUniStrFromX509Name(void *xn, int nid);
void LoadXNames(X *x);
void FreeXNames(X *x);
void FreeName(NAME *n);
bool CompareName(NAME *n1, NAME *n2);
K *GetKFromX(X *x);
bool CheckSignature(X *x, K *k);
X *X509ToX(X509 *x509);
bool CheckX(X *x, X *x_issuer);
bool CheckXEx(X *x, X *x_issuer, bool check_name, bool check_date);
bool Asn1TimeToSystem(SYSTEMTIME *s, void *asn1_time);
bool StrToSystem(SYSTEMTIME *s, char *str);
UINT64 Asn1TimeToUINT64(void *asn1_time);
bool SystemToAsn1Time(void *asn1_time, SYSTEMTIME *s);
bool UINT64ToAsn1Time(void *asn1_time, UINT64 t);
bool SystemToStr(char *str, UINT size, SYSTEMTIME *s);
void LoadXDates(X *x);
bool CheckXDate(X *x, UINT64 current_system_time);
bool CheckXDateNow(X *x);
NAME *NewName(wchar_t *common_name, wchar_t *organization, wchar_t *unit,
	wchar_t *country, wchar_t *state, wchar_t *local);
void *NameToX509Name(NAME *nm);
void FreeX509Name(void *xn);
bool AddX509Name(void *xn, int nid, wchar_t *str);
X509 *NewRootX509(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial);
X *NewRootX(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial);
X509 *NewX509(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial);
X *NewX(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial);
UINT GetDaysUntil2038();
UINT GetDaysUntil2038Ex();
X_SERIAL *NewXSerial(void *data, UINT size);
void FreeXSerial(X_SERIAL *serial);
char *ByteToStr(BYTE *src, UINT src_size);
P12 *BioToP12(BIO *bio);
P12 *PKCS12ToP12(PKCS12 *pkcs12);
P12 *BufToP12(BUF *b);
BIO *P12ToBio(P12 *p12);
BUF *P12ToBuf(P12 *p12);
void FreePKCS12(PKCS12 *pkcs12);
void FreeP12(P12 *p12);
P12 *FileToP12(char *filename);
P12 *FileToP12W(wchar_t *filename);
bool P12ToFile(P12 *p12, char *filename);
bool P12ToFileW(P12 *p12, wchar_t *filename);
bool ParseP12(P12 *p12, X **x, K **k, char *password);
bool IsEncryptedP12(P12 *p12);
P12 *NewP12(X *x, K *k, char *password);
X *CloneX(X *x);
K *CloneK(K *k);
void FreeCryptLibrary();
void GetPrintNameFromX(wchar_t *str, UINT size, X *x);
void GetPrintNameFromXA(char *str, UINT size, X *x);
void GetPrintNameFromName(wchar_t *str, UINT size, NAME *name);
void GetAllNameFromX(wchar_t *str, UINT size, X *x);
void GetAllNameFromA(char *str, UINT size, X *x);
void GetAllNameFromName(wchar_t *str, UINT size, NAME *name);
void GetAllNameFromNameEx(wchar_t *str, UINT size, NAME *name);
void GetAllNameFromXEx(wchar_t *str, UINT size, X *x);
void GetAllNameFromXExA(char *str, UINT size, X *x);
BUF *BigNumToBuf(const BIGNUM *bn);
BIGNUM *BinToBigNum(void *data, UINT size);
BIGNUM *BufToBigNum(BUF *b);
char *BigNumToStr(BIGNUM *bn);
X_SERIAL *CloneXSerial(X_SERIAL *src);
bool CompareXSerial(X_SERIAL *s1, X_SERIAL *s2);
void GetXDigest(X *x, UCHAR *buf, bool sha1);
NAME *CopyName(NAME *n);


bool RsaGen(K **priv, K **pub, UINT bit);
bool RsaCheck();
bool RsaCheckEx();
bool RsaPublicEncrypt(void *dst, void *src, UINT size, K *k);
bool RsaPrivateDecrypt(void *dst, void *src, UINT size, K *k);
bool RsaPrivateEncrypt(void *dst, void *src, UINT size, K *k);
bool RsaPublicDecrypt(void *dst, void *src, UINT size, K *k);
bool RsaSign(void *dst, void *src, UINT size, K *k);
bool RsaSignEx(void *dst, void *src, UINT size, K *k, UINT bits);
bool HashForSign(void *dst, UINT dst_size, void *src, UINT src_size);
bool RsaVerify(void *data, UINT data_size, void *sign, K *k);
bool RsaVerifyEx(void *data, UINT data_size, void *sign, K *k, UINT bits);
UINT RsaPublicSize(K *k);
void RsaPublicToBin(K *k, void *data);
BUF *RsaPublicToBuf(K *k);
K *RsaBinToPublic(void *data, UINT size);

DES_KEY_VALUE *DesNewKeyValue(void *value);
DES_KEY_VALUE *DesRandKeyValue();
void DesFreeKeyValue(DES_KEY_VALUE *v);
DES_KEY *Des3NewKey(void *k1, void *k2, void *k3);
void Des3FreeKey(DES_KEY *k);
DES_KEY *DesNewKey(void *k1);
void DesFreeKey(DES_KEY *k);
DES_KEY *Des3RandKey();
DES_KEY *DesRandKey();
void Des3Encrypt(void *dest, void *src, UINT size, DES_KEY *key, void *ivec);
void Des3Encrypt2(void *dest, void *src, UINT size, DES_KEY_VALUE *k1, DES_KEY_VALUE *k2, DES_KEY_VALUE *k3, void *ivec);
void Des3Decrypt(void *dest, void *src, UINT size, DES_KEY *key, void *ivec);
void Des3Decrypt2(void *dest, void *src, UINT size, DES_KEY_VALUE *k1, DES_KEY_VALUE *k2, DES_KEY_VALUE *k3, void *ivec);
void Sha(UINT sha_type, void *dst, void *src, UINT size);
void Sha1(void *dst, void *src, UINT size);
void Sha2_256(void *dst, void *src, UINT size);
void Sha2_384(void *dst, void *src, UINT size);
void Sha2_512(void *dst, void *src, UINT size);

void Md5(void *dst, void *src, UINT size);
void MacSha1(void *dst, void *key, UINT key_size, void *data, UINT data_size);
void MacSha196(void *dst, void *key, void *data, UINT data_size);
void DesEncrypt(void *dest, void *src, UINT size, DES_KEY_VALUE *k, void *ivec);
void DesDecrypt(void *dest, void *src, UINT size, DES_KEY_VALUE *k, void *ivec);
void DesEcbEncrypt(void *dst, void *src, void *key_7bytes);

bool DhCompute(DH_CTX *dh, void *dst_priv_key, void *src_pub_key, UINT key_size);
DH_CTX *DhNewGroup1();
DH_CTX *DhNewGroup2();
DH_CTX *DhNewGroup5();
DH_CTX *DhNewSimple160();
DH_CTX *DhNew2048();
DH_CTX *DhNew3072();
DH_CTX *DhNew4096();
DH_CTX *DhNew(char *prime, UINT g);
void DhFree(DH_CTX *dh);
BUF *DhToBuf(DH_CTX *dh);

AES_KEY_VALUE *AesNewKey(void *data, UINT size);
void AesFreeKey(AES_KEY_VALUE *k);
void AesEncrypt(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec);
void AesDecrypt(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec);

bool IsIntelAesNiSupported();
void CheckIfIntelAesNiSupportedInit();

#ifdef	USE_INTEL_AESNI_LIBRARY
void AesEncryptWithIntel(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec);
void AesDecryptWithIntel(void *dest, void *src, UINT size, AES_KEY_VALUE *k, void *ivec);
#endif	// USE_INTEL_AESNI_LIBRARY

void OpenSSL_InitLock();
void OpenSSL_FreeLock();
void OpenSSL_Lock(int mode, int n, const char *file, int line);
unsigned long OpenSSL_Id(void);
void FreeOpenSSLThreadState();

CIPHER *NewCipher(char *name);
void FreeCipher(CIPHER *c);
void SetCipherKey(CIPHER *c, void *key, bool enc);
UINT CipherProcess(CIPHER *c, void *iv, void *dest, void *src, UINT size);

MD *NewMd(char *name);
void FreeMd(MD *md);
void SetMdKey(MD *md, void *key, UINT key_size);
void MdProcess(MD *md, void *dest, void *src, UINT size);
void Enc_tls1_PRF(unsigned char *label, int label_len, const unsigned char *sec,
	int slen, unsigned char *out1, int olen);

void HMacSha1(void *dst, void *key, UINT key_size, void *data, UINT data_size);
void HMacMd5(void *dst, void *key, UINT key_size, void *data, UINT data_size);

BUF *EasyEncrypt(BUF *src_buf);
BUF *EasyDecrypt(BUF *src_buf);

void DisableIntelAesAccel();

//////////////////////////////////////////////////////////////////////////
// Kernel


// Memory usage information
struct MEMINFO
{
	UINT64 TotalMemory;
	UINT64 UsedMemory;
	UINT64 FreeMemory;
	UINT64 TotalPhys;
	UINT64 UsedPhys;
	UINT64 FreePhys;
};

// Locale information
struct LOCALE
{
	wchar_t YearStr[16], MonthStr[16], DayStr[16];
	wchar_t HourStr[16], MinuteStr[16], SecondStr[16];
	wchar_t DayOfWeek[7][16];
	wchar_t SpanDay[16], SpanHour[16], SpanMinute[16], SpanSecond[16];
	wchar_t Unknown[32];
};


// Thread procedure
typedef void (THREAD_PROC)(THREAD *thread, void *param);

// Thread
struct THREAD
{
	REF *ref;
	THREAD_PROC *thread_proc;
	void *param;
	void *pData;
	EVENT *init_finished_event;
	void *AppData1, *AppData2, *AppData3;
	UINT AppInt1, AppInt2, AppInt3;
	UINT ThreadId;
	bool PoolThread;
	THREAD *PoolHostThread;
	LIST *PoolWaitList;						// Thread termination waiting list
	volatile bool PoolHalting;				// Thread stopped
	EVENT *release_event;
	bool Stopped;							// Indicates that the operation is Stopped
	char *Name;								// Thread name
};

// Thread pool data
struct THREAD_POOL_DATA
{
	EVENT *Event;						// Waiting Event
	EVENT *InitFinishEvent;				// Initialization is completed event
	THREAD *Thread;						// Threads that are currently assigned
	THREAD_PROC *ThreadProc;			// Thread procedure that is currently assigned
};

// Instance
struct INSTANCE
{
	char *Name;							// Name
	void *pData;						// Data
};

// Create a new thread
#define	NewThread(thread_proc, param) NewThreadNamed((thread_proc), (param), (#thread_proc))

// Function prototype
void SleepThread(UINT time);
THREAD *NewThreadInternal(THREAD_PROC *thread_proc, void *param);
void ReleaseThreadInternal(THREAD *t);
void CleanupThreadInternal(THREAD *t);
void NoticeThreadInitInternal(THREAD *t);
void WaitThreadInitInternal(THREAD *t);
bool WaitThreadInternal(THREAD *t);
THREAD *NewThreadNamed(THREAD_PROC *thread_proc, void *param, char *name);
void ReleaseThread(THREAD *t);
void CleanupThread(THREAD *t);
void NoticeThreadInit(THREAD *t);
void WaitThreadInit(THREAD *t);
bool WaitThread(THREAD *t, UINT timeout);
void InitThreading();
void FreeThreading();
void ThreadPoolProc(THREAD *t, void *param);
void SetThreadName(UINT thread_id, char *name, void *param);

struct tm * c_gmtime_r(const time_64t* timep, struct tm *tm);
time_64t c_mkgmtime(struct tm *tm);
time_64t System64ToTime(UINT64 i);
void TmToSystem(SYSTEMTIME *st, struct tm *t);
void SystemToTm(struct tm *t, SYSTEMTIME *st);
void TimeToSystem(SYSTEMTIME *st, time_64t t);
UINT64 TimeToSystem64(time_64t t);
time_64t SystemToTime(SYSTEMTIME *st);
time_64t TmToTime(struct tm *t);
void TimeToTm(struct tm *t, time_64t time);
void NormalizeTm(struct tm *t);
void NormalizeSystem(SYSTEMTIME *st);
void LocalToSystem(SYSTEMTIME *system, SYSTEMTIME *local);
void SystemToLocal(SYSTEMTIME *local, SYSTEMTIME *system);
INT64 GetTimeDiffEx(SYSTEMTIME *basetime, bool local_time);
void UINT64ToSystem(SYSTEMTIME *st, UINT64 sec64);
UINT64 SystemToUINT64(SYSTEMTIME *st);
UINT64 LocalTime64();
UINT64 SystemTime64();
USHORT SystemToDosDate(SYSTEMTIME *st);
USHORT System64ToDosDate(UINT64 i);
USHORT SystemToDosTime(SYSTEMTIME *st);
USHORT System64ToDosTime(UINT64 i);
void LocalTime(SYSTEMTIME *st);
void SystemTime(SYSTEMTIME *st);
void SetLocale(wchar_t *str);
bool LoadLocale(LOCALE *locale, wchar_t *str);
void GetCurrentLocale(LOCALE *locale);
void GetDateTimeStr(char *str, UINT size, SYSTEMTIME *st);
void GetDateTimeStrMilli(char *str, UINT size, SYSTEMTIME *st);
void GetDateStr(char *str, UINT size, SYSTEMTIME *st);
void GetDateTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetDateStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetTimeStrMilli(char *str, UINT size, SYSTEMTIME *st);
void GetTimeStr(char *str, UINT size, SYSTEMTIME *st);
UINT Tick();
UINT TickRealtime();
UINT TickRealtimeManual();
UINT64 TickGetRealtimeTickValue64();
UINT64 SystemToLocal64(UINT64 t);
UINT64 LocalToSystem64(UINT64 t);
UINT ThreadId();
void GetDateTimeStr64(char *str, UINT size, UINT64 sec64);
void GetDateTimeStr64Uni(wchar_t *str, UINT size, UINT64 sec64);
void GetDateTimeStrMilli64(char *str, UINT size, UINT64 sec64);
void GetDateTimeStrMilli64ForFileName(char *str, UINT size, UINT64 sec64);
void GetDateTimeStrMilliForFileName(char *str, UINT size, SYSTEMTIME *tm);
void GetDateStr64(char *str, UINT size, UINT64 sec64);
void GetDateTimeStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale);
void GetTimeStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale);
void GetDateStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale);
void GetTimeStrMilli64(char *str, UINT size, UINT64 sec64);
void GetTimeStr64(char *str, UINT size, UINT64 sec64);
void GetDateTimeStrRFC3339(char *str, UINT size, SYSTEMTIME *st, int timezone_min);
UINT64 SafeTime64(UINT64 sec64);
bool Run(char *filename, char *arg, bool hide, bool wait);
bool RunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
void HashInstanceName(char *name, UINT size, char *instance_name);
void HashInstanceNameLocal(char *name, UINT size, char *instance_name);
INSTANCE *NewSingleInstance(char *instance_name);
INSTANCE *NewSingleInstanceEx(char *instance_name, bool user_local);
void FreeSingleInstance(INSTANCE *inst);
void GetSpanStr(char *str, UINT size, UINT64 sec64);
void GetSpanStrEx(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale);
void GetSpanStrMilli(char *str, UINT size, UINT64 sec64);
void GetMemInfo(MEMINFO *info);
bool GetEnv(char *name, char *data, UINT size);
bool GetEnvW(wchar_t *name, wchar_t *data, UINT size);
bool GetEnvW_ForWin32(wchar_t *name, wchar_t *data, UINT size);
bool GetEnvW_ForUnix(wchar_t *name, wchar_t *data, UINT size);
void GetHomeDir(char *path, UINT size);
void GetHomeDirW(wchar_t *path, UINT size);
void AbortExit();
void AbortExitEx(char *msg);
void YieldCpu();
UINT DoNothing();
LIST *NewThreadList();
void AddThreadToThreadList(LIST *o, THREAD *t);
void DelThreadFromThreadList(LIST *o, THREAD *t);
void MainteThreadList(LIST *o);
void FreeThreadList(LIST *o);
void StopThreadList(LIST *o);
void WaitAllThreadsWillBeStopped(LIST *o);
UINT GetNumberOfCpu();


//////////////////////////////////////////////////////////////////////////
// Pack

// Constant
#ifdef CPU_64

#define	MAX_VALUE_SIZE			(384 * 1024 * 1024)	// Maximum Data size that can be stored in a single VALUE
#define	MAX_VALUE_NUM			262144	// Maximum VALUE number that can be stored in a single ELEMENT
#define	MAX_ELEMENT_NAME_LEN	63		// The length of the name that can be attached to the ELEMENT
#define	MAX_ELEMENT_NUM			262144	// Maximum ELEMENT number that can be stored in a single PACK
#define	MAX_PACK_SIZE			(512 * 1024 * 1024)	// Maximum size of a serialized PACK

#else	// CPU_64

#define	MAX_VALUE_SIZE			(96 * 1024 * 1024)	// Maximum Data size that can be stored in a single VALUE
#define	MAX_VALUE_NUM			65536	// Maximum VALUE number that can be stored in a single ELEMENT
#define	MAX_ELEMENT_NAME_LEN	63		// The length of the name that can be attached to the ELEMENT
#define	MAX_ELEMENT_NUM			131072	// Maximum ELEMENT number that can be stored in a single PACK
#define	MAX_PACK_SIZE			(128 * 1024 * 1024)	// Maximum size of a serialized PACK

#endif	// CPU_64

// Type of VALUE
#define	VALUE_INT			0		// Integer type
#define	VALUE_DATA			1		// Data type
#define	VALUE_STR			2		// ANSI string type
#define	VALUE_UNISTR		3		// Unicode string type
#define	VALUE_INT64			4		// 64 bit integer type

// The number of allowable NOOP
#define	MAX_NOOP_PER_SESSION	30

// VALUE object
struct VALUE
{
	UINT Size;				// Size
	UINT IntValue;			// Integer value
	void *Data;				// Data
	char *Str;				// ANSI string
	wchar_t *UniStr;		// Unicode strings
	UINT64 Int64Value;		// 64 bit integer type
};

// ELEMENT object
struct ELEMENT
{
	char name[MAX_ELEMENT_NAME_LEN + 1];	// Element name
	UINT num_value;			// Number of values (>=1)
	UINT type;				// Type
	VALUE **values;			// List of pointers to the value
};

// PACK object
struct PACK
{
	LIST *elements;			// Element list
};


// Function prototype
PACK *NewPack();
bool AddElement(PACK *p, ELEMENT *e);
void DelElement(PACK *p, char *name);
bool IsElement(PACK *p, char *name);
ELEMENT *GetElement(PACK *p, char *name, UINT type);
void FreePack(PACK *p);
ELEMENT *NewElement(char *name, UINT type, UINT num_value, VALUE **values);
VALUE *NewIntValue(UINT i);
VALUE *NewDataValue(void *data, UINT size);
VALUE *NewStrValue(char *str);
VALUE *NewUniStrValue(wchar_t *str);
void FreeValue(VALUE *v, UINT type);
int ComparePackName(void *p1, void *p2);
void FreeElement(ELEMENT *e);
UINT GetValueNum(ELEMENT *e);
UINT GetIntValue(ELEMENT *e, UINT index);
UINT64 GetInt64Value(ELEMENT *e, UINT index);
char *GetStrValue(ELEMENT *e, UINT index);
wchar_t *GetUniStrValue(ELEMENT *e, UINT index);
UINT GetDataValueSize(ELEMENT *e, UINT index);
void *GetDataValue(ELEMENT *e, UINT index);
BUF *PackToBuf(PACK *p);
void WritePack(BUF *b, PACK *p);
void WriteElement(BUF *b, ELEMENT *e);
void WriteValue(BUF *b, VALUE *v, UINT type);
PACK *BufToPack(BUF *b);
bool ReadPack(BUF *b, PACK *p);
ELEMENT *ReadElement(BUF *b);
VALUE *ReadValue(BUF *b, UINT type);
void Bit160ToStr(char *str, UCHAR *data);
void Bit128ToStr(char *str, UCHAR *data);
VALUE *NewInt64Value(UINT64 i);
TOKEN_LIST *GetPackElementNames(PACK *p);

X *PackGetX(PACK *p, char *name);
K *PackGetK(PACK *p, char *name);
void PackAddX(PACK *p, char *name, X *x);
void PackAddK(PACK *p, char *name, K *k);
void PackAddStr(PACK *p, char *name, char *str);
void PackAddStrEx(PACK *p, char *name, char *str, UINT index, UINT total);
void PackAddUniStr(PACK *p, char *name, wchar_t *unistr);
void PackAddUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT index, UINT total);
void PackAddInt(PACK *p, char *name, UINT i);
void PackAddNum(PACK *p, char *name, UINT num);
void PackAddIntEx(PACK *p, char *name, UINT i, UINT index, UINT total);
void PackAddInt64(PACK *p, char *name, UINT64 i);
void PackAddInt64Ex(PACK *p, char *name, UINT64 i, UINT index, UINT total);
void PackAddData(PACK *p, char *name, void *data, UINT size);
void PackAddDataEx(PACK *p, char *name, void *data, UINT size, UINT index, UINT total);
void PackAddBuf(PACK *p, char *name, BUF *b);
void PackAddBufEx(PACK *p, char *name, BUF *b, UINT index, UINT total);
bool PackGetStr(PACK *p, char *name, char *str, UINT size);
bool PackGetStrEx(PACK *p, char *name, char *str, UINT size, UINT index);
bool PackGetUniStr(PACK *p, char *name, wchar_t *unistr, UINT size);
bool PackGetUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT size, UINT index);
bool PackCmpStr(PACK *p, char *name, char *str);
UINT PackGetIndexCount(PACK *p, char *name);
UINT PackGetInt(PACK *p, char *name);
UINT PackGetNum(PACK *p, char *name);
UINT PackGetIntEx(PACK *p, char *name, UINT index);
UINT64 PackGetInt64(PACK *p, char *name);
UINT64 PackGetInt64Ex(PACK *p, char *name, UINT index);
UINT PackGetDataSizeEx(PACK *p, char *name, UINT index);
UINT PackGetDataSize(PACK *p, char *name);
bool PackGetData(PACK *p, char *name, void *data);
bool PackGetDataEx(PACK *p, char *name, void *data, UINT index);
BUF *PackGetBuf(PACK *p, char *name);
BUF *PackGetBufEx(PACK *p, char *name, UINT index);
bool PackGetBool(PACK *p, char *name);
void PackAddBool(PACK *p, char *name, bool b);
void PackAddBoolEx(PACK *p, char *name, bool b, UINT index, UINT total);
bool PackGetBoolEx(PACK *p, char *name, UINT index);
void PackAddIp(PACK *p, char *name, IP *ip);
void PackAddIpEx(PACK *p, char *name, IP *ip, UINT index, UINT total);
bool PackGetIp(PACK *p, char *name, IP *ip);
bool PackGetIpEx(PACK *p, char *name, IP *ip, UINT index);
UINT PackGetIp32(PACK *p, char *name);
UINT PackGetIp32Ex(PACK *p, char *name, UINT index);
void PackAddIp32(PACK *p, char *name, UINT ip32);
void PackAddIp32Ex(PACK *p, char *name, UINT ip32, UINT index, UINT total);
void PackAddIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index, UINT total);
bool PackGetIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index);
void PackAddIp6Addr(PACK *p, char *name, IPV6_ADDR *addr);
bool PackGetIp6Addr(PACK *p, char *name, IPV6_ADDR *addr);
bool PackGetData2(PACK *p, char *name, void *data, UINT size);
bool PackGetDataEx2(PACK *p, char *name, void *data, UINT size, UINT index);
bool PackIsValueExists(PACK *p, char *name);



//////////////////////////////////////////////////////////////////////////
// Cfg


#define	SAVE_BINARY_FILE_NAME_SWITCH	L"@save_binary"

// Constants
#define	TAG_DECLARE			"declare"
#define	TAG_STRING			"string"
#define	TAG_INT				"uint"
#define	TAG_INT64			"uint64"
#define	TAG_BOOL			"bool"
#define	TAG_BYTE			"byte"
#define	TAG_TRUE			"true"
#define	TAG_FALSE			"false"
#define	TAG_END				"end"
#define	TAG_ROOT			"root"

#define	TAG_CPYRIGHT		"\xef\xbb\xbf# Software Configuration File\r\n# ---------------------------\r\n# \r\n# You may edit this file when the program is not running.\r\n# \r\n# In prior to edit this file manually by your text editor,\r\n# shutdown the background service.\r\n# Otherwise, all changes will be lost.\r\n# \r\n"
#define	TAG_BINARY			"SEVPN_DB"

// Data type
#define	ITEM_TYPE_INT		1		// int
#define	ITEM_TYPE_INT64		2		// int64
#define	ITEM_TYPE_BYTE		3		// byte
#define	ITEM_TYPE_STRING	4		// string
#define	ITEM_TYPE_BOOL		5		// bool

// Folder
struct FOLDER
{
	char *Name;				// Folder name
	LIST *Items;			// List of items
	LIST *Folders;			// Subfolder
	struct FOLDER *Parent;	// Parent Folder
};

// Item
struct ITEM
{
	char *Name;				// Item Name
	UINT Type;				// Data type
	void *Buf;				// Data
	UINT size;				// Data size
	FOLDER *Parent;			// Parent Folder
};

// Configuration file reader and writer
struct CFG_RW
{
	LOCK *lock;				// Lock
	char *FileName;			// File name (ANSI)
	wchar_t *FileNameW;		// File name (Unicode)
	IO *Io;					// IO
	UCHAR LashHash[SHA1_SIZE];	// Hash value which is written last
	bool DontBackup;		// Do not use the backup
	wchar_t LastSavedDateStr[MAX_SIZE];	// Date and time string that last saved
};

typedef bool(*ENUM_FOLDER)(FOLDER *f, void *param);
typedef bool(*ENUM_ITEM)(ITEM *t, void *param);

// Parameters for the enumeration
struct CFG_ENUM_PARAM
{
	BUF *b;
	FOLDER *f;
	UINT depth;
};

int CmpItemName(void *p1, void *p2);
int CmpFolderName(void *p1, void *p2);
ITEM *CfgCreateItem(FOLDER *parent, char *name, UINT type, void *buf, UINT size);
void CfgDeleteFolder(FOLDER *f);
FOLDER *CfgCreateFolder(FOLDER *parent, char *name);
void CfgEnumFolder(FOLDER *f, ENUM_FOLDER proc, void *param);
TOKEN_LIST *CfgEnumFolderToTokenList(FOLDER *f);
TOKEN_LIST *CfgEnumItemToTokenList(FOLDER *f);
void CfgEnumItem(FOLDER *f, ENUM_ITEM proc, void *param);
FOLDER *CfgFindFolder(FOLDER *parent, char *name);
ITEM *CfgFindItem(FOLDER *parent, char *name);
ITEM *CfgAddInt(FOLDER *f, char *name, UINT i);
ITEM *CfgAddBool(FOLDER *f, char *name, bool b);
ITEM *CfgAddInt64(FOLDER *f, char *name, UINT64 i);
ITEM *CfgAddByte(FOLDER *f, char *name, void *buf, UINT size);
ITEM *CfgAddBuf(FOLDER *f, char *name, BUF *b);
ITEM *CfgAddStr(FOLDER *f, char *name, char *str);
ITEM *CfgAddUniStr(FOLDER *f, char *name, wchar_t *str);
FOLDER *CfgGetFolder(FOLDER *parent, char *name);
UINT CfgGetInt(FOLDER *f, char *name);
bool CfgGetBool(FOLDER *f, char *name);
UINT64 CfgGetInt64(FOLDER *f, char *name);
UINT CfgGetByte(FOLDER *f, char *name, void *buf, UINT size);
BUF *CfgGetBuf(FOLDER *f, char *name);
bool CfgGetStr(FOLDER *f, char *name, char *str, UINT size);
bool CfgGetUniStr(FOLDER *f, char *name, wchar_t *str, UINT size);
bool CfgIsItem(FOLDER *f, char *name);
bool CfgIsFolder(FOLDER *f, char *name);
void CfgTest();
void CfgTest2(FOLDER *f, UINT n);
char *CfgEscape(char *name);
bool CfgCheckCharForName(char c);
char *CfgUnescape(char *str);
BUF *CfgFolderToBuf(FOLDER *f, bool textmode);
BUF *CfgFolderToBufEx(FOLDER *f, bool textmode, bool no_banner);
BUF *CfgFolderToBufText(FOLDER *f);
BUF *CfgFolderToBufTextEx(FOLDER *f, bool no_banner);
BUF *CfgFolderToBufBin(FOLDER *f);
void CfgOutputFolderText(BUF *b, FOLDER *f, UINT depth);
void CfgOutputFolderBin(BUF *b, FOLDER *f);
void CfgAddLine(BUF *b, char *str, UINT depth);
void CfgAddDeclare(BUF *b, char *name, UINT depth);
void CfgAddEnd(BUF *b, UINT depth);
void CfgAddData(BUF *b, UINT type, char *name, char *data, char *sub, UINT depth);
UINT CfgStrToType(char *str);
char *CfgTypeToStr(UINT type);
void CfgAddItemText(BUF *b, ITEM *t, UINT depth);
bool CfgEnumFolderProc(FOLDER *f, void *param);
bool CfgEnumItemProc(ITEM *t, void *param);
FOLDER *CfgBufTextToFolder(BUF *b);
FOLDER *CfgBufBinToFolder(BUF *b);
void CfgReadNextFolderBin(BUF *b, FOLDER *parent);
char *CfgReadNextLine(BUF *b);
bool CfgReadNextTextBUF(BUF *b, FOLDER *current);
void CfgSave(FOLDER *f, char *name);
void CfgSaveW(FOLDER *f, wchar_t *name);
bool CfgSaveEx(CFG_RW *rw, FOLDER *f, char *name);
bool CfgSaveExW(CFG_RW *rw, FOLDER *f, wchar_t *name);
bool CfgSaveExW2(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size);
bool CfgSaveExW3(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size, bool write_binary);
FOLDER *CfgRead(char *name);
FOLDER *CfgReadW(wchar_t *name);
FOLDER *CfgCreateRoot();
void CfgTest();
void CfgTest2(FOLDER *f, UINT n);
CFG_RW *NewCfgRw(FOLDER **root, char *cfg_name);
CFG_RW *NewCfgRwW(FOLDER **root, wchar_t *cfg_name);
CFG_RW *NewCfgRwEx(FOLDER **root, char *cfg_name, bool dont_backup);
CFG_RW *NewCfgRwExW(FOLDER **root, wchar_t *cfg_name, bool dont_backup);
CFG_RW *NewCfgRwEx2W(FOLDER **root, wchar_t *cfg_name, bool dont_backup, wchar_t *template_name);
CFG_RW *NewCfgRwEx2A(FOLDER **root, char *cfg_name_a, bool dont_backup, char *template_name_a);
UINT SaveCfgRw(CFG_RW *rw, FOLDER *f);
UINT SaveCfgRwEx(CFG_RW *rw, FOLDER *f, UINT revision_number);
void FreeCfgRw(CFG_RW *rw);
ITEM *CfgAddIp32(FOLDER *f, char *name, UINT ip);
UINT CfgGetIp32(FOLDER *f, char *name);
bool CfgGetIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr);
ITEM *CfgAddIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr);
bool FileCopy(char *src, char *dst);
bool FileCopyW(wchar_t *src, wchar_t *dst);
bool FileCopyExW(wchar_t *src, wchar_t *dst, bool read_lock);
void BackupCfgWEx(CFG_RW *rw, FOLDER *f, wchar_t *original, UINT revision_number);

#if	(!defined(SECLIB_INTERNAL)) || (!defined(OS_UNIX))
bool CfgGetIp(FOLDER *f, char *name, struct IP *ip);
ITEM *CfgAddIp(FOLDER *f, char *name, struct IP *ip);
#endif


//////////////////////////////////////////////////////////////////////////
// Table


#define	UNICODE_CACHE_FILE		L".unicode_cache_%s.dat"

#define	LANGLIST_FILENAME		"|languages.txt"
#define	LANGLIST_FILENAME_WINE	"|languages_wine.txt"

#define	LANG_CONFIG_FILENAME	L"@lang.config"
#define	LANG_CONFIG_TEMPLETE	"|lang.config"

// Language constant
#define SE_LANG_JAPANESE			0	// Japanese
#define SE_LANG_ENGLISH				1	// English
#define SE_LANG_CHINESE_ZH			2	// Simplified Chinese


// String table
struct TABLE
{
	char *name;
	char *str;
	wchar_t *unistr;
};

// Unicode cache structure
typedef struct UNICODE_CACHE
{
	char StrFileName[256];	// String file name
	UINT StrFileSize;		// String file size
	char MachineName[256];	// Machine name
	UINT OsType;			// OS type
	UCHAR hash[MD5_SIZE];	// Hash
	UCHAR CharSet[64];		// Type of character code
} UNICODE_CACHE;

// Macro
#define	_SS(name)		(GetTableStr((char *)(name)))
#define	_UU(name)		(GetTableUniStr((char *)(name)))
#define	_II(name)		(GetTableInt((char *)(name)))
#define	_E(name)		(GetUniErrorStr((UINT)(name)))
#define	_EA(name)		(GetErrorStr((UINT)(name)))
#define _GETLANG()		(_II("LANG"))

// Language list
struct LANGLIST
{
	UINT Id;						// Number
	char Name[32];					// Identifier
	wchar_t TitleEnglish[128];		// English notation
	wchar_t TitleLocal[128];		// Local notation
	LIST *LcidList;					// Windows LCID list
	LIST *LangList;					// UNIX LANG environment variable list
};


// Function prototype
bool LoadTable(char *filename);
bool LoadTableW(wchar_t *filename);
bool LoadTableMain(wchar_t *filename);
bool LoadTableFromBuf(BUF *b);
void FreeTable();
TABLE *ParseTableLine(char *line, char *prefix, UINT prefix_size, LIST *replace_list);
void UnescapeStr(char *src);
int CmpTableName(void *p1, void *p2);
TABLE *FindTable(char *name);
TOKEN_LIST *GetTableNameStartWith(char *str);
char *GetTableStr(char *name);
wchar_t *GetTableUniStr(char *name);
char *GetErrorStr(UINT err);
wchar_t *GetUniErrorStr(UINT err);
UINT GetTableInt(char *name);
void GenerateUnicodeCacheFileName(wchar_t *name, UINT size, wchar_t *strfilename, UINT strfilesize, UCHAR *filehash);
void SaveUnicodeCache(wchar_t *strfilename, UINT strfilesize, UCHAR *hash);
bool LoadUnicodeCache(wchar_t *strfilename, UINT strfilesize, UCHAR *hash);
void InitTable();

LIST *LoadLangList();
void FreeLangList(LIST *o);

LANGLIST *GetBestLangByName(LIST *o, char *name);
LANGLIST *GetBestLangByLcid(LIST *o, UINT lcid);
LANGLIST *GetBestLangByLangStr(LIST *o, char *str);
LANGLIST *GetBestLangForCurrentEnvironment(LIST *o);
LANGLIST *GetLangById(LIST *o, UINT id);

bool LoadLangConfig(wchar_t *filename, char *str, UINT str_size);
bool LoadLangConfigCurrentDir(char *str, UINT str_size);
bool SaveLangConfig(wchar_t *filename, char *str);
bool SaveLangConfigCurrentDir(char *str);

void GetCurrentLang(LANGLIST *e);
UINT GetCurrentLangId();

void GetCurrentOsLang(LANGLIST *e);
UINT GetCurrentOsLangId();


//////////////////////////////////////////////////////////////////////////
// Network


// Dynamic Value
struct DYN_VALUE
{
	char Name[256];								// Name
	UINT64 Value;								// Value
};

#define	DYN64(id, default_value)	( (UINT64)GetDynValueOrDefaultSafe ( #id , (UINT64)( default_value )))
#define	DYN32(id, default_value)	(UINT)DYN64(id, (UINT)default_value)

#define	MAX_HOST_NAME_LEN			255		// Maximum length of the host name

#define	TIMEOUT_GETIP				2300

#define	TIMEOUT_INFINITE			(0x7fffffff)
#define	TIMEOUT_TCP_PORT_CHECK		(10 * 1000)
#define	TIMEOUT_SSL_CONNECT			(15 * 1000)

#define	TIMEOUT_HOSTNAME			(500)
#define	TIMEOUT_NETBIOS_HOSTNAME	(100)
#define	EXPIRES_HOSTNAME			(10 * 60 * 1000)

#define	SOCKET_BUFFER_SIZE			0x10000000

#define	IPV6_DUMMY_FOR_IPV4			0xFEFFFFDF

#define	UDPLISTENER_CHECK_INTERVAL	1000ULL
#define	UDPLISTENER_WAIT_INTERVAL	1234

#define	UDP_MAX_MSG_SIZE_DEFAULT	65507

#define	MAX_NUM_IGNORE_ERRORS		1024

#ifndef	USE_STRATEGY_LOW_MEMORY
#define	DEFAULT_GETIP_THREAD_MAX_NUM		512
#else	// USE_STRATEGY_LOW_MEMORY
#define	DEFAULT_GETIP_THREAD_MAX_NUM		64
#endif	// USE_STRATEGY_LOW_MEMORY


// SSL logging function
//#define	ENABLE_SSL_LOGGING
#define	SSL_LOGGING_DIRNAME			"@ssl_log"

// Private IP list file
#define	PRIVATE_IP_TXT_FILENAME		"@private_ip.txt"

// Start range of the random UDP port
#define	RAND_UDP_PORT_START			5000
#define	RAND_UDP_PORT_END			65530
#define	RAND_UDP_PORT_DEFAULT_NUM_RETRY	64

// Special Port
#define	MAKE_SPECIAL_PORT(p)		(UINT)((UINT)0x10000 | (UINT)(p))
#define	IS_SPECIAL_PORT(p)			(MAKEBOOL((p) & (UINT)0x10000))
#define	GET_SPECIAL_PORT(p)			(UINT)((UINT)(p) & (UINT)0xffff)

// Random R-UDP port ID
#define	RAND_PORT_ID_SERVER_LISTEN	1

// UDP buffer size
#define	UDP_MAX_BUFFER_SIZE			11911168

// Expiration of the cache acquired from the IP address list of the host
#define	HOST_IP_ADDRESS_LIST_CACHE	(5 * 1000)

// IP address
struct IP
{
	UCHAR addr[4];					// IPv4 address, (meaning that 223.255.255.254 = IPv6)
	UCHAR ipv6_addr[16];			// IPv6 address
	UINT ipv6_scope_id;				// IPv6 scope ID
};

// Size when comparing the IP structures only in the address part
#define	SIZE_OF_IP_FOR_ADDR			(sizeof(UCHAR) * 20)

// Compare the IP address part
#define	CmpIpAddr(ip1, ip2)			(Cmp((ip1), (ip2), SIZE_OF_IP_FOR_ADDR))

// IPv6 address (different format)
struct IPV6_ADDR
{
	UCHAR Value[16];				// Value
} GCC_PACKED;

// IPv6 Address Types
#define IPV6_ADDR_UNICAST						1	// Unicast
#define IPV6_ADDR_LOCAL_UNICAST					2	// Local unicast
#define IPV6_ADDR_GLOBAL_UNICAST				4	// Global Unicast
#define IPV6_ADDR_MULTICAST						8	// Multicast
#define IPV6_ADDR_ALL_NODE_MULTICAST			16	// All-nodes multicast
#define IPV6_ADDR_ALL_ROUTER_MULTICAST			32	// All routers multicast
#define IPV6_ADDR_SOLICIATION_MULTICAST			64	// Solicited-node multicast
#define	IPV6_ADDR_ZERO							128	// All zeros
#define	IPV6_ADDR_LOOPBACK						256	// Loop-back


// DNS cache list
struct DNSCACHE
{
	char *HostName;
	IP IpAddress;
};

// Client list
struct IP_CLIENT
{
	IP IpAddress;					// IP address
	UINT NumConnections;			// The number of connections
};

// Socket event
struct SOCK_EVENT
{
	REF *ref;						// Reference counter
#ifdef	OS_WIN32
	void *hEvent;					// Pointer to a Win32 event handle
#else	// OS_WIN32
	LIST *SockList;					// Socket list
	int pipe_read, pipe_write;		// Pipe
	UINT current_pipe_data;			// Amount of data in the current pipe
#endif	// OS_WIN32
};

// Type of socket
#define	SOCK_TCP				1
#define	SOCK_UDP				2
#define	SOCK_INPROC				3
#define	SOCK_RUDP_LISTEN		5
#define	SOCK_REVERSE_LISTEN		6

// SSL Accept Settings
struct SSL_ACCEPT_SETTINGS
{
	bool AcceptOnlyTls;
	bool Tls_Disable1_0;
	bool Tls_Disable1_1;
	bool Tls_Disable1_2;
};

// Socket
struct SOCK
{
	REF *ref;					// Reference counter
	LOCK *lock;					// Lock
	LOCK *ssl_lock;				// Lock related to the SSL
	LOCK *disconnect_lock;		// Disconnection lock
	SOCKET socket;				// Socket number
	SSL *ssl;					// SSL object
	struct ssl_ctx_st *ssl_ctx;	// SSL_CTX
	char SniHostname[256];		// SNI host name
	UINT Type;					// Type of socket
	bool Connected;				// Connecting flag
	bool ServerMode;			// Server mode
	bool AsyncMode;				// Asynchronous mode
	bool SecureMode;			// SSL communication mode
	bool ListenMode;			// In listening
	BUF *SendBuf;				// Transmission buffer
	bool IpClientAdded;			// Whether it has been added to the list IP_CLIENT
	bool LocalOnly;				// Only local
	bool EnableConditionalAccept;	// Conditional Accept is Enabled
	IP RemoteIP;				// IP address of the remote host
	IP LocalIP;					// IP address of the local host
	char *RemoteHostname;		// Remote host name
	UINT RemotePort;			// Port number of the remote side
	UINT LocalPort;				// Port number of the local side
	UINT64 SendSize;			// Total size of the sent data
	UINT64 RecvSize;			// Total size of received data
	UINT64 SendNum;				// Number of sent data blocks
	UINT64 RecvNum;				// Number of received data blocks
	X *RemoteX;					// Certificate of the remote host
	X *LocalX;					// Certificate of the local host
	char *CipherName;			// Cipher algorithm name
	char *WaitToUseCipher;		// Set the algorithm name to want to use
	bool IgnoreRecvErr;			// Whether the RecvFrom error is ignorable
	bool IgnoreSendErr;			// Whether the SendTo error is ignorable
	UINT TimeOut;				// Time-out value
	SOCK_EVENT *SockEvent;		// Associated socket-event
	bool CancelAccept;			// Cancel flag of the Accept
	bool AcceptCanceled;		// Flag which shows canceling of the Accept
	bool WriteBlocked;			// Previous write is blocked
	bool NoNeedToRead;			// Is not required to read
	bool Disconnecting;			// Disconnecting
	bool UdpBroadcast;			// UDP broadcast mode
	void *Param;				// Any parameters
	bool IPv6;					// IPv6
	bool IsRawSocket;			// Whether it is a raw socket
	const char *SslVersion;		// SSL version
	UINT RawSocketIPProtocol;	// IP protocol number if it's a raw socket
	TUBE *SendTube;				// Tube for transmission
	TUBE *RecvTube;				// Tube for reception
	QUEUE *InProcAcceptQueue;	// Accept queue of the in-process socket
	EVENT *InProcAcceptEvent;	// Accept event of the in-process socket
	FIFO *InProcRecvFifo;		// Receive FIFO of the in-process socket
	UINT UdpMaxMsgSize;			// Maximum transmitting and receiving size at a time on UDP
	int CurrentTos;				// Current ToS value
	bool IsTtlSupported;		// Whether the TTL value is supported
	UINT CurrentTtl;			// Current TTL value
	RUDP_STACK *R_UDP_Stack;	// R-UDP stack
	char UnderlayProtocol[64];	// Underlying protocol
	QUEUE *ReverseAcceptQueue;	// Accept queue for the reverse socket
	EVENT *ReverseAcceptEvent;	// Accept event for the reverse socket
	bool IsReverseAcceptedSocket;	// Whether it is a reverse socket
	IP Reverse_MyServerGlobalIp;	// Self global IP address when using the reverse socket
	UINT Reverse_MyServerPort;		// Self port number when using the reverse socket
	UCHAR Ssl_Init_Async_SendAlert[2];	// Initial state of SSL send_alert
	SSL_ACCEPT_SETTINGS SslAcceptSettings;	// SSL Accept Settings
	bool RawIP_HeaderIncludeFlag;

#ifdef	ENABLE_SSL_LOGGING
	// SSL Logging (for debug)
	bool IsSslLoggingEnabled;	// Flag
	IO *SslLogging_Recv;		// for Recv
	IO *SslLogging_Send;		// for Send
	LOCK *SslLogging_Lock;		// Locking
#endif	// ENABLE_SSL_LOGGING

	void *hAcceptEvent;			// Event for Accept

								// R-UDP socket related
	bool IsRUDPSocket;			// Whether this is R-UDP socket
	TUBE *BulkSendTube;			// Tube for Bulk send
	TUBE *BulkRecvTube;			// Tube for Bulk receive
	SHARED_BUFFER *BulkSendKey;	// Bulk send key
	SHARED_BUFFER *BulkRecvKey;	// Bulk receive key
	UINT RUDP_OptimizedMss;		// Optimal MSS value

#ifdef	OS_UNIX
	pthread_t CallingThread;	// Thread that is calling the system call
#endif	// OS_UNIX

#ifdef	OS_WIN32
	void *hEvent;				// Event for asynchronous mode
#endif	// OS_WIN32
};

// Underlying protocol description string of socket
#define	SOCK_UNDERLAY_NATIVE_V6		"Standard TCP/IP (IPv6)"
#define	SOCK_UNDERLAY_NATIVE_V4		"Standard TCP/IP (IPv4)"
#define	SOCK_UNDERLAY_NAT_T			"VPN over UDP with NAT-T (IPv4)"
#define	SOCK_UNDERLAY_DNS			"VPN over DNS (IPv4)"
#define	SOCK_UNDERLAY_ICMP			"VPN over ICMP (IPv4)"
#define	SOCK_UNDERLAY_INPROC		"In-Process Pipe"
#define	SOCK_UNDERLAY_INPROC_EX		"Legacy VPN - %s"
#define	SOCK_UNDERLAY_AZURE			"TCP/IP via VPN Azure (IPv4)"

// Constant of the return value
#define	SOCK_LATER	(0xffffffff)	// In blocking

// Socket Set
#define	MAX_SOCKSET_NUM		60		// Number of sockets that can be stored in a socket set
struct SOCKSET
{
	UINT NumSocket;					// The number of sockets
	SOCK *Sock[MAX_SOCKSET_NUM];	// Array of pointers to the socket
};

// Cancel object
struct CANCEL
{
	REF *ref;						// Reference counter
	bool SpecialFlag;				// Special flag (associated to the event which is generated by Win32 driver)
#ifdef	OS_WIN32
	void *hEvent;					// Pointer to a Win32 event handle
#else	// OS_WIN32
	int pipe_read, pipe_write;		// Pipe
	int pipe_special_read2, pipe_special_read3;
#endif	// OS_WIN32
};

// Routing table entry
struct ROUTE_ENTRY
{
	IP DestIP;
	IP DestMask;
	IP GatewayIP;
	bool LocalRouting;
	bool PPPConnection;
	UINT Metric;
	UINT OldIfMetric;
	UINT InterfaceID;
	UINT64 InnerScore;
};

// Routing table
struct ROUTE_TABLE
{
	UINT NumEntry;
	UINT HashedValue;
	ROUTE_ENTRY **Entry;
};

// ICMP response result
struct ICMP_RESULT
{
	bool Ok;										// Whether a correct response returned
	bool Timeout;									// Whether a time-out is occurred
	UCHAR Type;										// Message type
	UCHAR Code;										// Message code
	UCHAR Ttl;										// TTL
	UCHAR *Data;									// Data body
	UINT DataSize;									// Data size
	UINT Rtt;										// Round Trip Time
	IP IpAddress;									// IP address
};


// Host name cache list
typedef struct HOSTCACHE
{
	UINT64 Expires;							// Expiration
	IP IpAddress;							// IP address
	char HostName[256];						// Host name
} HOSTCACHE;

// NETBIOS name requests
typedef struct NBTREQUEST
{
	USHORT TransactionId;
	USHORT Flags;
	USHORT NumQuestions;
	USHORT AnswerRRs;
	USHORT AuthorityRRs;
	USHORT AdditionalRRs;
	UCHAR Query[38];
} NBTREQUEST;

// NETBIOS name response
typedef struct NBTRESPONSE
{
	USHORT TransactionId;
	USHORT Flags;
	USHORT NumQuestions;
	USHORT AnswerRRs;
	USHORT AuthorityRRs;
	USHORT AdditionalRRs;
	UCHAR Response[61];
} NBTRESPONSE;

// Socket list
typedef struct SOCKLIST
{
	LIST *SockList;
} SOCKLIST;


// Parameters for timeout thread for Solaris
typedef struct SOCKET_TIMEOUT_PARAM {
	SOCK *sock;
	CANCEL *cancel;
	THREAD *thread;
	bool unblocked;
} SOCKET_TIMEOUT_PARAM;

// Parameters for GetIP thread
struct GETIP_THREAD_PARAM
{
	REF *Ref;
	char HostName[MAX_PATH];
	bool IPv6;
	UINT Timeout;
	IP Ip;
	bool Ok;
};

// Parameters for the IP address release thread
struct WIN32_RELEASEADDRESS_THREAD_PARAM
{
	REF *Ref;
	char Guid[MAX_SIZE];
	UINT Timeout;
	bool Ok;
	bool Renew;
};

// TCP table entry
typedef struct TCPTABLE
{
	UINT Status;
	IP LocalIP;
	UINT LocalPort;
	IP RemoteIP;
	UINT RemotePort;
	UINT ProcessId;
} TCPTABLE;

// State of TCP
#define	TCP_STATE_CLOSED				1
#define	TCP_STATE_LISTEN				2
#define	TCP_STATE_SYN_SENT				3
#define	TCP_STATE_SYN_RCVD				4
#define	TCP_STATE_ESTAB					5
#define	TCP_STATE_FIN_WAIT1				6
#define	TCP_STATE_FIN_WAIT2				7
#define	TCP_STATE_CLOSE_WAIT			8
#define	TCP_STATE_CLOSING				9
#define	TCP_STATE_LAST_ACK				10
#define	TCP_STATE_TIME_WAIT				11
#define	TCP_STATE_DELETE_TCB			12

// Routing table changing notification
struct ROUTE_CHANGE
{
	ROUTE_CHANGE_DATA *Data;
};

// Tube flush list
struct TUBE_FLUSH_LIST
{
	LIST *List;							// List
};

// Tube
struct TUBE
{
	REF *Ref;							// Reference counter
	LOCK *Lock;							// Lock
	QUEUE *Queue;						// Packet queue
	EVENT *Event;						// Event
	SOCK_EVENT *SockEvent;				// SockEvent
	UINT SizeOfHeader;					// Header size
	TUBEPAIR_DATA *TubePairData;		// Tube pair data
	UINT IndexInTubePair;				// Number in the tube pair
	bool IsInFlushList;					// Whether it is registered in the Tube Flush List
	void *Param1, *Param2, *Param3;
	UINT IntParam1, IntParam2, IntParam3;
};

// Data that is to send and to receive in the tube
struct TUBEDATA
{
	void *Data;							// Body of data
	UINT DataSize;						// The size of the data
	void *Header;						// The body of the header
	UINT HeaderSize;					// Size of the header
};

// Tube pair data
struct TUBEPAIR_DATA
{
	bool IsDisconnected;				// Disconnection flag
	REF *Ref;							// Reference counter
	LOCK *Lock;							// Lock
	EVENT *Event1, *Event2;				// Event
	SOCK_EVENT *SockEvent1, *SockEvent2;	// SockEvent
};

// UDP listener socket entry
struct UDPLISTENER_SOCK
{
	IP IpAddress;						// IP address
	UINT Port;							// Port number
	SOCK *Sock;							// Socket
	bool HasError;						// Whether an error occurs
	bool Mark;							// Mark
	bool ErrorDebugDisplayed;			// Whether the error has been displayed
	UINT64 NextMyIpAndPortPollTick;		// Time to check the self IP address and port number next
	IP PublicIpAddress;					// Global IP address
	UINT PublicPort;					// Global port number
};

// UDP packet
struct UDPPACKET
{
	IP SrcIP;							// Source IP address
	IP DstIP;							// Destination IP address
	UINT SrcPort;						// Source port
	UINT DestPort;						// Destination port
	UINT Size;							// Data size
	void *Data;							// Data body
	UINT Type;							// Type
};

// UDP listener packet receipt notification procedure
typedef void (UDPLISTENER_RECV_PROC)(UDPLISTENER *u, LIST *packet_list);

// UDP listener
struct UDPLISTENER
{
	bool Halt;							// Halting flag
	SOCK_EVENT *Event;					// Event
	THREAD *Thread;						// Thread
	LIST *PortList;						// Port list
	LIST *SockList;						// Socket list
	UINT64 LastCheckTick;				// Time which the socket list was checked last
	UDPLISTENER_RECV_PROC *RecvProc;	// Receive procedure
	LIST *SendPacketList;				// Transmission packet list
	void *Param;						// Parameters
	INTERRUPT_MANAGER *Interrupts;		// Interrupt manager
	bool HostIPAddressListChanged;		// IP address list of the host has changed
	bool IsEspRawPortOpened;			// Whether the raw port opens
	bool PollMyIpAndPort;				// Examine whether the global IP and the port number of its own
	QUERYIPTHREAD *GetNatTIpThread;		// NAT-T IP address acquisition thread
};

#define	QUERYIPTHREAD_INTERVAL_LAST_OK	(3 * 60 * 60 * 1000)
#define	QUERYIPTHREAD_INTERVAL_LAST_NG	(30 * 1000)

// IP address acquisition thread
struct QUERYIPTHREAD
{
	THREAD *Thread;						// Thread
	EVENT *HaltEvent;					// Halting event
	bool Halt;							// Halting flag
	LOCK *Lock;							// Lock
	IP Ip;								// Get the IP address
	char Hostname[MAX_SIZE];			// Host name
	UINT IntervalLastOk;				// Interval if last was OK
	UINT IntervalLastNg;				// Interval if last was NG
};

// Interrupt management
struct INTERRUPT_MANAGER
{
	LIST *TickList;						// Time list
};

// SSL BIO
struct SSL_BIO
{
	BIO *bio;							// BIO
	FIFO *SendFifo;						// Transmission FIFO
	FIFO *RecvFifo;						// Reception FIFO
	bool IsDisconnected;				// Disconnected
	bool NoFree;						// Not to release the BIO
};

// SSL pipe
struct SSL_PIPE
{
	bool ServerMode;					// Whether it's in the server mode
	bool IsDisconnected;				// Disconnected
	SSL *ssl;							// SSL object
	struct ssl_ctx_st *ssl_ctx;			// SSL_CTX
	SSL_BIO *SslInOut;					// I/O BIO for the data in the SSL tunnel
	SSL_BIO *RawIn, *RawOut;			// Input and output BIO of the data flowing through the physical network
};

// IP address block list
struct IPBLOCK
{
	IP Ip;							// IP address
	IP Mask;						// Subnet mask
};


// R-UDP related constants
#define	RUDP_RESEND_TIMER				200			// Retransmission timer (initial value)
#define	RUDP_RESEND_TIMER_MAX			4792		// Retransmission timer (maximum value)
#define	RUDP_KEEPALIVE_INTERVAL_MIN		2500		// Transmission interval of Keep Alive (minimum)
#define	RUDP_KEEPALIVE_INTERVAL_MAX		4792		// Transmission interval of Keep Alive (maximum)
#define	RUDP_TIMEOUT					12000		// Time-out of R-UDP communication
#define	RUDP_DIRECT_CONNECT_TIMEOUT		5000		// R-UDP direct connection time-out
#define	RUDP_MAX_SEGMENT_SIZE			512			// Maximum segment size
// Maximum R-UDP packet size
#define	RUDP_MAX_PACKET_SIZE			(RUDP_MAX_SEGMENT_SIZE + sizeof(UINT64) * RUDP_MAX_NUM_ACK + SHA1_SIZE * 2 + sizeof(UINT64) * 4 + sizeof(UINT) + 255)
#define	RUDP_MAX_NUM_ACK				64			// Maximum number of ACKs
#define	RUDP_LOOP_WAIT_INTERVAL_S		1234		// Waiting time in the thread main loop (in server side)
#define	RUDP_LOOP_WAIT_INTERVAL_C		100			// Waiting time in the thread main loop (in client side)
#define	RUDP_MAX_FIFO_SIZE				(1600 * 1600)	// The maximum FIFO buffer size

// Interval for sending ICMP Echo from the client side when R-UDP used in ICMP mode
#define	RUDP_CLIENT_ECHO_REQUEST_SEND_INTERVAL_MIN	1000
#define	RUDP_CLIENT_ECHO_REQUEST_SEND_INTERVAL_MAX	3000

// R-UDP error code
#define	RUDP_ERROR_OK					0			// Success
#define	RUDP_ERROR_UNKNOWN				1			// Unknown Error
#define	RUDP_ERROR_TIMEOUT				2			// Time-out
#define	RUDP_ERROR_NAT_T_GETIP_FAILED	3			// IP address acquisition failure of NAT-T server
#define	RUDP_ERROR_NAT_T_NO_RESPONSE	4			// There is no response from the NAT-T server
#define	RUDP_ERROR_NAT_T_TWO_OR_MORE	5			// There are two or more hosts on the same destination IP address
#define	RUDP_ERROR_NAT_T_NOT_FOUND		6			// Host does not exist at the specified IP address
#define	RUDP_ERROR_USER_CANCELED		7			// Cancel by the user

// R-UDP segment
struct RUDP_SEGMENT
{
	UINT64 SeqNo;									// Sequence number
	UINT Size;										// Size
	UCHAR Data[RUDP_MAX_SEGMENT_SIZE];				// Data
	UINT64 NextSendTick;							// Next transmission time
	UINT NumSent;									// Number of times sent
};

// Status of R-UDP session
#define	RUDP_SESSION_STATUS_CONNECT_SENT	0		// Connection request sent
#define	RUDP_SESSION_STATUS_ESTABLISHED		1		// Connection established

// Quota
#define	RUDP_QUOTA_MAX_NUM_SESSIONS_PER_IP	DYN32(RUDP_QUOTA_MAX_NUM_SESSIONS_PER_IP, 1000)	// The number of R-UDP sessions per an IP address
#define	RUDP_QUOTA_MAX_NUM_SESSIONS			DYN32(RUDP_QUOTA_MAX_NUM_SESSIONS, 30000)	// Limit of the Number of sessions

// Range of the sequence numbers of bulk packet
#define	RUDP_BULK_SEQ_NO_RANGE				16384ULL
#define	RUDP_BULK_MAX_RECV_PKTS_IN_QUEUE	8192

// R-UDP session
struct RUDP_SESSION
{
	UINT Status;						// Status
	bool ServerMode;					// Whether it's in the server mode
	bool DisconnectFlag;				// Disconnection flag
	bool DisconnectedByYou;				// Disconnected from opponent
	bool UseHMac;
	IP MyIp;							// IP address of itself
	UINT MyPort;						// Port number of itself
	IP YourIp;							// Opponent IP address
	UINT YourPort;						// Opponent port number
	LIST *SendSegmentList;				// Transmission segment list
	LIST *RecvSegmentList;				// Received segments list
	LIST *ReplyAckList;					// List of ACKs in response
	SOCK *TcpSock;						// Corresponding TCP socket
	UINT64 LastSentTick;				// Time which the data has been sent last
	UINT64 LastRecvTick;				// Time which the data has been received last
	UCHAR Key_Init[SHA1_SIZE];			// Initial key
	UCHAR Key_Send[SHA1_SIZE];			// Key that is used to send
	UCHAR Key_Recv[SHA1_SIZE];			// Key that is used to receive
	UCHAR Magic_KeepAliveRequest[SHA1_SIZE];	// The magic number for the KeepAlive request
	UCHAR Magic_KeepAliveResponse[SHA1_SIZE];	// The magic number for KeepAlive response
	UINT64 Magic_Disconnect;			// Disconnection Signal
	UINT64 NextSendSeqNo;				// Transmission sequence number to be used next
	UINT64 LastRecvCompleteSeqNo;		// Sequence number of receiving complete
										// (This indicates all segments which have sequence number up to this number are received completely)
	UCHAR NextIv[SHA1_SIZE];			// IV value to be used next
	UINT NextKeepAliveInterval;			// Interval value of KeepAlive to be used next
	FIFO *RecvFifo;						// Reception FIFO
	FIFO *SendFifo;						// Transmission FIFO
	UINT64 YourTick;					// The largest value among received Tick from the opponent
	UINT64 LatestRecvMyTick;			// Value of the last tick among the received tick values
	UINT64 LatestRecvMyTick2;			// Variable for confirming whether LatestRecvMyTick2 changes
	UINT CurrentRtt;					// Current RTT value

	UINT Icmp_Type;						// Number of Type to be used in the ICMP
	USHORT Dns_TranId;					// Value of transaction ID used in DNS
	UINT64 Client_Icmp_NextSendEchoRequest;	// Time to send the next Echo Request in the ICMP
	SHARED_BUFFER *BulkSendKey;			// Bulk send key
	SHARED_BUFFER *BulkRecvKey;			// Bulk receive key
	UCHAR BulkNextIv[SHA1_SIZE];		// Next IV to the bulk send
	UINT64 BulkNextSeqNo;				// Next SEQ NO to the bulk send
	bool FlushBulkSendTube;				// Flag to be Flush the bulk send Tube
	UINT64 BulkRecvSeqNoMax;			// Highest sequence number received
};

// NAT Traversal Server Information
#define	UDP_NAT_T_SERVER_TAG				"x%c.x%c.servers.nat-traversal.softether-network.net."
#define	UDP_NAT_T_SERVER_TAG_ALT			"x%c.x%c.servers.nat-traversal.uxcom.jp."
#define	UDP_NAT_T_PORT						5004

// Related to processing to get the IP address of the NAT-T server
#define	UDP_NAT_T_GET_IP_INTERVAL			DYN32(UDP_NAT_T_GET_IP_INTERVAL, (5 * 1000))		// IP address acquisition interval of NAT-T server (before success)
#define	UDP_NAT_T_GET_IP_INTERVAL_MAX		DYN32(UDP_NAT_T_GET_IP_INTERVAL, (150 * 1000))		// IP address acquisition interval of NAT-T server (before success)
#define	UDP_NAT_T_GET_IP_INTERVAL_AFTER		DYN32(UDP_NAT_T_GET_IP_INTERVAL_AFTER, (5 * 60 * 1000))	// IP address acquisition interval of NAT-T server (after success)

// Related to process to get the private IP address of itself with making a TCP connection to the NAT-T server
#define	UDP_NAT_T_GET_PRIVATE_IP_TCP_SERVER		"www.msftncsi.com."

#define	UDP_NAT_T_PORT_FOR_TCP_1			80
#define	UDP_NAT_T_PORT_FOR_TCP_2			443

#define	UDP_NAT_TRAVERSAL_VERSION			1

#define	UDP_NAT_T_GET_PRIVATE_IP_INTERVAL	DYN32(UDP_NAT_T_GET_PRIVATE_IP_INTERVAL, (15 * 60 * 1000))			// Polling interval (before success)
#define	UDP_NAT_T_GET_PRIVATE_IP_INTERVAL_AFTER_MIN	DYN32(UDP_NAT_T_GET_PRIVATE_IP_INTERVAL_AFTER_MIN, (30 * 60 * 1000))	// Polling interval (after success)
#define	UDP_NAT_T_GET_PRIVATE_IP_INTERVAL_AFTER_MAX	DYN32(UDP_NAT_T_GET_PRIVATE_IP_INTERVAL_AFTER_MAX, (60 * 60 * 1000))	// Polling interval (after success)
#define	UDP_NAT_T_GET_PRIVATE_IP_CONNECT_TIMEOUT	DYN32(UDP_NAT_T_GET_PRIVATE_IP_CONNECT_TIMEOUT, (5 * 1000))			// TCP connection time-out

// About token acquisition from the NAT-T server
#define	UDP_NAT_T_GET_TOKEN_INTERVAL_1		DYN32(UDP_NAT_T_GET_TOKEN_INTERVAL_1, (5 * 1000))		// Token acquisition interval from the NAT-T server (If not acquired)
#define	UDP_NAT_T_GET_TOKEN_INTERVAL_FAIL_MAX	DYN32(UDP_NAT_T_GET_TOKEN_INTERVAL_FAIL_MAX, 20)
#define	UDP_NAT_T_GET_TOKEN_INTERVAL_2_MIN	DYN32(UDP_NAT_T_GET_TOKEN_INTERVAL_2_MIN, (20 * 60 * 1000))	// Token acquisition interval minimum value from the NAT-T server (If token have been obtained)
#define	UDP_NAT_T_GET_TOKEN_INTERVAL_2_MAX	DYN32(UDP_NAT_T_GET_TOKEN_INTERVAL_2_MAX, (30 * 60 * 1000))	// Token acquisition interval maximum value from the NAT-T server (If token have been obtained)

// The Register interval for NAT-T server
#define	UDP_NAT_T_REGISTER_INTERVAL_INITIAL	DYN32(UDP_NAT_T_REGISTER_INTERVAL_INITIAL, (5 * 1000))		// Transmission interval when the Register is not completed
#define	UDP_NAT_T_REGISTER_INTERVAL_FAIL_MAX	DYN32(UDP_NAT_T_REGISTER_INTERVAL_FAIL_MAX, 20)
#define	UDP_NAT_T_REGISTER_INTERVAL_MIN		DYN32(UDP_NAT_T_REGISTER_INTERVAL_MIN, (220 * 1000))		// Minimum value of the Register interval
#define	UDP_NAT_T_REGISTER_INTERVAL_MAX		DYN32(UDP_NAT_T_REGISTER_INTERVAL_MAX, (240 * 1000))		// Maximum value of the Register interval

// Interval for checking whether the port number or the IP address is changed
#define	UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MIN	DYN32(UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MIN, (24 * 1000))
#define	UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MAX	DYN32(UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MAX, (28 * 1000))

// The Connect Request interval for NAT-T server
#define	UDP_NAT_T_CONNECT_INTERVAL			DYN32(UDP_NAT_T_CONNECT_INTERVAL, 200)

// Polling interval for its own IP information acquisition to the NAT-T server in regular communication between the client and the server
#define	UDP_NAT_T_INTERVAL_MIN				DYN32(UDP_NAT_T_INTERVAL_MIN, (5 * 60 * 1000))
#define	UDP_NAT_T_INTERVAL_MAX				DYN32(UDP_NAT_T_INTERVAL_MAX, (10 * 60 * 1000))
#define	UDP_NAT_T_INTERVAL_INITIAL			DYN32(UDP_NAT_T_INTERVAL_INITIAL, (3 * 1000))
#define	UDP_NAT_T_INTERVAL_FAIL_MAX			DYN32(UDP_NAT_T_INTERVAL_FAIL_MAX, 60)

// R-UDP stack callback function definition
typedef void (RUDP_STACK_INTERRUPTS_PROC)(RUDP_STACK *r);
typedef bool (RUDP_STACK_RPC_RECV_PROC)(RUDP_STACK *r, UDPPACKET *p);

// ICMP protocol number
#define	IP_PROTO_ICMPV4		0x01	// ICMPv4 protocol
#define	IP_PROTO_ICMPV6		0x3a	// ICMPv6 protocol

// R-UDP protocol
#define	RUDP_PROTOCOL_UDP				0	// UDP
#define	RUDP_PROTOCOL_ICMP				1	// ICMP
#define	RUDP_PROTOCOL_DNS				2	// DNS

// Maximum time of continously changing of the NAT-T hostname
#define	RUDP_NATT_MAX_CONT_CHANGE_HOSTNAME	30
#define	RUDP_NATT_CONT_CHANGE_HOSTNAME_RESET_INTERVAL	(5 * 60 * 1000)

// Minimum time to wait for a trial to connect by ICMP and DNS in case failing to connect by TCP
#define	SOCK_CONNECT_WAIT_FOR_ICMP_AND_DNS_AT_LEAST		5000

#define	RUDP_MAX_VALIDATED_SOURCE_IP_ADDRESSES		512
#define	RUDP_VALIDATED_SOURCE_IP_ADDRESS_EXPIRES	(RUDP_TIMEOUT * 2)

// Validated Source IP Addresses for R-UDP
struct RUDP_SOURCE_IP
{
	UINT64 ExpiresTick;					// Expires
	IP ClientIP;						// Client IP address
};

// R-UDP stack
struct RUDP_STACK
{
	bool ServerMode;					// Whether it's in the server mode
	char SvcName[MAX_SIZE];				// Service name
	UCHAR SvcNameHash[SHA1_SIZE];		// Hash of the service name
	bool Halt;							// Halting flag
	void *Param;						// Parameters that can be used by developers
	UINT64 Now;							// Current time
	EVENT *HaltEvent;					// Halting event
	INTERRUPT_MANAGER *Interrupt;		// Interrupt manager
	LIST *SessionList;					// Session List
	SOCK *UdpSock;						// UDP socket
	UINT Port;							// Port number
	UINT Protocol;						// Protocol
	SOCK_EVENT *SockEvent;				// Socket event
	THREAD *Thread;						// Thread
	LOCK *Lock;							// Lock
	RUDP_STACK_INTERRUPTS_PROC *ProcInterrupts;	// Interrupt notification callback
	RUDP_STACK_RPC_RECV_PROC *ProcRpcRecv;	// RPC reception notification callback
	THREAD *IpQueryThread;				// NAT-T server IP inquiry thread
	UCHAR TmpBuf[65536];				// Temporary buffer
	LIST *SendPacketList;				// Transmission UDP packet list
	EVENT *NewSockConnectEvent;			// Event to inform that a new socket is connected
	QUEUE *NewSockQueue;				// Queue of new socket
	UINT64 TotalPhysicalReceived;		// Physical amount of data received
	UINT64 TotalLogicalReceived;		// Logical amount of data received
	UINT64 TotalPhysicalSent;			// Physical amount of data transmitted
	UINT64 TotalLogicalSent;			// Logical amount of data transmitted
	char CurrentRegisterHostname[MAX_SIZE];	// The host name of the the current destination of registration
	UINT NumChangedHostname;			// How number of changing NAT-T hostname has occured continously
	UINT64 NumChangedHostnameValueResetTick;

	// NAT-T server related
	bool NoNatTRegister;				// Flag not to register with the NAT-T server
	UINT64 NatT_TranId;					// Transaction ID is used to communicate with the NAT-T server
	UINT64 NatT_SessionKey;				// Current Session Key
	IP NatT_IP;							// IP address of the NAT-T server
	IP NatT_IP_Safe;					// IP address of the NAT-T server (thread-safe)
	IP My_Private_IP;					// Private IP address of itself
	IP My_Private_IP_Safe;				// Private IP address of itself (thread-safe)
	UINT64 NatT_GetTokenNextTick;		// Time to get the next token
	UINT NatT_GetTokenFailNum;			// Token acquisition failure times
	char NatT_Token[MAX_SIZE];			// Token needed to communicate with NAT-T Server
	bool NatT_Token_Ok;					// Flag of whether it have a valid token
	UINT64 NatT_RegisterNextTick;		// Time to register next
	UINT NatT_RegisterFailNum;			// The number of Register failures
	bool NatT_Register_Ok;				// Is a successful registration
	char NatT_Registered_IPAndPort[128];		// IP address and port number at the time of registration success
	UINT64 NatT_NextNatStatusCheckTick;	// Time to check the NAT state next
	UINT LastDDnsFqdnHash;				// DNS FQDN hash value when last checked
	volatile UINT *NatTGlobalUdpPort;	// NAT-T global UDP port
	UCHAR RandPortId;					// Random UDP port ID
	bool NatT_EnableSourceIpValidation;	// Enable the source IP address validation mechanism
	LIST *NatT_SourceIpList;			// Authenticated source IP adddress list

										// For Client
	bool TargetIpAndPortInited;			// The target IP address and the port number are initialized
	IP TargetIp;						// Target IP address
	UINT TargetPort;					// Target port number
	EVENT *TargetConnectedEvent;		// Event to be set when the connection to the target is successful
	SOCK *TargetConnectedSock;			// Connected socket
	bool ClientInitiated;				// Flag to indicate that the connection is initiated
	bool DoNotSetTargetConnectedSock;	// Flag indicating that it should not set the TargetConnectedSock
	USHORT Client_IcmpId, Client_IcmpSeqNo;	// Sequence number and ICMP ID that is randomly generated on the client side
};

// Data for the thread for concurrent connection attempts for the R-UDP and TCP
struct CONNECT_TCP_RUDP_PARAM
{
	IP Ip;
	UINT Port;
	UINT Timeout;
	char Hostname[MAX_SIZE];
	bool *CancelFlag;
	UINT NatT_ErrorCode;
	char SvcName[MAX_SIZE];
	char HintStr[MAX_SIZE];
	char TargetHostname[MAX_SIZE];
	SOCK *Result_Nat_T_Sock;
	SOCK *Result_Tcp_Sock;
	bool Finished;
	bool Ok;
	UINT64 FinishedTick;
	EVENT *FinishEvent;
	UINT RUdpProtocol;
	UINT Delay;
	bool Tcp_TryStartSsl;
	bool Tcp_SslNoTls;
	LOCK *CancelLock;
	SOCK *CancelDisconnectSock;
	bool Tcp_InNegotiation;
};

#define	SSL_DEFAULT_CONNECT_TIMEOUT		(15 * 1000)		// SSL default timeout

// Header for TCP Pair 
struct TCP_PAIR_HEADER
{
	bool EnableHMac;
};

// The constants for file query by using UDP
#define	UDP_FILE_QUERY_RETRY_INTERVAL	100			// Retry interval
#define	UDP_FILE_QUERY_DST_PORT			5004		// Destination UDP port number
#define	UDP_FILE_QUERY_MAGIC_NUMBER		"{5E465695-7923-4CCD-9B51-44444BE1E758}"	// Magic number
#define	UDP_FILE_QUERY_BFLETS_TXT_FILENAME	"|BFletsUdpList.txt"	// Text file name of the IPv6 node list

// The constant for DNS proxy for the B FLETs
#define	BFLETS_DNS_PROXY_PORT			443
#define	BFLETS_DNS_PROXY_PATH			"/ddns/queryhost.aspx"
#define	BFLETS_DNS_PROXY_CERT_HASH		"EFAC5FA0CDD14E0F864EED58A73C35D7E33B62F3"
#define	BFLETS_DNS_PROXY_TIMEOUT_FOR_GET_F	500		// Timeout when searching for the server by UDP
#define	BFLETS_DNS_PROXY_TIMEOUT_FOR_QUERY	3000	// Timeout for the response from the proxy DNS server

// FLET'S Hikar-Next (East) DNS proxy host name
#define	FLETS_NGN_EAST_DNS_PROXY_HOSTNAME		"senet.aoi.flets-east.jp"
#define	FLETS_NGN_WEST_DNS_PROXY_HOSTNAME		"senet.p-ns.flets-west.jp"
#define	FLETS_NGN_DNS_QUERY_TIMEOUT				1000		// FLET'S Hikar-Next host name query timeout

// Detection result of the type of FLET'S line
#define	FLETS_DETECT_TYPE_EAST_BFLETS_PRIVATE		1	// NTT East B-FLETs
#define	FLETS_DETECT_TYPE_EAST_NGN_PRIVATE			2	// Wrapping in network of NTT East NGN
#define	FLETS_DETECT_TYPE_WEST_NGN_PRIVATE			4	// Wrapping in network of NTT West NGN

// NIC adapter entry
struct NIC_ENTRY
{
	char IfName[MAX_SIZE];
	UCHAR MacAddress[6];
};


// HTTP value
struct HTTP_VALUE
{
	char *Name;						// Name
	char *Data;						// Data
};

// HTTP header
struct HTTP_HEADER
{
	char *Method;					// Method
	char *Target;					// Target
	char *Version;					// Version
	LIST *ValueList;				// Value list
};

// HTTPS server / client related string constant
#define	DEFAULT_USER_AGENT	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0"
#define	DEFAULT_ACCEPT		"image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/msword, application/vnd.ms-powerpoint, application/vnd.ms-excel, */*"
#define	DEFAULT_ENCODING	"gzip, deflate"
#define	HTTP_CONTENT_TYPE	"text/html; charset=iso-8859-1"
#define	HTTP_CONTENT_TYPE2	"application/octet-stream"
#define	HTTP_CONTENT_TYPE3	"image/jpeg"
#define	HTTP_CONTENT_TYPE4	"text/html"
#define	HTTP_CONTENT_TYPE5	"message/rfc822"
#define	HTTP_KEEP_ALIVE		"timeout=15; max=19"
#define	HTTP_VPN_TARGET		"/vpnsvc/vpn.cgi"
#define	HTTP_VPN_TARGET2	"/vpnsvc/connect.cgi"
#define HTTP_VPN_TARGET_POSTDATA	"VPNCONNECT"
#define	HTTP_SAITAMA		"/saitama.jpg"
#define	HTTP_PICTURES		"/picture"
// Maximum size of a single line in the HTTP header
#define	HTTP_HEADER_LINE_MAX_SIZE	4096
// Maximum number of lines in the HTTP header
#define	HTTP_HEADER_MAX_LINES		128
// Maximum size of the random number to be included in the PACK
#define	HTTP_PACK_RAND_SIZE_MAX		1000
// Maximum PACK size in the HTTP
#define	HTTP_PACK_MAX_SIZE			65536





int GetCurrentTimezone();

bool GetSniNameFromSslPacket(UCHAR *packet_buf, UINT packet_size, char *sni, UINT sni_size);
bool GetSniNameFromPreSslConnection(SOCK *s, char *sni, UINT sni_size);

bool IsUseDnsProxy();
bool IsUseAlternativeHostname();

#ifdef	OS_WIN32
int GetCurrentTimezoneWin32();
#endif	// OS_WIN32

HTTP_VALUE *GetHttpValue(HTTP_HEADER *header, char *name);
void AddHttpValue(HTTP_HEADER *header, HTTP_VALUE *value);
HTTP_HEADER *NewHttpHeader(char *method, char *target, char *version);
HTTP_HEADER *NewHttpHeaderEx(char *method, char *target, char *version, bool no_sort);
int CompareHttpValue(void *p1, void *p2);
void FreeHttpValue(HTTP_VALUE *value);
void FreeHttpHeader(HTTP_HEADER *header);

bool SendPack(SOCK *s, PACK *p);
PACK *RecvPack(SOCK *s);
PACK *RecvPackWithHash(SOCK *s);
bool SendPackWithHash(SOCK *s, PACK *p);

UINT GetErrorFromPack(PACK *p);
PACK *PackError(UINT error);

void CreateDummyValue(PACK *p);

HTTP_VALUE *NewHttpValue(char *name, char *data);
char *RecvLine(SOCK *s, UINT max_size);
HTTP_HEADER *RecvHttpHeader(SOCK *s);
bool SendHttpHeader(SOCK *s, HTTP_HEADER *header);
char *HttpHeaderToStr(HTTP_HEADER *header);
bool PostHttp(SOCK *s, HTTP_HEADER *header, void *post_data, UINT post_size);
UINT GetContentLength(HTTP_HEADER *header);
void GetHttpDateStr(char *str, UINT size, UINT64 t);
bool HttpSendForbidden(SOCK *s, char *target, char *server_id);
bool HttpSendNotFound(SOCK *s, char *target);
bool HttpSendNotImplemented(SOCK *s, char *method, char *target, char *version);
bool HttpSendInvalidHostname(SOCK *s, char *method);
bool HttpServerSend(SOCK *s, PACK *p);
bool HttpClientSend(SOCK *s, PACK *p);
PACK *HttpServerRecv(SOCK *s);
PACK *HttpClientRecv(SOCK *s);

bool HttpSendServerError(SOCK *s, char *target);

bool GetIPViaDnsProxyForJapanFlets(IP *ip_ret, char *hostname, bool ipv6, UINT timeout, bool *cancel, char *dns_proxy_hostname);
bool GetDnsProxyIPAddressForJapanBFlets(IP *ip_ret, UINT timeout, bool *cancel);
BUF *QueryFileByUdpForJapanBFlets(UINT timeout, bool *cancel);
BUF *QueryFileByIPv6Udp(LIST *ip_list, UINT timeout, bool *cancel);
UINT DetectFletsType();

void ListenTcpForPopupFirewallDialog();

bool DetectIsServerSoftEtherVPN(SOCK *s);
void ConnectThreadForTcp(THREAD *thread, void *param);
void ConnectThreadForRUDP(THREAD *thread, void *param);
void ConnectThreadForOverDnsOrIcmp(THREAD *thread, void *param);
SOCK *NewRUDPClientNatT(char *svc_name, IP *ip, UINT *error_code, UINT timeout, bool *cancel, char *hint_str, char *target_hostname);
RUDP_STACK *NewRUDPServer(char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, bool no_natt_register, bool over_dns_mode, volatile UINT *natt_global_udp_port, UCHAR rand_port_id);
SOCK *NewRUDPClientDirect(char *svc_name, IP *ip, UINT port, UINT *error_code, UINT timeout, bool *cancel, SOCK *sock, SOCK_EVENT *sock_event, UINT local_port, bool over_dns_mode);
RUDP_STACK *NewRUDP(bool server_mode, char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, SOCK *sock, SOCK_EVENT *sock_event, bool server_no_natt_register, bool over_dns_mode, IP *client_target_ip, volatile UINT *natt_global_udp_port, UCHAR rand_port_id);
void FreeRUDP(RUDP_STACK *r);
void RUDPMainThread(THREAD *thread, void *param);
void RUDPRecvProc(RUDP_STACK *r, UDPPACKET *p);
void RUDPInterruptProc(RUDP_STACK *r);
void RUDPIpQueryThread(THREAD *thread, void *param);
void RUDPSendPacket(RUDP_STACK *r, IP *dest_ip, UINT dest_port, void *data, UINT size, UINT icmp_type);
void GetCurrentMachineIpProcessHash(void *hash);
void GetCurrentMachineIpProcessHashInternal(void *hash);
int RUDPCompareSessionList(void *p1, void *p2);
RUDP_SESSION *RUDPNewSession(bool server_mode, IP *my_ip, UINT my_port, IP *your_ip, UINT your_port, UCHAR *init_key);
void RUDPFreeSession(RUDP_SESSION *se);
int RUDPCompareSegmentList(void *p1, void *p2);
RUDP_SESSION *RUDPSearchSession(RUDP_STACK *r, IP *my_ip, UINT my_port, IP *your_ip, UINT your_port);
void RUDPSendSegmentNow(RUDP_STACK *r, RUDP_SESSION *se, UINT64 seq_no, void *data, UINT size);
void RUDPSendSegment(RUDP_STACK *r, RUDP_SESSION *se, void *data, UINT size);
bool RUDPProcessRecvPacket(RUDP_STACK *r, RUDP_SESSION *se, void *recv_data, UINT recv_size);
bool RUDPCheckSignOfRecvPacket(RUDP_STACK *r, RUDP_SESSION *se, void *recv_data, UINT recv_size);
void RUDPProcessAck(RUDP_STACK *r, RUDP_SESSION *se, UINT64 seq);
void RUDPProcessAck2(RUDP_STACK *r, RUDP_SESSION *se, UINT64 max_seq);
void RUDPProcessRecvPayload(RUDP_STACK *r, RUDP_SESSION *se, UINT64 seq, void *payload_data, UINT payload_size);
void RUDPInitSock(RUDP_STACK *r, RUDP_SESSION *se);
void RUDPDisconnectSession(RUDP_STACK *r, RUDP_SESSION *se, bool disconnected_by_you);
UINT64 RUDPGetCurrentSendingMinSeqNo(RUDP_SESSION *se);
UINT64 RUDPGetCurrentSendingMaxSeqNo(RUDP_SESSION *se);
SOCK *ListenRUDP(char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, bool no_natt_register, bool over_dns_mode);
SOCK *ListenRUDPEx(char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, bool no_natt_register, bool over_dns_mode,
	volatile UINT *natt_global_udp_port, UCHAR rand_port_id);
SOCK *AcceptRUDP(SOCK *s);
void *InitWaitUntilHostIPAddressChanged();
void FreeWaitUntilHostIPAddressChanged(void *p);
void WaitUntilHostIPAddressChanged(void *p, EVENT *event, UINT timeout, UINT ip_check_interval);
UINT GetHostIPAddressHash32();
bool GetMyPrivateIP(IP *ip, bool from_vg);
char *GetRandHostNameForGetMyPrivateIP();
UINT GenRandInterval(UINT min, UINT max);
void RUDPProcess_NatT_Recv(RUDP_STACK *r, UDPPACKET *udp);
void RUDPDo_NatT_Interrupt(RUDP_STACK *r);
void RUDPGetRegisterHostNameByIP(char *dst, UINT size, IP *ip);
bool RUDPParseIPAndPortStr(void *data, UINT data_size, IP *ip, UINT *port);
void ParseNtUsername(char *src_username, char *dst_username, UINT dst_username_size, char *dst_domain, UINT dst_domain_size, bool do_not_parse_atmark);
void RUDPBulkSend(RUDP_STACK *r, RUDP_SESSION *se, void *data, UINT data_size);
bool RUDPProcessBulkRecvPacket(RUDP_STACK *r, RUDP_SESSION *se, void *recv_data, UINT recv_size);
UINT RUDPCalcBestMssForBulk(RUDP_STACK *r, RUDP_SESSION *se);
bool IsIPLocalHostOrMySelf(IP *ip);
UINT RUDPGetRandPortNumber(UCHAR rand_port_id);
void RUDPSetSourceIpValidationForceDisable(bool b);
bool RUDPIsIpInValidateList(RUDP_STACK *r, IP *ip);
void RUDPAddIpToValidateList(RUDP_STACK *r, IP *ip);

bool GetBestLocalIpForTarget(IP *local_ip, IP *target_ip);
SOCK *NewUDP4ForSpecificIp(IP *target_ip, UINT port);

#ifdef	OS_WIN32

// Function prototype for Win32
void Win32InitSocketLibrary();
void Win32FreeSocketLibrary();
void Win32Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2);
void Win32InitAsyncSocket(SOCK *sock);
void Win32JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event);
void Win32FreeAsyncSocket(SOCK *sock);
void Win32IpForwardRowToRouteEntry(ROUTE_ENTRY *entry, void *ip_forward_row);
void Win32RouteEntryToIpForwardRow(void *ip_forward_row, ROUTE_ENTRY *entry);
int Win32CompareRouteEntryByMetric(void *p1, void *p2);
ROUTE_TABLE *Win32GetRouteTable();
bool Win32AddRouteEntry(ROUTE_ENTRY *e, bool *already_exists);
void Win32DeleteRouteEntry(ROUTE_ENTRY *e);
void Win32UINTToIP(IP *ip, UINT i);
UINT Win32IPToUINT(IP *ip);
UINT Win32GetVLanInterfaceID(char *instance_name);
char **Win32EnumVLan(char *tag_name);
void Win32Cancel(CANCEL *c);
void Win32CleanupCancel(CANCEL *c);
CANCEL *Win32NewCancel();
SOCK_EVENT *Win32NewSockEvent();
void Win32SetSockEvent(SOCK_EVENT *event);
void Win32CleanupSockEvent(SOCK_EVENT *event);
bool Win32WaitSockEvent(SOCK_EVENT *event, UINT timeout);
bool Win32GetDefaultDns(IP *ip, char *domain, UINT size);
bool Win32GetDnsSuffix(char *domain, UINT size);
void Win32RenewDhcp();
void Win32RenewDhcp9x(UINT if_id);
void Win32ReleaseDhcp9x(UINT if_id, bool wait);
void Win32FlushDnsCache();
int CompareIpAdapterIndexMap(void *p1, void *p2);
LIST *Win32GetTcpTableList();
LIST *Win32GetTcpTableListByGetExtendedTcpTable();
LIST *Win32GetTcpTableListByAllocateAndGetTcpExTableFromStack();
LIST *Win32GetTcpTableListByGetTcpTable();
ROUTE_CHANGE *Win32NewRouteChange();
void Win32FreeRouteChange(ROUTE_CHANGE *r);
bool Win32IsRouteChanged(ROUTE_CHANGE *r);
bool Win32GetAdapterFromGuid(void *a, char *guid);
SOCKET Win32Accept(SOCK *sock, SOCKET s, struct sockaddr *addr, int *addrlen, bool ipv6);

bool Win32ReleaseAddress(void *a);
bool Win32ReleaseAddressByGuid(char *guid);
bool Win32ReleaseAddressByGuidEx(char *guid, UINT timeout);
void Win32ReleaseAddressByGuidExThread(THREAD *t, void *param);
void ReleaseWin32ReleaseAddressByGuidThreadParam(WIN32_RELEASEADDRESS_THREAD_PARAM *p);
bool Win32ReleaseOrRenewAddressByGuidEx(char *guid, UINT timeout, bool renew);
bool Win32RenewAddress(void *a);
bool Win32RenewAddressByGuid(char *guid);
bool Win32RenewAddressByGuidEx(char *guid, UINT timeout);


#else	// OS_WIN32

// Function prototype for UNIX
void UnixInitSocketLibrary();
void UnixFreeSocketLibrary();
void UnixSelect(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2);
void UnixInitAsyncSocket(SOCK *sock);
void UnixJoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event);
void UnixFreeAsyncSocket(SOCK *sock);
void UnixIpForwardRowToRouteEntry(ROUTE_ENTRY *entry, void *ip_forward_row);
void UnixRouteEntryToIpForwardRow(void *ip_forward_row, ROUTE_ENTRY *entry);
int UnixCompareRouteEntryByMetric(void *p1, void *p2);
ROUTE_TABLE *UnixGetRouteTable();
bool UnixAddRouteEntry(ROUTE_ENTRY *e, bool *already_exists);
void UnixDeleteRouteEntry(ROUTE_ENTRY *e);
UINT UnixGetVLanInterfaceID(char *instance_name);
char **UnixEnumVLan(char *tag_name);
void UnixCancel(CANCEL *c);
void UnixCleanupCancel(CANCEL *c);
CANCEL *UnixNewCancel();
SOCK_EVENT *UnixNewSockEvent();
void UnixSetSockEvent(SOCK_EVENT *event);
void UnixCleanupSockEvent(SOCK_EVENT *event);
bool UnixWaitSockEvent(SOCK_EVENT *event, UINT timeout);
bool UnixGetDefaultDns(IP *ip);
void UnixRenewDhcp();
void UnixNewPipe(int *pipe_read, int *pipe_write);
void UnixWritePipe(int pipe_write);
void UnixDeletePipe(int p1, int p2);
void UnixSelectInner(UINT num_read, UINT *reads, UINT num_write, UINT *writes, UINT timeout);
void UnixSetSocketNonBlockingMode(int fd, bool nonblock);

#endif	// OS_WIN32

// Function prototype
void InitNetwork();
void FreeNetwork();
void InitDnsCache();
void FreeDnsCache();
void LockDnsCache();
void UnlockDnsCache();
int CompareDnsCache(void *p1, void *p2);
void GenDnsCacheKeyName(char *dst, UINT size, char *src, bool ipv6);
void NewDnsCacheEx(char *hostname, IP *ip, bool ipv6);
DNSCACHE *FindDnsCacheEx(char *hostname, bool ipv6);
bool QueryDnsCacheEx(IP *ip, char *hostname, bool ipv6);
void NewDnsCache(char *hostname, IP *ip);
DNSCACHE *FindDnsCache(char *hostname);
bool QueryDnsCache(IP *ip, char *hostname);
void InAddrToIP(IP *ip, struct in_addr *addr);
void InAddrToIP6(IP *ip, struct in6_addr *addr);
void IPToInAddr(struct in_addr *addr, IP *ip);
void IPToInAddr6(struct in6_addr *addr, IP *ip);
bool StrToIP(IP *ip, char *str);
UINT StrToIP32(char *str);
bool UniStrToIP(IP *ip, wchar_t *str);
UINT UniStrToIP32(wchar_t *str);
void IPToStr(char *str, UINT size, IP *ip);
void IPToStr4(char *str, UINT size, IP *ip);
void IPToStr32(char *str, UINT size, UINT ip);
void IPToStr128(char *str, UINT size, UCHAR *ip_bytes);
void IPToStr4or6(char *str, UINT size, UINT ip_4_uint, UCHAR *ip_6_bytes);
void IPToUniStr(wchar_t *str, UINT size, IP *ip);
void IPToUniStr32(wchar_t *str, UINT size, UINT ip);
bool GetIPEx(IP *ip, char *hostname, bool ipv6);
bool GetIP46(IP *ip4, IP *ip6, char *hostname);
bool GetIP46Ex(IP *ip4, IP *ip6, char *hostname, UINT timeout, bool *cancel);
bool GetIP46Any4(IP *ip, char *hostname);
bool GetIP46Any6(IP *ip, char *hostname);
bool GetIP(IP *ip, char *hostname);
bool GetIP4(IP *ip, char *hostname);
bool GetIP6(IP *ip, char *hostname);
bool GetIP4Ex(IP *ip, char *hostname, UINT timeout, bool *cancel);
bool GetIP6Ex(IP *ip, char *hostname, UINT timeout, bool *cancel);
bool GetIP4Ex6Ex(IP *ip, char *hostname, UINT timeout, bool ipv6, bool *cancel);
bool GetIP4Ex6Ex2(IP *ip, char *hostname, UINT timeout, bool ipv6, bool *cancel, bool only_direct_dns);
void GetIP4Ex6ExThread(THREAD *t, void *param);
void ReleaseGetIPThreadParam(GETIP_THREAD_PARAM *p);
void CleanupGetIPThreadParam(GETIP_THREAD_PARAM *p);
bool GetIP4Inner(IP *ip, char *hostname);
bool GetIP6Inner(IP *ip, char *hostname);
bool GetHostNameInner(char *hostname, UINT size, IP *ip);
bool GetHostNameInner6(char *hostname, UINT size, IP *ip);
bool GetHostName(char *hostname, UINT size, IP *ip);
void GetHostNameThread(THREAD *t, void *p);
void GetMachineName(char *name, UINT size);
void GetMachineNameEx(char *name, UINT size, bool no_load_hosts);
bool GetMachineNameFromHosts(char *name, UINT size);
void GetMachineIp(IP *ip);
void GetMachineHostName(char *name, UINT size);
void UINTToIP(IP *ip, UINT value);
UINT IPToUINT(IP *ip);
SOCK *NewSock();
void ReleaseSock(SOCK *s);
void CleanupSock(SOCK *s);
SOCK *Connect(char *hostname, UINT port);
SOCK *ConnectEx(char *hostname, UINT port, UINT timeout);
SOCK *ConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag);
SOCK *ConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, char *nat_t_svc_name, UINT *nat_t_error_code, bool try_start_ssl, bool ssl_no_tls, bool no_get_hostname);
SOCK *ConnectEx4(char *hostname, UINT port, UINT timeout, bool *cancel_flag, char *nat_t_svc_name, UINT *nat_t_error_code, bool try_start_ssl, bool ssl_no_tls, bool no_get_hostname, IP *ret_ip);
SOCKET ConnectTimeoutIPv4(IP *ip, UINT port, UINT timeout, bool *cancel_flag);
void SetSocketSendRecvBufferSize(SOCKET s, UINT size);
UINT GetSocketBufferSize(SOCKET s, bool send);
bool SetSocketBufferSize(SOCKET s, bool send, UINT size);
UINT SetSocketBufferSizeWithBestEffort(SOCKET s, bool send, UINT size);
void InitUdpSocketBufferSize(SOCKET s);
void QuerySocketInformation(SOCK *sock);
bool SetTtl(SOCK *sock, UINT ttl);
void Disconnect(SOCK *sock);
SOCK *Listen(UINT port);
SOCK *ListenEx(UINT port, bool local_only);
SOCK *ListenEx2(UINT port, bool local_only, bool enable_ca);
SOCK *Listen6(UINT port);
SOCK *ListenEx6(UINT port, bool local_only);
SOCK *ListenEx62(UINT port, bool local_only, bool enable_ca);
SOCK *Accept(SOCK *sock);
SOCK *Accept6(SOCK *sock);
UINT Send(SOCK *sock, void *data, UINT size, bool secure);
UINT Recv(SOCK *sock, void *data, UINT size, bool secure);
UINT Peek(SOCK *sock, void *data, UINT size);
void SetNoNeedToRead(SOCK *sock);
UINT SecureSend(SOCK *sock, void *data, UINT size);
UINT SecureRecv(SOCK *sock, void *data, UINT size);
bool StartSSL(SOCK *sock, X *x, K *priv);
bool StartSSLEx(SOCK *sock, X *x, K *priv, bool client_tls, UINT ssl_timeout, char *sni_hostname);
bool AddChainSslCert(struct ssl_ctx_st *ctx, X *x);
void AddChainSslCertOnDirectory(struct ssl_ctx_st *ctx);
bool SendAll(SOCK *sock, void *data, UINT size, bool secure);
void SendAdd(SOCK *sock, void *data, UINT size);
bool SendNow(SOCK *sock, int secure);
bool RecvAll(SOCK *sock, void *data, UINT size, bool secure);
bool RecvAllEx(SOCK *sock, void **data_new_ptr, UINT size, bool secure);
void InitSockSet(SOCKSET *set);
void AddSockSet(SOCKSET *set, SOCK *sock);
CANCEL *NewCancel();
CANCEL *NewCancelSpecial(void *hEvent);
void ReleaseCancel(CANCEL *c);
void CleanupCancel(CANCEL *c);
void Cancel(CANCEL *c);
void Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2);
void SetWantToUseCipher(SOCK *sock, char *name);
void InitAsyncSocket(SOCK *sock);
SOCK *NewUDP(UINT port);
SOCK *NewUDPEx(UINT port, bool ipv6);
SOCK *NewUDPEx2(UINT port, bool ipv6, IP *ip);
SOCK *NewUDPEx3(UINT port, IP *ip);
SOCK *NewUDP4(UINT port, IP *ip);
SOCK *NewUDP6(UINT port, IP *ip);
SOCK *NewUDPEx2Rand(bool ipv6, IP *ip, void *rand_seed, UINT rand_seed_size, UINT num_retry);
SOCK *NewUDPEx2RandMachineAndExePath(bool ipv6, IP *ip, UINT num_retry, UCHAR rand_port_id);
void ClearSockDfBit(SOCK *s);
void SetRawSockHeaderIncludeOption(SOCK *s, bool enable);
UINT GetNewAvailableUdpPortRand();
UINT NewRandPortByMachineAndExePath(UINT start_port, UINT end_port, UINT additional_int);
void DisableUDPChecksum(SOCK *s);
UINT SendTo(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size);
UINT SendToEx(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast);
UINT SendTo6(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size);
UINT SendTo6Ex(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast);
UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size);
UINT RecvFrom6(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size);
void SetTimeout(SOCK *sock, UINT timeout);
UINT GetTimeout(SOCK *sock);
bool CheckTCPPort(char *hostname, UINT port);
bool CheckTCPPortEx(char *hostname, UINT port, UINT timeout);
void CheckTCPPortThread(THREAD *thread, void *param);
ROUTE_TABLE *GetRouteTable();
void FreeRouteTable(ROUTE_TABLE *t);
bool AddRouteEntryEx(ROUTE_ENTRY *e, bool *already_exists);
bool AddRouteEntry(ROUTE_ENTRY *e);
void DeleteRouteEntry(ROUTE_ENTRY *e);
char **EnumVLan(char *tag_name);
void FreeEnumVLan(char **s);
UINT GetVLanInterfaceID(char *tag_name);
ROUTE_ENTRY *GetBestRouteEntry(IP *ip);
ROUTE_ENTRY *GetBestRouteEntryEx(IP *ip, UINT exclude_if_id);
ROUTE_ENTRY *GetBestRouteEntryFromRouteTable(ROUTE_TABLE *table, IP *ip);
ROUTE_ENTRY *GetBestRouteEntryFromRouteTableEx(ROUTE_TABLE *table, IP *ip, UINT exclude_if_id);
void FreeRouteEntry(ROUTE_ENTRY *e);
void JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event);
SOCK_EVENT *NewSockEvent();
void SetSockEvent(SOCK_EVENT *event);
void CleanupSockEvent(SOCK_EVENT *event);
bool WaitSockEvent(SOCK_EVENT *event, UINT timeout);
void ReleaseSockEvent(SOCK_EVENT *event);
void SetIP(IP *ip, UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4);
UINT SetIP32(UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4);
bool GetDefaultDns(IP *ip);
bool GetDomainName(char *name, UINT size);
bool UnixGetDomainName(char *name, UINT size);
void RenewDhcp();
void AcceptInit(SOCK *s);
void AcceptInitEx(SOCK *s, bool no_lookup_hostname);
void DisableGetHostNameWhenAcceptInit();
bool CheckCipherListName(char *name);
TOKEN_LIST *GetCipherList();
COUNTER *GetNumTcpConnectionsCounter();
void InitWaitThread();
void FreeWaitThread();
void AddWaitThread(THREAD *t);
void DelWaitThread(THREAD *t);
void InitHostCache();
void FreeHostCache();
int CompareHostCache(void *p1, void *p2);
void AddHostCache(IP *ip, char *hostname);
bool GetHostCache(char *hostname, UINT size, IP *ip);
bool IsSubnetMask(IP *ip);
bool IsSubnetMask4(IP *ip);
bool IsSubnetMask32(UINT ip);
bool IsNetworkAddress(IP *ip, IP *mask);
bool IsNetworkAddress4(IP *ip, IP *mask);
bool IsNetworkAddress32(UINT ip, UINT mask);
bool IsHostIPAddress4(IP *ip);
bool IsHostIPAddress32(UINT ip);
bool IsZeroIp(IP *ip);
bool IsZeroIP(IP *ip);
bool IsZeroIP6Addr(IPV6_ADDR *addr);
UINT IntToSubnetMask32(UINT i);
void IntToSubnetMask4(IP *ip, UINT i);
bool GetNetBiosName(char *name, UINT size, IP *ip);
bool NormalizeMacAddress(char *dst, UINT size, char *src);
SOCKLIST *NewSockList();
void AddSockList(SOCKLIST *sl, SOCK *s);
void DelSockList(SOCKLIST *sl, SOCK *s);
void StopSockList(SOCKLIST *sl);
void FreeSockList(SOCKLIST *sl);
bool IsIPv6Supported();
void SetSockTos(SOCK *s, int tos);
void SetSockHighPriority(SOCK *s, bool flag);
void InitIpClientList();
void FreeIpClientList();
int CompareIpClientList(void *p1, void *p2);
void AddIpClient(IP *ip);
void DelIpClient(IP *ip);
IP_CLIENT *SearchIpClient(IP *ip);
UINT GetNumIpClient(IP *ip);
void SetLinuxArpFilter();
LIST *GetTcpTableList();
void FreeTcpTableList(LIST *o);
int CompareTcpTable(void *p1, void *p2);
void PrintTcpTableList(LIST *o);
TCPTABLE *GetTcpTableFromEndPoint(LIST *o, IP *local_ip, UINT local_port, IP *remote_ip, UINT remote_port);
UINT GetTcpProcessIdFromSocket(SOCK *s);
UINT GetTcpProcessIdFromSocketReverse(SOCK *s);
bool CanGetTcpProcessId();
int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag);
void EnableNetworkNameCache();
void DisableNetworkNameCache();
bool IsNetworkNameCacheEnabled();
ROUTE_CHANGE *NewRouteChange();
void FreeRouteChange(ROUTE_CHANGE *r);
bool IsRouteChanged(ROUTE_CHANGE *r);
void RouteToStr(char *str, UINT str_size, ROUTE_ENTRY *e);
void DebugPrintRoute(ROUTE_ENTRY *e);
void DebugPrintRouteTable(ROUTE_TABLE *r);
bool IsIPv6LocalNetworkAddress(IP *ip);
UINT GetNumWaitThread();

#ifdef	ENABLE_SSL_LOGGING
void SockEnableSslLogging(SOCK *s);
void SockWriteSslLog(SOCK *s, void *send_data, UINT send_size, void *recv_data, UINT recv_size);
void SockCloseSslLogging(SOCK *s);
#endif	// ENABLE_SSL_LOGGING

void SocketTimeoutThread(THREAD *t, void *param);
SOCKET_TIMEOUT_PARAM *NewSocketTimeout(SOCK *sock);
void FreeSocketTimeout(SOCKET_TIMEOUT_PARAM *ttp);

void CopyIP(IP *dst, IP *src);
bool CheckSubnetLength6(UINT i);
bool IsIP6(IP *ip);
bool IsIP4(IP *ip);
bool IsSameIPVer(IP *ip1, IP *ip2);
void IPv6AddrToIP(IP *ip, IPV6_ADDR *addr);
bool IPToIPv6Addr(IPV6_ADDR *addr, IP *ip);
void SetIP6(IP *ip, UCHAR *value);
void GetLocalHostIP6(IP *ip);
void GetLocalHostIP4(IP *ip);
bool IsLocalHostIP6(IP *ip);
bool IsLocalHostIP4(IP *ip);
bool IsLocalHostIP(IP *ip);
void ZeroIP6(IP *ip);
void ZeroIP4(IP *ip);
bool CheckIPItemStr6(char *str);
void IPItemStrToChars6(UCHAR *chars, char *str);
bool StrToIP6(IP *ip, char *str);
bool StrToIP6Addr(IPV6_ADDR *ip, char *str);
void IPToStr6(char *str, UINT size, IP *ip);
void IP6AddrToStr(char *str, UINT size, IPV6_ADDR *addr);
void IPToStr6Array(char *str, UINT size, UCHAR *bytes);
void IPToStr6Inner(char *str, IP *ip);
void IntToSubnetMask6(IP *ip, UINT i);
void IPNot6(IP *dst, IP *a);
void IPOr6(IP *dst, IP *a, IP *b);
void IPAnd6(IP *dst, IP *a, IP *b);
void GetAllRouterMulticastAddress6(IP *ip);
void GetAllNodeMulticaseAddress6(IP *ip);
void GetLoopbackAddress6(IP *ip);
void GetAllFilledAddress6(IP *ip);
UINT GetIPAddrType6(IP *ip);
UINT GetIPv6AddrType(IPV6_ADDR *addr);
void GenerateMulticastMacAddress6(UCHAR *mac, IP *ip);
void GetSoliciationMulticastAddr6(IP *dst, IP *src);
bool CheckUnicastAddress(IP *ip);
bool IsNetworkPrefixAddress6(IP *ip, IP *subnet);
bool IsNetworkAddress6(IP *ip, IP *subnet);
void GetHostAddress6(IP *dst, IP *ip, IP *subnet);
void GetPrefixAddress6(IP *dst, IP *ip, IP *subnet);
bool IsNetworkPrefixAddress6(IP *ip, IP *subnet);
bool IsInSameNetwork6(IP *a1, IP *a2, IP *subnet);
bool IsInSameNetwork6ByStr(char *ip1, char *ip2, char *subnet);
void GenerateEui64Address6(UCHAR *dst, UCHAR *mac);
void GenerateEui64LocalAddress(IP *a, UCHAR *mac);
void GenerateEui64GlobalAddress(IP *ip, IP *prefix, IP *subnet, UCHAR *mac);
bool IsSubnetMask6(IP *a);
UINT SubnetMaskToInt(IP *a);
UINT SubnetMaskToInt6(IP *a);
UINT SubnetMaskToInt4(IP *a);
bool IsStrIPv6Address(char *str);
void IPNot4(IP *dst, IP *a);
void IPOr4(IP *dst, IP *a, IP *b);
void IPAnd4(IP *dst, IP *a, IP *b);
bool IsInSameNetwork4(IP *a1, IP *a2, IP *subnet);
bool IsInSameNetwork4Standard(IP *a1, IP *a2);
bool IsInSameLocalNetworkToMe4(IP *a);

bool ParseIpAndSubnetMask4(char *src, UINT *ip, UINT *mask);
bool ParseIpAndSubnetMask6(char *src, IP *ip, IP *mask);
bool ParseIpAndSubnetMask46(char *src, IP *ip, IP *mask);
bool ParseIpAndMask4(char *src, UINT *ip, UINT *mask);
bool ParseIpAndMask6(char *src, IP *ip, IP *mask);
bool ParseIpAndMask46(char *src, IP *ip, IP *mask);
bool IsIpStr4(char *str);
bool IsIpStr6(char *str);
bool IsIpMask6(char *str);
bool IsIpStr46(char *str);
bool StrToMask4(IP *mask, char *str);
bool StrToMask6(IP *mask, char *str);
bool StrToMask6Addr(IPV6_ADDR *mask, char *str);
bool StrToMask46(IP *mask, char *str, bool ipv6);
void MaskToStr(char *str, UINT size, IP *mask);
void Mask6AddrToStrEx(char *str, UINT size, IPV6_ADDR *mask, bool always_full_address);
void Mask6AddrToStr(char *str, UINT size, IPV6_ADDR *mask);
void MaskToStr32(char *str, UINT size, UINT mask);
void MaskToStr32Ex(char *str, UINT size, UINT mask, bool always_full_address);
void MaskToStrEx(char *str, UINT size, IP *mask, bool always_full_address);

TUBEDATA *NewTubeData(void *data, UINT size, void *header, UINT header_size);
void FreeTubeData(TUBEDATA *d);
TUBE *NewTube(UINT size_of_header);
void ReleaseTube(TUBE *t);
void CleanupTube(TUBE *t);
bool TubeSend(TUBE *t, void *data, UINT size, void *header);
bool TubeSendEx(TUBE *t, void *data, UINT size, void *header, bool no_flush);
bool TubeSendEx2(TUBE *t, void *data, UINT size, void *header, bool no_flush, UINT max_num_in_queue);
void TubeFlush(TUBE *t);
void TubeFlushEx(TUBE *t, bool force);
TUBEDATA *TubeRecvAsync(TUBE *t);
TUBEDATA *TubeRecvSync(TUBE *t, UINT timeout);
TUBEPAIR_DATA *NewTubePairData();
void ReleaseTubePairData(TUBEPAIR_DATA *d);
void CleanupTubePairData(TUBEPAIR_DATA *d);
void NewTubePair(TUBE **t1, TUBE **t2, UINT size_of_header);
void TubeDisconnect(TUBE *t);
bool IsTubeConnected(TUBE *t);
void SetTubeSockEvent(TUBE *t, SOCK_EVENT *e);
SOCK_EVENT *GetTubeSockEvent(TUBE *t);

TUBE_FLUSH_LIST *NewTubeFlushList();
void FreeTubeFlushList(TUBE_FLUSH_LIST *f);
void AddTubeToFlushList(TUBE_FLUSH_LIST *f, TUBE *t);
void FlushTubeFlushList(TUBE_FLUSH_LIST *f);

LIST *GetHostIPAddressListInternal();
LIST *GetHostIPAddressList();
LIST *CloneIPAddressList(LIST *o);
bool IsMyIPAddress(IP *ip);
void FreeHostIPAddressList(LIST *o);
void AddHostIPAddressToList(LIST *o, IP *ip);
int CmpIpAddressList(void *p1, void *p2);
UINT64 GetHostIPAddressListHash();

UDPLISTENER *NewUdpListener(UDPLISTENER_RECV_PROC *recv_proc, void *param);
void UdpListenerThread(THREAD *thread, void *param);
void UdpListenerGetPublicPortList(UDPLISTENER *u, char *dst, UINT size);
void FreeUdpListener(UDPLISTENER *u);
void AddPortToUdpListener(UDPLISTENER *u, UINT port);
void DeletePortFromUdpListener(UDPLISTENER *u, UINT port);
void DeleteAllPortFromUdpListener(UDPLISTENER *u);
UINT GetUdpListenerPortList(UDPLISTENER *u, UINT **port_list);
void UdpListenerSendPackets(UDPLISTENER *u, LIST *packet_list);
void UdpListenerSendPacket(UDPLISTENER *u, UDPPACKET *packet);
UDPPACKET *NewUdpPacket(IP *src_ip, UINT src_port, IP *dst_ip, UINT dst_port, void *data, UINT size);
void FreeUdpPacket(UDPPACKET *p);
UDPLISTENER_SOCK *DetermineUdpSocketForSending(UDPLISTENER *u, UDPPACKET *p);
bool IsUdpPortOpened(UDPLISTENER *u, IP *server_ip, UINT port);

INTERRUPT_MANAGER *NewInterruptManager();
void FreeInterruptManager(INTERRUPT_MANAGER *m);
void AddInterrupt(INTERRUPT_MANAGER *m, UINT64 tick);
UINT GetNextIntervalForInterrupt(INTERRUPT_MANAGER *m);

void NewSocketPair(SOCK **client, SOCK **server, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port);
SOCK *NewInProcSocket(TUBE *tube_send, TUBE *tube_recv);
SOCK *ListenInProc();
SOCK *AcceptInProc(SOCK *s);
SOCK *ConnectInProc(SOCK *listen_sock, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port);
UINT SendInProc(SOCK *sock, void *data, UINT size);
UINT RecvInProc(SOCK *sock, void *data, UINT size);
void WaitForTubes(TUBE **tubes, UINT num, UINT timeout);

SOCK *ListenReverse();
SOCK *AcceptReverse(SOCK *s);
void InjectNewReverseSocketToAccept(SOCK *listen_sock, SOCK *s, IP *client_ip, UINT client_port);

bool NewTcpPair(SOCK **s1, SOCK **s2);
SOCK *ListenAnyPortEx(bool local_only);
SOCK *ListenAnyPortEx2(bool local_only, bool disable_ca);

bool IsIcmpApiSupported();
ICMP_RESULT *IcmpApiEchoSend(IP *dest_ip, UCHAR ttl, UCHAR *data, UINT size, UINT timeout);
void IcmpApiFreeResult(ICMP_RESULT *ret);

#ifdef	OS_WIN32
void Win32WaitForTubes(TUBE **tubes, UINT num, UINT timeout);
#else	// OS_WIN32
void UnixWaitForTubes(TUBE **tubes, UINT num, UINT timeout);
#endif	// OS_WIN32

SSL_PIPE *NewSslPipe(bool server_mode, X *x, K *k, DH_CTX *dh);
void FreeSslPipe(SSL_PIPE *s);
bool SyncSslPipe(SSL_PIPE *s);

SSL_BIO *NewSslBioMem();
SSL_BIO *NewSslBioSsl();
void FreeSslBio(SSL_BIO *b);
bool SslBioSync(SSL_BIO *b, bool sync_send, bool sync_recv);

void SetCurrentGlobalIP(IP *ip, bool ipv6);
bool GetCurrentGlobalIP(IP *ip, bool ipv6);
void GetCurrentGlobalIPGuess(IP *ip, bool ipv6);
bool IsIPAddressInSameLocalNetwork(IP *a);

bool IsIPPrivate(IP *ip);
bool IsIPLocalOrPrivate(IP *ip);
bool IsIPMyHost(IP *ip);
void LoadPrivateIPFile();
bool IsOnPrivateIPFile(UINT ip);
void FreePrivateIPFile();

LIST *GetNicList();
void FreeNicList(LIST *o);
bool IsMacAddressLocal(void *addr);
bool IsMacAddressLocalInner(LIST *o, void *addr);
bool IsMacAddressLocalFast(void *addr);
void RefreshLocalMacAddressList();

struct ssl_ctx_st *NewSSLCtx(bool server_mode);
void FreeSSLCtx(struct ssl_ctx_st *ctx);

void SetCurrentDDnsFqdn(char *name);
void GetCurrentDDnsFqdn(char *name, UINT size);
UINT GetCurrentDDnsFqdnHash();

void GetSimpleHostname(char *hostname, UINT hostname_size, char *fqdn);

void DisableRDUPServerGlobally();
void DisableRUDPRegisterGlobally();
void SetNatTLowPriority();

void QueryIpThreadMain(THREAD *thread, void *param);
QUERYIPTHREAD *NewQueryIpThread(char *hostname, UINT interval_last_ok, UINT interval_last_ng);
bool GetQueryIpThreadResult(QUERYIPTHREAD *t, IP *ip);
void FreeQueryIpThread(QUERYIPTHREAD *t);

void SetGetIpThreadMaxNum(UINT num);
UINT GetGetIpThreadMaxNum();
UINT GetCurrentGetIpThreadNum();



bool IsIpInStrList(IP *ip, char *ip_list);
bool IsInStrByStrList(char *str, char *str_list);

#ifdef	OS_WIN32
LIST *Win32GetNicList();
#endif	// OS_WIN32


void InitDynList();
void FreeDynList();
void AddDynList(BUF *b);
void ExtractAndApplyDynList(PACK *p);
void SetDynListValue(char *name, UINT64 value);
UINT64 GetDynValue(char *name);
UINT64 GetDynValueOrDefault(char *name, UINT64 default_value, UINT64 min_value, UINT64 max_value);
UINT64 GetDynValueOrDefaultSafe(char *name, UINT64 default_value);

//////////////////////////////////////////////////////////////////////////
// TcpIp


#ifdef	OS_WIN32
#pragma pack(push, 1)
#endif	// OS_WIN32

// MTU when using of the PPPoE
#define	MTU_FOR_PPPOE		(1500 - 46)

// MAC header
struct MAC_HEADER
{
	UCHAR	DestAddress[6];			// Source MAC address
	UCHAR	SrcAddress[6];			// Destination MAC address
	USHORT	Protocol;				// Protocol
} GCC_PACKED;

// MAC protocol
#define	MAC_PROTO_ARPV4		0x0806	// ARPv4 packet
#define	MAC_PROTO_IPV4		0x0800	// IPv4 packets
#define	MAC_PROTO_IPV6		0x86dd	// IPv6 packets
#define	MAC_PROTO_TAGVLAN	0x8100	// Tagged VLAN packets

// LLC header
struct LLC_HEADER
{
	UCHAR	Dsap;
	UCHAR	Ssap;
	UCHAR	Ctl;
} GCC_PACKED;

// The value of the SSAP and the DSAP of the LLC header
#define	LLC_DSAP_BPDU		0x42
#define	LLC_SSAP_BPDU		0x42

// BPDU header
struct BPDU_HEADER
{
	USHORT	ProtocolId;				// Protocol ID (STP == 0x0000)
	UCHAR	Version;				// Version
	UCHAR	Type;					// Type
	UCHAR	Flags;					// Flag
	USHORT	RootPriority;			// Priority of the root bridge
	UCHAR	RootMacAddress[6];		// MAC address of the root bridge
	UINT	RootPathCost;			// Path cost to the root bridge
	USHORT	BridgePriority;			// Priority of the outgoing bridge
	UCHAR	BridgeMacAddress[6];	// MAC address of the outgoing bridge
	USHORT	BridgePortId;			// Port ID of the outgoing bridge
	USHORT	MessageAge;				// Expiration date
	USHORT	MaxAge;					// Maximum expiration date
	USHORT	HelloTime;				// Hello Time
	USHORT	ForwardDelay;			// Forward Delay
} GCC_PACKED;

// ARPv4 header
struct ARPV4_HEADER
{
	USHORT	HardwareType;			// Hardware type
	USHORT	ProtocolType;			// Protocol type
	UCHAR	HardwareSize;			// Hardware size
	UCHAR	ProtocolSize;			// Protocol size
	USHORT	Operation;				// Operation
	UCHAR	SrcAddress[6];			// Source MAC address
	UINT	SrcIP;					// Source IP address
	UCHAR	TargetAddress[6];		// Target MAC address
	UINT	TargetIP;				// Target IP address
} GCC_PACKED;

// ARP hardware type
#define	ARP_HARDWARE_TYPE_ETHERNET		0x0001

// ARP operation type
#define	ARP_OPERATION_REQUEST			1
#define	ARP_OPERATION_RESPONSE			2

// Tagged VLAN header
struct TAGVLAN_HEADER
{
	UCHAR Data[2];					// Data
} GCC_PACKED;

// IPv4 header
struct IPV4_HEADER
{
	UCHAR	VersionAndHeaderLength;		// Version and header size
	UCHAR	TypeOfService;				// Service Type
	USHORT	TotalLength;				// Total size
	USHORT	Identification;				// Identifier
	UCHAR	FlagsAndFlagmentOffset[2];	// Flag and Fragment offset
	UCHAR	TimeToLive;					// TTL
	UCHAR	Protocol;					// Protocol
	USHORT	Checksum;					// Checksum
	UINT	SrcIP;						// Source IP address
	UINT	DstIP;						// Destination IP address
} GCC_PACKED;

// Macro for IPv4 header operation
#define	IPV4_GET_VERSION(h)			(((h)->VersionAndHeaderLength >> 4 & 0x0f))
#define	IPV4_SET_VERSION(h, v)		((h)->VersionAndHeaderLength |= (((v) & 0x0f) << 4))
#define	IPV4_GET_HEADER_LEN(h)		((h)->VersionAndHeaderLength & 0x0f)
#define	IPV4_SET_HEADER_LEN(h, v)	((h)->VersionAndHeaderLength |= ((v) & 0x0f))

// Macro for IPv4 fragment related operation
#define	IPV4_GET_FLAGS(h)			(((h)->FlagsAndFlagmentOffset[0] >> 5) & 0x07)
#define	IPV4_SET_FLAGS(h, v)		((h)->FlagsAndFlagmentOffset[0] |= (((v) & 0x07) << 5))
#define	IPV4_GET_OFFSET(h)			(((h)->FlagsAndFlagmentOffset[0] & 0x1f) * 256 + ((h)->FlagsAndFlagmentOffset[1]))
#define	IPV4_SET_OFFSET(h, v)		{(h)->FlagsAndFlagmentOffset[0] |= (UCHAR)((v) / 256); (h)->FlagsAndFlagmentOffset[1] = (UCHAR)((v) % 256);}

// IPv4 / IPv6 common protocol
#define	IP_PROTO_TCP		0x06	// TCP protocol
#define	IP_PROTO_UDP		0x11	// UDP protocol
#define	IP_PROTO_ESP		50		// ESP protocol
#define	IP_PROTO_ETHERIP	97		// EtherIP protocol
#define	IP_PROTO_L2TPV3		115		// L2TPv3 protocol


// UDP header
struct UDP_HEADER
{
	USHORT	SrcPort;				// Source port number
	USHORT	DstPort;				// Destination port number
	USHORT	PacketLength;			// Data length
	USHORT	Checksum;				// Checksum
} GCC_PACKED;

// UDPv4 pseudo header
struct UDPV4_PSEUDO_HEADER
{
	UINT	SrcIP;					// Source IP address
	UINT	DstIP;					// Destination IP address
	UCHAR	Reserved;				// Unused
	UCHAR	Protocol;				// Protocol number
	USHORT	PacketLength1;			// UDP data length 1
	USHORT	SrcPort;				// Source port number
	USHORT	DstPort;				// Destination port number
	USHORT	PacketLength2;			// UDP data length 2
	USHORT	Checksum;				// Checksum
} GCC_PACKED;

// IPv4 pseudo header
struct IPV4_PSEUDO_HEADER
{
	UINT	SrcIP;					// Source IP address
	UINT	DstIP;					// Destination IP address
	UCHAR	Reserved;				// Unused
	UCHAR	Protocol;				// Protocol number
	USHORT	PacketLength;			// Packet size
} GCC_PACKED;

// TCP header
struct TCP_HEADER
{
	USHORT	SrcPort;					// Source port number
	USHORT	DstPort;					// Destination port number
	UINT	SeqNumber;				// Sequence number
	UINT	AckNumber;				// Acknowledgment number
	UCHAR	HeaderSizeAndReserved;	// Header size and Reserved area
	UCHAR	Flag;					// Flag
	USHORT	WindowSize;				// Window size
	USHORT	Checksum;				// Checksum
	USHORT	UrgentPointer;			// Urgent Pointer
} GCC_PACKED;

// TCP macro
#define	TCP_GET_HEADER_SIZE(h)	(((h)->HeaderSizeAndReserved >> 4) & 0x0f)
#define	TCP_SET_HEADER_SIZE(h, v)	((h)->HeaderSizeAndReserved = (((v) & 0x0f) << 4))

// TCP flags
#define	TCP_FIN						1
#define	TCP_SYN						2
#define	TCP_RST						4
#define	TCP_PSH						8
#define	TCP_ACK						16
#define	TCP_URG						32

// ICMP header
struct ICMP_HEADER
{
	UCHAR	Type;					// Type
	UCHAR	Code;					// Code
	USHORT	Checksum;				// Checksum
} GCC_PACKED;

// ICMP Echo
struct ICMP_ECHO
{
	USHORT	Identifier;						// ID
	USHORT	SeqNo;							// Sequence number
} GCC_PACKED;

// ICMP message type
#define	ICMP_TYPE_ECHO_REQUEST						8
#define	ICMP_TYPE_ECHO_RESPONSE						0
#define	ICMP_TYPE_DESTINATION_UNREACHABLE			3
#define	ICMP_TYPE_TIME_EXCEEDED						11
#define	ICMP_TYPE_INFORMATION_REQUEST				15
#define	ICMP_TYPE_INFORMATION_REPLY					16

// ICMP message code
// In case of ICMP_TYPE_DESTINATION_UNREACHABLE
#define	ICMP_CODE_NET_UNREACHABLE					0
#define	ICMP_CODE_HOST_UNREACHABLE					1
#define	ICMP_CODE_PROTOCOL_UNREACHABLE				2
#define	ICMP_CODE_PORT_UNREACHABLE					3
#define	ICMP_CODE_FRAGMENTATION_NEEDED_DF_SET		4
#define	ICMP_CODE_SOURCE_ROUTE_FAILED				5

// In case of TIME_EXCEEDED
#define	ICMP_CODE_TTL_EXCEEDED_IN_TRANSIT			0
#define	ICMP_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDED	1

// DHCPv4 Header
struct DHCPV4_HEADER
{
	UCHAR	OpCode;				// Op-code
	UCHAR	HardwareType;		// Hardware type
	UCHAR	HardwareAddressSize;	// Hardware address size
	UCHAR	Hops;				// Number of hops
	UINT	TransactionId;		// Transaction ID
	USHORT	Seconds;				// Seconds
	USHORT	Flags;				// Flag
	UINT	ClientIP;			// Client IP address
	UINT	YourIP;				// Assigned IP address
	UINT	ServerIP;			// Server IP address
	UINT	RelayIP;				// Relay IP address
	UCHAR	ClientMacAddress[6];	// Client MAC address
	UCHAR	Padding[10];			// Padding for non-Ethernet
} GCC_PACKED;

// DNSv4 header
struct DNSV4_HEADER
{
	USHORT	TransactionId;			// Transaction ID
	UCHAR	Flag1;					// Flag 1
	UCHAR	Flag2;					// Flag 2
	USHORT	NumQuery;				// Number of queries
	USHORT	AnswerRRs;				// Answer RR number
	USHORT	AuthorityRRs;			// Authority RR number
	USHORT	AdditionalRRs;			// Additional RR number
} GCC_PACKED;

#define	DHCP_MAGIC_COOKIE	0x63825363	// Magic Cookie (fixed)

// NetBIOS Datagram header
struct NBTDG_HEADER
{
	UCHAR MessageType;
	UCHAR MoreFlagments;
	USHORT DatagramId;
	UINT SrcIP;
	USHORT SrcPort;
	USHORT DatagramLen;
	USHORT PacketOffset;
} GCC_PACKED;

// IPv6 packet header information
struct IPV6_HEADER_PACKET_INFO
{
	IPV6_HEADER *IPv6Header;					// IPv6 header
	IPV6_OPTION_HEADER *HopHeader;				// Hop-by-hop option header
	UINT HopHeaderSize;							// Hop-by-hop option header size
	IPV6_OPTION_HEADER *EndPointHeader;			// End point option header
	UINT EndPointHeaderSize;					// End point option header size
	IPV6_OPTION_HEADER *RoutingHeader;			// Routing header
	UINT RoutingHeaderSize;						// Routing header size
	IPV6_FRAGMENT_HEADER *FragmentHeader;		// Fragment header
	void *Payload;								// Payload
	UINT PayloadSize;							// Payload size
	UCHAR Protocol;								// Payload protocol
	bool IsFragment;							// Whether it's a fragmented packet
	UINT TotalHeaderSize;						// Total header size
};

// IPv6 header
struct IPV6_HEADER
{
	UCHAR VersionAndTrafficClass1;		// Version Number (4 bit) and Traffic Class 1 (4 bit)
	UCHAR TrafficClass2AndFlowLabel1;	// Traffic Class 2 (4 bit) and Flow Label 1 (4 bit)
	UCHAR FlowLabel2;					// Flow Label 2 (8 bit)
	UCHAR FlowLabel3;					// Flow Label 3 (8 bit)
	USHORT PayloadLength;				// Length of the payload (including extension header)
	UCHAR NextHeader;					// Next header
	UCHAR HopLimit;						// Hop limit
	IPV6_ADDR SrcAddress;				// Source address
	IPV6_ADDR DestAddress;				// Destination address
} GCC_PACKED;


// Macro for IPv6 header operation
#define IPV6_GET_VERSION(h)			(((h)->VersionAndTrafficClass1 >> 4) & 0x0f)
#define IPV6_SET_VERSION(h, v)		((h)->VersionAndTrafficClass1 = ((h)->VersionAndTrafficClass1 & 0x0f) | ((v) << 4) & 0xf0)
#define IPV6_GET_TRAFFIC_CLASS(h)	((((h)->VersionAndTrafficClass1 << 4) & 0xf0) | ((h)->TrafficClass2AndFlowLabel1 >> 4) & 0x0f)
#define	IPV6_SET_TRAFFIC_CLASS(h, v)	((h)->VersionAndTrafficClass1 = ((h)->VersionAndTrafficClass1 & 0xf0) | (((v) >> 4) & 0x0f),\
	(h)->TrafficClass2AndFlowLabel1 = (h)->TrafficClass2AndFlowLabel1 & 0x0f | ((v) << 4) & 0xf0)
#define	IPV6_GET_FLOW_LABEL(h)		((((h)->TrafficClass2AndFlowLabel1 << 16) & 0xf0000) | (((h)->FlowLabel2 << 8) & 0xff00) |\
	(((h)->FlowLabel3) & 0xff))
#define IPV6_SET_FLOW_LABEL(h, v)	((h)->TrafficClass2AndFlowLabel1 = ((h)->TrafficClass2AndFlowLabel1 & 0xf0 | ((v) >> 16) & 0x0f),\
	(h)->FlowLabel2 = ((v) >> 8) & 0xff,\
	(h)->FlowLabel3 = (v) & 0xff)


// Maximum hops of IPv6 (not routing)
#define IPV6_HOP_MAX					255

// Standard hops of IPv6
#define IPV6_HOP_DEFAULT				127

// IPv6 header number
#define IPV6_HEADER_HOP					0	// Hop-by-hop option header
#define IPV6_HEADER_ENDPOINT			60	// End point option header
#define IPV6_HEADER_ROUTING				43	// Routing header
#define IPV6_HEADER_FRAGMENT			44	// Fragment header
#define IPV6_HEADER_NONE				59	// No Next Header

// IPv6 option header
// (Used on hop option header, end point option header, routing header)
struct IPV6_OPTION_HEADER
{
	UCHAR NextHeader;					// Next header
	UCHAR Size;							// Header size (/8)
} GCC_PACKED;

// IPv6 fragment header
// (fragment impossible part is until just before the routing header
// or hop-by-hop option header or first extended header or payload)
struct IPV6_FRAGMENT_HEADER
{
	UCHAR NextHeader;					// Next header
	UCHAR Reserved;						// Reserved
	UCHAR FlagmentOffset1;				// Fragment offset 1 (/8, 8 bit)
	UCHAR FlagmentOffset2AndFlags;		// Fragment offset 2 (/8, 5 bit) + Reserved (2 bit) + More flag (1 bit)
	UINT Identification;				// ID
} GCC_PACKED;

// Macro for IPv6 fragment header operation
#define IPV6_GET_FRAGMENT_OFFSET(h)		(((((h)->FlagmentOffset1) << 5) & 0x1fe0) | (((h)->FlagmentOffset2AndFlags >> 3) & 0x1f))
#define IPV6_SET_FRAGMENT_OFFSET(h, v)	((h)->FlagmentOffset1 = (v / 32) & 0xff,	\
	((h)->FlagmentOffset2AndFlags = ((v % 256) << 3) & 0xf8) | ((h)->FlagmentOffset2AndFlags & 0x07))
#define IPV6_GET_FLAGS(h)				((h)->FlagmentOffset2AndFlags & 0x0f)
#define IPV6_SET_FLAGS(h, v)				((h)->FlagmentOffset2AndFlags = (((h)->FlagmentOffset2AndFlags & 0xf8) | (v & 0x07)))

// Flag
#define IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS		0x01	// There are more fragments

// Virtual IPv6 header
struct IPV6_PSEUDO_HEADER
{
	IPV6_ADDR SrcAddress;				// Source address
	IPV6_ADDR DestAddress;				// Destination address
	UINT UpperLayerPacketSize;			// Upper layer packet size
	UCHAR Padding[3];					// Padding
	UCHAR NextHeader;					// Next Header (TCP / UDP)
} GCC_PACKED;

// ICMPv6 Router Solicitation header
struct ICMPV6_ROUTER_SOLICIATION_HEADER
{
	UINT Reserved;							// Reserved
											// + Option (source link-layer address [optional])
} GCC_PACKED;

// ICMPv6 Router Advertisement header
struct ICMPV6_ROUTER_ADVERTISEMENT_HEADER
{
	UCHAR CurHopLimit;						// Hop limit of the default
	UCHAR Flags;							// Flag (0)
	USHORT Lifetime;						// Lifetime
	UINT ReachableTime;						// 0
	UINT RetransTimer;						// 0
											// + Option (prefix information [required], MTU [optional])
} GCC_PACKED;

// ICMPv6 Neighbor Solicitation header
struct ICMPV6_NEIGHBOR_SOLICIATION_HEADER
{
	UINT Reserved;							// Reserved
	IPV6_ADDR TargetAddress;				// Target address
											// + Option (source link-layer address [required])
} GCC_PACKED;

// ICMPv6 Neighbor Advertisement header
struct ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER
{
	UCHAR Flags;							// Flag
	UCHAR Reserved[3];						// Reserved
	IPV6_ADDR TargetAddress;				// Target address
											// + Option (target link-layer address)
} GCC_PACKED;

#define ICMPV6_NEIGHBOR_ADVERTISEMENT_FLAG_ROUTER		0x80	// Router
#define ICMPV6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED	0x40	// Solicited flag
#define ICMPV6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERWRITE	0x20	// Overwrite flag

// ICMPv6 option list
struct ICMPV6_OPTION_LIST
{
	ICMPV6_OPTION_LINK_LAYER *SourceLinkLayer;		// Source link-layer address
	ICMPV6_OPTION_LINK_LAYER *TargetLinkLayer;		// Target link-layer address
	ICMPV6_OPTION_PREFIX *Prefix;					// Prefix Information
	ICMPV6_OPTION_MTU *Mtu;							// MTU
} GCC_PACKED;

// ICMPv6 option
struct ICMPV6_OPTION
{
	UCHAR Type;								// Type
	UCHAR Length;							// Length (/8, include type and length)
} GCC_PACKED;

#define	ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER	1		// Source link-layer address
#define ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER	2		// Target link-layer address
#define ICMPV6_OPTION_TYPE_PREFIX				3		// Prefix Information
#define ICMPV6_OPTION_TYPE_MTU					5		// MTU

// ICMPv6 link layer options
struct ICMPV6_OPTION_LINK_LAYER
{
	ICMPV6_OPTION IcmpOptionHeader;			// Option header
	UCHAR Address[6];						// MAC address
} GCC_PACKED;

// ICMPv6 prefix information option
struct ICMPV6_OPTION_PREFIX
{
	ICMPV6_OPTION IcmpOptionHeader;			// Option header
	UCHAR SubnetLength;						// Subnet length
	UCHAR Flags;							// Flag
	UINT ValidLifetime;						// Formal lifetime
	UINT PreferredLifetime;					// Preferred lifetime
	UINT Reserved;							// Reserved
	IPV6_ADDR Prefix;						// Prefix address
} GCC_PACKED;

#define ICMPV6_OPTION_PREFIX_FLAG_ONLINK		0x80	// On link
#define ICMPV6_OPTION_PREFIX_FLAG_AUTO			0x40	// Automatic

// ICMPv6 MTU option
struct ICMPV6_OPTION_MTU
{
	ICMPV6_OPTION IcmpOptionHeader;			// Option header
	USHORT Reserved;						// Reserved
	UINT Mtu;								// MTU value
} GCC_PACKED;


// IPv6 header information
struct IPV6_HEADER_INFO
{
	bool IsRawIpPacket;
	USHORT Size;
	UINT Id;
	UCHAR Protocol;
	UCHAR HopLimit;
	IPV6_ADDR SrcIpAddress;
	IPV6_ADDR DestIpAddress;
	bool UnicastForMe;
	bool UnicastForRouting;
	bool UnicastForRoutingWithProxyNdp;
	bool IsBroadcast;
	UINT TypeL4;
};

// ICMPv6 header information
struct ICMPV6_HEADER_INFO
{
	UCHAR Type;
	UCHAR Code;
	USHORT DataSize;
	void *Data;
	ICMP_ECHO EchoHeader;
	void *EchoData;
	UINT EchoDataSize;

	union
	{
		// Meaning is determined by the value of the Type
		ICMPV6_ROUTER_SOLICIATION_HEADER *RouterSoliciationHeader;
		ICMPV6_ROUTER_ADVERTISEMENT_HEADER *RouterAdvertisementHeader;
		ICMPV6_NEIGHBOR_SOLICIATION_HEADER *NeighborSoliciationHeader;
		ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER *NeighborAdvertisementHeader;
		void *HeaderPointer;
	} Headers;

	ICMPV6_OPTION_LIST OptionList;
};

// The Type value of ICMPv6
#define ICMPV6_TYPE_ECHO_REQUEST				128		// ICMPv6 Echo request
#define ICMPV6_TYPE_ECHO_RESPONSE				129		// ICMPv6 Echo response
#define ICMPV6_TYPE_ROUTER_SOLICIATION			133		// Router Solicitation
#define ICMPV6_TYPE_ROUTER_ADVERTISEMENT		134		// Router Advertisement
#define ICMPV6_TYPE_NEIGHBOR_SOLICIATION		135		// Neighbor Solicitation
#define ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT		136		// Neighbor Advertisement

// Minimum DHCP packet size
#define	DHCP_MIN_SIZE				300

// Constants about DHCP
#define	DHCP_ID_MESSAGE_TYPE		0x35
#define	DHCP_ID_REQUEST_IP_ADDRESS	0x32
#define	DHCP_ID_HOST_NAME			0x0c
#define	DHCP_ID_SERVER_ADDRESS		0x36
#define	DHCP_ID_LEASE_TIME			0x33
#define	DHCP_ID_DOMAIN_NAME			0x0f
#define	DHCP_ID_SUBNET_MASK			0x01
#define	DHCP_ID_GATEWAY_ADDR		0x03
#define	DHCP_ID_DNS_ADDR			0x06
#define	DHCP_ID_WINS_ADDR			0x2C
#define	DHCP_ID_CLIENT_ID			0x3d
#define	DHCP_ID_VENDOR_ID			0x3c
#define	DHCP_ID_REQ_PARAM_LIST		0x37
#define	DHCP_ID_USER_CLASS			0x4d
#define	DHCP_ID_CLASSLESS_ROUTE		0x79
#define	DHCP_ID_MS_CLASSLESS_ROUTE	0xF9
#define	DHCP_ID_PRIVATE				0xFA


// DHCP client action
#define	DHCP_DISCOVER		1
#define	DHCP_REQUEST		3
#define	DHCP_RELEASE		7
#define	DHCP_INFORM			8

// DHCP server action
#define	DHCP_OFFER			2
#define	DHCP_DECLINE		4
#define	DHCP_ACK			5
#define	DHCP_NACK			6

// HTTPLOG data structure
struct HTTPLOG
{
	char Method[32];						// Method
	char Hostname[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT Port;								// Port number
	char Path[MAX_SIZE];					// Path
	char Protocol[64];						// Protocol
	char UserAgent[MAX_SIZE];				// User Agent value
	char Referer[MAX_SIZE];					// Referer
	bool IsSsl;								// Is SSL
};

// Packet
struct PKT
{
	UCHAR			*PacketData;	// Packet data body
	UINT			PacketSize;		// Packet size
	MAC_HEADER		*MacHeader;		// MAC header
	UCHAR			*MacAddressSrc;	// Source MAC address
	UCHAR			*MacAddressDest;	// Destination MAC address
	bool			BroadcastPacket;		// Broadcast packet
	bool			InvalidSourcePacket;	// Packet with an invalid source address
	bool			AccessChecked;	// Packets that pass was confirmed by the access list
	UINT			VlanTypeID;		// TypeID of the tagged VLAN (usually 0x8100)
	UINT			VlanId;			// VLAN ID
	UINT			Delay;			// Delay
	UINT			Jitter;			// Jitter
	UINT			Loss;			// Packet loss
	UINT64			DelayedForwardTick;	// Sending time in case of delayed
	struct SESSION	*DelayedSrcSession;	// Source session
	UINT			TypeL3;			// Layer-3 packet classification
	IPV6_HEADER_PACKET_INFO IPv6HeaderPacketInfo;	// IPv6 packet header information (only for TypeL3 == L3_IPV6)
	ICMPV6_HEADER_INFO ICMPv6HeaderPacketInfo;		// ICMPv6 header information (Only for TypeL4 == L4_ICMPV6)
	UINT			DhcpOpCode;		// DHCP opcode
	union
	{
		IPV4_HEADER		*IPv4Header;	// IPv4 header
		ARPV4_HEADER	*ARPv4Header;	// ARPv4 header
		IPV6_HEADER		*IPv6Header;	// IPv6 header
		TAGVLAN_HEADER	*TagVlanHeader;	// Tag header
		BPDU_HEADER		*BpduHeader;	// BPDU header
		void			*PointerL3;
	} L3;
	UINT			TypeL4;				// Layer-4 packet classification
	UINT			IPv4PayloadSize;	// IPv4 payload size
	void			*IPv4PayloadData;	// IPv4 payload data
	union
	{
		UDP_HEADER	*UDPHeader;			// UDP header
		TCP_HEADER	*TCPHeader;			// TCP header
		ICMP_HEADER	*ICMPHeader;		// ICMP header
		void		*PointerL4;
	} L4;
	UINT			TypeL7;			// Layer-7 packet classification
	union
	{
		DHCPV4_HEADER	*DHCPv4Header;	// DHCPv4 header
		IKE_HEADER		*IkeHeader;		// IKE header
		void			*PointerL7;
	} L7;
	UCHAR				*Payload;		// Pointer to the payload of TCP or UDP
	UINT				PayloadSize;	// Payload size
	struct HTTPLOG		*HttpLog;		// HTTP log
	char DnsQueryHost[64];				// DNS hostname
} GCC_PACKED;

// Layer-3 packet classification
#define	L3_UNKNOWN			0		// Unknown
#define	L3_ARPV4			1		// ARPv4 packet
#define	L3_IPV4				2		// IPv4 packet
#define	L3_TAGVLAN			3		// Tagged VLAN packet
#define	L3_BPDU				4		// BPDU packet
#define L3_IPV6				5		// IPv6 packet

// Layer-4 packet classification
#define	L4_UNKNOWN			0		// Unknown
#define	L4_UDP				1		// UDPv4 packet
#define	L4_TCP				2		// TCPv4 packet
#define	L4_ICMPV4			3		// ICMPv4 packet
#define	L4_ICMPV6			4		// ICMPv6 packet
#define	L4_FRAGMENT			5		// Fragment packet

// Layer-7 packet classification
#define	L7_UNKNOWN			0		// Unknown
#define	L7_DHCPV4			1		// DHCPv4 packet
#define	L7_IKECONN			2		// IKE connection request packet
#define	L7_OPENVPNCONN		3		// OpenVPN connection request packet
#define L7_DNS				4		// DNS packet


// IKE header
struct IKE_HEADER
{
	UINT64 InitiatorCookie;						// Initiator cookie
	UINT64 ResponderCookie;						// Responder cookie
	UCHAR NextPayload;							// Next payload
	UCHAR Version;								// Version
	UCHAR ExchangeType;							// Exchange type
	UCHAR Flag;									// Flag
	UINT MessageId;								// Message ID
	UINT MessageSize;							// Message size
} GCC_PACKED;

// IKE exchange type
#define	IKE_EXCHANGE_TYPE_MAIN				2	// Main mode
#define IKE_EXCHANGE_TYPE_AGGRESSIVE		4	// Aggressive mode
#define IKE_EXCHANGE_TYPE_INFORMATION		5	// Information exchange
#define IKE_EXCHANGE_TYPE_QUICK				32	// Quick mode

// DHCPv4 data
struct DHCPV4_DATA
{
	UCHAR *Data;
	UINT Size;
	IP SrcIP;
	UINT SrcPort;
	IP DestIP;
	UINT DestPort;
	UINT OpCode;

	UCHAR *OptionData;
	UINT OptionSize;

	DHCPV4_HEADER *Header;
	LIST *OptionList;

	struct DHCP_OPTION_LIST *ParsedOptionList;
};
// DHCP Option
struct DHCP_OPTION
{
	UINT Id;						// ID
	UINT Size;						// Size
	void *Data;						// Data
};

// DHCP classless static route entry
struct DHCP_CLASSLESS_ROUTE
{
	bool Exists;					// Existing flag
	IP Network;						// Network address
	IP SubnetMask;					// Subnet mask
	IP Gateway;						// Gateway
	UINT SubnetMaskLen;				// Subnet mask length
};

#define	MAX_DHCP_CLASSLESS_ROUTE_ENTRIES	64
#define	MAX_DHCP_CLASSLESS_ROUTE_TABLE_STR_SIZE	3200

// DHCP classless static route table
struct DHCP_CLASSLESS_ROUTE_TABLE
{
	UINT NumExistingRoutes;			// Number of existing routing table entries
	DHCP_CLASSLESS_ROUTE Entries[MAX_DHCP_CLASSLESS_ROUTE_ENTRIES];	// Entries
};

#define	MAX_USER_CLASS_LEN	255

// DHCP option list
struct DHCP_OPTION_LIST
{
	// Common Item
	UINT Opcode;					// DHCP opcode

									// Client request
	UINT RequestedIp;				// Requested IP address
	char Hostname[MAX_HOST_NAME_LEN + 1]; // Host name
	char UserClass[MAX_USER_CLASS_LEN + 1]; // User class
											// RFC3003 defines that User Class option is array of text strings,
											// but the most popular DHCP clients and servers,
											// i.e. ISC DHCP and Microsoft DHCP Server, consider it a text string

											// Server response
	UINT ClientAddress;				// Client address
	UINT ServerAddress;				// DHCP server address
	UINT LeaseTime;					// Lease time
	char DomainName[MAX_HOST_NAME_LEN + 1];	// Domain name
	UINT SubnetMask;				// Subnet mask
	UINT Gateway;					// Gateway address
	UINT DnsServer;					// DNS server address 1
	UINT DnsServer2;				// DNS server address 2
	UINT WinsServer;				// WINS server address 1
	UINT WinsServer2;				// WINS server address 2
	DHCP_CLASSLESS_ROUTE_TABLE ClasslessRoute;	// Classless static routing table
};

// Modification option in the DHCP packet
struct DHCP_MODIFY_OPTION
{
	bool RemoveDefaultGatewayOnReply;			// Remove the default gateway from the DHCP Reply
};

// Special IP address
#define	SPECIAL_IPV4_ADDR_LLMNR_DEST		0xE00000FC	// 224.0.0.252

// Special port
#define	SPECIAL_UDP_PORT_LLMNR				5355	// LLMNR
#define	SPECIAL_UDP_PORT_NBTNS				137		// NetBIOS Name Service
#define	SPECIAL_UDP_PORT_NBTDGM				138		// NetBIOS Datagram
#define	SPECIAL_UDP_PORT_WSD				3702	// WS-Discovery
#define	SPECIAL_UDP_PORT_SSDP				1900	// SSDP


PKT *ParsePacketIPv4WithDummyMacHeader(UCHAR *buf, UINT size);
PKT *ParsePacket(UCHAR *buf, UINT size);
PKT *ParsePacketEx(UCHAR *buf, UINT size, bool no_l3);
PKT *ParsePacketEx2(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id);
PKT *ParsePacketEx3(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address);
PKT *ParsePacketEx4(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address, bool no_http, bool correct_checksum);
void FreePacket(PKT *p);
void FreePacketWithData(PKT *p);
void FreePacketIPv4(PKT *p);
void FreePacketTagVlan(PKT *p);
void FreePacketARPv4(PKT *p);
void FreePacketUDPv4(PKT *p);
void FreePacketTCPv4(PKT *p);
void FreePacketICMPv4(PKT *p);
void FreePacketDHCPv4(PKT *p);
bool ParsePacketL2(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketL2Ex(PKT *p, UCHAR *buf, UINT size, bool no_l3);
bool ParsePacketARPv4(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketIPv4(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketBPDU(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketTAGVLAN(PKT *p, UCHAR *buf, UINT size);
bool ParseICMPv4(PKT *p, UCHAR *buf, UINT size);
bool ParseICMPv6(PKT *p, UCHAR *buf, UINT size);
bool ParseTCP(PKT *p, UCHAR *buf, UINT size);
bool ParseUDP(PKT *p, UCHAR *buf, UINT size);
void ParseDHCPv4(PKT *p, UCHAR *buf, UINT size);
void ParseDNS(PKT *p, UCHAR *buf, UINT size);
PKT *ClonePacket(PKT *p, bool copy_data);
void FreeClonePacket(PKT *p);

void CorrectChecksum(PKT *p);

bool ParsePacketIPv6(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketIPv6Header(IPV6_HEADER_PACKET_INFO *info, UCHAR *buf, UINT size);
bool ParseIPv6ExtHeader(IPV6_HEADER_PACKET_INFO *info, UCHAR next_header, UCHAR *buf, UINT size);
bool ParseICMPv6Options(ICMPV6_OPTION_LIST *o, UCHAR *buf, UINT size);
void CloneICMPv6Options(ICMPV6_OPTION_LIST *dst, ICMPV6_OPTION_LIST *src);
void FreeCloneICMPv6Options(ICMPV6_OPTION_LIST *o);
USHORT CalcChecksumForIPv4(UINT src_ip, UINT dst_ip, UCHAR protocol, void *data, UINT size, UINT real_size);
USHORT CalcChecksumForIPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR protocol, void *data, UINT size, UINT real_size);
BUF *BuildICMPv6Options(ICMPV6_OPTION_LIST *o);
void BuildICMPv6OptionValue(BUF *b, UCHAR type, void *header_pointer, UINT total_size);
BUF *BuildIPv6(IPV6_ADDR *dest_ip, IPV6_ADDR *src_ip, UINT id, UCHAR protocol, UCHAR hop_limit, void *data,
	UINT size);
BUF *BuildIPv6PacketHeader(IPV6_HEADER_PACKET_INFO *info, UINT *bytes_before_payload);
UCHAR IPv6GetNextHeaderFromQueue(QUEUE *q);
void BuildAndAddIPv6PacketOptionHeader(BUF *b, IPV6_OPTION_HEADER *opt, UCHAR next_header, UINT size);
BUF *BuildICMPv6NeighborSoliciation(IPV6_ADDR *src_ip, IPV6_ADDR *target_ip, UCHAR *my_mac_address, UINT id);
BUF *BuildICMPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR hop_limit, UCHAR type, UCHAR code, void *data, UINT size, UINT id);

bool VLanRemoveTag(void **packet_data, UINT *packet_size, UINT vlan_id, UINT vlan_tpid);
void VLanInsertTag(void **packet_data, UINT *packet_size, UINT vlan_id, UINT vlan_tpid);

DHCPV4_DATA *ParseDHCPv4Data(PKT *pkt);
void FreeDHCPv4Data(DHCPV4_DATA *d);

bool AdjustTcpMssL3(UCHAR *src, UINT src_size, UINT mss);
bool AdjustTcpMssL2(UCHAR *src, UINT src_size, UINT mss, USHORT tag_vlan_tpid);
UINT GetIpHeaderSize(UCHAR *src, UINT src_size);
bool ParseDnsQuery(char *name, UINT name_size, void *data, UINT data_size);
UCHAR GetNextByte(BUF *b);

bool IsDhcpPacketForSpecificMac(UCHAR *data, UINT size, UCHAR *mac_address);

ICMP_RESULT *IcmpEchoSendBySocket(IP *dest_ip, UCHAR ttl, UCHAR *data, UINT size, UINT timeout);
ICMP_RESULT *IcmpEchoSend(IP *dest_ip, UCHAR ttl, UCHAR *data, UINT size, UINT timeout);
ICMP_RESULT *IcmpParseResult(IP *dest_ip, USHORT src_id, USHORT src_seqno, UCHAR *recv_buffer, UINT recv_buffer_size);
void IcmpFreeResult(ICMP_RESULT *r);

USHORT IpChecksum(void *buf, UINT size);
bool IpCheckChecksum(IPV4_HEADER *ip);

LIST *BuildDhcpOption(DHCP_OPTION_LIST *opt);
DHCP_OPTION *NewDhcpOption(UINT id, void *data, UINT size);
DHCP_OPTION_LIST *ParseDhcpOptionList(void *data, UINT size);
DHCP_OPTION *GetDhcpOption(LIST *o, UINT id);
void FreeDhcpOptions(LIST *o);
LIST *ParseDhcpOptions(void *data, UINT size);
BUF *BuildDhcpOptionsBuf(LIST *o);
HTTPLOG *ParseHttpAccessLog(PKT *pkt);
HTTPLOG *ParseHttpsAccessLog(PKT *pkt);

BUF *DhcpModify(DHCP_MODIFY_OPTION *m, void *data, UINT size);
BUF *DhcpModifyIPv4(DHCP_MODIFY_OPTION *m, void *data, UINT size);

DHCP_CLASSLESS_ROUTE *GetBestClasslessRoute(DHCP_CLASSLESS_ROUTE_TABLE *t, IP *ip);
void DhcpParseClasslessRouteData(DHCP_CLASSLESS_ROUTE_TABLE *t, void *data, UINT size);
BUF *DhcpBuildClasslessRouteData(DHCP_CLASSLESS_ROUTE_TABLE *t);
bool ParseClasslessRouteStr(DHCP_CLASSLESS_ROUTE *r, char *str);
bool ParseClasslessRouteTableStr(DHCP_CLASSLESS_ROUTE_TABLE *d, char *str);
bool CheckClasslessRouteTableStr(char *str);
void BuildClasslessRouteStr(char *str, UINT str_size, DHCP_CLASSLESS_ROUTE *r);
void BuildClasslessRouteTableStr(char *str, UINT str_size, DHCP_CLASSLESS_ROUTE_TABLE *t);
bool NormalizeClasslessRouteTableStr(char *dst, UINT dst_size, char *src);



#ifdef	OS_WIN32
#pragma pack(pop)
#endif	// OS_WIN32


//////////////////////////////////////////////////////////////////////////
// Tick64


// Maximum number of correction list entries
#define	MAX_ADJUST_TIME				1024

// Correction list entry
struct ADJUST_TIME
{
	UINT64 Tick;
	UINT64 Time;
};

// TICK64 structure
struct TICK64
{
	THREAD *Thread;
	UINT64 Tick;
	UINT64 TickStart;
	UINT64 Time64;
	UINT64 Tick64WithTime64;
	UINT LastTick;
	UINT RoundCount;
	LOCK *TickLock;
	volatile bool Halt;
	LIST *AdjustTime;
};

// Constant
#define	TICK64_SPAN			10		// Measurement interval (Usually less than 10ms)
#define	TICK64_SPAN_WIN32	1000	// Interval of measurement on Win32
#define	TICK64_ADJUST_SPAN	5000	// Correct the clock if it shifts more than this value

// Function prototype
void InitTick64();
void FreeTick64();
void Tick64Thread(THREAD *thread, void *param);
UINT64 Tick64();
UINT64 Diff64(UINT64 a, UINT64 b);
UINT64 Tick64ToTime64(UINT64 tick);
UINT64 TickToTime(UINT64 tick);
UINT64 TickHighres64();

//////////////////////////////////////////////////////////////////////////
// OS


// Function prototype
char *OsTypeToStr(UINT type);

void OSInit();
void OSFree();
void *OSMemoryAlloc(UINT size);
void *OSMemoryReAlloc(void *addr, UINT size);
void OSMemoryFree(void *addr);
UINT OSGetTick();
void OSGetSystemTime(SYSTEMTIME *system_time);
void OSInc32(UINT *value);
void OSDec32(UINT *value);
void OSSleep(UINT time);
LOCK *OSNewLock();
bool OSLock(LOCK *lock);
void OSUnlock(LOCK *lock);
void OSDeleteLock(LOCK *lock);
void OSInitEvent(EVENT *event);
void OSSetEvent(EVENT *event);
void OSResetEvent(EVENT *event);
bool OSWaitEvent(EVENT *event, UINT timeout);
void OSFreeEvent(EVENT *event);
bool OSWaitThread(THREAD *t);
void OSFreeThread(THREAD *t);
bool OSInitThread(THREAD *t);
void *OSFileOpen(char *name, bool write_mode, bool read_lock);
void *OSFileOpenW(wchar_t *name, bool write_mode, bool read_lock);
void *OSFileCreate(char *name);
void *OSFileCreateW(wchar_t *name);
bool OSFileWrite(void *pData, void *buf, UINT size);
bool OSFileRead(void *pData, void *buf, UINT size);
void OSFileClose(void *pData, bool no_flush);
void OSFileFlush(void *pData);
UINT64 OSFileSize(void *pData);
bool OSFileSeek(void *pData, UINT mode, int offset);
bool OSFileDelete(char *name);
bool OSFileDeleteW(wchar_t *name);
bool OSMakeDir(char *name);
bool OSMakeDirW(wchar_t *name);
bool OSDeleteDir(char *name);
bool OSDeleteDirW(wchar_t *name);
CALLSTACK_DATA *OSGetCallStack();
bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s);
bool OSFileRename(char *old_name, char *new_name);
bool OSFileRenameW(wchar_t *old_name, wchar_t *new_name);
UINT OSThreadId();
bool OSRun(char *filename, char *arg, bool hide, bool wait);
bool OSRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
bool OSIsSupportedOs();
void OSGetOsInfo(OS_INFO *info);
void OSAlert(char *msg, char *caption);
void OSAlertW(wchar_t *msg, wchar_t *caption);
char* OSGetProductId();
void OSSetHighPriority();
void OSRestorePriority();
void *OSNewSingleInstance(char *instance_name);
void OSFreeSingleInstance(void *data);
void OSGetMemInfo(MEMINFO *info);
void OSYield();

// Dispatch table
typedef struct OS_DISPATCH_TABLE
{
	void(*Init)();
	void(*Free)();
	void *(*MemoryAlloc)(UINT size);
	void *(*MemoryReAlloc)(void *addr, UINT size);
	void(*MemoryFree)(void *addr);
	UINT(*GetTick)();
	void(*GetSystemTime)(SYSTEMTIME *system_time);
	void(*Inc32)(UINT *value);
	void(*Dec32)(UINT *value);
	void(*Sleep)(UINT time);
	LOCK *(*NewLock)();
	bool(*Lock)(LOCK *lock);
	void(*Unlock)(LOCK *lock);
	void(*DeleteLock)(LOCK *lock);
	void(*InitEvent)(EVENT *event);
	void(*SetEvent)(EVENT *event);
	void(*ResetEvent)(EVENT *event);
	bool(*WaitEvent)(EVENT *event, UINT timeout);
	void(*FreeEvent)(EVENT *event);
	bool(*WaitThread)(THREAD *t);
	void(*FreeThread)(THREAD *t);
	bool(*InitThread)(THREAD *t);
	UINT(*ThreadId)();
	void *(*FileOpen)(char *name, bool write_mode, bool read_lock);
	void *(*FileOpenW)(wchar_t *name, bool write_mode, bool read_lock);
	void *(*FileCreate)(char *name);
	void *(*FileCreateW)(wchar_t *name);
	bool(*FileWrite)(void *pData, void *buf, UINT size);
	bool(*FileRead)(void *pData, void *buf, UINT size);
	void(*FileClose)(void *pData, bool no_flush);
	void(*FileFlush)(void *pData);
	UINT64(*FileSize)(void *pData);
	bool(*FileSeek)(void *pData, UINT mode, int offset);
	bool(*FileDelete)(char *name);
	bool(*FileDeleteW)(wchar_t *name);
	bool(*MakeDir)(char *name);
	bool(*MakeDirW)(wchar_t *name);
	bool(*DeleteDir)(char *name);
	bool(*DeleteDirW)(wchar_t *name);
	CALLSTACK_DATA *(*GetCallStack)();
	bool(*GetCallStackSymbolInfo)(CALLSTACK_DATA *s);
	bool(*FileRename)(char *old_name, char *new_name);
	bool(*FileRenameW)(wchar_t *old_name, wchar_t *new_name);
	bool(*Run)(char *filename, char *arg, bool hide, bool wait);
	bool(*RunW)(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
	bool(*IsSupportedOs)();
	void(*GetOsInfo)(OS_INFO *info);
	void(*Alert)(char *msg, char *caption);
	void(*AlertW)(wchar_t *msg, wchar_t *caption);
	char *(*GetProductId)();
	void(*SetHighPriority)();
	void(*RestorePriority)();
	void *(*NewSingleInstance)(char *instance_name);
	void(*FreeSingleInstance)(void *data);
	void(*GetMemInfo)(MEMINFO *info);
	void(*Yield)();
} OS_DISPATCH_TABLE;

// Include the OS-specific header
#ifdef	OS_WIN32
// Begin for Win32

// Function prototype
OS_DISPATCH_TABLE *Win32GetDispatchTable();

void Win32Init();
void Win32Free();
void *Win32MemoryAlloc(UINT size);
void *Win32MemoryReAlloc(void *addr, UINT size);
void Win32MemoryFree(void *addr);
UINT Win32GetTick();
void Win32GetSystemTime(SYSTEMTIME *system_time);
void Win32Inc32(UINT *value);
void Win32Dec32(UINT *value);
void Win32Sleep(UINT time);
LOCK *Win32NewLock();
bool Win32Lock(LOCK *lock);
void Win32Unlock(LOCK *lock);
void Win32DeleteLock(LOCK *lock);
void Win32InitEvent(EVENT *event);
void Win32SetEvent(EVENT *event);
void Win32ResetEvent(EVENT *event);
bool Win32WaitEvent(EVENT *event, UINT timeout);
void Win32FreeEvent(EVENT *event);
bool Win32WaitThread(THREAD *t);
void Win32FreeThread(THREAD *t);
bool Win32InitThread(THREAD *t);
UINT Win32ThreadId();
void *Win32FileOpen(char *name, bool write_mode, bool read_lock);
void *Win32FileOpenW(wchar_t *name, bool write_mode, bool read_lock);
void *Win32FileCreate(char *name);
void *Win32FileCreateW(wchar_t *name);
bool Win32FileWrite(void *pData, void *buf, UINT size);
bool Win32FileRead(void *pData, void *buf, UINT size);
bool Win32FileSetDate(void *pData, UINT64 created_time, UINT64 updated_time);
bool Win32FileGetDate(void *pData, UINT64 *created_time, UINT64 *updated_time, UINT64 *accessed_date);
void Win32FileClose(void *pData, bool no_flush);
void Win32FileFlush(void *pData);
UINT64 Win32FileSize(void *pData);
bool Win32FileSeek(void *pData, UINT mode, int offset);
bool Win32FileDelete(char *name);
bool Win32FileDeleteW(wchar_t *name);
bool Win32MakeDir(char *name);
bool Win32MakeDirW(wchar_t *name);
bool Win32DeleteDir(char *name);
bool Win32DeleteDirW(wchar_t *name);
CALLSTACK_DATA *Win32GetCallStack();
bool Win32GetCallStackSymbolInfo(CALLSTACK_DATA *s);
bool Win32FileRename(char *old_name, char *new_name);
bool Win32FileRenameW(wchar_t *old_name, wchar_t *new_name);
bool Win32Run(char *filename, char *arg, bool hide, bool wait);
bool Win32RunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
void *Win32RunEx(char *filename, char *arg, bool hide);
void *Win32RunEx2(char *filename, char *arg, bool hide, UINT *process_id);
void *Win32RunEx3(char *filename, char *arg, bool hide, UINT *process_id, bool disableWow);
void *Win32RunExW(wchar_t *filename, wchar_t *arg, bool hide);
void *Win32RunEx2W(wchar_t *filename, wchar_t *arg, bool hide, UINT *process_id);
void *Win32RunEx3W(wchar_t *filename, wchar_t *arg, bool hide, UINT *process_id, bool disableWow);
bool Win32WaitProcess(void *h, UINT timeout);
bool Win32RunAndWaitProcess(wchar_t *filename, wchar_t *arg, bool hide, bool disableWow, UINT timeout);
bool Win32IsProcessAlive(void *handle);
bool Win32TerminateProcess(void *handle);
void Win32CloseProcess(void *handle);
bool Win32IsSupportedOs();
void Win32GetOsInfo(OS_INFO *info);
void Win32Alert(char *msg, char *caption);
void Win32AlertW(wchar_t *msg, wchar_t *caption);
void Win32DebugAlert(char *msg);
char* Win32GetProductId();
void Win32SetHighPriority();
void Win32RestorePriority();
void *Win32NewSingleInstance(char *instance_name);
void Win32FreeSingleInstance(void *data);
void Win32GetMemInfo(MEMINFO *info);
void Win32Yield();

void Win32UnlockEx(LOCK *lock, bool inner);
UINT Win32GetOsType();
UINT Win32GetSpVer(char *str);
UINT Win32GetOsSpVer();
void Win32NukuEn(char *dst, UINT size, char *src);
void Win32NukuEnW(wchar_t *dst, UINT size, wchar_t *src);
void Win32GetDirFromPath(char *dst, UINT size, char *src);
void Win32GetDirFromPathW(wchar_t *dst, UINT size, wchar_t *src);
void Win32GetExeDir(char *name, UINT size);
void Win32GetExeDirW(wchar_t *name, UINT size);
void Win32GetCurrentDir(char *dir, UINT size);
void Win32GetCurrentDirW(wchar_t *dir, UINT size);
void Win32GetExeName(char *name, UINT size);
void Win32GetExeNameW(wchar_t *name, UINT size);
DIRLIST *Win32EnumDirEx(char *dirname, COMPARE *compare);
DIRLIST *Win32EnumDirExW(wchar_t *dirname, COMPARE *compare);
bool Win32GetDiskFreeW(wchar_t *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
bool Win32GetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
bool Win32SetFolderCompress(char *path, bool compressed);
bool Win32SetFolderCompressW(wchar_t *path, bool compressed);
UINT64 Win32FastTick64();
void Win32InitNewThread();
bool Win32IsNt();
bool Win32InputW(wchar_t *str, UINT size);
bool Win32InputFromFileW(wchar_t *str, UINT size);
char *Win32InputFromFileLineA();
void Win32PrintW(wchar_t *str);
void Win32PrintToFileW(wchar_t *str);
bool Win32GetVersionExInternal(void *info);
bool Win32GetVersionExInternalForWindows81orLater(void *info);
UINT Win32GetNumberOfCpuInner();


void Win32SetThreadName(UINT thread_id, char *name);

// End for Win32
#else	//OS_WIN32
// Begin for UNIX



// End for UNIX
#endif	// OS_WIN32


//////////////////////////////////////////////////////////////////////////
// Microsoft

#ifdef	OS_WIN32

// Make available the types for Windows even if windows.h is not included
#ifndef	_WINDEF_

typedef void *HWND;

#endif	// _WINDEF_


// Constant for Event log
#define	MS_EVENTLOG_TYPE_INFORMATION		0
#define	MS_EVENTLOG_TYPE_WARNING			1
#define	MS_EVENTLOG_TYPE_ERROR				2

#define	MS_RC_EVENTLOG_TYPE_INFORMATION		0x40000001L
#define	MS_RC_EVENTLOG_TYPE_WARNING			0x80000002L
#define	MS_RC_EVENTLOG_TYPE_ERROR			0xC0000003L


// TCP/IP registry value
#define	TCP_MAX_NUM_CONNECTIONS				16777214

#define	DEFAULT_TCP_MAX_WINDOW_SIZE_RECV	5955584
#define	DEFAULT_TCP_MAX_WINDOW_SIZE_SEND	131072
#define	DEFAULT_TCP_MAX_NUM_CONNECTIONS		16777214

// Constant
#define	SVC_ARG_INSTALL				"/install"
#define	SVC_ARG_UNINSTALL			"/uninstall"
#define	SVC_ARG_START				"/start"
#define	SVC_ARG_STOP				"/stop"
#define	SVC_ARG_TEST				"/test"
#define	SVC_ARG_USERMODE			"/usermode"
#define	SVC_ARG_USERMODE_SHOWTRAY	"/usermode_showtray"
#define	SVC_ARG_USERMODE_HIDETRAY	"/usermode_hidetray"
#define	SVC_ARG_SERVICE				"/service"
#define	SVC_ARG_SETUP_INSTALL		"/setup_install"
#define	SVC_ARG_SETUP_UNINSTALL		"/setup_uninstall"
#define	SVC_ARG_WIN9X_SERVICE		"/win9x_service"
#define	SVC_ARG_WIN9X_INSTALL		"/win9x_install"
#define	SVC_ARG_WIN9X_UNINSTALL		"/win9x_uninstall"
#define	SVC_ARG_TCP					"/tcp"
#define	SVC_ARG_TCP_UAC				"/tcp_uac"
#define	SVC_ARG_TCP_UAC_W			L"/tcp_uac"
#define	SVC_ARG_TCP_SETUP			"/tcpsetup"
#define	SVC_ARG_TRAFFIC				"/traffic"
#define	SVC_ARG_UIHELP				"/uihelp"
#define	SVC_ARG_UIHELP_W			L"/uihelp"
#define SVC_ARG_SILENT				"/silent"

// Time to suicide, if the service freezed
#define	SVC_SELFKILL_TIMEOUT		(5 * 60 * 1000)

// The name of the device driver of the virtual LAN card for Win32 (first part)
#define	VLAN_ADAPTER_NAME			"VPN Client Adapter"
#define	VLAN_ADAPTER_NAME_OLD		"SoftEther VPN Client 2.0 Adapter"

// The name of the device driver of the virtual LAN card for Win32 (full name)
#define	VLAN_ADAPTER_NAME_TAG		"VPN Client Adapter - %s"
#define	VLAN_ADAPTER_NAME_TAG_OLD	"SoftEther VPN Client 2.0 Adapter - %s"

// Display name of Virtual LAN card in the [Network Connections] in Win32 (full name)
#define	VLAN_CONNECTION_NAME		"%s - VPN Client"
#define	VLAN_CONNECTION_NAME_OLD	"%s - SoftEther VPN Client 2.0"


// Suspend handler windows class name
#define	MS_SUSPEND_HANDLER_WNDCLASSNAME	"MS_SUSPEND_HANDLER"

// Command line format in the service mode
#define	SVC_RUN_COMMANDLINE			L"\"%s\" /service"

// Mode value
#define	SVC_MODE_NONE				0
#define	SVC_MODE_INSTALL			1
#define	SVC_MODE_UNINSTALL			2
#define	SVC_MODE_START				3
#define	SVC_MODE_STOP				4
#define	SVC_MODE_TEST				5
#define	SVC_MODE_USERMODE			6
#define	SVC_MODE_SERVICE			7
#define	SVC_MODE_SETUP_INSTALL		8
#define	SVC_MODE_SETUP_UNINSTALL	9
#define	SVC_MODE_WIN9X_SERVICE		10
#define	SVC_MODE_WIN9X_INSTALL		11
#define	SVC_MODE_WIN9X_UNINSTALL	12
#define	SVC_MODE_TCP				13
#define	SVC_MODE_TCPSETUP			14
#define	SVC_MODE_TRAFFIC			15
#define	SVC_MODE_UIHELP				16
#define	SVC_MODE_TCP_UAC			17


#define	WIN9X_SVC_REGKEY_1			"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
#define	WIN9X_SVC_REGKEY_2			"Software\\Microsoft\\Windows\\CurrentVersion\\Run"

#define	VISTA_MMCSS_KEYNAME			"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks"
#define	VISTA_MMCSS_FILENAME		"mmcss_backup.dat"

#define	SVC_NAME					"SVC_%s_NAME"
#define	SVC_TITLE					"SVC_%s_TITLE"
#define	SVC_DESCRIPT				"SVC_%s_DESCRIPT"

#define	SVC_USERMODE_SETTING_KEY	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\UserMode Settings"
#define	SVC_HIDETRAY_REG_VALUE		"HideTray_%S"

#define	SVC_CALLING_SM_PROCESS_ID_KEY	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\Service Control\\%s"
#define SVC_CALLING_SM_PROCESS_ID_VALUE	"ProcessId"

#define	SOFTETHER_FW_SCRIPT_HASH	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\FW ScriptHash"

#define	MMCSS_PROFILE_KEYNAME		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile"

// Other constants
#define	MS_REG_TCP_SETTING_KEY		"Software\\" GC_REG_COMPANY_NAME "\\Network Settings"



// Constants about driver
#define	DRIVER_INSTALL_SYS_NAME_TAG_NEW	"Neo_%04u.sys"
#define	DRIVER_INSTALL_SYS_NAME_TAG_MAXID	128				// Maximum number of install


// Vista driver installer related
#define	VISTA_DRIVER_INSTALLER_SRC	L"|driver_installer.exe"
#define	VISTA_DRIVER_INSTALLER_SRC_X64	L"|driver_installer_x64.exe"
#define	VISTA_DRIVER_INSTALLER_SRC_IA64	L"|driver_installer_ia64.exe"
#define	VISTA_DRIVER_INSTALLER_DST	L"%s\\driver_installer.exe"

#define	DRIVER_DEVICE_ID_TAG		"NeoAdapter_%s"


#ifdef SECLIB_INTERNAL


#ifdef SECLIB_C


typedef enum __TCP_TABLE_CLASS {
	_TCP_TABLE_BASIC_LISTENER,
	_TCP_TABLE_BASIC_CONNECTIONS,
	_TCP_TABLE_BASIC_ALL,
	_TCP_TABLE_OWNER_PID_LISTENER,
	_TCP_TABLE_OWNER_PID_CONNECTIONS,
	_TCP_TABLE_OWNER_PID_ALL,
	_TCP_TABLE_OWNER_MODULE_LISTENER,
	_TCP_TABLE_OWNER_MODULE_CONNECTIONS,
	_TCP_TABLE_OWNER_MODULE_ALL
} _TCP_TABLE_CLASS, *_PTCP_TABLE_CLASS;

#endif // SECLIB_C

// A pointer to the network related Win32 API function
typedef struct NETWORK_WIN32_FUNCTIONS
{
	HINSTANCE hIpHlpApi32;
	HINSTANCE hIcmp;
	DWORD(WINAPI *DeleteIpForwardEntry)(PMIB_IPFORWARDROW);
	DWORD(WINAPI *CreateIpForwardEntry)(PMIB_IPFORWARDROW);
	DWORD(WINAPI *GetIpForwardTable)(PMIB_IPFORWARDTABLE, PULONG, BOOL);
	DWORD(WINAPI *GetNetworkParams)(PFIXED_INFO, PULONG);
	ULONG(WINAPI *GetAdaptersAddresses)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
	DWORD(WINAPI *GetIfTable)(PMIB_IFTABLE, PULONG, BOOL);
	DWORD(WINAPI *GetIfTable2)(void **);
	void (WINAPI *FreeMibTable)(PVOID);
	DWORD(WINAPI *IpRenewAddress)(PIP_ADAPTER_INDEX_MAP);
	DWORD(WINAPI *IpReleaseAddress)(PIP_ADAPTER_INDEX_MAP);
	DWORD(WINAPI *GetInterfaceInfo)(PIP_INTERFACE_INFO, PULONG);
	DWORD(WINAPI *GetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
	DWORD(WINAPI *GetExtendedTcpTable)(PVOID, PDWORD, BOOL, ULONG, _TCP_TABLE_CLASS, ULONG);
	DWORD(WINAPI *AllocateAndGetTcpExTableFromStack)(PVOID *, BOOL, HANDLE, DWORD, DWORD);
	DWORD(WINAPI *GetTcpTable)(PMIB_TCPTABLE, PDWORD, BOOL);
	DWORD(WINAPI *NotifyRouteChange)(PHANDLE, LPOVERLAPPED);
	BOOL(WINAPI *CancelIPChangeNotify)(LPOVERLAPPED);
	DWORD(WINAPI *NhpAllocateAndGetInterfaceInfoFromStack)(IP_INTERFACE_NAME_INFO **,
		PDWORD, BOOL, HANDLE, DWORD);
	HANDLE(WINAPI *IcmpCreateFile)();
	BOOL(WINAPI *IcmpCloseHandle)(HANDLE);
	DWORD(WINAPI *IcmpSendEcho)(HANDLE, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION,
		LPVOID, DWORD, DWORD);
} NETWORK_WIN32_FUNCTIONS;
#endif


#ifdef	SECLIB_INTERNAL
// WCM related code on Windows 8
typedef enum _MS_WCM_PROPERTY
{
	ms_wcm_global_property_domain_policy,
	ms_wcm_global_property_minimize_policy,
	ms_wcm_global_property_roaming_policy,
	ms_wcm_global_property_powermanagement_policy,
	ms_wcm_intf_property_connection_cost,   //used to set/get cost level and flags for the connection
	ms_wcm_intf_property_dataplan_status,   //used by MNO to indicate plan data associated with new cost
	ms_wcm_intf_property_hotspot_profile,   //used to store hotspot profile (WISPr credentials)
} MS_WCM_PROPERTY, *MS_PWCM_PROPERTY;

typedef struct _MS_WCM_POLICY_VALUE {
	BOOL fValue;
	BOOL fIsGroupPolicy;
} MS_WCM_POLICY_VALUE, *MS_PWCM_POLICY_VALUE;

#define MS_WCM_MAX_PROFILE_NAME            256

typedef enum _MS_WCM_MEDIA_TYPE
{
	ms_wcm_media_unknown,
	ms_wcm_media_ethernet,
	ms_wcm_media_wlan,
	ms_wcm_media_mbn,
	ms_wcm_media_invalid,
	ms_wcm_media_max
} MS_WCM_MEDIA_TYPE, *MS_PWCM_MEDIA_TYPE;

typedef struct _MS_WCM_PROFILE_INFO {
	WCHAR strProfileName[MS_WCM_MAX_PROFILE_NAME];
	GUID AdapterGUID;
	MS_WCM_MEDIA_TYPE Media;
} MS_WCM_PROFILE_INFO, *MS_PWCM_PROFILE_INFO;

typedef struct _MS_WCM_PROFILE_INFO_LIST {
	DWORD            dwNumberOfItems;

	MS_WCM_PROFILE_INFO ProfileInfo[1];

} MS_WCM_PROFILE_INFO_LIST, *MS_PWCM_PROFILE_INFO_LIST;


// Internal structure
typedef struct MS
{
	HINSTANCE hInst;
	HINSTANCE hKernel32;
	bool IsNt;
	bool IsAdmin;
	struct NT_API *nt;
	HANDLE hCurrentProcess;
	UINT CurrentProcessId;
	bool MiniDumpEnabled;
	char *ExeFileName;
	char *ExeFileDir;
	char *WindowsDir;
	char *System32Dir;
	char *TempDir;
	char *WinTempDir;
	char *WindowsDrive;
	char *ProgramFilesDir;
	char *ProgramFilesDirX86;
	char *ProgramFilesDirX64;
	char *CommonStartMenuDir;
	char *CommonProgramsDir;
	char *CommonStartupDir;
	char *CommonAppDataDir;
	char *CommonDesktopDir;
	char *PersonalStartMenuDir;
	char *PersonalProgramsDir;
	char *PersonalStartupDir;
	char *PersonalAppDataDir;
	char *PersonalDesktopDir;
	char *MyDocumentsDir;
	char *LocalAppDataDir;
	char *MyTempDir;
	char *UserName;
	char *UserNameEx;
	wchar_t *ExeFileNameW;
	wchar_t *ExeFileDirW;
	wchar_t *WindowsDirW;
	wchar_t *System32DirW;
	wchar_t *TempDirW;
	wchar_t *WinTempDirW;
	wchar_t *WindowsDriveW;
	wchar_t *ProgramFilesDirW;
	wchar_t *ProgramFilesDirX86W;
	wchar_t *ProgramFilesDirX64W;
	wchar_t *CommonStartMenuDirW;
	wchar_t *CommonProgramsDirW;
	wchar_t *CommonStartupDirW;
	wchar_t *CommonAppDataDirW;
	wchar_t *CommonDesktopDirW;
	wchar_t *PersonalStartMenuDirW;
	wchar_t *PersonalProgramsDirW;
	wchar_t *PersonalStartupDirW;
	wchar_t *PersonalAppDataDirW;
	wchar_t *PersonalDesktopDirW;
	wchar_t *MyDocumentsDirW;
	wchar_t *LocalAppDataDirW;
	wchar_t *MyTempDirW;
	wchar_t *UserNameW;
	wchar_t *UserNameExW;
	wchar_t *MinidumpBaseFileNameW;
	IO *LockFile;
	bool IsWine;
} MS;

// For Windows NT API
typedef struct NT_API
{
	HINSTANCE hAdvapi32;
	HINSTANCE hShell32;
	HINSTANCE hNewDev;
	HINSTANCE hSetupApi;
	HINSTANCE hWtsApi32;
	HINSTANCE hPsApi;
	HINSTANCE hKernel32;
	HINSTANCE hSecur32;
	HINSTANCE hUser32;
	HINSTANCE hDbgHelp;
	HINSTANCE hWcmapi;
	HINSTANCE hDwmapi;
	BOOL(WINAPI *OpenProcessToken)(HANDLE, DWORD, PHANDLE);
	BOOL(WINAPI *LookupPrivilegeValue)(char *, char *, PLUID);
	BOOL(WINAPI *AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
	BOOL(WINAPI *InitiateSystemShutdown)(LPTSTR, LPTSTR, DWORD, BOOL, BOOL);
	BOOL(WINAPI *LogonUserW)(wchar_t *, wchar_t *, wchar_t *, DWORD, DWORD, HANDLE *);
	BOOL(WINAPI *LogonUserA)(char *, char *, char *, DWORD, DWORD, HANDLE *);
	BOOL(WINAPI *UpdateDriverForPlugAndPlayDevicesW)(HWND hWnd, wchar_t *hardware_id, wchar_t *inf_path, UINT flag, BOOL *need_reboot);
	UINT(WINAPI *CM_Get_DevNode_Status_Ex)(UINT *, UINT *, DWORD, UINT, HANDLE);
	UINT(WINAPI *CM_Get_Device_ID_ExA)(DWORD, char *, UINT, UINT, HANDLE);
	UINT(WINAPI *WTSQuerySessionInformation)(HANDLE, DWORD, WTS_INFO_CLASS, wchar_t *, DWORD *);
	void (WINAPI *WTSFreeMemory)(void *);
	BOOL(WINAPI *WTSDisconnectSession)(HANDLE, DWORD, BOOL);
	BOOL(WINAPI *WTSEnumerateSessions)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFO *, DWORD *);
	BOOL(WINAPI *WTSRegisterSessionNotification)(HWND, DWORD);
	BOOL(WINAPI *WTSUnRegisterSessionNotification)(HWND);
	SC_HANDLE(WINAPI *OpenSCManager)(LPCTSTR, LPCTSTR, DWORD);
	SC_HANDLE(WINAPI *CreateServiceA)(SC_HANDLE, LPCTSTR, LPCTSTR, DWORD, DWORD, DWORD, DWORD, LPCTSTR, LPCTSTR, LPDWORD, LPCTSTR, LPCTSTR, LPCTSTR);
	SC_HANDLE(WINAPI *CreateServiceW)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
	BOOL(WINAPI *ChangeServiceConfig2)(SC_HANDLE, DWORD, LPVOID);
	BOOL(WINAPI *CloseServiceHandle)(SC_HANDLE);
	SC_HANDLE(WINAPI *OpenService)(SC_HANDLE, LPCTSTR, DWORD);
	BOOL(WINAPI *QueryServiceStatus)(SC_HANDLE, LPSERVICE_STATUS);
	BOOL(WINAPI *StartService)(SC_HANDLE, DWORD, LPCTSTR);
	BOOL(WINAPI *ControlService)(SC_HANDLE, DWORD, LPSERVICE_STATUS);
	BOOL(WINAPI *SetServiceStatus)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS);
	SERVICE_STATUS_HANDLE(WINAPI *RegisterServiceCtrlHandler)(LPCTSTR, LPHANDLER_FUNCTION);
	BOOL(WINAPI *StartServiceCtrlDispatcher)(CONST LPSERVICE_TABLE_ENTRY);
	BOOL(WINAPI *DeleteService)(SC_HANDLE);
	BOOL(WINAPI *EnumProcesses)(DWORD *, DWORD, DWORD *);
	BOOL(WINAPI *EnumProcessModules)(HANDLE, HMODULE *, DWORD, DWORD *);
	DWORD(WINAPI *GetModuleFileNameExA)(HANDLE, HMODULE, LPSTR, DWORD);
	DWORD(WINAPI *GetModuleFileNameExW)(HANDLE, HMODULE, LPWSTR, DWORD);
	DWORD(WINAPI *GetProcessImageFileNameA)(HANDLE, LPSTR, DWORD);
	DWORD(WINAPI *GetProcessImageFileNameW)(HANDLE, LPWSTR, DWORD);
	BOOL(WINAPI *QueryFullProcessImageNameA)(HANDLE, DWORD, LPSTR, PDWORD);
	BOOL(WINAPI *QueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
	LONG(WINAPI *RegDeleteKeyExA)(HKEY, LPCTSTR, REGSAM, DWORD);
	BOOL(WINAPI *IsWow64Process)(HANDLE, BOOL *);
	void (WINAPI *GetNativeSystemInfo)(SYSTEM_INFO *);
	BOOL(WINAPI *DuplicateTokenEx)(HANDLE, DWORD, SECURITY_ATTRIBUTES *, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, HANDLE *);
	BOOL(WINAPI *ConvertStringSidToSidA)(LPCSTR, PSID *);
	BOOL(WINAPI *SetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, void *, DWORD);
	BOOL(WINAPI *GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, void *, DWORD, PDWORD);
	BOOL(WINAPI *CreateProcessAsUserA)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, void *, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
	BOOL(WINAPI *CreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, void *, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
	BOOL(WINAPI *LookupAccountSidA)(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
	BOOL(WINAPI *LookupAccountNameA)(LPCSTR, LPCSTR, PSID, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
	BOOL(WINAPI *GetUserNameExA)(EXTENDED_NAME_FORMAT, LPSTR, PULONG);
	BOOL(WINAPI *GetUserNameExW)(EXTENDED_NAME_FORMAT, LPWSTR, PULONG);
	BOOL(WINAPI *SwitchDesktop)(HDESK);
	HDESK(WINAPI *OpenDesktopA)(LPTSTR, DWORD, BOOL, ACCESS_MASK);
	BOOL(WINAPI *CloseDesktop)(HDESK);
	BOOL(WINAPI *SetProcessShutdownParameters)(DWORD, DWORD);
	HANDLE(WINAPI *RegisterEventSourceW)(LPCWSTR, LPCWSTR);
	BOOL(WINAPI *ReportEventW)(HANDLE, WORD, WORD, DWORD, PSID, WORD, DWORD, LPCWSTR *, LPVOID);
	BOOL(WINAPI *DeregisterEventSource)(HANDLE);
	BOOL(WINAPI *Wow64DisableWow64FsRedirection)(void **);
	BOOLEAN(WINAPI *Wow64EnableWow64FsRedirection)(BOOLEAN);
	BOOL(WINAPI *Wow64RevertWow64FsRedirection)(void *);
	BOOL(WINAPI *GetFileInformationByHandle)(HANDLE, LPBY_HANDLE_FILE_INFORMATION);
	HANDLE(WINAPI *GetProcessHeap)();
	BOOL(WINAPI *MiniDumpWriteDump)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
		PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION,
		PMINIDUMP_CALLBACK_INFORMATION);
	BOOL(WINAPI *AllocateLocallyUniqueId)(PLUID);
	NTSTATUS(NTAPI *LsaConnectUntrusted)(PHANDLE);
	NTSTATUS(NTAPI *LsaLookupAuthenticationPackage)(HANDLE, PLSA_STRING, PULONG);
	NTSTATUS(NTAPI *LsaLogonUser)(HANDLE, PLSA_STRING, SECURITY_LOGON_TYPE, ULONG,
		PVOID, ULONG, PTOKEN_GROUPS, PTOKEN_SOURCE, PVOID, PULONG, PLUID, PHANDLE,
		PQUOTA_LIMITS, PNTSTATUS);
	NTSTATUS(NTAPI *LsaDeregisterLogonProcess)(HANDLE);
	NTSTATUS(NTAPI *LsaFreeReturnBuffer)(PVOID);
	DWORD(WINAPI *WcmQueryProperty)(const GUID *, LPCWSTR, MS_WCM_PROPERTY, PVOID, PDWORD, PBYTE *);
	DWORD(WINAPI *WcmSetProperty)(const GUID *, LPCWSTR, MS_WCM_PROPERTY, PVOID, DWORD, const BYTE *);
	void (WINAPI *WcmFreeMemory)(PVOID);
	DWORD(WINAPI *WcmGetProfileList)(PVOID, MS_WCM_PROFILE_INFO_LIST **ppProfileList);
	DWORD(WINAPI *SetNamedSecurityInfoW)(LPWSTR, UINT, SECURITY_INFORMATION, PSID, PSID, PACL, PACL);
	BOOL(WINAPI *AddAccessAllowedAceEx)(PACL, DWORD, DWORD, DWORD, PSID);
	HRESULT(WINAPI *DwmIsCompositionEnabled)(BOOL *);
	BOOL(WINAPI *GetComputerNameExW)(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD);
	LONG(WINAPI *RegLoadKeyW)(HKEY, LPCWSTR, LPCWSTR);
	LONG(WINAPI *RegUnLoadKeyW)(HKEY, LPCWSTR);
} NT_API;

typedef struct MS_EVENTLOG
{
	HANDLE hEventLog;
} MS_EVENTLOG;

extern NETWORK_WIN32_FUNCTIONS *w32net;

typedef struct MS_USERMODE_SVC_PULSE_THREAD_PARAM
{
	void *hWnd;
	void *GlobalPulse;
	volatile bool Halt;
} MS_USERMODE_SVC_PULSE_THREAD_PARAM;

#endif	// MICROSOFT_C

// Structure to suppress the warning message
typedef struct NO_WARNING
{
	DWORD ThreadId;
	THREAD *NoWarningThread;
	EVENT *HaltEvent;
	volatile bool Halt;
	wchar_t *SoundFileName;
	UINT64 StartTimer;
	UINT64 StartTick;
} NO_WARNING;

// ID of the root key
#define	REG_CLASSES_ROOT		0	// HKEY_CLASSES_ROOT
#define	REG_LOCAL_MACHINE		1	// HKEY_LOCAL_MACHINE
#define	REG_CURRENT_USER		2	// HKEY_CURRENT_USER
#define	REG_USERS				3	// HKEY_USERS

// Service Functions
typedef void (SERVICE_FUNCTION)();

// Process list item
typedef struct MS_PROCESS
{
	char ExeFilename[MAX_PATH];		// EXE file name
	wchar_t ExeFilenameW[MAX_PATH];	// EXE file name (Unicode)
	UINT ProcessId;					// Process ID
} MS_PROCESS;

#define	MAX_MS_ADAPTER_IP_ADDRESS	64

// Network adapter
typedef struct MS_ADAPTER
{
	char Title[MAX_PATH];			// Display name
	wchar_t TitleW[MAX_PATH];		// Display Name (Unicode)
	UINT Index;						// Index
	UINT Type;						// Type
	UINT Status;					// Status
	UINT Mtu;						// MTU
	UINT Speed;						// Speed
	UINT AddressSize;				// Address size
	UCHAR Address[8];				// Address
	UINT64 RecvBytes;				// Number of received bytes
	UINT64 RecvPacketsBroadcast;	// Number of broadcast packets received
	UINT64 RecvPacketsUnicast;		// Number of unicast packets received
	UINT64 SendBytes;				// Number of bytes sent
	UINT64 SendPacketsBroadcast;	// Number of sent broadcast packets
	UINT64 SendPacketsUnicast;		// Number of sent unicast packets
	bool Info;						// Whether there is detailed information
	char Guid[MAX_SIZE];			// GUID
	UINT NumIpAddress;				// The number of IP addresses
	IP IpAddresses[MAX_MS_ADAPTER_IP_ADDRESS];	// IP address
	IP SubnetMasks[MAX_MS_ADAPTER_IP_ADDRESS];	// Subnet mask
	UINT NumGateway;				// The number of the gateway
	IP Gateways[MAX_MS_ADAPTER_IP_ADDRESS];	// Gateway
	bool UseDhcp;					// Using DHCP flag
	IP DhcpServer;					// DHCP Server
	UINT64 DhcpLeaseStart;			// DHCP lease start date and time
	UINT64 DhcpLeaseExpires;		// DHCP lease expiration date and time
	bool UseWins;					// WINS use flag
	IP PrimaryWinsServer;			// Primary WINS server
	IP SecondaryWinsServer;			// Secondary WINS server
	bool IsWireless;				// Whether wireless
	bool IsNotEthernetLan;			// Whether It isn't a Ethernet LAN
} MS_ADAPTER;

// Network adapter list
typedef struct MS_ADAPTER_LIST
{
	UINT Num;						// Count
	MS_ADAPTER **Adapters;			// Content
} MS_ADAPTER_LIST;

typedef struct MS_ISLOCKED
{
	HWND hWnd;
	THREAD *Thread;
	volatile bool IsLockedFlag;
} MS_ISLOCKED;

// TCP setting
typedef struct MS_TCP
{
	UINT RecvWindowSize;			// Receive window size
	UINT SendWindowSize;			// Send window size
} MS_TCP;

// Sleep prevention
typedef struct MS_NOSLEEP
{
	THREAD *Thread;					// Thread
	EVENT *HaltEvent;				// Halting event
	volatile bool Halt;				// Halting flag
	bool NoScreenSaver;				// Prevent Screensaver

									// Following is for Windows Vista
	wchar_t ScreenSaveActive[MAX_PATH];
	wchar_t SCRNSAVE_EXE[MAX_PATH];
} MS_NOSLEEP;

// Child window enumeration
typedef struct ENUM_CHILD_WINDOW_PARAM
{
	LIST *o;
	bool no_recursion;
	bool include_ipcontrol;
} ENUM_CHILD_WINDOW_PARAM;

// Driver version information
typedef struct MS_DRIVER_VER
{
	UINT Year, Month, Day;
	UINT Major, Minor, Build;
} MS_DRIVER_VER;

// Suspend handler
typedef struct MS_SUSPEND_HANDLER
{
	HWND hWnd;
	THREAD *Thread;
	volatile bool AboutToClose;
} MS_SUSPEND_HANDLER;


// Function prototype
void MsInit();
void MsFree();
char *MsCutExeNameFromCommandLine(char *str);
wchar_t *MsCutExeNameFromUniCommandLine(wchar_t *str);

DWORD MsRegAccessMaskFor64Bit(bool force32bit);
DWORD MsRegAccessMaskFor64BitEx(bool force32bit, bool force64bit);

bool MsRegIsKey(UINT root, char *name);
bool MsRegIsKeyEx(UINT root, char *name, bool force32bit);
bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit, bool force64bit);

bool MsRegIsValue(UINT root, char *keyname, char *valuename);
bool MsRegIsValueEx(UINT root, char *keyname, char *valuename, bool force32bit);
bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsRegGetValueTypeAndSize(UINT root, char *keyname, char *valuename, UINT *type, UINT *size);
bool MsRegGetValueTypeAndSizeEx(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit);
bool MsRegGetValueTypeAndSizeEx2(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit, bool force64bit);
bool MsRegGetValueTypeAndSizeW(UINT root, char *keyname, char *valuename, UINT *type, UINT *size);
bool MsRegGetValueTypeAndSizeExW(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit);
bool MsRegGetValueTypeAndSizeEx2W(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit, bool force64bit);

bool MsRegReadValue(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size);
bool MsRegReadValueEx(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit);
bool MsRegReadValueEx2(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit, bool force64bit);
bool MsRegReadValueW(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size);
bool MsRegReadValueExW(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit);
bool MsRegReadValueEx2W(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit, bool force64bit);

char *MsRegReadStr(UINT root, char *keyname, char *valuename);
char *MsRegReadStrEx(UINT root, char *keyname, char *valuename, bool force32bit);
char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);
wchar_t *MsRegReadStrW(UINT root, char *keyname, char *valuename);
wchar_t *MsRegReadStrExW(UINT root, char *keyname, char *valuename, bool force32bit);
wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

UINT MsRegReadInt(UINT root, char *keyname, char *valuename);
UINT MsRegReadIntEx(UINT root, char *keyname, char *valuename, bool force32bit);
UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);
LIST *MsRegReadStrList(UINT root, char *keyname, char *valuename);
LIST *MsRegReadStrListEx(UINT root, char *keyname, char *valuename, bool force32bit);
LIST *MsRegReadStrListEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

BUF *MsRegReadBin(UINT root, char *keyname, char *valuename);
BUF *MsRegReadBinEx(UINT root, char *keyname, char *valuename, bool force32bit);
BUF *MsRegReadBinEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsRegNewKey(UINT root, char *keyname);
bool MsRegNewKeyEx(UINT root, char *keyname, bool force32bit);
bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);

bool MsRegWriteValue(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size);
bool MsRegWriteValueEx(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit);
bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit);
bool MsRegWriteValueW(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size);
bool MsRegWriteValueExW(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit);
bool MsRegWriteValueEx2W(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit);

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str);
bool MsRegWriteStrEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit);
bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit);
bool MsRegWriteStrExpand(UINT root, char *keyname, char *valuename, char *str);
bool MsRegWriteStrExpandEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit);
bool MsRegWriteStrExpandEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit);
bool MsRegWriteStrW(UINT root, char *keyname, char *valuename, wchar_t *str);
bool MsRegWriteStrExW(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit);
bool MsRegWriteStrEx2W(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit, bool force64bit);
bool MsRegWriteStrExpandW(UINT root, char *keyname, char *valuename, wchar_t *str);
bool MsRegWriteStrExpandExW(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit);
bool MsRegWriteStrExpandEx2W(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit, bool force64bit);

bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value);
bool MsRegWriteIntEx(UINT root, char *keyname, char *valuename, UINT value, bool force32bit);
bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit, bool force64bit);
bool MsRegWriteBin(UINT root, char *keyname, char *valuename, void *data, UINT size);
bool MsRegWriteBinEx(UINT root, char *keyname, char *valuename, void *data, UINT size, bool force32bit);
bool MsRegWriteBinEx2(UINT root, char *keyname, char *valuename, void *data, UINT size, bool force32bit, bool force64bit);

TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname);
TOKEN_LIST *MsRegEnumKeyEx(UINT root, char *keyname, bool force32bit);
TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);
TOKEN_LIST *MsRegEnumValue(UINT root, char *keyname);
TOKEN_LIST *MsRegEnumValueEx(UINT root, char *keyname, bool force32bit);
TOKEN_LIST *MsRegEnumValueEx2(UINT root, char *keyname, bool force32bit, bool force64bit);

bool MsRegDeleteKey(UINT root, char *keyname);
bool MsRegDeleteKeyEx(UINT root, char *keyname, bool force32bit);
bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);
bool MsRegDeleteValue(UINT root, char *keyname, char *valuename);
bool MsRegDeleteValueEx(UINT root, char *keyname, char *valuename, bool force32bit);
bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsRegLoadHive(UINT root, wchar_t *keyname, wchar_t *filename);
bool MsRegUnloadHive(UINT root, wchar_t *keyname);

bool MsIsNt();
bool MsIsAdmin();
bool MsIsWine();
bool MsEnablePrivilege(char *name, bool enable);
void *MsGetCurrentProcess();
UINT MsGetCurrentProcessId();
char *MsGetExeFileName();
char *MsGetExeDirName();
wchar_t *MsGetExeDirNameW();

void MsIsLockedThreadProc(THREAD *thread, void *param);
MS_ISLOCKED *MsNewIsLocked();
void MsFreeIsLocked(MS_ISLOCKED *d);
void MsStartIsLockedThread();
void MsStopIsLockedThread();
bool MsDetermineIsLockedByWtsApi();


bool MsShutdown(bool reboot, bool force);
bool MsShutdownEx(bool reboot, bool force, UINT time_limit, char *message);
bool MsCheckLogon(wchar_t *username, char *password);
bool MsIsPasswordEmpty(wchar_t *username);
TOKEN_LIST *MsEnumNetworkAdapters(char *start_with_name, char *start_with_name_2);
TOKEN_LIST *MsEnumNetworkAdaptersNeo();
bool MsGetNeoDeiverFilename(char *name, UINT size, char *instance_name);
bool MsMakeNewNeoDriverFilename(char *name, UINT size);
void MsGenerateNeoDriverFilenameFromInt(char *name, UINT size, UINT n);
TOKEN_LIST *MsEnumNeoDriverFilenames();
char *MsGetNetworkAdapterGuid(char *tag_name, char *instance_name);
wchar_t *MsGetNetworkConnectionName(char *guid);
char *MsGetNetworkConfigRegKeyNameFromGuid(char *guid);
char *MsGetNetworkConfigRegKeyNameFromInstanceName(char *tag_name, char *instance_name);
void MsSetNetworkConfig(char *tag_name, char *instance_name, char *friendly_name, bool show_icon);
void MsInitNetworkConfig(char *tag_name, char *instance_name, char *connection_tag_name);
void MsNormalizeInterfaceDefaultGatewaySettings(char *tag_name, char *instance_name);

char *MsGetSpecialDir(int id);
wchar_t *MsGetSpecialDirW(int id);
void MsGetSpecialDirs();
bool MsCheckIsAdmin();
void MsInitTempDir();
void MsFreeTempDir();
void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir);
void MsDeleteTempDir();
void MsDeleteAllFile(char *dir);
void MsDeleteAllFileW(wchar_t *dir);
char *MsCreateTempFileName(char *name);
char *MsCreateTempFileNameByExt(char *ext);
IO *MsCreateTempFile(char *name);
IO *MsCreateTempFileByExt(char *ext);

bool MsInstallVLan(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver);
bool MsInstallVLanWithoutLock(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver);
bool MsInstallVLanInternal(wchar_t *infpath, wchar_t *hwid_w, char *hwid);
bool MsUpgradeVLan(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver);
bool MsUpgradeVLanWithoutLock(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver);
bool MsEnableVLan(char *instance_name);
bool MsEnableVLanWithoutLock(char *instance_name);
bool MsDisableVLan(char *instance_name);
bool MsDisableVLanWithoutLock(char *instance_name);
bool MsUninstallVLan(char *instance_name);
bool MsUninstallVLanWithoutLock(char *instance_name);
bool MsIsVLanEnabled(char *instance_name);
bool MsIsVLanEnabledWithoutLock(char *instance_name);
bool MsIsValidVLanInstanceNameForInfCatalog(char *instance_name);
void MsGetInfCatalogDir(char *dst, UINT size);
void MsRestartVLan(char *instance_name);
void MsRestartVLanWithoutLock(char *instance_name);
bool MsIsVLanExists(char *tag_name, char *instance_name);
void MsDeleteTroubleVLAN(char *tag_name, char *instance_name);
bool MsStartDriverInstall(char *instance_name, UCHAR *mac_address, char *neo_sys, UCHAR *ret_mac_address, MS_DRIVER_VER *ver);
void MsFinishDriverInstall(char *instance_name, char *neo_sys);
void MsGetDriverPath(char *instance_name, wchar_t *src_inf, wchar_t *src_sys, wchar_t *dest_inf, wchar_t *dest_sys, wchar_t *src_cat, wchar_t *dest_cat, char *neo_sys);
void MsGetDriverPathA(char *instance_name, char *src_inf, char *src_sys, char *dest_inf, char *dest_sys, char *src_cat, char *dst_cat, char *neo_sys);
void MsGenMacAddress(UCHAR *mac);
char *MsGetMacAddress(char *tag_name, char *instance_name);
char *MsGetNetCfgRegKeyName(char *tag_name, char *instance_name);
void MsSetMacAddress(char *tag_name, char *instance_name, char *mac_address);
char *MsGetDriverVersion(char *tag_name, char *instance_name);
char *MsGetDriverFileName(char *tag_name, char *instance_name);
void MsTest();
void MsInitGlobalNetworkConfig();
void MsDisableNetworkOffloadingEtc();
void MsSetThreadPriorityHigh();
void MsSetThreadPriorityLow();
void MsSetThreadPriorityIdle();
void MsSetThreadPriorityRealtime();
void MsRestoreThreadPriority();
char *MsGetLocalAppDataDir();
char *MsGetCommonAppDataDir();
char *MsGetWindowsDir();
char *MsGetSystem32Dir();
char *MsGetTempDir();
char *MsGetWindowsDrive();
char *MsGetProgramFilesDir();
char *MsGetProgramFilesDirX86();
char *MsGetProgramFilesDirX64();
char *MsGetCommonStartMenuDir();
char *MsGetCommonProgramsDir();
char *MsGetCommonStartupDir();
char *MsGetCommonAppDataDir();
char *MsGetCommonDesktopDir();
char *MsGetPersonalStartMenuDir();
char *MsGetPersonalProgramsDir();
char *MsGetPersonalStartupDir();
char *MsGetPersonalAppDataDir();
char *MsGetPersonalDesktopDir();
char *MsGetMyDocumentsDir();
char *MsGetMyTempDir();
char *MsGetUserName();
char *MsGetUserNameEx();
char *MsGetWinTempDir();
wchar_t *MsGetWindowsDirW();
wchar_t *MsGetExeFileNameW();
wchar_t *MsGetExeFileDirW();
wchar_t *MsGetWindowDirW();
wchar_t *MsGetSystem32DirW();
wchar_t *MsGetTempDirW();
wchar_t *MsGetWindowsDriveW();
wchar_t *MsGetProgramFilesDirW();
wchar_t *MsGetProgramFilesDirX86W();
wchar_t *MsGetProgramFilesDirX64W();
wchar_t *MsGetCommonStartMenuDirW();
wchar_t *MsGetCommonProgramsDirW();
wchar_t *MsGetCommonStartupDirW();
wchar_t *MsGetCommonAppDataDirW();
wchar_t *MsGetCommonDesktopDirW();
wchar_t *MsGetPersonalStartMenuDirW();
wchar_t *MsGetPersonalProgramsDirW();
wchar_t *MsGetPersonalStartupDirW();
wchar_t *MsGetPersonalAppDataDirW();
wchar_t *MsGetPersonalDesktopDirW();
wchar_t *MsGetMyDocumentsDirW();
wchar_t *MsGetLocalAppDataDirW();
wchar_t *MsGetMyTempDirW();
wchar_t *MsGetUserNameW();
wchar_t *MsGetUserNameExW();
wchar_t *MsGetWinTempDirW();
struct SAFE_TABLE *MsGetSafeTable();
UINT MsGetProcessId();
void MsTerminateProcess();
bool MsIsServiceInstalled(char *name);
bool MsInstallService(char *name, char *title, wchar_t *description, char *path);
bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path, UINT *error_code);
bool MsInstallServiceW(char *name, wchar_t *title, wchar_t *description, wchar_t *path);
bool MsInstallDeviceDriverW(char *name, wchar_t *title, wchar_t *path, UINT *error_code);
bool MsUpdateServiceConfig(char *name);
bool MsSetServiceDescription(char *name, wchar_t *description);
bool MsUninstallService(char *name);
bool MsStartService(char *name);
bool MsStartServiceEx(char *name, UINT *error_code);
bool MsStopService(char *name);
bool MsIsServiceRunning(char *name);
bool MsIsTerminalServiceInstalled();
bool MsIsUserSwitchingInstalled();
bool MsIsTerminalServiceMultiUserInstalled();
UINT MsGetCurrentTerminalSessionId();
bool MsIsTerminalSessionActive(UINT session_id);
bool MsIsCurrentTerminalSessionActive();
bool MsIsCurrentDesktopAvailableForVnc();
wchar_t *MsGetSessionUserName(UINT session_id);
UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon, char *cmd_line);
void MsTestModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void MsTestMode(char *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void MsServiceMode(SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void MsUserModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon);
void MsUserMode(char *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon);
bool MsIsUserMode();
void MsTestOnly();
void MsStopUserModeFromService();
char *MsGetPenCoreDllFileName();
void MsPlaySound(char *name);
void MsSetThreadSingleCpu();
void MsWin9xTest();
bool MsCheckVLanDeviceIdFromRootEnum(char *name);
bool MsInstallVLan9x(char *instance_name, MS_DRIVER_VER *ver);
void MsUpdateCompatibleIDs(char *instance_name);
LIST *MsGetProcessList();
LIST *MsGetProcessList9x();
LIST *MsGetProcessListNt();
void MsFreeProcessList(LIST *o);
void MsPrintProcessList(LIST *o);
int MsCompareProcessList(void *p1, void *p2);
MS_PROCESS *MsSearchProcessById(LIST *o, UINT id);
void MsGetCurrentProcessExeName(char *name, UINT size);
void MsGetCurrentProcessExeNameW(wchar_t *name, UINT size);
bool MsKillProcess(UINT id);
UINT MsKillProcessByExeName(wchar_t *name);
void MsKillOtherInstance();
void MsKillOtherInstanceEx(char *exclude_svcname);
bool MsGetShortPathNameA(char *long_path, char *short_path, UINT short_path_size);
bool MsGetShortPathNameW(wchar_t *long_path, wchar_t *short_path, UINT short_path_size);
void MsWriteCallingServiceManagerProcessId(char *svcname, UINT pid);
UINT MsReadCallingServiceManagerProcessId(char *svcname, bool current_user);
bool MsStopIPsecService();
char *MsGetIPsecServiceName();
bool MsStartIPsecService();

void MsGenerateUserModeSvcGlobalPulseName(char *name, UINT size, char *svc_name);
void *MsCreateUserModeSvcGlocalPulse(char *svc_name);
void MsStopUserModeSvc(char *svc_name);
void MsUserModeGlobalPulseRecvThread(THREAD *thread, void *param);

MS_ADAPTER_LIST *MsCreateAdapterListInner();
MS_ADAPTER_LIST *MsCreateAdapterListInnerEx(bool no_info);
MS_ADAPTER_LIST *MsCreateAdapterListInnerExVista(bool no_info);
void MsFreeAdapter(MS_ADAPTER *a);
void MsFreeAdapterList(MS_ADAPTER_LIST *o);
wchar_t *MsGetAdapterTypeStr(UINT type);
wchar_t *MsGetAdapterStatusStr(UINT status);
MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a);
MS_ADAPTER_LIST *MsCloneAdapterList(MS_ADAPTER_LIST *o);
void MsInitAdapterListModule();
void MsFreeAdapterListModule();
MS_ADAPTER_LIST *MsCreateAdapterList();
MS_ADAPTER_LIST *MsCreateAdapterListEx(bool no_info);
void MsGetAdapterTcpIpInformation(MS_ADAPTER *a);
MS_ADAPTER *MsGetAdapter(char *title);
MS_ADAPTER *MsGetAdapterByGuid(char *guid);
MS_ADAPTER *MsGetAdapterByGuidFromList(MS_ADAPTER_LIST *o, char *guid);
UINT ConvertMidStatusVistaToXp(UINT st);

void *MsLoadLibrary(char *name);
void *MsLoadLibraryW(wchar_t *name);
void *MsLoadLibraryAsDataFile(char *name);
void *MsLoadLibraryAsDataFileW(wchar_t *name);
void *MsLoadLibraryRawW(wchar_t *name);
void MsFreeLibrary(void *h);
void *MsGetProcAddress(void *h, char *name);

void MsPrintTick();
bool MsDisableIme();

void MsGetTcpConfig(MS_TCP *tcp);
void MsSetTcpConfig(MS_TCP *tcp);
void MsSaveTcpConfigReg(MS_TCP *tcp);
bool MsLoadTcpConfigReg(MS_TCP *tcp);
bool MsIsTcpConfigSupported();
void MsApplyTcpConfig();
bool MsIsShouldShowTcpConfigApp();
void MsDeleteTcpConfigReg();

UINT MsGetConsoleWidth();
UINT MsSetConsoleWidth(UINT size);
NO_WARNING *MsInitNoWarning();
NO_WARNING *MsInitNoWarningEx(UINT start_timer);
void MsFreeNoWarning(NO_WARNING *nw);
void MsNoWarningThreadProc(THREAD *thread, void *param);
char *MsNoWarningSoundInit();
void MsNoWarningSoundFree(char *s);
bool MsCloseWarningWindow(NO_WARNING *nw, UINT thread_id);
LIST *MsEnumChildWindows(LIST *o, HWND hWnd);
void MsAddWindowToList(LIST *o, HWND hWnd);
UINT MsGetThreadLocale();
LIST *NewWindowList();
int CmpWindowList(void *p1, void *p2);
void AddWindow(LIST *o, HWND hWnd);
void FreeWindowList(LIST *o);
LIST *EnumAllChildWindow(HWND hWnd);
LIST *EnumAllChildWindowEx(HWND hWnd, bool no_recursion, bool include_ipcontrol, bool no_self);
LIST *EnumAllWindow();
LIST *EnumAllWindowEx(bool no_recursion, bool include_ipcontrol);
LIST *EnumAllTopWindow();

bool MsExecDriverInstaller(char *arg);
bool MsIsVista();
bool MsIsWin2000();
bool MsIsWin2000OrGreater();
bool MsIsWinXPOrGreater();
void MsRegistWindowsFirewallEx(char *title, char *exe);
void MsRegistWindowsFirewallEx2(char *title, char *exe, char *dir);
bool MsIs64BitWindows();
bool MsIsX64();
bool MsIsIA64();
void *MsDisableWow64FileSystemRedirection();
void MsRestoreWow64FileSystemRedirection(void *p);
void MsSetWow64FileSystemRedirectionEnable(bool enable);
bool MsIsWindows10();
bool MsIsWindows81();
bool MsIsWindows8();
bool MsIsWindows7();
bool MsIsInfCatalogRequired();

bool MsCheckFileDigitalSignature(HWND hWnd, char *name, bool *danger);
bool MsCheckFileDigitalSignatureW(HWND hWnd, wchar_t *name, bool *danger);


bool MsGetProcessExeName(char *path, UINT size, UINT id);
bool MsGetProcessExeNameW(wchar_t *path, UINT size, UINT id);
bool MsGetWindowOwnerProcessExeName(char *path, UINT size, HWND hWnd);
bool MsGetWindowOwnerProcessExeNameW(wchar_t *path, UINT size, HWND hWnd);

void *MsRunAsUserEx(char *filename, char *arg, bool hide);
void *MsRunAsUserExW(wchar_t *filename, wchar_t *arg, bool hide);
void *MsRunAsUserExInner(char *filename, char *arg, bool hide);
void *MsRunAsUserExInnerW(wchar_t *filename, wchar_t *arg, bool hide);

UINT MsGetCursorPosHash();
bool MsIsProcessExists(char *exename);
bool MsIsProcessExistsW(wchar_t *exename);
bool MsGetProcessNameFromId(wchar_t *exename, UINT exename_size, UINT pid);
bool MsIsProcessIdExists(UINT pid);

void MsGetComputerName(char *name, UINT size);
void MsGetComputerNameFull(wchar_t *name, UINT size);
void MsGetComputerNameFullEx(wchar_t *name, UINT size, bool with_cache);
void MsNoSleepThread(THREAD *thread, void *param);
void MsNoSleepThreadVista(THREAD *thread, void *param);
UINT64 MsGetScreenSaverTimeout();
void *MsNoSleepStart(bool no_screensaver);
void MsNoSleepEnd(void *p);
bool MsIsRemoteDesktopAvailable();
bool MsIsRemoteDesktopCanEnableByRegistory();
bool MsIsRemoteDesktopEnabled();
bool MsEnableRemoteDesktop();

void MsSetFileToHidden(char *name);
void MsSetFileToHiddenW(wchar_t *name);
bool MsGetFileVersion(char *name, UINT *v1, UINT *v2, UINT *v3, UINT *v4);
bool MsGetFileVersionW(wchar_t *name, UINT *v1, UINT *v2, UINT *v3, UINT *v4);

bool MsExtractCabinetFileFromExe(char *exe, char *cab);
bool MsExtractCabinetFileFromExeW(wchar_t *exe, wchar_t *cab);
BUF *MsExtractResourceFromExe(char *exe, char *type, char *name);
BUF *MsExtractResourceFromExeW(wchar_t *exe, char *type, char *name);
bool MsExtractCab(char *cab_name, char *dest_dir_name);
bool MsExtractCabW(wchar_t *cab_name, wchar_t *dest_dir_name);
bool MsGetCabarcExeFilename(char *name, UINT size);
bool MsGetCabarcExeFilenameW(wchar_t *name, UINT size);
bool MsExtractCabFromMsi(char *msi, char *cab);
bool MsExtractCabFromMsiW(wchar_t *msi, wchar_t *cab);
bool MsIsDirectory(char *name);
bool MsIsDirectoryW(wchar_t *name);
bool MsUniIsDirectory(wchar_t *name);
bool MsUniFileDelete(wchar_t *name);
bool MsUniDirectoryDelete(wchar_t *name);
bool MsUniMakeDir(wchar_t *name);
void MsUniMakeDirEx(wchar_t *name);
void MsMakeDirEx(char *name);
bool MsMakeDir(char *name);
bool MsDirectoryDelete(char *name);
bool MsFileDelete(char *name);
bool MsExecute(char *exe, char *arg);
bool MsExecute2(char *exe, char *arg, bool runas);
bool MsExecuteW(wchar_t *exe, wchar_t *arg);
bool MsExecute2W(wchar_t *exe, wchar_t *arg, bool runas);
bool MsExecuteEx(char *exe, char *arg, void **process_handle);
bool MsExecuteEx2(char *exe, char *arg, void **process_handle, bool runas);
bool MsExecuteExW(wchar_t *exe, wchar_t *arg, void **process_handle);
bool MsExecuteEx2W(wchar_t *exe, wchar_t *arg, void **process_handle, bool runas);
void MsCloseHandle(void *handle);
UINT MsWaitProcessExit(void *process_handle);
bool MsIsFileLocked(char *name);
bool MsIsFileLockedW(wchar_t *name);
bool MsIsLocalDrive(char *name);
bool MsIsLocalDriveW(wchar_t *name);
void MsUpdateSystem();
bool MsGetPhysicalMacAddressFromNetbios(void *address);
bool MsGetPhysicalMacAddressFromApi(void *address);
bool MsGetPhysicalMacAddress(void *address);
bool MsIsUseWelcomeLogin();
UINT64 MsGetHiResCounter();
double MsGetHiResTimeSpan(UINT64 diff);
UINT64 MsGetHiResTimeSpanUSec(UINT64 diff);
BUF *MsRegSubkeysToBuf(UINT root, char *keyname, bool force32bit, bool force64bit);
void MsBufToRegSubkeys(UINT root, char *keyname, BUF *b, bool overwrite, bool force32bit, bool force64bit);
void MsRegDeleteSubkeys(UINT root, char *keyname, bool force32bit, bool force64bit);
void MsRestartMMCSS();
bool MsIsMMCSSNetworkThrottlingEnabled();
void MsSetMMCSSNetworkThrottlingEnable(bool enable);
void MsSetShutdownParameters(UINT level, UINT flag);
void MsChangeIconOnTrayEx2(void *icon, wchar_t *tooltip, wchar_t *info_title, wchar_t *info, UINT info_flags);
bool MsIsTrayInited();
UINT MsGetClipboardOwnerProcessId();
void MsDeleteClipboard();
void *MsInitEventLog(wchar_t *src_name);
void MsFreeEventLog(void *p);
bool MsWriteEventLog(void *p, UINT type, wchar_t *str);
bool MsIsWinXPOrWinVista();
bool MsGetFileInformation(void *h, void *info);
void MsSetErrorModeToSilent();
void MsSetEnableMinidump(bool enabled);
void MsWriteMinidump(wchar_t *filename, void *ex);


void *MsInitGlobalLock(char *name, bool ts_local);
void MsGlobalLock(void *p);
void MsGlobalUnlock(void *p);
void MsFreeGlobalLock(void *p);

void *MsOpenOrCreateGlobalPulse(char *name);
bool MsWaitForGlobalPulse(void *p, UINT timeout);
void MsCloseGlobalPulse(void *p);
void MsSendGlobalPulse(void *p);

bool MsPerformMsChapV2AuthByLsa(char *username, UCHAR *challenge8, UCHAR *client_response_24, UCHAR *ret_pw_hash_hash);

void MsDisableWcmNetworkMinimize();
bool MsSetFileSecureAcl(wchar_t *path);

bool MsGetMsiInstalledDir(char *component_code, wchar_t *dir, UINT dir_size);
bool MsMsiUninstall(char *product_code, HWND hWnd, bool *reboot_required);

UINT MsGetUserLocaleId();
UINT MsGetSystemLocaleId();
bool MsIsCurrentUserLocaleIdJapanese();

TOKEN_LIST *MsEnumResources(void *hModule, char *type);
void *MsGetCurrentModuleHandle();

bool MsIsAeroEnabled();
bool MsIsAeroColor();

bool MsIsInVmMain();
bool MsIsInVm();

void MsTest();

bool MsSaveSystemInfo(wchar_t *dst_filename);
bool MsCollectVpnInfo(BUF *bat, char *tmpdir, char *svc_name, wchar_t *config_name, wchar_t *logdir_name);

MS_SUSPEND_HANDLER *MsNewSuspendHandler();
void MsFreeSuspendHandler(MS_SUSPEND_HANDLER *h);

void MsBeginVLanCard();
void MsEndVLanCard();
bool MsIsVLanCardShouldStop();
void MsProcEnterSuspend();
void MsProcLeaveSuspend();
UINT64 MsGetSuspendModeBeginTick();

// Inner functions
#ifdef	SECLIB_INTERNAL

LONG CALLBACK MsExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo);
HKEY MsGetRootKeyFromInt(UINT root);
NT_API *MsLoadNtApiFunctions();
void MsFreeNtApiFunctions(NT_API *nt);
void MsDestroyDevInfo(HDEVINFO info);
HDEVINFO MsGetDevInfoFromDeviceId(SP_DEVINFO_DATA *dev_info_data, char *device_id);
bool MsStartDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
bool MsStopDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
bool MsDeleteDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
bool MsIsDeviceRunning(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
void CALLBACK MsServiceDispatcher(DWORD argc, LPTSTR *argv);
void CALLBACK MsServiceHandler(DWORD opcode);
bool MsServiceStopProc();
void MsServiceStoperMainThread(THREAD *t, void *p);
void MsServiceStarterMainThread(THREAD *t, void *p);
LRESULT CALLBACK MsUserModeWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
bool MsShowIconOnTray(HWND hWnd, HICON icon, wchar_t *tooltip, UINT msg);
void MsRestoreIconOnTray();
void MsChangeIconOnTray(HICON icon, wchar_t *tooltip);
bool MsChangeIconOnTrayEx(HICON icon, wchar_t *tooltip, wchar_t *info_title, wchar_t *info, UINT info_flags, bool add);
void MsHideIconOnTray();
void MsUserModeTrayMenu(HWND hWnd);
bool MsAppendMenu(HMENU hMenu, UINT flags, UINT_PTR id, wchar_t *str);
bool MsInsertMenu(HMENU hMenu, UINT pos, UINT flags, UINT_PTR id_new_item, wchar_t *lp_new_item);
bool CALLBACK MsEnumChildWindowProc(HWND hWnd, LPARAM lParam);
BOOL CALLBACK EnumTopWindowProc(HWND hWnd, LPARAM lParam);
bool CALLBACK MsEnumThreadWindowProc(HWND hWnd, LPARAM lParam);
HANDLE MsCreateUserToken();
SID *MsGetSidFromAccountName(char *name);
void MsFreeSid(SID *sid);
bool CALLBACK MsEnumResourcesInternalProc(HMODULE hModule, const char *type, char *name, LONG_PTR lParam);
void CALLBACK MsScmDispatcher(DWORD argc, LPTSTR *argv);
LRESULT CALLBACK MsSuspendHandlerWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
void MsSuspendHandlerThreadProc(THREAD *thread, void *param);



#endif	// SECLIB_INTERNAL


#endif	// OS_WIN32


// Global variables
extern bool g_memcheck;
extern bool g_debug;
extern char *cmdline;
extern wchar_t *uni_cmdline;
extern bool g_little_endian;
extern LOCK *tick_manual_lock;

// Kernel state
#define	NUM_KERNEL_STATUS	128
extern UINT64 kernel_status[NUM_KERNEL_STATUS];
extern UINT64 kernel_status_max[NUM_KERNEL_STATUS];
extern LOCK *kernel_status_lock[NUM_KERNEL_STATUS];
extern BOOL kernel_status_inited;

// Kernel state operation macro
#define	KS_LOCK(id)		LockKernelStatus(id)
#define	KS_UNLOCK(id)	UnlockKernelStatus(id)
#define	KS_GET64(id)	(kernel_status[id])
#define	KS_GET(id)		((UINT)KS_GET64(id))
#define	KS_GETMAX64(id)	(kernel_status_max[id])
#define	KS_GETMAX(id)	((UINT)KS_GETMAX64(id))

#ifdef	DONT_USE_KERNEL_STATUS
// Disable operations of the kernel status
#define	KS_INC(id)
#define	KS_DEC(id)
#define	KS_ADD(id, n)
#define	KS_SUB(id, n)
#else	// DONT_USE_KERNEL_STATUS
// Enable operations of the kernel status
#define	KS_INC(id)							\
if (kernel_status_inited) {					\
	KS_LOCK(id);							\
	kernel_status[id]++;					\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);							\
}
#define	KS_DEC(id)							\
if (kernel_status_inited) {					\
	KS_LOCK(id);							\
	kernel_status[id]--;					\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);							\
}
#define	KS_ADD(id, n)						\
if (kernel_status_inited) {					\
	KS_LOCK(id);							\
	kernel_status[id] += n;					\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);							\
}
#define	KS_SUB(id, n)						\
if (kernel_status_inited) {					\
	KS_LOCK(id);							\
	kernel_status[id] -= n;					\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);							\
}
#endif	// DONT_USE_KERNEL_STATUS

// Kernel status
// String related
#define	KS_STRCPY_COUNT			0		// number of calls StrCpy
#define	KS_STRLEN_COUNT			1		// number of calls StrLen
#define	KS_STRCHECK_COUNT		2		// number of calls StrCheck
#define	KS_STRCAT_COUNT			3		// number of calls StrCat
#define	KS_FORMAT_COUNT			4		// number of calls Format
// Memory related
#define	KS_MALLOC_COUNT			5		// Number of calls Malloc
#define	KS_REALLOC_COUNT		6		// Number of calls ReAlloc
#define	KS_FREE_COUNT			7		// number of calls Free
#define	KS_TOTAL_MEM_SIZE		8		// The total size of the memory that was allocated so far
#define	KS_CURRENT_MEM_COUNT	9		// Number of memory blocks that are currently reserved
#define	KS_TOTAL_MEM_COUNT		10		// The total number of memory blocks that ware allocated so far
#define	KS_ZERO_COUNT			11		// Number of calls Zero
#define	KS_COPY_COUNT			12		// Number of calls Copy
// Lock related
#define	KS_NEWLOCK_COUNT		13		// Number of calls NewLock
#define	KS_DELETELOCK_COUNT		14		// Number of calls DeleteLock
#define	KS_LOCK_COUNT			15		// Number of calls Lock
#define	KS_UNLOCK_COUNT			16		// Number of calls Unlock
#define	KS_CURRENT_LOCK_COUNT	17		// Current number of LOCK objects
#define	KS_CURRENT_LOCKED_COUNT	18		// Current number of locked LOCK objects
// Counter information
#define	KS_NEW_COUNTER_COUNT	19		// Number of calls NewCounter
#define	KS_DELETE_COUNTER_COUNT	20		// Number of calls DeleteCounter
#define	KS_INC_COUNT			21		// Number of calls Inc
#define	KS_DEC_COUNT			22		// Number of calls Dec
#define	KS_CURRENT_COUNT		23		// Current total number of counts
// Reference counter information
#define	KS_NEWREF_COUNT			24		// Number of calls NewRef
#define	KS_FREEREF_COUNT		72		// Number of times REF objects are deleted
#define	KS_ADDREF_COUNT			25		// Number of calls AddRef
#define	KS_RELEASE_COUNT		26		// Number of calls Release
#define	KS_CURRENT_REF_COUNT	27		// Current number of REF objects
#define	KS_CURRENT_REFED_COUNT	28		// The sum of the current number of references
// Buffer information
#define	KS_NEWBUF_COUNT			29		// Number of calls NewBuf
#define	KS_FREEBUF_COUNT		30		// NNumber of calls FreeBuf
#define	KS_CURRENT_BUF_COUNT	31		// Current number of objects in the BUF
#define	KS_READ_BUF_COUNT		32		// Number of calls ReadBuf
#define	KS_WRITE_BUF_COUNT		33		// Number of calls WriteBuf
#define	KS_ADJUST_BUFSIZE_COUNT	34		// Number of times to adjust the buffer size
#define	KS_SEEK_BUF_COUNT		35		// Number of calls SeekBuf
// FIFO information
#define	KS_NEWFIFO_COUNT		36		// Number of calls NewFifo
#define	KS_FREEFIFO_COUNT		37		// Number of times the FIFO object is deleted
#define	KS_READ_FIFO_COUNT		38		// Number of calls ReadFifo
#define	KS_WRITE_FIFO_COUNT		39		// Number of calls WriteFifo
#define	KS_PEEK_FIFO_COUNT		40		// Number of calls PeekFifo
// List related
#define	KS_NEWLIST_COUNT		41		// Number of calls NewList
#define	KS_FREELIST_COUNT		42		// Number of times the object LIST was deleted
#define	KS_INSERT_COUNT			43		// Number of calls Add
#define	KS_DELETE_COUNT			44		// Number of calls Delete
#define	KS_SORT_COUNT			45		// Number of calls Sort
#define	KS_SEARCH_COUNT			46		// Number of calls Search
#define	KS_TOARRAY_COUNT		47		// Number of calls ToArray
// Queue related
#define	KS_NEWQUEUE_COUNT		48		// Number of calls NewQueue
#define	KS_FREEQUEUE_COUNT		49		// Number of times you delete the object QUEUE
#define	KS_PUSH_COUNT			50		// Number of calls Push
#define	KS_POP_COUNT			51		// Number of calls POP
// Stack related
#define	KS_NEWSK_COUNT			52		// Number of calls NewSk
#define	KS_FREESK_COUNT			53		// Number of times you delete the object SK
#define	KS_INSERT_QUEUE_COUNT	54		// Number of calls InsertQueue
#define	KS_GETNEXT_COUNT		55		// Number of calls GetNext
// Kernel related
#define	KS_GETTIME_COUNT		56		// Number of times to get the time
#define	KS_GETTICK_COUNT		57		// Number of times to get the system timer
#define	KS_NEWTHREAD_COUNT		58		// Number of calls NewThread
#define	KS_FREETHREAD_COUNT		59		// Number of times you delete the object THREAD
#define	KS_WAITFORTHREAD_COUNT	60		// Number of calls WaitForThread
#define	KS_NEWEVENT_COUNT		61		// Number of calls NewEvent
#define	KS_FREEEVENT_COUNT		62		// Number of times which EVENT object is deleted
#define	KS_WAIT_COUNT			63		// Number of calls Wait
#define	KS_SLEEPTHREAD_COUNT	64		// Number of calls SleepThread
// About IO
#define	KS_IO_OPEN_COUNT		65		// Number of times to open the file
#define	KS_IO_CREATE_COUNT		66		// Number of times that the file was created
#define	KS_IO_CLOSE_COUNT		67		// Number of times to close the file
#define	KS_IO_READ_COUNT		68		// Number of times to read from the file
#define	KS_IO_WRITE_COUNT		69		// Number of times to write to a file
#define	KS_IO_TOTAL_READ_SIZE	70		// Total number of bytes read from the file
#define	KS_IO_TOTAL_WRITE_SIZE	71		// The total number of bytes written to the file
// Memory pool related
#define	KS_MEMPOOL_MALLOC_COUNT	75		// Number of times to allocate the memory pool
#define	KS_MEMPOOL_FREE_COUNT	73		// Number of times you release the memory pool
#define	KS_MEMPOOL_CURRENT_NUM	74		// Current number of the memory pool
#define	KS_MEMPOOL_REALLOC_COUNT	76	// Number of times you have realloc the memory pool


// Macro
#define	IsDebug()		(g_debug)		// A debug mode
#define	IsMemCheck()	(g_memcheck)	// Memory check mode

// Function prototype
void InitMayaqua(bool memcheck, bool debug, int argc, char **argv);
void FreeMayaqua();
bool IsNt();
bool IsUnicode();
void MayaquaDotNetMode();
bool MayaquaIsDotNetMode();
void MayaquaMinimalMode();
bool MayaquaIsMinimalMode();
bool Is64();
bool Is32();
bool IsIA64();
bool IsX64();
void InitKernelStatus();
void FreeKernelStatus();
void PrintDebugInformation();
void LockKernelStatus(UINT id);
void UnlockKernelStatus(UINT id);
void PrintKernelStatus();
void InitCommandLineStr(int argc, char **argv);
void FreeCommandLineStr();
void SetCommandLineStr(char *str);
void SetCommandLineUniStr(wchar_t *str);
char *GetCommandLineStr();
wchar_t *GetCommandLineUniStr();
void ParseCommandLineTokens();
void FreeCommandLineTokens();
TOKEN_LIST *GetCommandLineToken();
UNI_TOKEN_LIST *GetCommandLineUniToken();
void InitOsInfo();
void FreeOsInfo();
void Alert(char *msg, char *caption);
void AlertW(wchar_t *msg, wchar_t *caption);
OS_INFO *GetOsInfo();
UINT GetOsType();
void PrintOsInfo(OS_INFO *info);
void CheckEndian();
void CheckUnixTempDir();
void TimeCheck();
void SetHamMode();
bool IsHamMode();
void InitProbe();
void FreeProbe();
void EnableProbe(bool enable);
bool IsProbeEnabled();
void WriteProbe(char *filename, UINT line, char *str);
void WriteProbeData(char *filename, UINT line, char *str, void *data, UINT size);
USHORT CalcChecksum16(void *buf, UINT size);


#ifdef	OS_WIN32
// Import library (for Win32)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

// OpenSSL
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "zlib.lib")
#endif	// OS_WIN32



// Switches
#if	defined(OS_UNIX) || (_MSC_VER >= 1900)
#define SECLIB_SW_USE_NEW_WCSTOK
#endif


#endif // SECLIB_H



//////////////////////////////////////////////////////////////////////////
// Cedar


// Version number
#define	CEDAR_VER					425

// Build Number
#define	CEDAR_BUILD					9656

// Beta number
//#define	BETA_NUMBER					3

// RC or not
#define	RELEASE_CANDIDATE

// Specify the name of the person in charge building
#ifndef	BUILDER_NAME
#define	BUILDER_NAME		"yagi"
#endif	// BUILDER_NAME

// Specify the location to build
#ifndef	BUILD_PLACE
#define	BUILD_PLACE			"pc33"
#endif	// BUILD_PLACE

// Specifies the build date
#define	BUILD_DATE_Y		2018
#define	BUILD_DATE_M		1
#define	BUILD_DATE_D		15
#define	BUILD_DATE_HO		9
#define	BUILD_DATE_MI		33
#define	BUILD_DATE_SE		22

// Tolerable time difference
#define	ALLOW_TIMESTAMP_DIFF		(UINT64)(3 * 24 * 60 * 60 * 1000)


// Configuration of communication related control switch
#define	USE_DOS_ATTACK_DETECTION		// Enable the DOS attack detection
//#define	USE_SECURE_PACKET				// Enable the scrambled packet

// Designate the IDS detection signatures
#define	CEDAR_SIGNATURE_STR			"SE-VPN4-PROTOCOL"

// Default RSA certificate name of the smart card
#define	SECURE_DEFAULT_CERT_NAME	"VPN_RSA_CERT"

// Default RSA private key name of the smart card
#define	SECURE_DEFAULT_KEY_NAME		"VPN_RSA_KEY"

// Hidden password string of 8 characters
#define	HIDDEN_PASSWORD				"********"


//////////////////////////////////////////////////////////////////////
// 
// Definition of the maximum length of various string
// 
//////////////////////////////////////////////////////////////////////

#define	MAX_ACCOUNT_NAME_LEN		255		// Maximum account name length
#define	MAX_USERNAME_LEN			255		// User name maximum length
#define	MAX_PASSWORD_LEN			255		// Password name maximum length
#define	MAX_PROXY_USERNAME_LEN		255		// Proxy user name maximum length
#define	MAX_PROXY_PASSWORD_LEN		255		// Proxy Password maximum length
#define	MAX_SERVER_STR_LEN			255		// Maximum length of server string
#define	MAX_CLIENT_STR_LEN			255		// Maximum length of client string
#define	MAX_HUBNAME_LEN				255		// Maximum length of HUB name
#define	MAX_SESSION_NAME_LEN		255		// Session name maximum length
#define	MAX_CONNECTION_NAME_LEN		255		// Maximum length of connection name
#define	MAX_DEVICE_NAME_LEN			31		// Device name maximum length
#define	MAX_DEVICE_NAME_LEN_9X		4		// Maximum length of Virtual LAN card name in Win9x
#define	MAX_ACCESSLIST_NOTE_LEN		255		// Maximum length of the note of access list entry
#define	MAX_SECURE_DEVICE_FILE_LEN	255		// Secure device file name maximum length
#define	MAX_ADMIN_OPTION_NAME_LEN	63		// Management option name
#define	MAX_REDIRECT_URL_LEN		255		// URL length to redirect


//////////////////////////////////////////////////////////////////////
// 
// Server and session management related constants
// 
//////////////////////////////////////////////////////////////////////

#define	SERVER_MAX_SESSIONS			4096	// Maximum number of sessions that the server supports
#define SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION	100000	// Maximum number of sessions that the server supports (Carrier Edition)
#define	NAT_MAX_SESSIONS			4096	// Maximum number of sessions that are supported by NAT
#define	NAT_MAX_SESSIONS_KERNEL		65536	// Maximum number of sessions that are supported by NAT (In the case of kernel-mode NAT)
#define	MAX_HUBS					4096	// The maximum number of virtual HUB
#define MAX_HUBS_FOR_CARRIER_EDITION	100000	// The maximum number of virtual HUB (Carrier Edition)
#define	MAX_ACCESSLISTS				(4096 * 8)	// Maximum number of access list entries
#define	MAX_USERS					10000	// The maximum number of users
#define	MAX_GROUPS					10000	// Maximum number of groups
#define	MAX_MAC_TABLES				VPN_GP(GP_MAX_MAC_TABLES, 65536)	// Maximum number of MAC address table entries
#define	MAX_IP_TABLES				VPN_GP(GP_MAX_IP_TABLES, 65536)	// Maximum number of IP address table entries
#define	MAX_HUB_CERTS				4096	// Maximum number of Root CA that can be registered
#define	MAX_HUB_CRLS				4096	// Maximum number of CRL that can be registered
#define	MAX_HUB_ACS					4096	// Maximum number of AC that can be registered
#define	MAX_HUB_LINKS				VPN_GP(GP_MAX_HUB_LINKS, 1024)	// Maximum number of Cascade that can be registered
#define	MAX_HUB_ADMIN_OPTIONS		4096	// Maximum number of Virtual HUB management options that can be registered

#ifndef	USE_STRATEGY_LOW_MEMORY
#define	MEM_FIFO_REALLOC_MEM_SIZE	VPN_GP(GP_MEM_FIFO_REALLOC_MEM_SIZE, (65536 * 10))
#define	QUEUE_BUDGET				VPN_GP(GP_QUEUE_BUDGET, 2048)
#define	FIFO_BUDGET					VPN_GP(GP_FIFO_BUDGET, 1600 * 1600 * 4)
#else	// USE_STRATEGY_LOW_MEMORY
#define	MEM_FIFO_REALLOC_MEM_SIZE	VPN_GP(GP_MEM_FIFO_REALLOC_MEM_SIZE, (65536))
#define	QUEUE_BUDGET				VPN_GP(GP_QUEUE_BUDGET, 1024)
#define	FIFO_BUDGET					VPN_GP(GP_FIFO_BUDGET, 1000000)
#endif	// USE_STRATEGY_LOW_MEMORY

#define	MAX_PACKET_SIZE				1600	// Maximum packet size
#define	UDP_BUF_SIZE				(32 * 1024) // Aim of the UDP packet size

#ifndef	USE_STRATEGY_LOW_MEMORY
#define	MAX_SEND_SOCKET_QUEUE_SIZE	VPN_GP(GP_MAX_SEND_SOCKET_QUEUE_SIZE, (1600 * 1600 * 1))	// Maximum transmit queue size
#define	MIN_SEND_SOCKET_QUEUE_SIZE	VPN_GP(GP_MIN_SEND_SOCKET_QUEUE_SIZE, (1600 * 200 * 1))	// Minimum transmit queue size
#define	MAX_STORED_QUEUE_NUM		VPN_GP(GP_MAX_STORED_QUEUE_NUM, 1024)		// The number of queues that can be stored in each session
#define	MAX_BUFFERING_PACKET_SIZE	VPN_GP(GP_MAX_BUFFERING_PACKET_SIZE, (1600 * 1600))	// Maximum packet size can be buffered
#else	// USE_STRATEGY_LOW_MEMORY
#define	MAX_SEND_SOCKET_QUEUE_SIZE	VPN_GP(GP_MAX_SEND_SOCKET_QUEUE_SIZE, (1600 * 200 * 1))	// Maximum transmit queue size
#define	MIN_SEND_SOCKET_QUEUE_SIZE	VPN_GP(GP_MIN_SEND_SOCKET_QUEUE_SIZE, (1600 * 50 * 1))	// Minimum transmit queue size
#define	MAX_STORED_QUEUE_NUM		VPN_GP(GP_MAX_STORED_QUEUE_NUM, 384)		// The number of queues that can be stored in each session
#define	MAX_BUFFERING_PACKET_SIZE	VPN_GP(GP_MAX_BUFFERING_PACKET_SIZE, (1600 * 300 * 1))	// Maximum packet size can be buffered
#endif	// USE_STRATEGY_LOW_MEMORY

#define	MAX_SEND_SOCKET_QUEUE_NUM	VPN_GP(GP_MAX_SEND_SOCKET_QUEUE_NUM, 128)		// Maximum number of transmission queue items per processing
#define	MAX_TCP_CONNECTION			32		// The maximum number of TCP connections
#define	NUM_TCP_CONNECTION_FOR_UDP_RECOVERY	2	// Maximum number of connections when using UDP recovery
#define	SELECT_TIME					VPN_GP(GP_SELECT_TIME, 256)
#define	SELECT_TIME_FOR_NAT			VPN_GP(GP_SELECT_TIME_FOR_NAT, 30)
#define	SELECT_TIME_FOR_DELAYED_PKT	1		// If there is a delayed packet

#define	TIMEOUT_MIN					(5 * 1000)	// Minimum timeout in seconds
#define	TIMEOUT_MAX					(60 * 1000)	// Maximum timeout in seconds
#define	TIMEOUT_DEFAULT				(30 * 1000) // Default number of seconds to timeout
#define	CONNECTING_TIMEOUT			(15 * 1000)	// Timeout in seconds of being connected
#define	CONNECTING_TIMEOUT_PROXY	(4 * 1000)	// Timeout in seconds of being connected (Proxy)
#define	CONNECTING_POOLING_SPAN		(3 * 1000) // Polling interval of connected
#define	MIN_RETRY_INTERVAL			(5 * 1000)		// Minimum retry interval
#define	MAX_RETRY_INTERVAL			(300 * 1000)	// Maximum retry interval
#define	RETRY_INTERVAL_SPECIAL		(60 * 1000)		// Reconnection interval of a special case

#define	MAX_ADDITONAL_CONNECTION_FAILED_COUNTER	16	// Allowable number that can be serially failed to additional connection
#define	ADDITIONAL_CONNECTION_COUNTER_RESET_INTERVAL	(30 * 60 * 1000)	// Reset period of additional connection failure counter

#define	MAC_MIN_LIMIT_COUNT			3		// Minimum number of MAC addresses
#define	IP_MIN_LIMIT_COUNT			4		// Number of IPv4 addresses minimum
#define	IP_MIN_LIMIT_COUNT_V6		5		// Number of IPv6 addresses minimum
#define	IP_LIMIT_WHEN_NO_ROUTING_V6	15		// Maximum number of IPv6 addresses when NoRouting policy is enabled

#define	MAC_TABLE_EXCLUSIVE_TIME	(13 * 1000)			// Period that can occupy the MAC address
#define	IP_TABLE_EXCLUSIVE_TIME		(13 * 1000)			// Period that can occupy the IP address
#define	MAC_TABLE_EXPIRE_TIME		VPN_GP(GP_MAC_TABLE_EXPIRE_TIME, (600 * 1000))			// MAC address table expiration time
#define	IP_TABLE_EXPIRE_TIME		VPN_GP(GP_IP_TABLE_EXPIRE_TIME, (60 * 1000))			// IP address table expiration time
#define	IP_TABLE_EXPIRE_TIME_DHCP	VPN_GP(GP_IP_TABLE_EXPIRE_TIME_DHCP, (5 * 60 * 1000))		// IP address table expiration time (In the case of DHCP)
#define	HUB_ARP_SEND_INTERVAL		VPN_GP(GP_HUB_ARP_SEND_INTERVAL, (5 * 1000))			// ARP packet transmission interval (alive check)

#define	LIMITER_SAMPLING_SPAN		1000	// Sampling interval of the traffic limiting device

#define	STORM_CHECK_SPAN			VPN_GP(GP_STORM_CHECK_SPAN, 500)		// Broadcast storm check interval
#define	STORM_DISCARD_VALUE_START	VPN_GP(GP_STORM_DISCARD_VALUE_START, 3)		// Broadcast packet discard value start value
#define	STORM_DISCARD_VALUE_END		VPN_GP(GP_STORM_DISCARD_VALUE_END, 1024)	// Broadcast packet discard value end value

#define	KEEP_INTERVAL_MIN			5		// Packet transmission interval minimum value
#define	KEEP_INTERVAL_DEFAULT		50		// Packet transmission interval default value
#define	KEEP_INTERVAL_MAX			600		// Packet transmission interval maximum value
#define KEEP_TCP_TIMEOUT			1000	// TCP time-out value

#define	TICKET_EXPIRES				(60 * 1000)	// Expiration date of ticket

#define	SEND_KILL_NUM_X				256			// Number of 'X' characters to send the Kill


#define	FARM_BASE_POINT				100000		// Reference value of the cluster score
#define	FARM_DEFAULT_WEIGHT			100			// Standard performance ratio



#define	SE_UDP_SIGN			"SE2P"		// Not used (only old UDP mode)

// R-UDP service name
#define	VPN_RUDP_SVC_NAME		"SoftEther_VPN"

// Traffic information update interval
#define	INCREMENT_TRAFFIC_INTERVAL		(10 * 1000)

// State of the client session
#define	CLIENT_STATUS_CONNECTING	0		// Connecting
#define	CLIENT_STATUS_NEGOTIATION	1		// Negotiating
#define	CLIENT_STATUS_AUTH			2		// During user authentication
#define	CLIENT_STATUS_ESTABLISHED	3		// Connection complete
#define	CLIENT_STATUS_RETRY			4		// Wait to retry
#define	CLIENT_STATUS_IDLE			5		// Idle state

// Expiration date of the black list
#define	BLACK_LIST_EXPIRES			(30 * 10000)

// Number Blacklist entries
#define	MAX_BLACK_LIST				4096
#define	BLACK_LIST_CHECK_SPAN		1000

// Blocks to be transmitted at one during the file transfer
#define	FTP_BLOCK_SIZE				(640 * 1024)

// Syslog configuration
#define SYSLOG_NONE							0		// Do not use syslog
#define SYSLOG_SERVER_LOG					1		// Only server log
#define SYSLOG_SERVER_AND_HUB_SECURITY_LOG	2		// Server and Virtual HUB security log
#define SYSLOG_SERVER_AND_HUB_ALL_LOG		3		// Server, Virtual HUB security, and packet log

#define SYSLOG_PORT					514			// Syslog port number
#define SYSLOG_POLL_IP_INTERVAL		(UINT64)(3600 * 1000)	// Interval to examine the IP address
#define	SYSLOG_POLL_IP_INTERVAL_NG	(UINT64)(60 * 1000)	// Interval to examine the IP address (previous failure)

//////////////////////////////////////////////////////////////////////
// 
// Connection-related constant
// 
//////////////////////////////////////////////////////////////////////

// Internet connection maintenance function (KeepAlive)

#define	KEEP_RETRY_INTERVAL		(60 * 1000)			// Reconnection interval on connection failure
#define	KEEP_MIN_PACKET_SIZE	1					// Minimum packet size
#define	KEEP_MAX_PACKET_SIZE	128					// Maximum packet size
#define	KEEP_POLLING_INTERVAL	250					// KEEP polling interval

// Constants
#define	RECV_BUF_SIZE				65536			// Buffer size to be received at a time

// Type of proxy
#define	PROXY_DIRECT			0	// Direct TCP connection
#define	PROXY_HTTP				1	// Connection via HTTP proxy server
#define	PROXY_SOCKS				2	// Connection via SOCKS proxy server

// Direction of data flow
#define	TCP_BOTH				0	// Bi-directional
#define	TCP_SERVER_TO_CLIENT	1	// Only server -> client direction
#define	TCP_CLIENT_TO_SERVER	2	// Only client -> server direction

// Type of connection
#define	CONNECTION_TYPE_CLIENT			0	// Client
#define	CONNECTION_TYPE_INIT			1	// During initialization
#define	CONNECTION_TYPE_LOGIN			2	// Login connection
#define	CONNECTION_TYPE_ADDITIONAL		3	// Additional connection
#define	CONNECTION_TYPE_FARM_RPC		4	// RPC for server farm
#define	CONNECTION_TYPE_ADMIN_RPC		5	// RPC for Management
#define	CONNECTION_TYPE_ENUM_HUB		6	// HUB enumeration
#define	CONNECTION_TYPE_PASSWORD		7	// Password change
#define	CONNECTION_TYPE_SSTP			8	// SSTP
#define	CONNECTION_TYPE_OPENVPN			9	// OpenVPN

// Protocol
#define	CONNECTION_TCP					0	// TCP protocol
#define	CONNECTION_UDP					1	// UDP protocol
#define	CONNECTION_HUB_LAYER3			6	// Layer-3 switch session
#define	CONNECTION_HUB_BRIDGE			7	// Bridge session
#define	CONNECTION_HUB_SECURE_NAT		8	// Secure NAT session
#define	CONNECTION_HUB_LINK_SERVER		9	// HUB link session


// Status
#define	CONNECTION_STATUS_ACCEPTED		0	// The connection is accepted (client side)
#define	CONNECTION_STATUS_NEGOTIATION	1	// Negotiating
#define	CONNECTION_STATUS_USERAUTH		2	// During user authentication
#define	CONNECTION_STATUS_ESTABLISHED	3	// Connection has been established
#define	CONNECTION_STATUS_CONNECTING	0	// Connecting (client side)

// Magic number of KeepAlive packet
#define	KEEP_ALIVE_MAGIC				0xffffffff
#define	MAX_KEEPALIVE_SIZE				512



//////////////////////////////////////////////////////////////////////
// 
// Virtual HUB-related constant
// 
//////////////////////////////////////////////////////////////////////

#define	SE_HUB_MAC_ADDR_SIGN				0xAE					// Sign virtual HUB MAC address

// Traffic difference value
#define	TRAFFIC_DIFF_USER		0		// User
#define	TRAFFIC_DIFF_HUB		1		// Virtual HUB
#define	MAX_TRAFFIC_DIFF		30000	// Maximum number of items

// Type of HUB
#define	HUB_TYPE_STANDALONE			0	// Stand-alone HUB
#define	HUB_TYPE_FARM_STATIC		1	// Static HUB
#define	HUB_TYPE_FARM_DYNAMIC		2	// Dynamic HUB

// Related to delay, jitter, packet loss in the access list
#define	HUB_ACCESSLIST_DELAY_MAX	10000		// Maximum delay
#define	HUB_ACCESSLIST_JITTER_MAX	100			// Maximum jitter
#define	HUB_ACCESSLIST_LOSS_MAX		100			// Maximum packet loss

// Message related
#define	HUB_MAXMSG_LEN				20000		// The maximum number of characters in a message



//////////////////////////////////////////////////////////////////////
// 
// Type of user authentication
// 
//////////////////////////////////////////////////////////////////////

// Constant in the server-side
#define	AUTHTYPE_ANONYMOUS				0			// Anonymous authentication
#define	AUTHTYPE_PASSWORD				1			// Password authentication
#define	AUTHTYPE_USERCERT				2			// User certificate authentication
#define	AUTHTYPE_ROOTCERT				3			// Root certificate which is issued by trusted Certificate Authority
#define	AUTHTYPE_RADIUS					4			// Radius authentication
#define	AUTHTYPE_NT						5			// Windows NT authentication
#define	AUTHTYPE_TICKET					99			// Ticket authentication

// Constant of the client side
#define	CLIENT_AUTHTYPE_ANONYMOUS		0			// Anonymous authentication
#define	CLIENT_AUTHTYPE_PASSWORD		1			// Password authentication
#define	CLIENT_AUTHTYPE_PLAIN_PASSWORD	2			// Plain password authentication
#define	CLIENT_AUTHTYPE_CERT			3			// Certificate authentication
#define	CLIENT_AUTHTYPE_SECURE			4			// Secure device authentication



//////////////////////////////////////////////////////////////////////
// 
// TCP listener related constants
// 
//////////////////////////////////////////////////////////////////////

// Retries in case it fails to Listen
#define	LISTEN_RETRY_TIME			(2 * 1000)		// If fail to Listen normally
#define LISTEN_RETRY_TIME_NOIPV6	(60 * 1000)		// If IPv6 support is disabled

#define	DOS_TABLE_EXPIRES_FIRST		250				// Initial value of the expiration date of DOS attack list
#define	DOS_TABLE_EXPIRES_MAX		1000			// Maximum value of the expiration date of DOS attack list
#define	DOS_TABLE_REFRESH_INTERVAL	(10 * 1000)		// Interval to update the DOS attack list
#define	DOS_TABLE_MAX_LIMIT_PER_IP	16				// Accessible number per an IP
#define	DOS_TABLE_EXPIRES_TOTAL		(3000 * 1000)	// Time to force delete the entry


// Protocol to be used for the listener
#define	LISTENER_TCP				0		// TCP/IP
#define	LISTENER_UDP				1		// UDP/IP (not being used)
#define	LISTENER_INPROC				2		// In-process communication
#define	LISTENER_RUDP				3		// R-UDP with NAT-T
#define	LISTENER_ICMP				4		// VPN over ICMP
#define	LISTENER_DNS				5		// VPN over DNS
#define	LISTENER_REVERSE			6		// Reverse socket

// Status of the listener
#define	LISTENER_STATUS_TRYING		0		// While attempting
#define	LISTENER_STATUS_LISTENING	1		// Listening

// Largest packet size of UDP
#define	UDP_PACKET_SIZE				65536

// Number of standard connections per IP address
#define DEFAULT_MAX_CONNECTIONS_PER_IP	256
#define MIN_MAX_CONNECTIONS_PER_IP	10		// Minimum value

// Allowed number of outstanding connections
#define	DEFAULT_MAX_UNESTABLISHED_CONNECTIONS	1000
#define	MIN_MAX_UNESTABLISHED_CONNECTIONS	30	// Minimum value


//////////////////////////////////////////////////////////////////////
// 
// Log related constant
// 
//////////////////////////////////////////////////////////////////////

#define	LOG_ENGINE_SAVE_START_CACHE_COUNT	100000		// Number to start saving forcibly
#define	LOG_ENGINE_BUFFER_CACHE_SIZE_MAX	(10 * 1024 * 1024)	// Write cache size

// Constant such as a file name
#define	SERVER_LOG_DIR_NAME			"@server_log"
#define	BRIDGE_LOG_DIR_NAME			SERVER_LOG_DIR_NAME
#define	SERVER_LOG_PERFIX			"vpn"

#define	HUB_SECURITY_LOG_DIR_NAME	"@security_log"
#define	HUB_SECURITY_LOG_FILE_NAME	"@security_log/%s"
#define	HUB_SECURITY_LOG_PREFIX		"sec"
#define	HUB_PACKET_LOG_DIR_NAME		"@packet_log"
#define	HUB_PACKET_LOG_FILE_NAME	"@packet_log/%s"
#define	HUB_PACKET_LOG_PREFIX		"pkt"

#define	NAT_LOG_DIR_NAME			"@secure_nat_log"
#define	NAT_LOG_FILE_NAME			"@secure_nat_log/%s"
#define	NAT_LOG_PREFIX				"snat"

#define	CLIENT_LOG_DIR_NAME			"@client_log"
#define	CLIENT_LOG_PREFIX			"client"

// Packet log settings
#define	NUM_PACKET_LOG				16
#define	PACKET_LOG_TCP_CONN			0		// TCP connection log
#define	PACKET_LOG_TCP				1		// TCP packet log
#define	PACKET_LOG_DHCP				2		// DHCP Log
#define	PACKET_LOG_UDP				3		// UDP log
#define	PACKET_LOG_ICMP				4		// ICMP log
#define	PACKET_LOG_IP				5		// IP log
#define	PACKET_LOG_ARP				6		// ARP log
#define	PACKET_LOG_ETHERNET			7		// Ethernet log

#define	PACKET_LOG_NONE				0		// Not save
#define	PACKET_LOG_HEADER			1		// Only header
#define	PACKET_LOG_ALL				2		// Store also data

// Timing of log switching
#define	LOG_SWITCH_NO				0		// No switching
#define	LOG_SWITCH_SECOND			1		// Secondly basis
#define	LOG_SWITCH_MINUTE			2		// Minutely basis
#define	LOG_SWITCH_HOUR				3		// Hourly basis
#define	LOG_SWITCH_DAY				4		// Daily basis
#define	LOG_SWITCH_MONTH			5		// Monthly basis

// Minimum amount of free disk space
#define	DISK_FREE_SPACE_MIN			1048576	// 1 MBytes
#define	DISK_FREE_SPACE_DEFAULT		(DISK_FREE_SPACE_MIN * 100)	// 100 Mbytes
#define	DISK_FREE_SPACE_DEFAULT_WINDOWS	((UINT64)(8ULL * 1024ULL * 1024ULL * 1024ULL))	// 8GBytes

// Interval to check the free space
#define	DISK_FREE_CHECK_INTERVAL_DEFAULT	(5 * 60 * 1000)

// Simple log
#define TINY_LOG_DIRNAME			"@tiny_log"
#define TINY_LOG_FILENAME			"@tiny_log/%04u%02u%02u_%02u%02u%02u.log"


//////////////////////////////////////////////////////////////////////
// 
// Constant related to Carrier Edition
// 
//////////////////////////////////////////////////////////////////////

#define CE_SNAPSHOT_INTERVAL		((UINT64)(3600 * 1000))
//#define CE_SNAPSHOT_INTERVAL		((UINT64)(3000))
#define CE_SNAPSHOT_POLLING_INTERVAL	(1 * 1000)
#define CE_SNAPSHOT_POLLING_INTERVAL_LICENSE	(30 * 1000)
#define CE_SNAPSHOT_DIR_NAME		"@carrier_log"
#define CE_SNAPSHOT_PREFIX			"carrier"


//////////////////////////////////////////////////////////////////////
// 
// Communication protocol related constant
// 
//////////////////////////////////////////////////////////////////////

// Administrator Username
#define	ADMINISTRATOR_USERNAME		"administrator"
// Maximum value of random size
#define	RAND_SIZE_MAX				4096
// Expiration date of random size cache
#define	RAND_SIZE_CACHE_EXPIRE		(24 * 60 * 60 * 1000)
// Management allowed IP address list file name
#define	ADMINIP_TXT					"@adminip.txt"

#define NON_SSL_MIN_COUNT			60
#define NON_SSL_ENTRY_EXPIRES		(10 * 60 * 1000)

//////////////////////////////////////////////////////////////////////
// 
// The cascade related constants
// 
//////////////////////////////////////////////////////////////////////

#define	LINK_DEVICE_NAME		"_SEHUBLINKCLI_"
#define	LINK_USER_NAME			"link"
#define	LINK_USER_NAME_PRINT	"Cascade"



//////////////////////////////////////////////////////////////////////
// 
// Constant related to SecureNAT connection
// 
//////////////////////////////////////////////////////////////////////

#define	SNAT_DEVICE_NAME		"_SEHUBSECURENAT_"
#define	SNAT_USER_NAME			"securenat"
#define	SNAT_USER_NAME_PRINT	"SecureNAT"



//////////////////////////////////////////////////////////////////////
// 
// Constant related to bridge connection
// 
//////////////////////////////////////////////////////////////////////

#define	BRIDGE_DEVICE_NAME				"_SEHUBBRIDGE_"
#define	BRIDGE_USER_NAME				"localbridge"
#define	BRIDGE_USER_NAME_PRINT			"Local Bridge"
#define	BRIDGE_TRY_SPAN					1000
#define	BRIDGE_NUM_DEVICE_CHECK_SPAN	(5 * 60 * 1000)
#define BRIDGE_NETWORK_CONNECTION_STR	L"%s [%S]"



//////////////////////////////////////////////////////////////////////
// 
// EtherLogger related constants
// 
//////////////////////////////////////////////////////////////////////

#define	EL_ADMIN_PORT			22888
#define	EL_CONFIG_FILENAME		"@etherlogger.config"
#define	EL_PACKET_LOG_DIR_NAME	"@etherlogger_log"
#define	EL_PACKET_LOG_FILE_NAME	"@etherlogger_log/%s"
#define	EL_PACKET_LOG_PREFIX	"pkt"
#define	EL_LICENSE_CHECK_SPAN	(10 * 1000)



//////////////////////////////////////////////////////////////////////
// 
// Layer-3 Switch related constants
// 
//////////////////////////////////////////////////////////////////////

#define	MAX_NUM_L3_SWITCH		4096
#define	MAX_NUM_L3_IF			4096
#define	MAX_NUM_L3_TABLE		4096



//////////////////////////////////////////////////////////////////////
// 
// Constant related to User-mode Router
// 
//////////////////////////////////////////////////////////////////////

#define	ARP_ENTRY_EXPIRES			(30 * 1000)		// ARP table expiration date
#define	ARP_ENTRY_POLLING_TIME		(1 * 1000)		// ARP table cleaning timer
#define	ARP_REQUEST_TIMEOUT			(1000)			// ARP request time-out period
#define	ARP_REQUEST_GIVEUP			(5 * 1000)		// Time to give up sending the ARP request
#define	IP_WAIT_FOR_ARP_TIMEOUT		(5 * 1000)		// Total time that an IP packet waiting for ARP table
#define	IP_COMBINE_TIMEOUT			(10 * 1000)		// Time-out of IP packet combining
#define	NAT_TCP_MAX_TIMEOUT			(2000000 * 1000)	// Maximum TCP session timeout in seconds
#define	NAT_UDP_MAX_TIMEOUT			(2000000 * 1000)	// Maximum UDP session timeout in seconds
#define	NAT_TCP_MIN_TIMEOUT			(1 * 60 * 1000)		// Minimum TCP session timeout in seconds
#define	NAT_UDP_MIN_TIMEOUT			(10 * 1000)			// Minimum UDP session timeout in seconds
#define	NAT_TCP_RECV_WINDOW_SIZE	64512				// TCP receive window size
#define	NAT_TCP_SYNACK_SEND_TIMEOUT	250					// Sending TCP SYN+ACK interval
#define	NAT_ICMP_TIMEOUT			(10 * 1000)			// ICMP timeout in seconds
#define	NAT_ICMP_TIMEOUT_WITH_API	(3 * 1000)			// Timeout in seconds in the case of using the ICMP API
#define	NAT_SEND_BUF_SIZE			(64 * 1024)			// TCP send buffer size
#define	NAT_RECV_BUF_SIZE			(64 * 1024)			// TCP receive buffer size
#define	NAT_TMPBUF_SIZE				(128 * 1024)		// TCP temporally memory area size
#define	NAT_ACK_KEEPALIVE_SPAN		(5 * 1000)			// ACK transmission interval for TCP keep alive
#define	NAT_INITIAL_RTT_VALUE		500					// Initial RTT value
#define	NAT_FIN_SEND_INTERVAL		1000				// FIN transmission interval
#define	NAT_FIN_SEND_MAX_COUNT		5					// Total number of FIN transmissions
#define	NAT_DNS_PROXY_PORT			53					// DNS proxy port number
#define	NAT_DNS_RESPONSE_TTL		(20 * 60)			// TTL of the DNS response
#define	NAT_DHCP_SERVER_PORT		67					// DHCP server port number
#define	NAT_DHCP_CLIENT_PORT		68					// DHCP client port number
#define	DHCP_MIN_EXPIRE_TIMESPAN	(15 * 1000)			// DHCP minimum expiration date
#define	DHCP_POLLING_INTERVAL		1000				// DHCP polling interval
#define	X32							((UINT64)4294967296ULL)	// 32bit + 1
#define	NAT_DNS_QUERY_TIMEOUT		(512)				// Time-out value of DNS queries

// Beacon transmission interval
#define	BEACON_SEND_INTERVAL		(5 * 1000)

// Total size quota allowed in the queue for the combining the IP packet
#define	IP_COMBINE_WAIT_QUEUE_SIZE_QUOTA	(50 * 1024 * 1024)

// Header size constant
#define	MAC_HEADER_SIZE				(sizeof(MAC_HEADER))
#define	ARP_HEADER_SIZE				(sizeof(ARP_HEADER))
#define	IP_HEADER_SIZE				(sizeof(IPV4_HEADER))
#define	TCP_HEADER_SIZE				(sizeof(TCP_HEADER))
#define	UDP_HEADER_SIZE				(sizeof(UDP_HEADER))

// Data maximum size constant
#define	MAX_L3_DATA_SIZE			(1500)
#define	MAX_IP_DATA_SIZE			(MAX_L3_DATA_SIZE - IP_HEADER_SIZE)
#define	MAX_TCP_DATA_SIZE			(MAX_IP_DATA_SIZE - TCP_HEADER_SIZE)
#define	MAX_UDP_DATA_SIZE			(MAX_IP_DATA_SIZE - UDP_HEADER_SIZE)
#define	MAX_IP_DATA_SIZE_TOTAL		(65535)

// IP packet option constant
#define	DEFAULT_IP_TOS				0				// TOS in the IP header
#define	DEFAULT_IP_TTL				128				// TTL in the IP header

// Type of NAT session
#define	NAT_TCP						0		// TCP NAT
#define	NAT_UDP						1		// UDP NAT
#define	NAT_DNS						2		// DNS NAT
#define	NAT_ICMP					3		// ICMP NAT

// State of NAT session
#define	NAT_TCP_CONNECTING			0		// Connecting
#define	NAT_TCP_SEND_RESET			1		// Send the RST (Connection failure or disconnected)
#define	NAT_TCP_CONNECTED			2		// Connection complete
#define	NAT_TCP_ESTABLISHED			3		// Connection established
#define	NAT_TCP_WAIT_DISCONNECT		4		// Wait for socket disconnection


//////////////////////////////////////////////////////////////////////
// 
// For UNIX virtual LAN card related constant
// 
//////////////////////////////////////////////////////////////////////

#define	TAP_FILENAME_1				"/dev/net/tun"
#define	TAP_FILENAME_2				"/dev/tun"
#ifdef	UNIX_MACOS
#ifdef	NO_VLAN
#define	TAP_MACOS_FILENAME			"/dev/tap0"
#else	// NO_VLAN
#define	TAP_MACOS_FILENAME			"tap"
#endif	// NO_VLAN
#define	TAP_MACOS_DIR				"/dev/"
#define	TAP_MACOS_NUMBER			(16)
#endif	// UNIX_MACOS





#define	LICENSE_EDITION_VPN3_NO_LICENSE					0		// Without license

#define	LICENSE_MAX_PRODUCT_NAME_LEN	255				// Maximum length of license product name
#define	LICENSE_NUM_SHA					10000			// Number of times to hash with SHA
#define	LICENSE_SYSTEM_KEY_NUM			2048			// Key number for system
#define	LICENSE_SYSTEM_KEYSIZE_BIT		144				// Number of key bits for system
#define	LICENSE_PRODUCT_KEY_NUM			16384			// Number of keys for product
#define	LICENSE_PRODUCT_KEYSIZE_BIT		56				// Number of key bits for product
#define	LICENSE_PRODUCT_COMMON_KEYSIZE_BIT	48			// Number of common key bits for product
#define	LICENSE_MASTER_KEYSIZE_BIT		1024			// Number of master key bits
#define	LICENSE_SYSTEM_ID_MIN			0ULL			// System ID minimum value
#define	LICENSE_SYSTEM_ID_MAX			549755813887ULL	// System ID maximum value
#define	LICENSE_SERIAL_ID_MIN			0				// Serial ID minimum value
#define	LICENSE_SERIAL_ID_MAX			65535			// Serial ID maximum value
#define	LICENSE_EXPIRES_MIN				0				// Expiration date minimum
#define	LICENSE_EXPIRES_MAX				16383			// Expiration date maximum
#define	LICENSE_KEYSTR_LEN				41				// Length of the license key
#define	LICENSE_LICENSEID_STR_LEN		33				// Length of the license ID

#define	LICENSE_STATUS_OK				0		// Enabled
#define	LICENSE_STATUS_EXPIRED			1		// Invalid (expired)
#define	LICENSE_STATUS_ID_DIFF			2		// Invalid (System ID mismatch)
#define	LICENSE_STATUS_DUP				3		// Invalid (duplicated)
#define	LICENSE_STATUS_INSUFFICIENT		4		// Invalid (other necessary license shortage)
#define	LICENSE_STATUS_COMPETITION		5		// Invalid (conflict with other licenses)
#define	LICENSE_STATUS_NONSENSE			6		// Invalid (meaningless in the current edition)
#define	LICENSE_STATUS_CPU				7		// Invalid (CPU type mismatch)

#define	BIT_TO_BYTE(x)					(((x) + 7) / 8)
#define	BYTE_TO_BIT(x)					((x) * 8)


//////////////////////////////////////////////////////////////////////
// 
// Error code
// 
//////////////////////////////////////////////////////////////////////

#define	ERR_NO_ERROR					0	// No error
#define	ERR_CONNECT_FAILED				1	// Connection to the server has failed
#define	ERR_SERVER_IS_NOT_VPN			2	// The destination server is not a VPN server
#define	ERR_DISCONNECTED				3	// The connection has been interrupted
#define	ERR_PROTOCOL_ERROR				4	// Protocol error
#define	ERR_CLIENT_IS_NOT_VPN			5	// Connecting client is not a VPN client
#define	ERR_USER_CANCEL					6	// User cancel
#define	ERR_AUTHTYPE_NOT_SUPPORTED		7	// Specified authentication method is not supported
#define	ERR_HUB_NOT_FOUND				8	// The HUB does not exist
#define	ERR_AUTH_FAILED					9	// Authentication failure
#define	ERR_HUB_STOPPING				10	// HUB is stopped
#define	ERR_SESSION_REMOVED				11	// Session has been deleted
#define	ERR_ACCESS_DENIED				12	// Access denied
#define	ERR_SESSION_TIMEOUT				13	// Session times out
#define	ERR_INVALID_PROTOCOL			14	// Protocol is invalid
#define	ERR_TOO_MANY_CONNECTION			15	// Too many connections
#define	ERR_HUB_IS_BUSY					16	// Too many sessions of the HUB
#define	ERR_PROXY_CONNECT_FAILED		17	// Connection to the proxy server fails
#define	ERR_PROXY_ERROR					18	// Proxy Error
#define	ERR_PROXY_AUTH_FAILED			19	// Failed to authenticate on the proxy server
#define	ERR_TOO_MANY_USER_SESSION		20	// Too many sessions of the same user
#define	ERR_LICENSE_ERROR				21	// License error
#define	ERR_DEVICE_DRIVER_ERROR			22	// Device driver error
#define	ERR_INTERNAL_ERROR				23	// Internal error
#define	ERR_SECURE_DEVICE_OPEN_FAILED	24	// The secure device cannot be opened
#define	ERR_SECURE_PIN_LOGIN_FAILED		25	// PIN code is incorrect
#define	ERR_SECURE_NO_CERT				26	// Specified certificate is not stored
#define	ERR_SECURE_NO_PRIVATE_KEY		27	// Specified private key is not stored
#define	ERR_SECURE_CANT_WRITE			28	// Write failure
#define	ERR_OBJECT_NOT_FOUND			29	// Specified object can not be found
#define	ERR_VLAN_ALREADY_EXISTS			30	// Virtual LAN card with the specified name already exists
#define	ERR_VLAN_INSTALL_ERROR			31	// Specified virtual LAN card cannot be created
#define	ERR_VLAN_INVALID_NAME			32	// Specified name of the virtual LAN card is invalid
#define	ERR_NOT_SUPPORTED				33	// Unsupported
#define	ERR_ACCOUNT_ALREADY_EXISTS		34	// Account already exists
#define	ERR_ACCOUNT_ACTIVE				35	// Account is operating
#define	ERR_ACCOUNT_NOT_FOUND			36	// Specified account doesn't exist
#define	ERR_ACCOUNT_INACTIVE			37	// Account is offline
#define	ERR_INVALID_PARAMETER			38	// Parameter is invalid
#define	ERR_SECURE_DEVICE_ERROR			39	// Error has occurred in the operation of the secure device
#define	ERR_NO_SECURE_DEVICE_SPECIFIED	40	// Secure device is not specified
#define	ERR_VLAN_IS_USED				41	// Virtual LAN card in use by account
#define	ERR_VLAN_FOR_ACCOUNT_NOT_FOUND	42	// Virtual LAN card of the account can not be found
#define	ERR_VLAN_FOR_ACCOUNT_USED		43	// Virtual LAN card of the account is already in use
#define	ERR_VLAN_FOR_ACCOUNT_DISABLED	44	// Virtual LAN card of the account is disabled
#define	ERR_INVALID_VALUE				45	// Value is invalid
#define	ERR_NOT_FARM_CONTROLLER			46	// Not a farm controller
#define	ERR_TRYING_TO_CONNECT			47	// Attempting to connect
#define	ERR_CONNECT_TO_FARM_CONTROLLER	48	// Failed to connect to the farm controller
#define	ERR_COULD_NOT_HOST_HUB_ON_FARM	49	// A virtual HUB on farm could not be created
#define	ERR_FARM_MEMBER_HUB_ADMIN		50	// HUB cannot be managed on a farm member
#define	ERR_NULL_PASSWORD_LOCAL_ONLY	51	// Accepting only local connections for an empty password
#define	ERR_NOT_ENOUGH_RIGHT			52	// Right is insufficient
#define	ERR_LISTENER_NOT_FOUND			53	// Listener can not be found
#define	ERR_LISTENER_ALREADY_EXISTS		54	// Listener already exists
#define	ERR_NOT_FARM_MEMBER				55	// Not a farm member
#define	ERR_CIPHER_NOT_SUPPORTED		56	// Encryption algorithm is not supported
#define	ERR_HUB_ALREADY_EXISTS			57	// HUB already exists
#define	ERR_TOO_MANY_HUBS				58	// Too many HUBs
#define	ERR_LINK_ALREADY_EXISTS			59	// Link already exists
#define	ERR_LINK_CANT_CREATE_ON_FARM	60	// The link can not be created on the server farm
#define	ERR_LINK_IS_OFFLINE				61	// Link is off-line
#define	ERR_TOO_MANY_ACCESS_LIST		62	// Too many access list
#define	ERR_TOO_MANY_USER				63	// Too many users
#define	ERR_TOO_MANY_GROUP				64	// Too many Groups
#define	ERR_GROUP_NOT_FOUND				65	// Group can not be found
#define	ERR_USER_ALREADY_EXISTS			66	// User already exists
#define	ERR_GROUP_ALREADY_EXISTS		67	// Group already exists
#define	ERR_USER_AUTHTYPE_NOT_PASSWORD	68	// Authentication method of the user is not a password authentication
#define	ERR_OLD_PASSWORD_WRONG			69	// The user does not exist or the old password is wrong
#define	ERR_LINK_CANT_DISCONNECT		73	// Cascade session cannot be disconnected
#define	ERR_ACCOUNT_NOT_PRESENT			74	// Not completed configure the connection to the VPN server
#define	ERR_ALREADY_ONLINE				75	// It is already online
#define	ERR_OFFLINE						76	// It is offline
#define	ERR_NOT_RSA_1024				77	// The certificate is not RSA 1024bit
#define	ERR_SNAT_CANT_DISCONNECT		78	// SecureNAT session cannot be disconnected
#define	ERR_SNAT_NEED_STANDALONE		79	// SecureNAT works only in stand-alone HUB
#define	ERR_SNAT_NOT_RUNNING			80	// SecureNAT function is not working
#define	ERR_SE_VPN_BLOCK				81	// Stopped by PacketiX VPN Block
#define	ERR_BRIDGE_CANT_DISCONNECT		82	// Bridge session can not be disconnected
#define	ERR_LOCAL_BRIDGE_STOPPING		83	// Bridge function is stopped
#define	ERR_LOCAL_BRIDGE_UNSUPPORTED	84	// Bridge feature is not supported
#define	ERR_CERT_NOT_TRUSTED			85	// Certificate of the destination server can not be trusted
#define	ERR_PRODUCT_CODE_INVALID		86	// Product code is different
#define	ERR_VERSION_INVALID				87	// Version is different
#define	ERR_CAPTURE_DEVICE_ADD_ERROR	88	// Adding capture device failure
#define	ERR_VPN_CODE_INVALID			89	// VPN code is different
#define	ERR_CAPTURE_NOT_FOUND			90	// Capture device can not be found
#define	ERR_LAYER3_CANT_DISCONNECT		91	// Layer-3 session cannot be disconnected
#define	ERR_LAYER3_SW_EXISTS			92	// L3 switch of the same already exists
#define	ERR_LAYER3_SW_NOT_FOUND			93	// Layer-3 switch can not be found
#define	ERR_INVALID_NAME				94	// Name is invalid
#define	ERR_LAYER3_IF_ADD_FAILED		95	// Failed to add interface
#define	ERR_LAYER3_IF_DEL_FAILED		96	// Failed to delete the interface
#define	ERR_LAYER3_IF_EXISTS			97	// Interface that you specified already exists
#define	ERR_LAYER3_TABLE_ADD_FAILED		98	// Failed to add routing table
#define	ERR_LAYER3_TABLE_DEL_FAILED		99	// Failed to delete the routing table
#define	ERR_LAYER3_TABLE_EXISTS			100	// Routing table entry that you specified already exists
#define	ERR_BAD_CLOCK					101	// Time is queer
#define	ERR_LAYER3_CANT_START_SWITCH	102	// The Virtual Layer 3 Switch can not be started
#define	ERR_CLIENT_LICENSE_NOT_ENOUGH	103	// Client connection licenses shortage
#define	ERR_BRIDGE_LICENSE_NOT_ENOUGH	104 // Bridge connection licenses shortage
#define	ERR_SERVER_CANT_ACCEPT			105	// Not Accept on the technical issues
#define	ERR_SERVER_CERT_EXPIRES			106	// Destination VPN server has expired
#define	ERR_MONITOR_MODE_DENIED			107	// Monitor port mode was rejected
#define	ERR_BRIDGE_MODE_DENIED			108	// Bridge-mode or Routing-mode was rejected
#define	ERR_IP_ADDRESS_DENIED			109	// Client IP address is denied
#define	ERR_TOO_MANT_ITEMS				110	// Too many items
#define	ERR_MEMORY_NOT_ENOUGH			111	// Out of memory
#define	ERR_OBJECT_EXISTS				112	// Object already exists
#define	ERR_FATAL						113	// A fatal error occurred
#define	ERR_SERVER_LICENSE_FAILED		114	// License violation has occurred on the server side
#define	ERR_SERVER_INTERNET_FAILED		115	// Server side is not connected to the Internet
#define	ERR_CLIENT_LICENSE_FAILED		116	// License violation occurs on the client side
#define	ERR_BAD_COMMAND_OR_PARAM		117	// Command or parameter is invalid
#define	ERR_INVALID_LICENSE_KEY			118	// License key is invalid
#define	ERR_NO_VPN_SERVER_LICENSE		119	// There is no valid license for the VPN Server
#define	ERR_NO_VPN_CLUSTER_LICENSE		120	// There is no cluster license
#define ERR_NOT_ADMINPACK_SERVER		121	// Not trying to connect to a server with the Administrator Pack license
#define ERR_NOT_ADMINPACK_SERVER_NET	122	// Not trying to connect to a server with the Administrator Pack license (for .NET)
#define ERR_BETA_EXPIRES				123	// Destination Beta VPN Server has expired
#define ERR_BRANDED_C_TO_S				124 // Branding string of connection limit is different (Authentication on the server side)
#define ERR_BRANDED_C_FROM_S			125	// Branding string of connection limit is different (Authentication for client-side)
#define	ERR_AUTO_DISCONNECTED			126	// VPN session is disconnected for a certain period of time has elapsed
#define	ERR_CLIENT_ID_REQUIRED			127	// Client ID does not match
#define	ERR_TOO_MANY_USERS_CREATED		128	// Too many created users
#define	ERR_SUBSCRIPTION_IS_OLDER		129	// Subscription expiration date Is earlier than the build date of the VPN Server
#define	ERR_ILLEGAL_TRIAL_VERSION		130	// Many trial license is used continuously
#define	ERR_NAT_T_TWO_OR_MORE			131	// There are multiple servers in the back of a global IP address in the NAT-T connection
#define	ERR_DUPLICATE_DDNS_KEY			132	// DDNS host key duplicate
#define	ERR_DDNS_HOSTNAME_EXISTS		133	// Specified DDNS host name already exists
#define	ERR_DDNS_HOSTNAME_INVALID_CHAR	134	// Characters that can not be used for the host name is included
#define	ERR_DDNS_HOSTNAME_TOO_LONG		135	// Host name is too long
#define	ERR_DDNS_HOSTNAME_IS_EMPTY		136	// Host name is not specified
#define	ERR_DDNS_HOSTNAME_TOO_SHORT		137	// Host name is too short
#define	ERR_MSCHAP2_PASSWORD_NEED_RESET	138	// Necessary that password is changed
#define	ERR_DDNS_DISCONNECTED			139	// Communication to the dynamic DNS server is disconnected
#define	ERR_SPECIAL_LISTENER_ICMP_ERROR	140	// The ICMP socket can not be opened
#define	ERR_SPECIAL_LISTENER_DNS_ERROR	141	// Socket for DNS port can not be opened
#define	ERR_OPENVPN_IS_NOT_ENABLED		142	// OpenVPN server feature is not enabled
#define	ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE	143	// It is the type of user authentication that are not supported in the open source version
#define	ERR_VPNGATE						144 // Operation on VPN Gate Server is not available
#define	ERR_VPNGATE_CLIENT				145 // Operation on VPN Gate Client is not available
#define	ERR_VPNGATE_INCLIENT_CANT_STOP	146	// Can not be stopped if operating within VPN Client mode
#define	ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE	147	// It is a feature that is not supported in the open source version
#define	ERR_SUSPENDING					148	// System is suspending


////////////////////////////
// Generally used structure

// Network Services
typedef struct NETSVC
{
	bool Udp;						// false=TCP, true=UDP
	UINT Port;						// Port number
	char *Name;						// Name
} NETSVC;

// Traffic data entry
typedef struct TRAFFIC_ENTRY
{
	UINT64 BroadcastCount;			// Number of broadcast packets
	UINT64 BroadcastBytes;			// Broadcast bytes
	UINT64 UnicastCount;			// Unicast count
	UINT64 UnicastBytes;			// Unicast bytes
} TRAFFIC_ENTRY;

// Traffic data
typedef struct TRAFFIC
{
	TRAFFIC_ENTRY Send;				// Transmitted data
	TRAFFIC_ENTRY Recv;				// Received data
} TRAFFIC;

// Non-SSL connection source
typedef struct NON_SSL
{
	IP IpAddress;					// IP address
	UINT64 EntryExpires;			// Expiration date of entry
	UINT Count;						// Number of connection count
} NON_SSL;

// Simple log storage
typedef struct TINY_LOG
{
	char FileName[MAX_PATH];		// File name
	IO *io;							// File
	LOCK *Lock;						// Lock
} TINY_LOG;

// CEDAR structure
typedef struct CEDAR
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	COUNTER *AcceptingSockets;		// Number of sockets in Accept
	UINT Type;						// Type
	LIST *ListenerList;				// Listener list
	LIST *HubList;					// HUB list
	LIST *ConnectionList;			// Negotiating connection list
	LIST *CaList;					// List of CA
	volatile bool Halt;				// Halt flag
	COUNTER *ConnectionIncrement;	// Connection increment counter
	X *ServerX;						// Server certificate
	K *ServerK;						// Private key of the server certificate
	char *CipherList;				// List of encryption algorithms
	UINT Version;					// Version information
	UINT Build;						// Build Number
	char *ServerStr;				// Server string
	char *MachineName;				// Computer name
	char *HttpUserAgent;			// HTTP user agent
	char *HttpAccept;				// HTTP Accept
	char *HttpAcceptLanguage;		// HTTP Accept Language
	char *HttpAcceptEncoding;		// HTTP Accept Encoding
	TRAFFIC *Traffic;				// Traffic information
	LOCK *TrafficLock;				// Traffic information lock
	LIST *UDPEntryList;				// UDP entry list
	COUNTER *CurrentSessions;		// The current number of sessions
	COUNTER *CurrentTcpConnections;	// Number of current TCP connections
	LIST *NetSvcList;				// Network service list
	char *VerString;				// Version string
	char *BuildInfo;				// Build Information
	struct CLIENT *Client;			// Client
	struct SERVER *Server;			// Server
	UINT64 CreatedTick;				// Generation date and time
	bool CheckExpires;				// Check the expiration date
	LIST *TrafficDiffList;			// Traffic difference list
	struct LOG *DebugLog;			// Debug log
	UCHAR UniqueId[16];				// Unique ID
	LIST *LocalBridgeList;			// Local bridge list
	bool Bridge;					// Bridge version
	LIST *L3SwList;					// Layer-3 switch list
	COUNTER *AssignedClientLicense;	// Number of assigned client licenses
	COUNTER *AssignedBridgeLicense;	// Number of assigned bridge licenses
	UINT64 LicenseViolationTick;	// License violation occurs
	LIST *NonSslList;				// Non-SSL connection list
	struct WEBUI *WebUI;			// Data for WebUI service
	UINT Beta;						// Beta number
	LOCK *CedarSuperLock;			// Cedar super lock!
	bool DisableIPv6Listener;		// Disable IPv6 listener
	UINT ClientId;					// Client ID
	UINT64 BuiltDate;				// Build Date
	LIST *UdpPortList;				// UDP port list in use
	char CurrentDDnsFqdn[MAX_SIZE];	// FQDN of the current DDNS
	char OpenVPNPublicPorts[MAX_SIZE];	// OpenVPN public UDP port list
	LOCK *OpenVPNPublicPortsLock;	// Lock of OpenVPN public UDP port list
	LOCK *CurrentRegionLock;		// Current region lock
	char CurrentRegion[128];		// Current region
	LOCK *CurrentTcpQueueSizeLock;	// Current TCP send queue size lock
	UINT CurrentTcpQueueSize;		// Current TCP send queue size
	COUNTER *CurrentActiveLinks;	// Current active cascade connections
	LOCK *QueueBudgetLock;			// Queue budget lock
	UINT QueueBudget;				// Queue budget
	LOCK *FifoBudgetLock;			// Fifo budget lock
	UINT FifoBudget;				// Fifo budget
	SSL_ACCEPT_SETTINGS SslAcceptSettings;	// SSL Accept Settings
	char OpenVPNDefaultClientOption[MAX_SIZE];	// OpenVPN Default Client Option String
} CEDAR;

// Type of CEDAR
#define	CEDAR_CLIENT				0	// Client
#define	CEDAR_STANDALONE_SERVER		1	// Stand-alone server
#define	CEDAR_FARM_CONTROLLER		2	// Server farm controller
#define	CEDAR_FARM_MEMBER			3	// Server farm member


//////////////////////////////////////////////////////////////////////////
// CedarType


// ==============================================================
//   Remote Procedure Call
// ==============================================================

typedef struct RPC RPC;


// ==============================================================
//   Account
// ==============================================================

typedef struct POLICY_ITEM POLICY_ITEM;
typedef struct POLICY POLICY;
typedef struct USERGROUP USERGROUP;
typedef struct USER USER;
typedef struct AUTHPASSWORD AUTHPASSWORD;
typedef struct AUTHUSERCERT AUTHUSERCERT;
typedef struct AUTHROOTCERT AUTHROOTCERT;
typedef struct AUTHRADIUS AUTHRADIUS;
typedef struct AUTHNT AUTHNT;


// ==============================================================
//   RADIUS
// ==============================================================

typedef struct RADIUS_LOGIN_OPTION RADIUS_LOGIN_OPTION;
typedef struct RADIUS_PACKET RADIUS_PACKET;
typedef struct RADIUS_AVP RADIUS_AVP;
typedef struct EAP_CLIENT EAP_CLIENT;
typedef struct EAP_MESSAGE EAP_MESSAGE;
typedef struct EAP_MSCHAPV2_GENERAL EAP_MSCHAPV2_GENERAL;
typedef struct EAP_MSCHAPV2_CHALLENGE EAP_MSCHAPV2_CHALLENGE;
typedef struct EAP_MSCHAPV2_RESPONSE EAP_MSCHAPV2_RESPONSE;
typedef struct EAP_MSCHAPV2_SUCCESS_SERVER EAP_MSCHAPV2_SUCCESS_SERVER;
typedef struct EAP_MSCHAPV2_SUCCESS_CLIENT EAP_MSCHAPV2_SUCCESS_CLIENT;
typedef struct EAP_PEAP EAP_PEAP;


// ==============================================================
//   Listener
// ==============================================================

typedef struct DOS DOS;
typedef struct LISTENER LISTENER;
typedef struct TCP_ACCEPTED_PARAM TCP_ACCEPTED_PARAM;
typedef struct UDP_ENTRY UDP_ENTRY;
typedef struct DYNAMIC_LISTENER DYNAMIC_LISTENER;


// ==============================================================
//   Logging
// ==============================================================

typedef struct PACKET_LOG PACKET_LOG;
typedef struct HUB_LOG HUB_LOG;
typedef struct RECORD RECORD;
typedef struct LOG LOG;
typedef struct ERASER ERASER;
typedef struct SLOG SLOG;


// ==============================================================
//   Connection
// ==============================================================

typedef struct KEEP KEEP;
typedef struct SECURE_SIGN SECURE_SIGN;
typedef struct RC4_KEY_PAIR RC4_KEY_PAIR;
typedef struct CLIENT_OPTION CLIENT_OPTION;
typedef struct CLIENT_AUTH CLIENT_AUTH;
typedef struct TCPSOCK TCPSOCK;
typedef struct TCP TCP;
typedef struct UDP UDP;
typedef struct BLOCK BLOCK;
typedef struct CONNECTION CONNECTION;


// ==============================================================
//   Session
// ==============================================================

typedef struct NODE_INFO NODE_INFO;
typedef struct PACKET_ADAPTER PACKET_ADAPTER;
typedef struct SESSION SESSION;
typedef struct UI_PASSWORD_DLG UI_PASSWORD_DLG;
typedef struct UI_MSG_DLG UI_MSG_DLG;
typedef struct UI_NICINFO UI_NICINFO;
typedef struct UI_CONNECTERROR_DLG UI_CONNECTERROR_DLG;
typedef struct UI_CHECKCERT UI_CHECKCERT;


// ==============================================================
//   Hub
// ==============================================================

typedef struct SE_LINK SE_LINK;
typedef struct TEST_HISTORY TEST_HISTORY;
typedef struct SE_TEST SE_TEST;
typedef struct HUBDB HUBDB;
typedef struct TRAFFIC_LIMITER TRAFFIC_LIMITER;
typedef struct STORM STORM;
typedef struct HUB_PA HUB_PA;
typedef struct HUB_OPTION HUB_OPTION;
typedef struct MAC_TABLE_ENTRY MAC_TABLE_ENTRY;
typedef struct IP_TABLE_ENTRY IP_TABLE_ENTRY;
typedef struct LOOP_LIST LOOP_LIST;
typedef struct ACCESS ACCESS;
typedef struct TICKET TICKET;
typedef struct TRAFFIC_DIFF TRAFFIC_DIFF;
typedef struct HUB HUB;
typedef struct ADMIN_OPTION ADMIN_OPTION;
typedef struct CRL CRL;
typedef struct AC AC;
typedef struct USERLIST USERLIST;


// ==============================================================
//   Protocol
// ==============================================================

typedef struct CHECK_CERT_THREAD_PROC CHECK_CERT_THREAD_PROC;
typedef struct SECURE_SIGN_THREAD_PROC SECURE_SIGN_THREAD_PROC;
typedef struct RAND_CACHE RAND_CACHE;
typedef struct BLACK BLACK;
typedef struct SEND_SIGNATURE_PARAM SEND_SIGNATURE_PARAM;
typedef struct UPDATE_CLIENT UPDATE_CLIENT;
typedef struct UPDATE_CLIENT_SETTING UPDATE_CLIENT_SETTING;


// ==============================================================
//   Link
// ==============================================================

typedef struct LINK LINK;


// ==============================================================
//   Virtual
// ==============================================================

typedef struct ARP_ENTRY ARP_ENTRY;
typedef struct ARP_WAIT ARP_WAIT;
typedef struct IP_WAIT IP_WAIT;
typedef struct IP_PART IP_PART;
typedef struct IP_COMBINE IP_COMBINE;
typedef struct NAT_ENTRY NAT_ENTRY;
typedef struct TCP_OPTION TCP_OPTION;
typedef struct VH VH;
typedef struct VH_OPTION VH_OPTION;
typedef struct DHCP_LEASE DHCP_LEASE;
typedef struct NATIVE_NAT NATIVE_NAT;
typedef struct NATIVE_NAT_ENTRY NATIVE_NAT_ENTRY;
typedef struct DNS_PARSED_PACKET DNS_PARSED_PACKET;


// ==============================================================
//   WPC
// ==============================================================

typedef struct INTERNET_SETTING INTERNET_SETTING;
typedef struct URL_DATA URL_DATA;
typedef struct WPC_ENTRY WPC_ENTRY;
typedef struct WPC_PACKET WPC_PACKET;
typedef struct WPC_CONNECT WPC_CONNECT;

// ==============================================================
//   VLAN
// ==============================================================

typedef struct ROUTE_TRACKING ROUTE_TRACKING;
typedef struct VLAN VLAN;
typedef struct INSTANCE_LIST INSTANCE_LIST;
typedef struct VLAN_PARAM VLAN_PARAM;

#ifdef	OS_UNIX
typedef struct UNIX_VLAN_LIST UNIX_VLAN_LIST;
#endif	// OS_UNIX

// ==============================================================
//   Null LAN
// ==============================================================

typedef struct NULL_LAN NULL_LAN;


// ==============================================================
//   Bridge
// ==============================================================

typedef struct ETH ETH;
typedef struct BRIDGE BRIDGE;
typedef struct LOCALBRIDGE LOCALBRIDGE;


// ==============================================================
//   Layer-3 Switch
// ==============================================================

typedef struct L3IF L3IF;
typedef struct L3SW L3SW;
typedef struct L3TABLE L3TABLE;
typedef struct L3ARPENTRY L3ARPENTRY;
typedef struct L3ARPWAIT L3ARPWAIT;
typedef struct L3PACKET L3PACKET;


// ==============================================================
//   Client
// ==============================================================

typedef struct ACCOUNT ACCOUNT;
typedef struct CLIENT_CONFIG CLIENT_CONFIG;
typedef struct RPC_CLIENT_VERSION RPC_CLIENT_VERSION;
typedef struct RPC_CLIENT_PASSWORD RPC_CLIENT_PASSWORD;
typedef struct RPC_CLIENT_PASSWORD_SETTING RPC_CLIENT_PASSWORD_SETTING;
typedef struct RPC_CLIENT_ENUM_CA_ITEM RPC_CLIENT_ENUM_CA_ITEM;
typedef struct RPC_CLIENT_ENUM_CA RPC_CLIENT_ENUM_CA;
typedef struct RPC_CERT RPC_CERT;
typedef struct RPC_CLIENT_DELETE_CA RPC_CLIENT_DELETE_CA;
typedef struct RPC_GET_CA RPC_GET_CA;
typedef struct RPC_GET_ISSUER RPC_GET_ISSUER;
typedef struct RPC_CLIENT_ENUM_SECURE_ITEM RPC_CLIENT_ENUM_SECURE_ITEM;
typedef struct RPC_CLIENT_ENUM_SECURE RPC_CLIENT_ENUM_SECURE;
typedef struct RPC_USE_SECURE RPC_USE_SECURE;
typedef struct RPC_ENUM_OBJECT_IN_SECURE RPC_ENUM_OBJECT_IN_SECURE;
typedef struct RPC_CLIENT_CREATE_VLAN RPC_CLIENT_CREATE_VLAN;
typedef struct RPC_CLIENT_GET_VLAN RPC_CLIENT_GET_VLAN;
typedef struct RPC_CLIENT_SET_VLAN RPC_CLIENT_SET_VLAN;
typedef struct RPC_CLIENT_ENUM_VLAN_ITEM RPC_CLIENT_ENUM_VLAN_ITEM;
typedef struct RPC_CLIENT_ENUM_VLAN RPC_CLIENT_ENUM_VLAN;
typedef struct RPC_CLIENT_CREATE_ACCOUNT RPC_CLIENT_CREATE_ACCOUNT;
typedef struct RPC_CLIENT_ENUM_ACCOUNT_ITEM RPC_CLIENT_ENUM_ACCOUNT_ITEM;
typedef struct RPC_CLIENT_ENUM_ACCOUNT RPC_CLIENT_ENUM_ACCOUNT;
typedef struct RPC_CLIENT_DELETE_ACCOUNT RPC_CLIENT_DELETE_ACCOUNT;
typedef struct RPC_RENAME_ACCOUNT RPC_RENAME_ACCOUNT;
typedef struct RPC_CLIENT_GET_ACCOUNT RPC_CLIENT_GET_ACCOUNT;
typedef struct RPC_CLIENT_CONNECT RPC_CLIENT_CONNECT;
typedef struct RPC_CLIENT_GET_CONNECTION_STATUS RPC_CLIENT_GET_CONNECTION_STATUS;
typedef struct CLIENT_RPC_CONNECTION CLIENT_RPC_CONNECTION;
typedef struct CLIENT CLIENT;
typedef struct RPC_CLIENT_NOTIFY RPC_CLIENT_NOTIFY;
typedef struct REMOTE_CLIENT REMOTE_CLIENT;
typedef struct NOTIFY_CLIENT NOTIFY_CLIENT;
typedef struct UNIX_VLAN UNIX_VLAN;
typedef struct CM_SETTING CM_SETTING;


// ==============================================================
//   Server
// ==============================================================

typedef struct HUB_LIST HUB_LIST;
typedef struct FARM_TASK FARM_TASK;
typedef struct FARM_MEMBER FARM_MEMBER;
typedef struct FARM_CONTROLLER FARM_CONTROLLER;
typedef struct SERVER_LISTENER SERVER_LISTENER;
typedef struct SERVER SERVER;
typedef struct RPC_ENUM_SESSION RPC_ENUM_SESSION;
typedef struct RPC_SESSION_STATUS RPC_SESSION_STATUS;
typedef struct CAPS CAPS;
typedef struct CAPSLIST CAPSLIST;
typedef struct LOG_FILE LOG_FILE;
typedef struct SYSLOG_SETTING SYSLOG_SETTING;
typedef struct HUB_SNAPSHOT HUB_SNAPSHOT;
typedef struct SERVER_SNAPSHOT SERVER_SNAPSHOT;
typedef struct SERVER_HUB_CREATE_HISTORY SERVER_HUB_CREATE_HISTORY;
typedef struct OPENVPN_SSTP_CONFIG OPENVPN_SSTP_CONFIG;

// ==============================================================
//   Server Admin Tool
// ==============================================================

typedef struct ADMIN ADMIN;
typedef struct RPC_TEST RPC_TEST;
typedef struct RPC_SERVER_INFO RPC_SERVER_INFO;
typedef struct RPC_SERVER_STATUS RPC_SERVER_STATUS;
typedef struct RPC_LISTENER RPC_LISTENER;
typedef struct RPC_LISTENER_LIST RPC_LISTENER_LIST;
typedef struct RPC_STR RPC_STR;
typedef struct RPC_SET_PASSWORD RPC_SET_PASSWORD;
typedef struct RPC_FARM RPC_FARM;
typedef struct RPC_FARM_HUB RPC_FARM_HUB;
typedef struct RPC_FARM_INFO RPC_FARM_INFO;
typedef struct RPC_ENUM_FARM_ITEM RPC_ENUM_FARM_ITEM;
typedef struct RPC_ENUM_FARM RPC_ENUM_FARM;
typedef struct RPC_FARM_CONNECTION_STATUS RPC_FARM_CONNECTION_STATUS;
typedef struct RPC_KEY_PAIR RPC_KEY_PAIR;
typedef struct RPC_HUB_OPTION RPC_HUB_OPTION;
typedef struct RPC_RADIUS RPC_RADIUS;
typedef struct RPC_HUB RPC_HUB;
typedef struct RPC_CREATE_HUB RPC_CREATE_HUB;
typedef struct RPC_ENUM_HUB_ITEM RPC_ENUM_HUB_ITEM;
typedef struct RPC_ENUM_HUB RPC_ENUM_HUB;
typedef struct RPC_DELETE_HUB RPC_DELETE_HUB;
typedef struct RPC_ENUM_CONNECTION_ITEM RPC_ENUM_CONNECTION_ITEM;
typedef struct RPC_ENUM_CONNECTION RPC_ENUM_CONNECTION;
typedef struct RPC_DISCONNECT_CONNECTION RPC_DISCONNECT_CONNECTION;
typedef struct RPC_CONNECTION_INFO RPC_CONNECTION_INFO;
typedef struct RPC_SET_HUB_ONLINE RPC_SET_HUB_ONLINE;
typedef struct RPC_HUB_STATUS RPC_HUB_STATUS;
typedef struct RPC_HUB_LOG RPC_HUB_LOG;
typedef struct RPC_HUB_ADD_CA RPC_HUB_ADD_CA;
typedef struct RPC_HUB_ENUM_CA_ITEM RPC_HUB_ENUM_CA_ITEM;
typedef struct RPC_HUB_ENUM_CA RPC_HUB_ENUM_CA;
typedef struct RPC_HUB_GET_CA RPC_HUB_GET_CA;
typedef struct RPC_HUB_DELETE_CA RPC_HUB_DELETE_CA;
typedef struct RPC_CREATE_LINK RPC_CREATE_LINK;
typedef struct RPC_ENUM_LINK_ITEM RPC_ENUM_LINK_ITEM;
typedef struct RPC_ENUM_LINK RPC_ENUM_LINK;
typedef struct RPC_LINK_STATUS RPC_LINK_STATUS;
typedef struct RPC_LINK RPC_LINK;
typedef struct RPC_ENUM_ACCESS_LIST RPC_ENUM_ACCESS_LIST;
typedef struct RPC_ADD_ACCESS RPC_ADD_ACCESS;
typedef struct RPC_DELETE_ACCESS RPC_DELETE_ACCESS;
typedef struct RPC_SET_USER RPC_SET_USER;
typedef struct RPC_ENUM_USER_ITEM RPC_ENUM_USER_ITEM;
typedef struct RPC_ENUM_USER RPC_ENUM_USER;
typedef struct RPC_SET_GROUP RPC_SET_GROUP;
typedef struct RPC_ENUM_GROUP_ITEM RPC_ENUM_GROUP_ITEM;
typedef struct RPC_ENUM_GROUP RPC_ENUM_GROUP;
typedef struct RPC_DELETE_USER RPC_DELETE_USER;
typedef struct RPC_ENUM_SESSION_ITEM RPC_ENUM_SESSION_ITEM;
typedef struct RPC_DELETE_SESSION RPC_DELETE_SESSION;
typedef struct RPC_ENUM_MAC_TABLE_ITEM RPC_ENUM_MAC_TABLE_ITEM;
typedef struct RPC_ENUM_MAC_TABLE RPC_ENUM_MAC_TABLE;
typedef struct RPC_ENUM_IP_TABLE_ITEM RPC_ENUM_IP_TABLE_ITEM;
typedef struct RPC_ENUM_IP_TABLE RPC_ENUM_IP_TABLE;
typedef struct RPC_DELETE_TABLE RPC_DELETE_TABLE;
typedef struct RPC_KEEP RPC_KEEP;
typedef struct RPC_ENUM_ETH_ITEM RPC_ENUM_ETH_ITEM;
typedef struct RPC_ENUM_ETH RPC_ENUM_ETH;
typedef struct RPC_LOCALBRIDGE RPC_LOCALBRIDGE;
typedef struct RPC_ENUM_LOCALBRIDGE RPC_ENUM_LOCALBRIDGE;
typedef struct RPC_BRIDGE_SUPPORT RPC_BRIDGE_SUPPORT;
typedef struct RPC_CONFIG RPC_CONFIG;
typedef struct RPC_ADMIN_OPTION RPC_ADMIN_OPTION;
typedef struct RPC_L3SW RPC_L3SW;
typedef struct RPC_L3IF RPC_L3IF;
typedef struct RPC_L3TABLE RPC_L3TABLE;
typedef struct RPC_ENUM_L3SW_ITEM RPC_ENUM_L3SW_ITEM;
typedef struct RPC_ENUM_L3SW RPC_ENUM_L3SW;
typedef struct RPC_ENUM_L3IF RPC_ENUM_L3IF;
typedef struct RPC_ENUM_L3TABLE RPC_ENUM_L3TABLE;
typedef struct RPC_CRL RPC_CRL;
typedef struct RPC_ENUM_CRL_ITEM RPC_ENUM_CRL_ITEM;
typedef struct RPC_ENUM_CRL RPC_ENUM_CRL;
typedef struct RPC_INT RPC_INT;
typedef struct RPC_AC_LIST RPC_AC_LIST;
typedef struct RPC_ENUM_LOG_FILE_ITEM RPC_ENUM_LOG_FILE_ITEM;
typedef struct RPC_ENUM_LOG_FILE RPC_ENUM_LOG_FILE;
typedef struct RPC_READ_LOG_FILE RPC_READ_LOG_FILE;
typedef struct DOWNLOAD_PROGRESS DOWNLOAD_PROGRESS;
typedef struct RPC_RENAME_LINK RPC_RENAME_LINK;
typedef struct RPC_ENUM_LICENSE_KEY RPC_ENUM_LICENSE_KEY;
typedef struct RPC_ENUM_LICENSE_KEY_ITEM RPC_ENUM_LICENSE_KEY_ITEM;
typedef struct RPC_LICENSE_STATUS RPC_LICENSE_STATUS;
typedef struct RPC_ENUM_ETH_VLAN_ITEM RPC_ENUM_ETH_VLAN_ITEM;
typedef struct RPC_ENUM_ETH_VLAN RPC_ENUM_ETH_VLAN;
typedef struct RPC_MSG RPC_MSG;
typedef struct RPC_WINVER RPC_WINVER;
typedef struct RPC_ENUM_ETHERIP_ID RPC_ENUM_ETHERIP_ID;
typedef struct RPC_SPECIAL_LISTENER RPC_SPECIAL_LISTENER;
typedef struct RPC_AZURE_STATUS RPC_AZURE_STATUS;


// ==============================================================
//  NAT
// ==============================================================

typedef struct NAT NAT;
typedef struct NAT_ADMIN NAT_ADMIN;
typedef struct RPC_DUMMY RPC_DUMMY;
typedef struct RPC_NAT_STATUS RPC_NAT_STATUS;
typedef struct RPC_NAT_INFO RPC_NAT_INFO;
typedef struct RPC_ENUM_NAT_ITEM RPC_ENUM_NAT_ITEM;
typedef struct RPC_ENUM_NAT RPC_ENUM_NAT;
typedef struct RPC_ENUM_DHCP_ITEM RPC_ENUM_DHCP_ITEM;
typedef struct RPC_ENUM_DHCP RPC_ENUM_DHCP;


// ==============================================================
//  SecureNAT
// ==============================================================

typedef struct SNAT SNAT;


// ==============================================================
//  WinUI
// ==============================================================

typedef struct LED LED;
typedef struct WIZARD WIZARD;
typedef struct WIZARD_PAGE WIZARD_PAGE;
typedef struct WINUI_UPDATE WINUI_UPDATE;
typedef struct WINUI_UPDATE_DLG_PARAM WINUI_UPDATE_DLG_PARAM;



// ==============================================================
//  Console
// ==============================================================

typedef struct PARAM PARAM;
typedef struct PARAM_VALUE PARAM_VALUE;
typedef struct CONSOLE CONSOLE;
typedef struct LOCAL_CONSOLE_PARAM LOCAL_CONSOLE_PARAM;
typedef struct CMD CMD;
typedef struct CMD_EVAL_MIN_MAX CMD_EVAL_MIN_MAX;


// ==============================================================
//  Command
// ==============================================================

typedef struct PS PS;
typedef struct PC PC;
typedef struct CT CT;
typedef struct CTC CTC;
typedef struct CTR CTR;
typedef struct TTC TTC;
typedef struct TTS TTS;
typedef struct TTS_WORKER TTS_WORKER;
typedef struct TTC_WORKER TTC_WORKER;
typedef struct TT_RESULT TT_RESULT;
typedef struct TTS_SOCK TTS_SOCK;
typedef struct TTC_SOCK TTC_SOCK;
typedef struct PT PT;

// ==============================================================
//  EtherLogger
// ==============================================================

typedef struct EL EL;
typedef struct EL_DEVICE EL_DEVICE;
typedef struct EL_LICENSE_STATUS EL_LICENSE_STATUS;
typedef struct RPC_ADD_DEVICE RPC_ADD_DEVICE;
typedef struct RPC_DELETE_DEVICE RPC_DELETE_DEVICE;
typedef struct RPC_ENUM_DEVICE_ITEM RPC_ENUM_DEVICE_ITEM;
typedef struct RPC_ENUM_DEVICE RPC_ENUM_DEVICE;
typedef struct RPC_EL_LICENSE_STATUS RPC_EL_LICENSE_STATUS;


// ==============================================================
//  Database
// ==============================================================

typedef struct LICENSE_PRODUCT LICENSE_PRODUCT;
typedef struct LICENSE_SYSTEM LICENSE_SYSTEM;
typedef struct LICENSE_DATA LICENSE_DATA;
typedef struct LICENSE LICENSE;
typedef struct LICENSE_STATUS LICENSE_STATUS;
typedef struct SECURE_PACK_FOLDER SECURE_PACK_FOLDER;
typedef struct WIDE_MACHINE_ID WIDE_MACHINE_ID;
typedef struct TRIAL_INFO TRIAL_INFO;


// ==============================================================
//  IPsec
// ==============================================================

typedef struct IPSEC_SERVER IPSEC_SERVER;
typedef struct IPSEC_SERVICES IPSEC_SERVICES;
typedef struct ETHERIP_ID ETHERIP_ID;


// ==============================================================
//  L2TP
// ==============================================================

typedef struct L2TP_SERVER L2TP_SERVER;
typedef struct L2TP_TUNNEL L2TP_TUNNEL;
typedef struct L2TP_SESSION L2TP_SESSION;
typedef struct L2TP_PACKET L2TP_PACKET;
typedef struct L2TP_AVP L2TP_AVP;
typedef struct L2TP_QUEUE L2TP_QUEUE;


// ==============================================================
//  PPP
// ==============================================================

typedef struct PPP_SESSION PPP_SESSION;
typedef struct PPP_OPTION PPP_OPTION;
typedef struct PPP_LCP PPP_LCP;
typedef struct PPP_PACKET PPP_PACKET;
typedef struct PPP_IPOPTION PPP_IPOPTION;


// ==============================================================
//  EtherIP
// ==============================================================

typedef struct ETHERIP_SERVER ETHERIP_SERVER;


// ==============================================================
//  IKE
// ==============================================================

typedef struct IKE_SERVER IKE_SERVER;
typedef struct IKE_SA IKE_SA;
typedef struct IKE_SA_TRANSFORM_SETTING IKE_SA_TRANSFORM_SETTING;
typedef struct IKE_CLIENT IKE_CLIENT;
typedef struct IPSECSA IPSECSA;
typedef struct IKE_CAPS IKE_CAPS;

// ==============================================================
//  IPSec Packet
// ==============================================================

typedef struct IKE_COMMON_HEADER IKE_COMMON_HEADER;
typedef struct IKE_SA_HEADER IKE_SA_HEADER;
typedef struct IKE_PROPOSAL_HEADER IKE_PROPOSAL_HEADER;
typedef struct IKE_TRANSFORM_HEADER IKE_TRANSFORM_HEADER;
typedef struct IKE_TRANSFORM_VALUE IKE_TRANSFORM_VALUE;
typedef struct IKE_ID_HEADER IKE_ID_HEADER;
typedef struct IKE_CERT_HEADER IKE_CERT_HEADER;
typedef struct IKE_CERT_REQUEST_HEADER IKE_CERT_REQUEST_HEADER;
typedef struct IKE_NOTICE_HEADER IKE_NOTICE_HEADER;
typedef struct IKE_DELETE_HEADER IKE_DELETE_HEADER;
typedef struct IKE_NAT_OA_HEADER IKE_NAT_OA_HEADER;
typedef struct IPSEC_SA_TRANSFORM_SETTING IPSEC_SA_TRANSFORM_SETTING;

typedef struct IKE_PACKET_SA_PAYLOAD IKE_PACKET_SA_PAYLOAD;
typedef struct IKE_PACKET_PROPOSAL_PAYLOAD IKE_PACKET_PROPOSAL_PAYLOAD;
typedef struct IKE_PACKET_TRANSFORM_PAYLOAD IKE_PACKET_TRANSFORM_PAYLOAD;
typedef struct IKE_PACKET_TRANSFORM_VALUE IKE_PACKET_TRANSFORM_VALUE;
typedef struct IKE_PACKET_DATA_PAYLOAD IKE_PACKET_DATA_PAYLOAD;
typedef struct IKE_PACKET_ID_PAYLOAD IKE_PACKET_ID_PAYLOAD;
typedef struct IKE_PACKET_CERT_PAYLOAD IKE_PACKET_CERT_PAYLOAD;
typedef struct IKE_PACKET_CERT_REQUEST_PAYLOAD IKE_PACKET_CERT_REQUEST_PAYLOAD;
typedef struct IKE_PACKET_NOTICE_PAYLOAD IKE_PACKET_NOTICE_PAYLOAD;
typedef struct IKE_PACKET_DELETE_PAYLOAD IKE_PACKET_DELETE_PAYLOAD;
typedef struct IKE_PACKET_NAT_OA_PAYLOAD IKE_PACKET_NAT_OA_PAYLOAD;

typedef struct IKE_PACKET_PAYLOAD IKE_PACKET_PAYLOAD;
typedef struct IKE_PACKET IKE_PACKET;

typedef struct IKE_P1_KEYSET IKE_P1_KEYSET;

typedef struct IKE_CRYPTO IKE_CRYPTO;
typedef struct IKE_HASH IKE_HASH;
typedef struct IKE_DH IKE_DH;
typedef struct IKE_ENGINE IKE_ENGINE;
typedef struct IKE_CRYPTO_KEY IKE_CRYPTO_KEY;
typedef struct IKE_CRYPTO_PARAM IKE_CRYPTO_PARAM;


// ==============================================================
//  IPSec for Windows 7 / Vista / 2008 / 2008 R2
// ==============================================================

typedef struct IPSEC_WIN7 IPSEC_WIN7;


// ==============================================================
//  In-Process VPN Client
// ==============================================================

typedef struct IPC IPC;
typedef struct IPC_ARP IPC_ARP;
typedef struct IPC_ASYNC IPC_ASYNC;
typedef struct IPC_PARAM IPC_PARAM;
typedef struct IPC_DHCP_RELESAE_QUEUE IPC_DHCP_RELESAE_QUEUE;
typedef struct IPC_MSCHAP_V2_AUTHINFO IPC_MSCHAP_V2_AUTHINFO;


// ==============================================================
//   UDP Acceleration
// ==============================================================

typedef struct UDP_ACCEL UDP_ACCEL;


// ==============================================================
//   SSTP (Microsoft Secure Socket Tunneling Protocol) Stack
// ==============================================================

typedef struct SSTP_SERVER SSTP_SERVER;
typedef struct SSTP_PACKET SSTP_PACKET;
typedef struct SSTP_ATTRIBUTE SSTP_ATTRIBUTE;


// ==============================================================
//   OpenVPN Protocol Stack
// ==============================================================

typedef struct OPENVPN_SERVER OPENVPN_SERVER;
typedef struct OPENVPN_SERVER_UDP OPENVPN_SERVER_UDP;
typedef struct OPENVPN_SESSION OPENVPN_SESSION;
typedef struct OPENVPN_CHANNEL OPENVPN_CHANNEL;
typedef struct OPENVPN_PACKET OPENVPN_PACKET;
typedef struct OPENVPN_CONTROL_PACKET OPENVPN_CONTROL_PACKET;
typedef struct OPENVPN_KEY_METHOD_2 OPENVPN_KEY_METHOD_2;


// ==============================================================
//   Dynamic DNS Client
// ==============================================================

typedef struct DDNS_CLIENT DDNS_CLIENT;
typedef struct DDNS_REGISTER_PARAM DDNS_REGISTER_PARAM;
typedef struct DDNS_CLIENT_STATUS DDNS_CLIENT_STATUS;


// ==============================================================
//   VPN Azure Client
// ==============================================================
typedef struct AZURE_CLIENT AZURE_CLIENT;
typedef struct AZURE_PARAM AZURE_PARAM;


// ==============================================================
//  VPN Gate Service
// ==============================================================

typedef struct VGS VGS;
typedef struct VGS_CONFIG VGS_CONFIG;
typedef struct VGC VGC;
typedef struct VGHOST VGHOST;
typedef struct VGHOSTLIST VGHOSTLIST;
typedef struct VGHOSTDAT VGHOSTDAT;
typedef struct VGCPOLLTASK VGCPOLLTASK;
typedef struct VGS_LOG VGS_LOG;
typedef struct VGC_UDPHOST VGC_UDPHOST;
typedef struct MIRROR_SERVER MIRROR_SERVER;


// ==============================================================
//   Native Stack
// ==============================================================

typedef struct NATIVE_STACK NATIVE_STACK;
typedef struct IPTABLES_STATE IPTABLES_STATE;
typedef struct IPTABLES_ENTRY IPTABLES_ENTRY;


// ==============================================================
//  SeLow User-mode
// ==============================================================

typedef struct SU SU;
typedef struct SU_ADAPTER SU_ADAPTER;
typedef struct SU_ADAPTER_LIST SU_ADAPTER_LIST;


//////////////////////////////////////////////////////////////////////////
// Account


// Policy item
struct POLICY_ITEM
{
	UINT Index;
	bool TypeInt;
	bool AllowZero;
	UINT MinValue;
	UINT MaxValue;
	UINT DefaultValue;
	char *FormatStr;
};

// Policy
struct POLICY
{
	// For Ver 2.0
	bool Access;					// Grant access
	bool DHCPFilter;				// Filter DHCP packets (IPv4)
	bool DHCPNoServer;				// Prohibit the behavior of the DHCP server (IPv4)
	bool DHCPForce;					// Force DHCP-assigned IP address (IPv4)
	bool NoBridge;					// Prohibit the bridge behavior
	bool NoRouting;					// Prohibit the router behavior (IPv4)
	bool CheckMac;					// Prohibit the duplicate MAC address
	bool CheckIP;					// Prohibit a duplicate IP address (IPv4)
	bool ArpDhcpOnly;				// Prohibit the broadcast other than ARP, DHCP, ICMPv6
	bool PrivacyFilter;				// Privacy filter mode
	bool NoServer;					// Prohibit to operate as a TCP/IP server (IPv4)
	bool NoBroadcastLimiter;		// Not to limit the number of broadcast
	bool MonitorPort;				// Allow monitoring mode
	UINT MaxConnection;				// Maximum number of TCP connections
	UINT TimeOut;					// Communication time-out period
	UINT MaxMac;					// Maximum number of MAC address
	UINT MaxIP;						// Maximum number of IP address (IPv4)
	UINT MaxUpload;					// Upload bandwidth
	UINT MaxDownload;				// Download bandwidth
	bool FixPassword;				// User can not change password
	UINT MultiLogins;				// Multiple logins limit
	bool NoQoS;						// Prohibit the use of VoIP / QoS features

									// For Ver 3.0
	bool RSandRAFilter;				// Filter the Router Solicitation / Advertising packet (IPv6)
	bool RAFilter;					// Filter the router advertisement packet (IPv6)
	bool DHCPv6Filter;				// Filter DHCP packets (IPv6)
	bool DHCPv6NoServer;			// Prohibit the behavior of the DHCP server (IPv6)
	bool NoRoutingV6;				// Prohibit the router behavior (IPv6)
	bool CheckIPv6;					// Prohibit the duplicate IP address (IPv6)
	bool NoServerV6;				// Prohibit to operate as a TCP/IP server (IPv6)
	UINT MaxIPv6;					// Maximum number of IP address (IPv6)
	bool NoSavePassword;			// Prohibit to save the password in the VPN Client
	UINT AutoDisconnect;			// Disconnect the VPN Client automatically at a certain period of time
	bool FilterIPv4;				// Filter all IPv4 packets
	bool FilterIPv6;				// Filter all IPv6 packets
	bool FilterNonIP;				// Filter all non-IP packets
	bool NoIPv6DefaultRouterInRA;	// Delete the default router specification from the IPv6 router advertisement
	bool NoIPv6DefaultRouterInRAWhenIPv6;	// Delete the default router specification from the IPv6 router advertisement (Enable IPv6 connection)
	UINT VLanId;					// Specify the VLAN ID

	bool Ver3;						// Whether version 3.0
};

// Group
struct USERGROUP
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	char *Name;						// Group name
	wchar_t *RealName;				// Display name
	wchar_t *Note;					// Note
	POLICY *Policy;					// Policy
	TRAFFIC *Traffic;				// Traffic data
};

// User
struct USER
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	char *Name;						// User name
	wchar_t *RealName;				// Real name
	wchar_t *Note;					// Note
	char *GroupName;				// Group name
	USERGROUP *Group;				// Group
	UINT AuthType;					// Authentication type
	void *AuthData;					// Authentication data
	UINT64 CreatedTime;				// Creation date and time
	UINT64 UpdatedTime;				// Updating date
	UINT64 ExpireTime;				// Expiration date
	UINT64 LastLoginTime;			// Last login time
	UINT NumLogin;					// Total number of logins
	POLICY *Policy;					// Policy
	TRAFFIC *Traffic;				// Traffic data
};

// Password authentication data
struct AUTHPASSWORD
{
	UCHAR HashedKey[SHA1_SIZE];		// Hashed passwords
	UCHAR NtLmSecureHash[MD5_SIZE];	// Encrypted password for the NTLM
};

// User certificate authentication data
struct AUTHUSERCERT
{
	X *UserX;						// X509 certificate for the user
};

// Root certification authority authentication data
struct AUTHROOTCERT
{
	X_SERIAL *Serial;				// Serial number
	wchar_t *CommonName;			// CommonName
};

// Radius authentication data
struct AUTHRADIUS
{
	wchar_t *RadiusUsername;		// User name in the Radius
};

// Windows NT authentication data
struct AUTHNT
{
	wchar_t *NtUsername;			// User name on NT
};



// Macro
#define	POLICY_CURRENT_VERSION		3
#define	NUM_POLICY_ITEM		((sizeof(POLICY) / sizeof(UINT)) - 1)
#define	NUM_POLICY_ITEM_FOR_VER2	22
#define	NUM_POLICY_ITEM_FOR_VER3	38

#define	IS_POLICY_FOR_VER2(index)	(((index) >= 0) && ((index) < NUM_POLICY_ITEM_FOR_VER2))
#define	IS_POLICY_FOR_VER3(index)	(((index) >= 0) && ((index) < NUM_POLICY_ITEM_FOR_VER3))

#define	IS_POLICY_FOR_CURRENT_VER(index, ver)	((ver) >= 3 ? IS_POLICY_FOR_VER3(index) : IS_POLICY_FOR_VER2(index))

#define	POLICY_BOOL(p, i)	(((bool *)(p))[(i)])
#define	POLICY_INT(p, i)	(((UINT *)(p))[(i)])

extern POLICY_ITEM policy_item[];




// Function prototype
int CompareUserName(void *p1, void *p2);
int CompareGroupName(void *p1, void *p2);
void AcLock(HUB *h);
void AcUnlock(HUB *h);
USERGROUP *NewGroup(char *name, wchar_t *realname, wchar_t *note);
void ReleaseGroup(USERGROUP *g);
void CleanupGroup(USERGROUP *g);
USER *NewUser(char *name, wchar_t *realname, wchar_t *note, UINT authtype, void *authdata);
void ReleaseUser(USER *u);
void CleanupUser(USER *u);
void FreeAuthData(UINT authtype, void *authdata);
bool AcAddUser(HUB *h, USER *u);
bool AcAddGroup(HUB *h, USERGROUP *g);
USER *AcGetUser(HUB *h, char *name);
USERGROUP *AcGetGroup(HUB *h, char *name);
bool AcIsUser(HUB *h, char *name);
bool AcIsGroup(HUB *h, char *name);
bool AcDeleteUser(HUB *h, char *name);
bool AcDeleteGroup(HUB *h, char *name);
void JoinUserToGroup(USER *u, USERGROUP *g);
void SetUserTraffic(USER *u, TRAFFIC *t);
void SetGroupTraffic(USERGROUP *g, TRAFFIC *t);
void AddUserTraffic(USER *u, TRAFFIC *diff);
void AddGroupTraffic(USERGROUP *g, TRAFFIC *diff);
void SetUserAuthData(USER *u, UINT authtype, void *authdata);
void *NewPasswordAuthData(char *username, char *password);
void *NewPasswordAuthDataRaw(UCHAR *hashed_password, UCHAR *ntlm_secure_hash);
void *NewUserCertAuthData(X *x);
void *NewRootCertAuthData(X_SERIAL *serial, wchar_t *common_name);
void *NewRadiusAuthData(wchar_t *username);
void *NewNTAuthData(wchar_t *username);
void HashPassword(void *dst, char *username, char *password);
POLICY *GetDefaultPolicy();
POLICY *ClonePolicy(POLICY *policy);
void SetUserPolicy(USER *u, POLICY *policy);
void OverwritePolicy(POLICY **target, POLICY *p);
POLICY *GetUserPolicy(USER *u);
void SetGroupPolicy(USERGROUP *g, POLICY *policy);
POLICY *GetGroupPolicy(USERGROUP *g);
wchar_t *GetPolicyTitle(UINT id);
wchar_t *GetPolicyDescription(UINT id);
bool IsUserName(char *name);
void *CopyAuthData(void *authdata, UINT authtype);
UINT PolicyNum();
bool PolicyIsSupportedForCascade(UINT i);
UINT PolicyStrToId(char *name);
char *PolicyIdToStr(UINT i);
POLICY_ITEM *GetPolicyItem(UINT id);
void GetPolicyValueRangeStr(wchar_t *str, UINT size, UINT id);
void FormatPolicyValue(wchar_t *str, UINT size, UINT id, UINT value);
char *NormalizePolicyName(char *name);

//////////////////////////////////////////////////////////////////////////
// Listener



// Function to call when receiving a new connection
typedef void (NEW_CONNECTION_PROC)(CONNECTION *c);



// Listener structure
struct LISTENER
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	CEDAR *Cedar;					// Cedar
	UINT Protocol;					// Protocol
	UINT Port;						// Port number
	THREAD *Thread;					// Operating thread
	SOCK *Sock;						// Socket
	EVENT *Event;					// Event
	volatile bool Halt;				// Halting flag
	UINT Status;					// State


	THREAD_PROC *ThreadProc;		// Thread procedure
	void *ThreadParam;				// Thread parameters
	bool LocalOnly;					// Can be connected only from localhost
	bool ShadowIPv6;				// Flag indicating that the shadow IPv6 listener
	LISTENER *ShadowListener;		// Reference to managing shadow IPv6 listener
	bool DisableDos;				// Disable the DoS attack detection
	volatile UINT *NatTGlobalUdpPort;	// NAT-T global UDP port number
	UCHAR RandPortId;				// NAT-T UDP random port ID
	bool EnableConditionalAccept;	// The flag of whether to enable the Conditional Accept
};

// Parameters of TCPAcceptedThread
struct TCP_ACCEPTED_PARAM
{
	LISTENER *r;
	SOCK *s;
};

// UDP entry
struct UDP_ENTRY
{
	UINT SessionKey32;				// 32bit session key
	SESSION *Session;				// Reference to the session
};

// Dynamic listener
struct DYNAMIC_LISTENER
{
	UINT Protocol;					// Protocol
	UINT Port;						// Port
	LOCK *Lock;						// Lock
	CEDAR *Cedar;					// Cedar
	bool *EnablePtr;				// A pointer to the flag of the valid / invalid state
	LISTENER *Listener;				// Listener
};


// Function prototype
LISTENER *NewListener(CEDAR *cedar, UINT proto, UINT port);
LISTENER *NewListenerEx(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param);
LISTENER *NewListenerEx2(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only);
LISTENER *NewListenerEx3(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only, bool shadow_ipv6);
LISTENER *NewListenerEx4(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only, bool shadow_ipv6,
	volatile UINT *natt_global_udp_port, UCHAR rand_port_id);
LISTENER *NewListenerEx5(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only, bool shadow_ipv6,
	volatile UINT *natt_global_udp_port, UCHAR rand_port_id, bool enable_ca);
void ReleaseListener(LISTENER *r);
void CleanupListener(LISTENER *r);
void ListenerThread(THREAD *thread, void *param);
void ListenerTCPMainLoop(LISTENER *r);
void StopListener(LISTENER *r);
int CompareListener(void *p1, void *p2);
void TCPAccepted(LISTENER *r, SOCK *s);
void EnableDosProtect();
void DisableDosProtect();
void TCPAcceptedThread(THREAD *t, void *param);
void ListenerUDPMainLoop(LISTENER *r);
void UDPReceivedPacket(CEDAR *cedar, SOCK *s, IP *ip, UINT port, void *data, UINT size);
int CompareUDPEntry(void *p1, void *p2);
void CleanupUDPEntry(CEDAR *cedar);
void AddUDPEntry(CEDAR *cedar, SESSION *session);
void DelUDPEntry(CEDAR *cedar, SESSION *session);
SESSION *GetSessionFromUDPEntry(CEDAR *cedar, UINT key32);
UINT GetMaxConnectionsPerIp();
void SetMaxConnectionsPerIp(UINT num);
UINT GetMaxUnestablishedConnections();
void SetMaxUnestablishedConnections(UINT num);
DYNAMIC_LISTENER *NewDynamicListener(CEDAR *c, bool *enable_ptr, UINT protocol, UINT port);
void ApplyDynamicListener(DYNAMIC_LISTENER *d);
void FreeDynamicListener(DYNAMIC_LISTENER *d);
bool ListenerRUDPRpcRecvProc(RUDP_STACK *r, UDPPACKET *p);
void ListenerSetProcRecvRpcEnable(bool b);


//////////////////////////////////////////////////////////////////////////
// Logging



// Port number for HTTP monitoring
#define	LOG_HTTP_PORT						80


#define	MAX_LOG_SIZE_DEFAULT				1073741823ULL

typedef char *(RECORD_PARSE_PROC)(RECORD *rec);

// Packet log structure
struct PACKET_LOG
{
	CEDAR *Cedar;
	struct PKT *Packet;
	char *SrcSessionName;
	char *DestSessionName;
	bool WritePhysicalIP;
	char SrcPhysicalIP[64];
	char DestPhysicalIP[64];
	bool PurePacket;						// Packet not cloned
	bool PurePacketNoPayload;				// Packet not cloned (without payload)
	SESSION *SrcSession;
	bool NoLog;								// Not to write a log
};

// Log save options of the HUB
struct HUB_LOG
{
	bool SaveSecurityLog;					// To save the security log
	UINT SecurityLogSwitchType;				// Switching type of security log
	bool SavePacketLog;						// To save the packet log
	UINT PacketLogSwitchType;				// Switching type of packet log
	UINT PacketLogConfig[NUM_PACKET_LOG];	// Packet log settings
};

// Record
struct RECORD
{
	UINT64 Tick;							// Time
	RECORD_PARSE_PROC *ParseProc;			// Parsing procedure
	void *Data;								// Data
};

// LOG object
struct LOG
{
	LOCK *lock;								// Lock
	THREAD *Thread;							// Thread
	char *DirName;							// Destination directory name
	char *Prefix;							// File name
	UINT SwitchType;						// Switching type of log file
	QUEUE *RecordQueue;						// Record queue
	volatile bool Halt;						// Halting flag
	EVENT *Event;							// Event for Log
	EVENT *FlushEvent;						// Flash completion event
	bool CacheFlag;
	UINT64 LastTick;
	UINT LastSwitchType;
	char LastStr[MAX_SIZE];
	UINT64 CurrentFilePointer;				// The current file pointer
	UINT CurrentLogNumber;					// Log file number of the current
	bool log_number_incremented;
};


// ERASER object
struct ERASER
{
	LOG *Log;								// Logger
	UINT64 MinFreeSpace;					// Disk space to start deleting files
	char *DirName;							// Directory name
	volatile bool Halt;						// Halting flag
	THREAD *Thread;							// Thread
	bool LastFailed;						// Whether deletion of the file failed at the end
	EVENT *HaltEvent;						// Halting event
};

// List of files that can be deleted
typedef struct ERASE_FILE
{
	char *FullPath;							// Full path
	UINT64 UpdateTime;						// Updating date
} ERASE_FILE;

// SYSLOG object
struct SLOG
{
	LOCK *lock;								// Lock
	SOCK *Udp;								// UDP socket
	IP DestIp;								// Destination IP address
	UINT DestPort;							// Destination port number
	char HostName[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT64 NextPollIp;						// Time of examination of the IP address at the end
};

// Function prototype
LOG *NewLog(char *dir, char *prefix, UINT switch_type);
void FreeLog(LOG *g);
void LogThread(THREAD *thread, void *param);
void WaitLogFlush(LOG *g);
void LockLog(LOG *g);
void UnlockLog(LOG *g);
void InsertRecord(LOG *g, void *data, RECORD_PARSE_PROC *proc);
void InsertStringRecord(LOG *g, char *str);
void InsertUnicodeRecord(LOG *g, wchar_t *unistr);
char *StringRecordParseProc(RECORD *rec);
bool MakeLogFileName(LOG *g, char *name, UINT size, char *dir, char *prefix, UINT64 tick, UINT switch_type, UINT num, char *old_datestr);
void MakeLogFileNameStringFromTick(LOG *g, char *str, UINT size, UINT64 tick, UINT switch_type);
void WriteRecordToBuffer(BUF *b, RECORD *r);
void SetLogDirName(LOG *g, char *dir);
void SetLogPrefix(LOG *g, char *prefix);
void SetLogSwitchType(LOG *g, UINT switch_type);
bool PacketLog(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *packet, UINT64 now);
char *PacketLogParseProc(RECORD *rec);
UINT CalcPacketLoggingLevel(HUB *hub, PKT *packet);
UINT CalcPacketLoggingLevelEx(HUB_LOG *g, PKT *packet);
char *GenCsvLine(TOKEN_LIST *t);
void ReplaceForCsv(char *str);
char *PortStr(CEDAR *cedar, UINT port, bool udp);
char *TcpFlagStr(UCHAR flag);
void WriteSecurityLog(HUB *h, char *str);
void SecLog(HUB *h, char *fmt, ...);
void SiSetDefaultLogSetting(HUB_LOG *g);
void DebugLog(CEDAR *c, char *fmt, ...);
void HubLog(HUB *h, wchar_t *fmt, ...);
void ServerLog(CEDAR *c, wchar_t *fmt, ...);
void SLog(CEDAR *c, char *name, ...);
void WriteHubLog(HUB *h, wchar_t *str);
void HLog(HUB *h, char *name, ...);
void NLog(VH *v, char *name, ...);
void IPCLog(IPC *ipc, char *name, ...);
void PPPLog(PPP_SESSION *p, char *name, ...);
void IPsecLog(IKE_SERVER *ike, IKE_CLIENT *c, IKE_SA *ike_sa, IPSECSA *ipsec_sa, char *name, ...);
void EtherIPLog(ETHERIP_SERVER *s, char *name, ...);
void WriteServerLog(CEDAR *c, wchar_t *str);
void ALog(ADMIN *a, HUB *h, char *name, ...);
void CLog(CLIENT *c, char *name, ...);
void WriteClientLog(CLIENT *c, wchar_t *str);
ERASER *NewEraser(LOG *log, UINT64 min_size);
void FreeEraser(ERASER *e);
void ELog(ERASER *e, char *name, ...);
void EraserThread(THREAD *t, void *p);
void EraserMain(ERASER *e);
bool CheckEraserDiskFreeSpace(ERASER *e);
int CompareEraseFile(void *p1, void *p2);
LIST *GenerateEraseFileList(ERASER *e);
void FreeEraseFileList(LIST *o);
void PrintEraseFileList(LIST *o);
void EnumEraseFile(LIST *o, char *dirname);
SLOG *NewSysLog(char *hostname, UINT port);
void SetSysLog(SLOG *g, char *hostname, UINT port);
void FreeSysLog(SLOG *g);
void SendSysLog(SLOG *g, wchar_t *str);
void WriteMultiLineLog(LOG *g, BUF *b);
char *BuildHttpLogStr(HTTPLOG *h);
void MakeSafeLogStr(char *str);
void AddLogBufToStr(BUF *b, char *name, char *value);
void SetEraserCheckInterval(UINT interval);
UINT GetEraserCheckInterval();
void SetMaxLogSize(UINT64 size);
UINT64 GetMaxLogSize();

//////////////////////////////////////////////////////////////////////////
// Connection


// Magic number indicating that the packet is compressed
#define	CONNECTION_BULK_COMPRESS_SIGNATURE	0xDEADBEEFCAFEFACEULL

#define	KEEP_ALIVE_STRING				"Internet Connection Keep Alive Packet"

#define	UPDATE_LAST_COMM_TIME(v, n)		{if ((v) <= (n)) { v = (n); } }

// KEEP CONNECT structure
struct KEEP
{
	LOCK *lock;										// Lock
	bool Server;									// Server mode
	volatile bool Halt;								// Stop flag
	bool Enable;									// Enable flag
	char ServerName[MAX_HOST_NAME_LEN + 1];			// Server name
	UINT ServerPort;								// Server port number
	bool UdpMode;									// UDP mode
	UINT Interval;									// Packet transmission interval
	THREAD *Thread;									// Connection thread
	EVENT *HaltEvent;								// Stop event
	CANCEL *Cancel;									// Cancel
};

// SECURE_SIGN Structure
struct SECURE_SIGN
{
	char SecurePublicCertName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// Secure device certificate name
	char SecurePrivateKeyName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// Secure device secret key name
	X *ClientCert;					// Client certificate
	UCHAR Random[SHA1_SIZE];		// Random value for signature
	UCHAR Signature[4096 / 8];		// Signed data
	UINT UseSecureDeviceId;
	UINT BitmapId;					// Bitmap ID
};

// Function type declaration
typedef bool (CHECK_CERT_PROC)(SESSION *s, CONNECTION *c, X *server_x, bool *expired);
typedef bool (SECURE_SIGN_PROC)(SESSION *s, CONNECTION *c, SECURE_SIGN *sign);

// RC4 key pair
struct RC4_KEY_PAIR
{
	UCHAR ServerToClientKey[16];
	UCHAR ClientToServerKey[16];
};

// Client Options
struct CLIENT_OPTION
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Connection setting name
	char Hostname[MAX_HOST_NAME_LEN + 1];			// Host name
	UINT Port;										// Port number
	UINT PortUDP;									// UDP port number (0: Use only TCP)
	UINT ProxyType;									// Type of proxy
	char ProxyName[MAX_HOST_NAME_LEN + 1];			// Proxy server name
	UINT ProxyPort;									// Port number of the proxy server
	char ProxyUsername[MAX_PROXY_USERNAME_LEN + 1];	// Maximum user name length
	char ProxyPassword[MAX_PROXY_PASSWORD_LEN + 1];	// Maximum password length
	UINT NumRetry;									// Automatic retries
	UINT RetryInterval;								// Retry interval
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB name
	UINT MaxConnection;								// Maximum number of concurrent TCP connections
	bool UseEncrypt;								// Use encrypted communication
	bool UseCompress;								// Use data compression
	bool HalfConnection;							// Use half connection in TCP
	bool NoRoutingTracking;							// Disable the routing tracking
	char DeviceName[MAX_DEVICE_NAME_LEN + 1];		// VLAN device name
	UINT AdditionalConnectionInterval;				// Connection attempt interval when additional connection establish
	UINT ConnectionDisconnectSpan;					// Disconnection interval
	bool HideStatusWindow;							// Hide the status window
	bool HideNicInfoWindow;							// Hide the NIC status window
	bool RequireMonitorMode;						// Monitor port mode
	bool RequireBridgeRoutingMode;					// Bridge or routing mode
	bool DisableQoS;								// Disable the VoIP / QoS function
	bool FromAdminPack;								// For Administration Pack
	bool NoTls1;									// Do not use TLS 1.0
	bool NoUdpAcceleration;							// Do not use UDP acceleration mode
	UCHAR HostUniqueKey[SHA1_SIZE];					// Host unique key
};

// Client authentication data
struct CLIENT_AUTH
{
	UINT AuthType;									// Authentication type
	char Username[MAX_USERNAME_LEN + 1];			// User name
	UCHAR HashedPassword[SHA1_SIZE];				// Hashed passwords
	char PlainPassword[MAX_PASSWORD_LEN + 1];		// Password
	X *ClientX;										// Client certificate
	K *ClientK;										// Client private key
	char SecurePublicCertName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// Secure device certificate name
	char SecurePrivateKeyName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// Secure device secret key name
	CHECK_CERT_PROC *CheckCertProc;					// Server certificate confirmation procedure
	SECURE_SIGN_PROC *SecureSignProc;				// Security signing procedure
};

// TCP socket data structure
struct TCPSOCK
{
	SOCK *Sock;						// Socket
	FIFO *RecvFifo;					// Reception buffer
	FIFO *SendFifo;					// Transmission buffer
	UINT Mode;						// Read mode
	UINT WantSize;					// Requested data size
	UINT NextBlockNum;				// Total number of blocks that can be read next
	UINT NextBlockSize;				// Block size that is planned to read next
	UINT CurrentPacketNum;			// Current packet number
	UINT64 LastCommTime;			// Last communicated time
	UINT64 LastRecvTime;			// Time the last data received
	UINT LateCount;					// The number of delay occurences
	UINT Direction;					// Direction
	UINT64 NextKeepAliveTime;		// Next time to send a KeepAlive packet
	RC4_KEY_PAIR Rc4KeyPair;		// RC4 key pair
	CRYPT *SendKey;					// Transmission key
	CRYPT *RecvKey;					// Reception key
	UINT64 DisconnectTick;			// Time to disconnect this connection
	UINT64 EstablishedTick;			// Establishment time
};

// TCP communication data structure
struct TCP
{
	LIST *TcpSockList;				// TCP socket list
};

// UDP communication data structure
struct UDP
{
	SOCK *s;						// UDP socket (for transmission)
	IP ip;							// Destination IP address
	UINT port;						// Destination port number
	UINT64 NextKeepAliveTime;		// Next time to send a KeepAlive packet
	UINT64 Seq;						// Packet sequence number
	UINT64 RecvSeq;
	QUEUE *BufferQueue;				// Queue of buffer to be sent
};

// Data block
struct BLOCK
{
	BOOL Compressed;				// Compression flag
	UINT Size;						// Block size
	UINT SizeofData;				// Data size
	UCHAR *Buf;						// Buffer
	bool PriorityQoS;				// Priority packet for VoIP / QoS function
	UINT Ttl;						// TTL value (Used only in ICMP NAT of Virtual.c)
	UINT Param1;					// Parameter 1
	bool IsFlooding;				// Is flooding packet
};

// Connection structure
struct CONNECTION
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	CEDAR *Cedar;					// Cedar
	struct SESSION *Session;		// Session
	UINT Protocol;					// Protocol
	SOCK *FirstSock;				// Socket for negotiation
	SOCK *TubeSock;					// Socket for in-process communication
	TCP *Tcp;						// TCP communication data structure
	UDP *Udp;						// UDP communication data structure
	bool ServerMode;				// Server mode
	UINT Status;					// Status
	char *Name;						// Connection name
	THREAD *Thread;					// Thread
	volatile bool Halt;				// Stop flag
	UCHAR Random[SHA1_SIZE];		// Random number for Authentication
	UINT ServerVer;					// Server version
	UINT ServerBuild;				// Server build number
	UINT ClientVer;					// Client version
	UINT ClientBuild;				// Client build number
	char ServerStr[MAX_SERVER_STR_LEN + 1];	// Server string
	char ClientStr[MAX_CLIENT_STR_LEN + 1];	// Client string
	UINT Err;						// Error value
	bool ClientConnectError_NoSavePassword;	// Don't save the password for the specified user name
	QUEUE *ReceivedBlocks;			// Block queue that is received
	QUEUE *SendBlocks;				// Block queue planned to be sent
	QUEUE *SendBlocks2;				// Send queue (high priority)
	COUNTER *CurrentNumConnection;	// Counter of the number of current connections
	LIST *ConnectingThreads;		// List of connected threads
	LIST *ConnectingSocks;			// List of the connected sockets
	bool flag1;						// Flag 1
	UCHAR *RecvBuf;					// Receive buffer
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT ServerPort;				// Port number
	bool RestoreServerNameAndPort;	// Flag to restore the  server name and port number to original
	bool UseTicket;					// Ticket using flag
	UCHAR Ticket[SHA1_SIZE];		// Ticket
	UINT CurrentSendQueueSize;		// Total size of the transmission queue
	X *ServerX;						// Server certificate
	X *ClientX;						// Client certificate
	char *CipherName;				// Encryption algorithm name
	UINT64 ConnectedTick;			// Time it is connected
	IP ClientIp;					// Client IP address
	char ClientHostname[MAX_HOST_NAME_LEN + 1];	// Client host name
	UINT Type;						// Type
	bool DontUseTls1;				// Do not use TLS 1.0
	void *hWndForUI;				// Parent window
	bool IsInProc;					// In-process
	char InProcPrefix[64];			// Prefix
	UINT AdditionalConnectionFailedCounter;		// Additional connection failure counter
	UINT64 LastCounterResetTick;	// Time the counter was reset finally
	bool WasSstp;					// Processed the SSTP
	bool WasDatProxy;				// DAT proxy processed
	UCHAR CToken_Hash[SHA1_SIZE];	// CTOKEN_HASH
	UINT LastTcpQueueSize;			// The last queue size of TCP sockets
	UINT LastPacketQueueSize;		// The last queue size of packets
	UINT LastRecvFifoTotalSize;		// The last RecvFifo total size
	UINT LastRecvBlocksNum;			// The last ReceivedBlocks num
};



// Function prototypes

CONNECTION *NewClientConnection(SESSION *s);
CONNECTION *NewClientConnectionEx(SESSION *s, char *client_str, UINT client_ver, UINT client_build);
CONNECTION *NewServerConnection(CEDAR *cedar, SOCK *s, THREAD *t);
void ReleaseConnection(CONNECTION *c);
void CleanupConnection(CONNECTION *c);
int CompareConnection(void *p1, void *p2);
void StopConnection(CONNECTION *c, bool no_wait);
void ConnectionAccept(CONNECTION *c);
void StartTunnelingMode(CONNECTION *c);
void EndTunnelingMode(CONNECTION *c);
void DisconnectTcpSockets(CONNECTION *c);
void ConnectionReceive(CONNECTION *c, CANCEL *c1, CANCEL *c2);
void ConnectionSend(CONNECTION *c, UINT64 now);
TCPSOCK *NewTcpSock(SOCK *s);
void FreeTcpSock(TCPSOCK *ts);
BLOCK *NewBlock(void *data, UINT size, int compress);
void FreeBlock(BLOCK *b);
void StopAllAdditionalConnectThread(CONNECTION *c);
UINT GenNextKeepAliveSpan(CONNECTION *c);
void SendKeepAlive(CONNECTION *c, TCPSOCK *ts);
void DisconnectUDPSockets(CONNECTION *c);
void PutUDPPacketData(CONNECTION *c, void *data, UINT size);
void SendDataWithUDP(SOCK *s, CONNECTION *c);
void InsertReveicedBlockToQueue(CONNECTION *c, BLOCK *block, bool no_lock);
void InitTcpSockRc4Key(TCPSOCK *ts, bool server_mode);
UINT TcpSockRecv(SESSION *s, TCPSOCK *ts, void *data, UINT size);
UINT TcpSockSend(SESSION *s, TCPSOCK *ts, void *data, UINT size);
void WriteSendFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size);
void WriteRecvFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size);
CLIENT_AUTH *CopyClientAuth(CLIENT_AUTH *a);
BUF *NewKeepPacket(bool server_mode);
void KeepThread(THREAD *thread, void *param);
KEEP *StartKeep();
void StopKeep(KEEP *k);
void InRpcSecureSign(SECURE_SIGN *t, PACK *p);
void OutRpcSecureSign(PACK *p, SECURE_SIGN *t);
void FreeRpcSecureSign(SECURE_SIGN *t);
void NormalizeEthMtu(BRIDGE *b, CONNECTION *c, UINT packet_size);
UINT GetMachineRand();


//////////////////////////////////////////////////////////////////////////
// Session.h


// Interval to increment the number of logins after the connection
#define	NUM_LOGIN_INCREMENT_INTERVAL		(30 * 1000)

// Packet adapter function
typedef bool (PA_INIT)(SESSION *s);
typedef CANCEL *(PA_GETCANCEL)(SESSION *s);
typedef UINT(PA_GETNEXTPACKET)(SESSION *s, void **data);
typedef bool (PA_PUTPACKET)(SESSION *s, void *data, UINT size);
typedef void (PA_FREE)(SESSION *s);

// Client related function
typedef void (CLIENT_STATUS_PRINTER)(SESSION *s, wchar_t *status);

// Node information
struct NODE_INFO
{
	char ClientProductName[64];		// Client product name
	UINT ClientProductVer;			// Client version
	UINT ClientProductBuild;		// Client build number
	char ServerProductName[64];		// Server product name
	UINT ServerProductVer;			// Server version
	UINT ServerProductBuild;		// Server build number
	char ClientOsName[64];			// Client OS name
	char ClientOsVer[128];			// Client OS version
	char ClientOsProductId[64];		// Client OS Product ID
	char ClientHostname[64];		// Client host name
	UINT ClientIpAddress;			// Client IP address
	UINT ClientPort;				// Client port number
	char ServerHostname[64];		// Server host name
	UINT ServerIpAddress;			// Server IP address
	UINT ServerPort;				// Server port number
	char ProxyHostname[64];			// Proxy host name
	UINT ProxyIpAddress;			// Proxy Server IP Address
	UINT ProxyPort;					// Proxy port number
	char HubName[64];				// HUB name
	UCHAR UniqueId[16];				// Unique ID
									// The following is for IPv6 support
	UCHAR ClientIpAddress6[16];		// Client IPv6 address
	UCHAR ServerIpAddress6[16];		// Server IP address
	UCHAR ProxyIpAddress6[16];		// Proxy Server IP Address
	char Padding[304 - (16 * 3)];	// Padding
};

// Packet adapter
struct PACKET_ADAPTER
{
	PA_INIT *Init;
	PA_GETCANCEL *GetCancel;
	PA_GETNEXTPACKET *GetNextPacket;
	PA_PUTPACKET *PutPacket;
	PA_FREE *Free;
	void *Param;
	UINT Id;
};

// Packet Adapter IDs
#define	PACKET_ADAPTER_ID_VLAN_WIN32		1


// Session structure
struct SESSION
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	CEDAR *Cedar;					// Cedar
	bool LocalHostSession;			// Local host session
	bool ServerMode;				// Server mode session
	bool NormalClient;				// Connecting session from a regular client (not such as localbridge)
	bool LinkModeClient;			// Link mode client
	bool LinkModeServer;			// Link mode server
	bool SecureNATMode;				// SecureNAT session
	bool BridgeMode;				// Bridge session
	bool BridgeIsEthLoopbackBlock;	// Loopback is disabled on the Ethernet level
	bool VirtualHost;				// Virtual host mode
	bool L3SwitchMode;				// Layer-3 switch mode
	bool InProcMode;				// In-process mode
	THREAD *Thread;					// Management thread
	CONNECTION *Connection;			// Connection
	char ClientIP[64];				// Client IP
	CLIENT_OPTION *ClientOption;	// Client connection options
	CLIENT_AUTH *ClientAuth;		// Client authentication data
	volatile bool Halt;				// Halting flag
	volatile bool CancelConnect;	// Cancel the connection
	EVENT *HaltEvent;				// Halting event
	UINT Err;						// Error value
	HUB *Hub;						// HUB
	CANCEL *Cancel1;				// Cancel object 1
	CANCEL *Cancel2;				// Cancel object 2
	PACKET_ADAPTER *PacketAdapter;	// Packet adapter
	UCHAR UdpSendKey[16];			// UDP encryption key for transmission
	UCHAR UdpRecvKey[16];			// UDP encryption key for reception
	UINT ClientStatus;				// Client Status
	bool RetryFlag;					// Retry flag (client)
	bool ForceStopFlag;				// Forced stop flag (client)
	UINT CurrentRetryCount;			// Current retry counter (client)
	UINT RetryInterval;				// Retry interval (client)
	bool ConnectSucceed;			// Connection success flag (client)
	bool SessionTimeOuted;			// Session times out
	UINT Timeout;					// Time-out period
	UINT64 NextConnectionTime;		// Time to put next additional connection
	IP ServerIP;					// IP address of the server
	bool ClientModeAndUseVLan;		// Use a virtual LAN card in client mode
	bool UseSSLDataEncryption;		// Use SSL data encryption
	LOCK *TrafficLock;				// Traffic data lock
	LINK *Link;						// A reference to the link object
	SNAT *SecureNAT;				// A reference to the SecureNAT object
	BRIDGE *Bridge;					// A reference to the Bridge object
	NODE_INFO NodeInfo;				// Node information
	UINT64 LastIncrementTraffic;	// Last time that updated the traffic data of the user
	bool AdministratorMode;			// Administrator mode
	LIST *CancelList;				// Cancellation list
	L3IF *L3If;						// Layer-3 interface
	IP DefaultDns;					// IP address of the default DNS server
	bool IPv6Session;				// IPv6 session (Physical communication is IPv6)
	UINT VLanId;					// VLAN ID
	UINT UniqueId;					// Unique ID
	UCHAR IpcMacAddress[6];			// MAC address for IPC
	UCHAR Padding[2];

	IP ServerIP_CacheForNextConnect;	// Server IP, cached for next connect

	UINT64 CreatedTime;				// Creation date and time
	UINT64 LastCommTime;			// Last communication date and time
	UINT64 LastCommTimeForDormant;	// Last communication date and time (for dormant)
	TRAFFIC *Traffic;				// Traffic data
	TRAFFIC *OldTraffic;			// Old traffic data
	UINT64 TotalSendSize;			// Total transmitted data size
	UINT64 TotalRecvSize;			// Total received data size
	UINT64 TotalSendSizeReal;		// Total transmitted data size (no compression)
	UINT64 TotalRecvSizeReal;		// Total received data size (no compression)
	char *Name;						// Session name
	char *Username;					// User name
	char UserNameReal[MAX_USERNAME_LEN + 1];	// User name (real)
	char GroupName[MAX_USERNAME_LEN + 1];	// Group name
	POLICY *Policy;					// Policy
	UCHAR SessionKey[SHA1_SIZE];	// Session key
	UINT SessionKey32;				// 32bit session key
	char SessionKeyStr[64];			// Session key string
	UINT MaxConnection;				// Maximum number of concurrent TCP connections
	bool UseEncrypt;				// Use encrypted communication
	bool UseFastRC4;				// Use high speed RC4 encryption
	bool UseCompress;				// Use data compression
	bool HalfConnection;			// Half connection mode
	bool QoS;						// VoIP / QoS
	bool NoSendSignature;			// Do not send a signature
	bool IsOpenVPNL3Session;		// Whether OpenVPN L3 session
	bool IsOpenVPNL2Session;		// Whether OpenVPN L2 session
	UINT NumDisconnected;			// Number of socket disconnection
	bool NoReconnectToSession;		// Disable to reconnect to the session
	char UnderlayProtocol[64];		// Physical communication protocol
	UINT64 FirstConnectionEstablisiedTime;	// Connection completion time of the first connection
	UINT64 CurrentConnectionEstablishTime;	// Completion time of this connection
	UINT NumConnectionsEatablished;	// Number of connections established so far
	UINT AdjustMss;					// MSS adjustment value
	bool IsVPNClientAndVLAN_Win32;	// Is the VPN Client session with a VLAN card (Win32)

	bool IsRUDPSession;				// Whether R-UDP session
	UINT RUdpMss;					// The value of the MSS should be applied while the R-UDP is used
	bool EnableBulkOnRUDP;			// Allow the bulk transfer in the R-UDP session
	bool EnableHMacOnBulkOfRUDP;	// Use the HMAC to sign the bulk transfer of R-UDP session
	bool EnableUdpRecovery;			// Enable the R-UDP recovery

	bool UseUdpAcceleration;		// Use of UDP acceleration mode
	bool UseHMacOnUdpAcceleration;	// Use the HMAC in the UDP acceleration mode
	UDP_ACCEL *UdpAccel;			// UDP acceleration
	bool IsUsingUdpAcceleration;	// Flag of whether the UDP acceleration is used
	UINT UdpAccelMss;				// MSS value to be applied while the UDP acceleration is used
	bool UdpAccelFastDisconnectDetect;	// Fast disconnection detection is enabled

	bool IsAzureSession;			// Whether the session via VPN Azure
	IP AzureRealServerGlobalIp;		// Real global IP of the server-side in the case of session via VPN Azure

	ACCOUNT *Account;				// Client account
	UINT VLanDeviceErrorCount;		// Number of times that the error occurred in the virtual LAN card
	bool Win32HideConnectWindow;	// Hide the status window
	bool Win32HideNicInfoWindow;	// Hide the NIC information window
	bool UserCanceled;				// Canceled by the user
	UINT64 LastTryAddConnectTime;	// Last time that attempted to add a connection

	bool IsMonitorMode;				// Whether the monitor mode
	bool IsBridgeMode;				// Whether the bridge mode
	bool UseClientLicense;			// Number of assigned client licenses
	bool UseBridgeLicense;			// Number of assigned bridge licenses

	COUNTER *LoggingRecordCount;	// Counter for the number of logging records

	bool FreeInfoShowed;			// Whether a warning about Free Edition has already displayed

	bool Client_NoSavePassword;		// Prohibit the password saving
	wchar_t *Client_Message;		// Message that has been sent from the server

	LIST *DelayedPacketList;		// Delayed packet list
	UINT Flag1;

	USER *NumLoginIncrementUserObject;	// User objects to increment the nymber of logins
	HUB *NumLoginIncrementHubObject;	// Virtual HUB object to increment the number of logins
	UINT64 NumLoginIncrementTick;		// Time to perform increment a number of log

	bool FirstTimeHttpRedirect;		// Redirect HTTP only for the first time
	char FirstTimeHttpRedirectUrl[128];	// URL for redirection only the first time
	UINT FirstTimeHttpAccessCheckIp;	// IP address for access checking

										// To examine the maximum number of alowed logging target packets per minute
	UINT64 MaxLoggedPacketsPerMinuteStartTick;	// Inspection start time
	UINT CurrentNumPackets;				// Current number of packets

										// Measures for D-Link bug
	UINT64 LastDLinkSTPPacketSendTick;	// Last D-Link STP packet transmission time
	UCHAR LastDLinkSTPPacketDataHash[MD5_SIZE];	// Last D-Link STP packet hash
};

// Password dialog
struct UI_PASSWORD_DLG
{
	UINT Type;						// Type of password
	char Username[MAX_USERNAME_LEN + 1];	// User name
	char Password[MAX_PASSWORD_LEN + 1];	// Password
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT RetryIntervalSec;			// Time to retry
	EVENT *CancelEvent;				// Event to cancel the dialog display
	bool ProxyServer;				// The authentication by the proxy server
	UINT64 StartTick;				// Start time
	bool AdminMode;					// Administrative mode
	bool ShowNoSavePassword;		// Whether to display a check box that does not save the password
	bool NoSavePassword;			// Mode that not to save the password
	SOCK *Sock;						// Socket
};

// Message dialog
struct UI_MSG_DLG
{
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	char HubName[MAX_HUBNAME_LEN + 1];	// Virtual HUB name
	wchar_t *Msg;					// Body
	SOCK *Sock;						// Socket
	bool Halt;						// Flag to close
};

// NIC information
struct UI_NICINFO
{
	wchar_t AccountName[MAX_SIZE];	// Connection setting name
	char NicName[MAX_SIZE];			// Virtual NIC name

	SOCK *Sock;						// Socket
	bool Halt;						// Flag to close
	ROUTE_CHANGE *RouteChange;		// Routing table change notification
	UINT CurrentIcon;				// Current icon
	UINT64 CloseAfterTime;			// Close automatically
};

// Connection Error dialog
struct UI_CONNECTERROR_DLG
{
	EVENT *CancelEvent;				// Event to cancel the dialog display
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT Err;						// Error code
	UINT CurrentRetryCount;			// Current retry count
	UINT RetryLimit;				// Limit of the number of retries
	UINT64 StartTick;				// Start time
	UINT RetryIntervalSec;			// Time to retry
	bool HideWindow;				// Hide the window
	SOCK *Sock;						// Socket
};

// Server certificate checking dialog
struct UI_CHECKCERT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	X *x;							// Server certificate
	X *parent_x;					// Parent certificate
	X *old_x;						// Certificate of previous
	bool DiffWarning;				// Display a warning of certificate forgery
	bool Ok;						// Connection permission flag
	bool SaveServerCert;			// Save the server certificate
	SESSION *Session;				// Session
	volatile bool Halt;				// Halting flag
	SOCK *Sock;						// Socket
};


// Function prototype
SESSION *NewClientSessionEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa, struct ACCOUNT *account);
SESSION *NewClientSession(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa);
SESSION *NewRpcSession(CEDAR *cedar, CLIENT_OPTION *option);
SESSION *NewRpcSessionEx(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str);
SESSION *NewRpcSessionEx2(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str, void *hWnd);
SESSION *NewServerSession(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy);
SESSION *NewServerSessionEx(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy, bool inproc_mode);
void ClientThread(THREAD *t, void *param);
void ReleaseSession(SESSION *s);
void CleanupSession(SESSION *s);
void StopSession(SESSION *s);
void StopSessionEx(SESSION *s, bool no_wait);
bool SessionConnect(SESSION *s);
bool ClientConnect(CONNECTION *c);
int CompareSession(void *p1, void *p2);
PACKET_ADAPTER *NewPacketAdapter(PA_INIT *init, PA_GETCANCEL *getcancel, PA_GETNEXTPACKET *getnext,
	PA_PUTPACKET *put, PA_FREE *free);
void FreePacketAdapter(PACKET_ADAPTER *pa);
void SessionMain(SESSION *s);
void NewSessionKey(CEDAR *cedar, UCHAR *session_key, UINT *session_key_32);
SESSION *GetSessionFromKey(CEDAR *cedar, UCHAR *session_key);
SESSION *GetSessionFromKey32(CEDAR *cedar, UINT key32);
void DebugPrintSessionKey(UCHAR *session_key);
bool IsIpcMacAddress(UCHAR *mac);
void ClientAdditionalConnectChance(SESSION *s);
void SessionAdditionalConnect(SESSION *s);
void ClientAdditionalThread(THREAD *t, void *param);
void PrintSessionTotalDataSize(SESSION *s);
void AddTrafficForSession(SESSION *s, TRAFFIC *t);
void IncrementUserTraffic(HUB *hub, char *username, SESSION *s);
void Notify(SESSION *s, UINT code);
void PrintStatus(SESSION *s, wchar_t *str);
LIST *NewCancelList();
void ReleaseCancelList(LIST *o);
void AddCancelList(LIST *o, CANCEL *c);
void CancelList(LIST *o);
bool CompareNodeInfo(NODE_INFO *a, NODE_INFO *b);
bool IsPriorityHighestPacketForQoS(void *data, UINT size);
UINT GetNextDelayedPacketTickDiff(SESSION *s);


//////////////////////////////////////////////////////////////////////////
// Remote.h

// RPC execution function
typedef PACK *(RPC_DISPATCHER)(RPC *r, char *function_name, PACK *p);

// RPC object
struct RPC
{
	SOCK *Sock;						// Socket
	bool ServerMode;				// Server mode
	RPC_DISPATCHER *Dispatch;		// Execution routine
	void *Param;					// Parameters
	bool ServerAdminMode;			// Server management mode
	char HubName[MAX_HUBNAME_LEN + 1];	// Managing HUB name
	char Name[MAX_SIZE];			// RPC session name
	LOCK *Lock;						// Lock
	bool IsVpnServer;				// Whether VPN Server management RPC
	CLIENT_OPTION VpnServerClientOption;
	char VpnServerHubName[MAX_HUBNAME_LEN + 1];
	UCHAR VpnServerHashedPassword[SHA1_SIZE];
	char VpnServerClientName[MAX_PATH];
};

// Function prototype
RPC *StartRpcClient(SOCK *s, void *param);
RPC *StartRpcServer(SOCK *s, RPC_DISPATCHER *dispatch, void *param);
PACK *RpcCallInternal(RPC *r, PACK *p);
PACK *RpcCall(RPC *r, char *function_name, PACK *p);
void RpcServer(RPC *r);
bool RpcRecvNextCall(RPC *r);
PACK *CallRpcDispatcher(RPC *r, PACK *p);
void RpcError(PACK *p, UINT err);
bool RpcIsOk(PACK *p);
UINT RpcGetError(PACK *p);
void EndRpc(RPC *rpc);
void RpcFree(RPC *rpc);

//////////////////////////////////////////////////////////////////////////
// Hub.h


// Prefix in the access list for investigating whether the user name which is contained in a particular file 
#define	ACCESS_LIST_INCLUDED_PREFIX		"include:"		// Included
#define	ACCESS_LIST_EXCLUDED_PREFIX		"exclude:"		// Not included

// The default value for the cache expiration of the user name reference file of the access list (in seconds)
#define	ACCESS_LIST_INCLUDE_FILE_CACHE_LIFETIME		30

// The maximum length of the include file in the access list
#define	ACCESS_LIST_INCLUDE_FILE_MAX_SIZE			(1024 * 1024)

// <INFO> tags of the URL in the access list
#define	ACCESS_LIST_URL_INFO_TAG					"<INFO>"

// Old MAC address entry flush interval
#define	OLD_MAC_ADDRESS_ENTRY_FLUSH_INTERVAL		1000

// Default flooding queue length
#define	DEFAULT_FLOODING_QUEUE_LENGTH				(32 * 1024 * 1024)

// SoftEther link control packet
struct SE_LINK
{
	UCHAR DestMacAddress[6];			// Destination MAC address
	UCHAR SrcMacAddress[6];				// Source MAC address
	UCHAR SignatureS;					// 'S'
	UCHAR SignatureE;					// 'E'
	UCHAR Padding[2];					// Padding
	UINT Type;							// Type
	UCHAR HubSignature[16];				// HUB signature
	UINT TransactionId;					// Transaction ID
	UINT Data;							// Data
	UCHAR Dummy[20];					// Dummy
	UCHAR Checksum[SHA1_SIZE];			// Checksum
};


// Test packet reception record
struct TEST_HISTORY
{
	SESSION *s1;
	SESSION *s2;
};

// State machine for link test
struct SE_TEST
{
	LOCK *lock;							// Lock
	UINT64 LastTestPacketSentTime;		// Time that sent the test packet at the last
	UINT NextTestPacketSendInterval;	// Next test packet transmission interval
	bool CurrentTesting;				// Test by sending a test packet currently
	UINT TransactionId;					// Transaction ID
	LIST *TestHistory;					// Reception history
};

// Macro
#define	NO_ACCOUNT_DB(h)		((h)->FarmMember)

// Database in the case of a stand-alone or a farm master HUB
struct HUBDB
{
	LIST *UserList;						// User List
	LIST *GroupList;					// Group List
	LIST *RootCertList;					// Certificate list to trust
	LIST *CrlList;						// CRL list
	LIST *AcList;						// AC List
};

// Traffic limiter
struct TRAFFIC_LIMITER
{
	UINT64 LastTime;					// Time of last measured
	UINT64 Value;						// The current value
};

// Record the number of broadcast of each endpoint
struct STORM
{
	UCHAR MacAddress[6];				// MAC address
	UCHAR Padding[2];					// Padding
	IP SrcIp;							// Source IP address
	IP DestIp;							// Destination IP address
	UINT64 CheckStartTick;				// Time that checking is started
	UINT CurrentBroadcastNum;			// The current number of broadcasts
	UINT DiscardValue;					// Ratio to discard the broadcast packet
	bool StrictMode;					// Strict mode
};

// Packet adapter information structure for HUB
struct HUB_PA
{
	CANCEL *Cancel;						// Cancel object
	QUEUE *PacketQueue;					// Packet queue
	bool MonitorPort;					// Monitor port
	UINT64 Now;							// Current time
	TRAFFIC_LIMITER UploadLimiter;		// Upload bandwidth limit
	TRAFFIC_LIMITER DownloadLimiter;	// Download bandwidth limitation
	SESSION *Session;					// Session
	LIST *StormList;					// Broadcast storm recording list
	UINT64 UsernameHash;				// User name hash
	UINT64 UsernameHashSimple;			// User name hash (simple)
	UINT64 GroupnameHash;				// Group name hash
};

// HUB options
struct HUB_OPTION
{
	// Standard options
	UINT MaxSession;					// Maximum number of simultaneous connections
	bool NoEnum;						// Excluded from the enumeration
										// Advanced options
	bool NoArpPolling;					// No ARP polling
	bool NoIPv6AddrPolling;				// No IPv6 address polling
	bool NoIpTable;						// Do not generate an IP address table
	bool NoMacAddressLog;				// Not to write the registration log of the MAC address
	bool ManageOnlyPrivateIP;			// Manage only private IP
	bool ManageOnlyLocalUnicastIPv6;	// Manage only local unicast IPv6 addresses
	bool DisableIPParsing;				// Disable the IP interpretation
	bool YieldAfterStorePacket;			// Yield after the packet is stored
	bool NoSpinLockForPacketDelay;		// Do not use the spin lock
	UINT BroadcastStormDetectionThreshold;	// Broadcast number limit threshold
	bool FilterPPPoE;					// Filtering the PPPoE (0x8863, 0x8864)
	bool FilterOSPF;					// Filtering the OSPF (ip_proto = 89)
	bool FilterIPv4;					// Filter IPv4 packets
	bool FilterIPv6;					// Filter IPv6 packets
	bool FilterNonIP;					// Filter all non-IP packets
	bool FilterBPDU;					// Filter the BPDU packets
	UINT ClientMinimumRequiredBuild;	// If the build number of the client is lower than a certain value, deny it
	bool NoIPv6DefaultRouterInRAWhenIPv6;	// Delete the default router specification from the IPv6 router advertisement (only in the case of IPv6 physical connection)
	bool NoIPv4PacketLog;				// Do not save the packet log for the IPv4 packet
	bool NoIPv6PacketLog;				// Do not save the packet log of IPv6 packets
	bool NoLookBPDUBridgeId;			// Don't look the BPDU bridge ID for switching
	bool NoManageVlanId;				// Don't manage the VLAN ID
	UINT VlanTypeId;					// Type ID of VLAN packets (usually 0x8100)
	bool FixForDLinkBPDU;				// Apply the fix for the BPDU of the strange behavior of the D-Link
	UINT RequiredClientId;				// Client ID
	UINT AdjustTcpMssValue;				// TCP MSS adjustment value
	bool DisableAdjustTcpMss;			// Completely disable the TCP MSS adjustment function
	bool NoDhcpPacketLogOutsideHub;		// Suppress DHCP unrelated log
	bool DisableHttpParsing;			// Prohibit the HTTP interpretation
	bool DisableUdpAcceleration;		// Prohibit the UDP acceleration function
	bool DisableUdpFilterForLocalBridgeNic;	// Not to perform filtering DHCP packets associated with local bridge NIC
	bool ApplyIPv4AccessListOnArpPacket;	// Apply an IPv4 access list to the ARP packet
	bool RemoveDefGwOnDhcpForLocalhost;	// Remove the designation of the DHCP server from the DHCP response packet addressed to localhost
	UINT SecureNAT_MaxTcpSessionsPerIp;		// Maximum number of TCP sessions per IP address
	UINT SecureNAT_MaxTcpSynSentPerIp;		// Maximum number of TCP sessions of SYN_SENT state per IP address
	UINT SecureNAT_MaxUdpSessionsPerIp;		// Maximum number of UDP sessions per IP address
	UINT SecureNAT_MaxDnsSessionsPerIp;		// Maximum number of DNS sessions per IP address
	UINT SecureNAT_MaxIcmpSessionsPerIp;	// Maximum number of ICMP sessions per IP address
	UINT AccessListIncludeFileCacheLifetime;	// Expiration of the access list external file (in seconds)
	bool DisableKernelModeSecureNAT;			// Disable the kernel mode NAT
	bool DisableIpRawModeSecureNAT;			// Disable the IP Raw Mode NAT
	bool DisableUserModeSecureNAT;			// Disable the user mode NAT
	bool DisableCheckMacOnLocalBridge;	// Disable the MAC address verification in local bridge
	bool DisableCorrectIpOffloadChecksum;	// Disable the correction of checksum that is IP-Offloaded
	bool BroadcastLimiterStrictMode;	// Strictly broadcast packets limiting mode
	UINT MaxLoggedPacketsPerMinute;		// Maximum number of logging target packets per minute
	bool DoNotSaveHeavySecurityLogs;	// Do not take heavy security log
	bool DropBroadcastsInPrivacyFilterMode;	// Drop broadcasting packets if the both source and destination session is PrivacyFilter mode
	bool DropArpInPrivacyFilterMode;	// Drop ARP packets if the both source and destination session is PrivacyFilter mode
	bool SuppressClientUpdateNotification;	// Suppress the update notification function on the VPN Client
	UINT FloodingSendQueueBufferQuota;	// The global quota of send queues of flooding packets
	bool AssignVLanIdByRadiusAttribute;	// Assign the VLAN ID for the VPN session, by the attribute value of RADIUS
	bool DenyAllRadiusLoginWithNoVlanAssign;	// Deny all RADIUS login with no VLAN ID assigned
	bool SecureNAT_RandomizeAssignIp;	// Randomize the assignment IP address for new DHCP client
	UINT DetectDormantSessionInterval;	// Interval (seconds) threshold to detect a dormant VPN session
	bool NoPhysicalIPOnPacketLog;		// Disable saving physical IP address on the packet log
	bool UseHubNameAsDhcpUserClassOption;	// Add HubName to DHCP request as User-Class option
	bool UseHubNameAsRadiusNasId;		// Add HubName to Radius request as NAS-Identifier attrioption
};

// MAC table entry
struct MAC_TABLE_ENTRY
{
	UCHAR MacAddress[6];				// MAC address
	UCHAR Padding[2];
	UINT VlanId;						// VLAN ID
	SESSION *Session;					// Session
	HUB_PA *HubPa;						// HUB packet adapter
	UINT64 CreatedTime;					// Creation date and time
	UINT64 UpdatedTime;					// Updating date
};

// IP table entry
struct IP_TABLE_ENTRY
{
	IP Ip;								// IP address
	SESSION *Session;					// Session
	bool DhcpAllocated;					// Assigned by DHCP
	UINT64 CreatedTime;					// Creation date and time
	UINT64 UpdatedTime;					// Updating date
	UCHAR MacAddress[6];				// MAC address
};

// Loop List
struct LOOP_LIST
{
	UINT NumSessions;
	SESSION **Session;
};

// Access list
struct ACCESS
{
	// IPv4
	UINT Id;							// ID
	wchar_t Note[MAX_ACCESSLIST_NOTE_LEN + 1];	// Note

												// --- Please add items to the bottom of here for enhancements ---
	bool Active;						// Enable flag
	UINT Priority;						// Priority
	bool Discard;						// Discard flag
	UINT SrcIpAddress;					// Source IP address
	UINT SrcSubnetMask;					// Source subnet mask
	UINT DestIpAddress;					// Destination IP address
	UINT DestSubnetMask;				// Destination subnet mask
	UINT Protocol;						// Protocol
	UINT SrcPortStart;					// Source port number starting point
	UINT SrcPortEnd;					// Source port number end point
	UINT DestPortStart;					// Destination port number starting point
	UINT DestPortEnd;					// Destination port number end point
	UINT64 SrcUsernameHash;				// Source user name hash
	bool IsSrcUsernameIncludeOrExclude;	// The source user name is formed as the "include:" or "exclude:"
	char SrcUsername[MAX_USERNAME_LEN + 1];
	bool IsDestUsernameIncludeOrExclude;	// The destination user name is formed as "include:" or "exclude:"
	UINT64 DestUsernameHash;			// Destination user name hash
	char DestUsername[MAX_USERNAME_LEN + 1];
	bool CheckSrcMac;					// Presence of a source MAC address setting
	UCHAR SrcMacAddress[6];				// Source MAC address
	UCHAR SrcMacMask[6];				// Source MAC address mask
	bool CheckDstMac;					// Whether the setting of the destination MAC address exists
	UCHAR DstMacAddress[6];				// Destination MAC address
	UCHAR DstMacMask[6];				// Destination MAC address mask
	bool CheckTcpState;					// The state of the TCP connection
	bool Established;					// Establieshed(TCP)
	UINT Delay;							// Delay
	UINT Jitter;						// Jitter
	UINT Loss;							// Packet loss
	char RedirectUrl[MAX_REDIRECT_URL_LEN + 1];	// URL to redirect to

												// IPv6
	bool IsIPv6;						// Whether it's an IPv6
	IPV6_ADDR SrcIpAddress6;			// The source IP address (IPv6)
	IPV6_ADDR SrcSubnetMask6;			// Source subnet mask (IPv6)
	IPV6_ADDR DestIpAddress6;			// Destination IP address (IPv6)
	IPV6_ADDR DestSubnetMask6;			// Destination subnet mask (IPv6)

										// --- Please add items to the above of here for enhancements ---

										// For management
	UINT UniqueId;						// Unique ID
};

// Ticket
struct TICKET
{
	UINT64 CreatedTick;						// Creation date and time
	UCHAR Ticket[SHA1_SIZE];				// Ticket
	char Username[MAX_USERNAME_LEN + 1];	// User name
	char UsernameReal[MAX_USERNAME_LEN + 1];	// Real user name
	char GroupName[MAX_USERNAME_LEN + 1];	// Group name
	char SessionName[MAX_SESSION_NAME_LEN + 1];	// Session name
	POLICY Policy;							// Policy
};

// Traffic difference
struct TRAFFIC_DIFF
{
	UINT Type;							// Type
	TRAFFIC Traffic;					// Traffic
	char *HubName;						// HUB name
	char *Name;							// Name
};

// Administration options
struct ADMIN_OPTION
{
	char Name[MAX_ADMIN_OPTION_NAME_LEN + 1];	// Name
	UINT Value;									// Data
};

// Certificate Revocation List entry
struct CRL
{
	X_SERIAL *Serial;					// Serial number
	NAME *Name;							// Name information
	UCHAR DigestMD5[MD5_SIZE];			// MD5 hash
	UCHAR DigestSHA1[SHA1_SIZE];		// SHA-1 hash
};

// Access control
struct AC
{
	UINT Id;							// ID
	UINT Priority;						// Priority
	bool Deny;							// Deny access
	bool Masked;						// Is masked
	IP IpAddress;						// IP address
	IP SubnetMask;						// Subnet mask
};

// User List
struct USERLIST
{
	char Filename[MAX_PATH];			// File name
	LIST *UserHashList;					// Hash list of user names
};

// HUB structure
struct HUB
{
	LOCK *lock;							// Lock
	LOCK *lock_online;					// Lock for Online
	REF *ref;							// Reference counter
	CEDAR *Cedar;						// Cedar
	UINT Type;							// Type
	HUBDB *HubDb;						// Database
	char *Name;							// The name of the HUB
	LOCK *RadiusOptionLock;				// Lock for Radius option
	char *RadiusServerName;				// Radius server name
	UINT RadiusServerPort;				// Radius server port number
	UINT RadiusRetryInterval;			// Radius retry interval
	BUF *RadiusSecret;					// Radius shared key
	char RadiusSuffixFilter[MAX_SIZE];	// Radius suffix filter
	char RadiusRealm[MAX_SIZE];			// Radius realm (optional)
	bool RadiusConvertAllMsChapv2AuthRequestToEap;	// Convert all MS-CHAPv2 auth request to EAP
	bool RadiusUsePeapInsteadOfEap;			// Use PEAP instead of EAP
	volatile bool Halt;					// Halting flag
	bool Offline;						// Offline
	bool BeingOffline;					// Be Doing Offline
	LIST *SessionList;					// Session list
	COUNTER *SessionCounter;			// Session number generation counter
	TRAFFIC *Traffic;					// Traffic information
	TRAFFIC *OldTraffic;				// Old traffic information
	LOCK *TrafficLock;					// Traffic lock
	COUNTER *NumSessions;				// The current number of sessions
	COUNTER *NumSessionsClient;			// The current number of sessions (client)
	COUNTER *NumSessionsBridge;			// The current number of sessions (bridge)
	HUB_OPTION *Option;					// HUB options
	HASH_LIST *MacHashTable;			// MAC address hash table
	LIST *IpTable;						// IP address table
	LIST *MonitorList;					// Monitor port session list
	LIST *LinkList;						// Linked list
	UCHAR HubSignature[16];				// HUB signature
	UCHAR HubMacAddr[6];				// MAC address of the HUB
	IP HubIp;							// IP address of the HUB (IPv4)
	IPV6_ADDR HubIpV6;					// IP address of the HUB (IPv6)
	UINT HubIP6Id;						// IPv6 packet ID of the HUB
	UCHAR Padding[2];					// Padding
	LOCK *LoopListLock;					// Lock for the loop list
	UINT NumLoopList;					// Number of loop lists
	LOOP_LIST **LoopLists;				// Loop List
	LIST *AccessList;					// Access list
	HUB_LOG LogSetting;					// Log Settings
	LOG *PacketLogger;					// Packet logger
	LOG *SecurityLogger;				// Security logger
	UCHAR HashedPassword[SHA1_SIZE];	// Password
	UCHAR SecurePassword[SHA1_SIZE];	// Secure password
	LIST *TicketList;					// Ticket list
	bool FarmMember;					// Farm member
	UINT64 LastIncrementTraffic;		// Traffic reporting time
	UINT64 LastSendArpTick;				// ARP transmission time of the last
	SNAT *SecureNAT;					// SecureNAT
	bool EnableSecureNAT;				// SecureNAT enable / disable flag
	VH_OPTION *SecureNATOption;			// SecureNAT Option
	THREAD *WatchDogThread;				// Watchdog thread
	EVENT *WatchDogEvent;				// Watchdog event
	bool WatchDogStarted;				// Whether the watchdog thread is used
	volatile bool HaltWatchDog;			// Stop the watchdog thread
	LIST *AdminOptionList;				// Administration options list
	UINT64 CreatedTime;					// Creation date and time
	UINT64 LastCommTime;				// Last communication date and time
	UINT64 LastLoginTime;				// Last login date and time
	UINT NumLogin;						// Number of logins
	bool HubIsOnlineButHalting;			// Virtual HUB is really online, but it is in offline state to stop
	UINT FarmMember_MaxSessionClient;	// Maximum client connection sessions for cluster members
	UINT FarmMember_MaxSessionBridge;	// Maximum bridge connection sessions for cluster members
	bool FarmMember_MaxSessionClientBridgeApply;	// Apply the FarmMember_MaxSession*
	UINT CurrentVersion;				// The current version
	UINT LastVersion;					// Version of when the update notification is issued at the last
	wchar_t *Msg;						// Message to be displayed when the client is connected
	LIST *UserList;						// Cache of the user list file
	bool IsVgsHub;						// Whether it's a VGS Virtual HUB
	bool IsVgsSuperRelayHub;			// Whether it's a VGS Super Relay Virtual HUB
	UINT64 LastFlushTick;				// Last tick to flush the MAC address table
	bool StopAllLinkFlag;				// Stop all link flag
	bool ForceDisableComm;				// Disable the communication function
};


// Global variable
extern ADMIN_OPTION admin_options[];
extern UINT num_admin_options;


// Function prototype
HUBDB *NewHubDb();
void DeleteHubDb(HUBDB *d);
HUB *NewHub(CEDAR *cedar, char *HubName, HUB_OPTION *option);
void SetHubMsg(HUB *h, wchar_t *msg);
wchar_t *GetHubMsg(HUB *h);
void GenHubMacAddress(UCHAR *mac, char *name);
void GenHubIpAddress(IP *ip, char *name);
bool IsHubIpAddress(IP *ip);
bool IsHubIpAddress32(UINT ip32);
bool IsHubIpAddress64(IPV6_ADDR *addr);
bool IsHubMacAddress(UCHAR *mac);
void ReleaseHub(HUB *h);
void CleanupHub(HUB *h);
int CompareHub(void *p1, void *p2);
void LockHubList(CEDAR *cedar);
void UnlockHubList(CEDAR *cedar);
HUB *GetHub(CEDAR *cedar, char *name);
bool IsHub(CEDAR *cedar, char *name);
void StopHub(HUB *h);
void AddSession(HUB *h, SESSION *s);
void DelSession(HUB *h, SESSION *s);
SESSION *SearchSessionByUniqueId(HUB *h, UINT id);
UINT GetNewUniqueId(HUB *h);
void StopAllSession(HUB *h);
bool HubPaInit(SESSION *s);
void HubPaFree(SESSION *s);
CANCEL *HubPaGetCancel(SESSION *s);
UINT HubPaGetNextPacket(SESSION *s, void **data);
bool HubPaPutPacket(SESSION *s, void *data, UINT size);
PACKET_ADAPTER *GetHubPacketAdapter();
int CompareMacTable(void *p1, void *p2);
UINT GetHashOfMacTable(void *p);
void StorePacket(HUB *hub, SESSION *s, PKT *packet);
bool StorePacketFilter(SESSION *s, PKT *packet);
void StorePacketToHubPa(HUB_PA *dest, SESSION *src, void *data, UINT size, PKT *packet, bool is_flooding, bool no_check_acl);
void SetHubOnline(HUB *h);
void SetHubOffline(HUB *h);
SESSION *GetSessionByPtr(HUB *hub, void *ptr);
SESSION *GetSessionByName(HUB *hub, char *name);
int CompareIpTable(void *p1, void *p2);
bool StorePacketFilterByPolicy(SESSION *s, PKT *p);
bool DeleteIPv6DefaultRouterInRA(PKT *p);
bool StorePacketFilterByTrafficLimiter(SESSION *s, PKT *p);
void IntoTrafficLimiter(TRAFFIC_LIMITER *tr, PKT *p);
bool IsMostHighestPriorityPacket(SESSION *s, PKT *p);
bool IsPriorityPacketForQoS(PKT *p);
int CompareStormList(void *p1, void *p2);
STORM *SearchStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict);
STORM *AddStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict);
bool CheckBroadcastStorm(HUB *hub, SESSION *s, PKT *p);
void AddRootCert(HUB *hub, X *x);
int CmpAccessList(void *p1, void *p2);
void InitAccessList(HUB *hub);
void FreeAccessList(HUB *hub);
void AddAccessList(HUB *hub, ACCESS *a);
void AddAccessListEx(HUB *hub, ACCESS *a, bool no_sort, bool no_reassign_id);
bool SetSessionFirstRedirectHttpUrl(SESSION *s, char *url);
bool IsTcpPacketNcsiHttpAccess(PKT *p);
UINT64 UsernameToInt64(char *name);
void MakeSimpleUsernameRemoveNtDomain(char *dst, UINT dst_size, char *src);
bool ApplyAccessListToStoredPacket(HUB *hub, SESSION *s, PKT *p);
void ForceRedirectToUrl(HUB *hub, SESSION *src_session, PKT *p, char *redirect_url);
BUF *BuildRedirectToUrlPayload(HUB *hub, SESSION *s, char *redirect_url);
bool ApplyAccessListToForwardPacket(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *p);
bool IsPacketMaskedByAccessList(SESSION *s, PKT *p, ACCESS *a, UINT64 dest_username, UINT64 dest_groupname, SESSION *dest_session);
void GetAccessListStr(char *str, UINT size, ACCESS *a);
void DeleteOldIpTableEntry(LIST *o);
void SetRadiusServer(HUB *hub, char *name, UINT port, char *secret);
void SetRadiusServerEx(HUB *hub, char *name, UINT port, char *secret, UINT interval);
bool GetRadiusServer(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size);
bool GetRadiusServerEx(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size, UINT *interval);
bool GetRadiusServerEx2(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size, UINT *interval, char *suffix_filter, UINT suffix_filter_size);
int CompareCert(void *p1, void *p2);
void GetHubLogSetting(HUB *h, HUB_LOG *setting);
void SetHubLogSetting(HUB *h, HUB_LOG *setting);
void SetHubLogSettingEx(HUB *h, HUB_LOG *setting, bool no_change_switch_type);
void DeleteExpiredIpTableEntry(LIST *o);
void DeleteExpiredMacTableEntry(HASH_LIST *h);
void AddTrafficDiff(HUB *h, char *name, UINT type, TRAFFIC *traffic);
void IncrementHubTraffic(HUB *h);
void EnableSecureNAT(HUB *h, bool enable);
void EnableSecureNATEx(HUB *h, bool enable, bool no_change);
void StartHubWatchDog(HUB *h);
void StopHubWatchDog(HUB *h);
void HubWatchDogThread(THREAD *t, void *param);
int CompareAdminOption(void *p1, void *p2);
UINT GetHubAdminOptionEx(HUB *h, char *name, UINT default_value);
UINT GetHubAdminOption(HUB *h, char *name);
void DeleteAllHubAdminOption(HUB *h, bool lock);
void AddHubAdminOptionsDefaults(HUB *h, bool lock);
bool IsCertMatchCrl(X *x, CRL *crl);
bool IsCertMatchCrlList(X *x, LIST *o);
wchar_t *GenerateCrlStr(CRL *crl);
bool IsValidCertInHub(HUB *h, X *x);
void FreeCrl(CRL *crl);
CRL *CopyCrl(CRL *crl);
int CmpAc(void *p1, void *p2);
LIST *NewAcList();
void AddAc(LIST *o, AC *ac);
bool DelAc(LIST *o, UINT id);
AC *GetAc(LIST *o, UINT id);
void SetAc(LIST *o, UINT id, AC *ac);
void DelAllAc(LIST *o);
void SetAcList(LIST *o, LIST *src);
void NormalizeAcList(LIST *o);
bool IsIpMaskedByAc(IP *ip, AC *ac);
bool IsIpDeniedByAcList(IP *ip, LIST *o);
char *GenerateAcStr(AC *ac);
void FreeAcList(LIST *o);
LIST *CloneAcList(LIST *o);
bool IsIPManagementTargetForHUB(IP *ip, HUB *hub);
wchar_t *GetHubAdminOptionHelpString(char *name);
void HubOptionStructToData(RPC_ADMIN_OPTION *ao, HUB_OPTION *o, char *hub_name);
ADMIN_OPTION *NewAdminOption(char *name, UINT value);
void DataToHubOptionStruct(HUB_OPTION *o, RPC_ADMIN_OPTION *ao);
UINT GetHubAdminOptionData(RPC_ADMIN_OPTION *ao, char *name);
void GetHubAdminOptionDataAndSet(RPC_ADMIN_OPTION *ao, char *name, UINT *dest);
bool IsURLMsg(wchar_t *str, char *url, UINT url_size);
LIST *NewUserList();
void DeleteAllUserListCache(LIST *o);
void FreeUserList(LIST *o);
void FreeUserListEntry(USERLIST *u);
int CompareUserList(void *p1, void *p2);
USERLIST *LoadUserList(LIST *o, char *filename);
USERLIST *FindUserList(LIST *o, char *filename);
bool IsUserMatchInUserList(LIST *o, char *filename, UINT64 user_hash);
bool IsUserMatchInUserListWithCacheExpires(LIST *o, char *filename, UINT64 user_hash, UINT64 lifetime);
bool IsUserMatchInUserListWithCacheExpiresAcl(LIST *o, char *name_in_acl, UINT64 user_hash, UINT64 lifetime);
void CalcTrafficEntryDiff(TRAFFIC_ENTRY *diff, TRAFFIC_ENTRY *old, TRAFFIC_ENTRY *current);
void CalcTrafficDiff(TRAFFIC *diff, TRAFFIC *old, TRAFFIC *current);
bool CheckMaxLoggedPacketsPerMinute(SESSION *s, UINT max_packets, UINT64 now);
void VgsSetUserAgentValue(char *str);
void VgsSetEmbTag(bool b);
EAP_CLIENT *HubNewEapClient(CEDAR *cedar, char *hubname, char *client_ip_str, char *username);



//////////////////////////////////////////////////////////////////////////
// Sam.h


// Function prototype
bool SamIsUser(HUB *h, char *username);
UINT SamGetUserAuthType(HUB *h, char *username);
bool SamAuthUserByPassword(HUB *h, char *username, void *random, void *secure_password, char *mschap_v2_password, UCHAR *mschap_v2_server_response_20, UINT *err);
bool SamAuthUserByAnonymous(HUB *h, char *username);
bool SamAuthUserByCert(HUB *h, char *username, X *x);
bool SamAuthUserByPlainPassword(CONNECTION *c, HUB *hub, char *username, char *password, bool ast, UCHAR *mschap_v2_server_response_20, RADIUS_LOGIN_OPTION *opt);
POLICY *SamGetUserPolicy(HUB *h, char *username);

void GenRamdom(void *random);
void SecurePassword(void *secure_password, void *password, void *random);
X *GetIssuerFromList(LIST *cert_list, X *cert);


//////////////////////////////////////////////////////////////////////////
// Radius.h



#define	RADIUS_DEFAULT_PORT		1812			// The default port number
#define	RADIUS_RETRY_INTERVAL	500				// Retransmission interval
#define	RADIUS_RETRY_TIMEOUT	(10 * 1000)		// Time-out period
#define	RADIUS_INITIAL_EAP_TIMEOUT	1600		// Initial timeout for EAP


// RADIUS attributes
#define	RADIUS_ATTRIBUTE_USER_NAME					1
#define	RADIUS_ATTRIBUTE_NAS_IP						4
#define	RADIUS_ATTRIBUTE_NAS_PORT					5
#define	RADIUS_ATTRIBUTE_SERVICE_TYPE				6
#define	RADIUS_ATTRIBUTE_FRAMED_PROTOCOL			7
#define	RADIUS_ATTRIBUTE_FRAMED_MTU					12
#define	RADIUS_ATTRIBUTE_STATE						24
#define	RADIUS_ATTRIBUTE_VENDOR_SPECIFIC			26
#define	RADIUS_ATTRIBUTE_CALLED_STATION_ID			30
#define	RADIUS_ATTRIBUTE_CALLING_STATION_ID			31
#define	RADIUS_ATTRIBUTE_NAS_ID						32
#define	RADIUS_ATTRIBUTE_PROXY_STATE				33
#define	RADIUS_ATTRIBUTE_ACCT_SESSION_ID			44
#define	RADIUS_ATTRIBUTE_NAS_PORT_TYPE				61
#define	RADIUS_ATTRIBUTE_TUNNEL_TYPE				64
#define	RADIUS_ATTRIBUTE_TUNNEL_MEDIUM_TYPE			65
#define	RADIUS_ATTRIBUTE_TUNNEL_CLIENT_ENDPOINT		66
#define	RADIUS_ATTRIBUTE_TUNNEL_SERVER_ENDPOINT		67
#define	RADIUS_ATTRIBUTE_EAP_MESSAGE				79
#define	RADIUS_ATTRIBUTE_EAP_AUTHENTICATOR			80
#define	RADIUS_ATTRIBUTE_VLAN_ID					81
#define	RADIUS_MAX_NAS_ID_LEN						253

// RADIUS codes
#define	RADIUS_CODE_ACCESS_REQUEST					1
#define	RADIUS_CODE_ACCESS_ACCEPT					2
#define	RADIUS_CODE_ACCESS_REJECT					3
#define	RADIUS_CODE_ACCESS_CHALLENGE				11

// RADIUS vendor ID
#define	RADIUS_VENDOR_MICROSOFT						311

// RADIUS MS attributes
#define	RADIUS_MS_RAS_VENDOR						9
#define	RADIUS_MS_CHAP_CHALLENGE					11
#define	RADIUS_MS_VERSION							18
#define	RADIUS_MS_CHAP2_RESPONSE					25
#define	RADIUS_MS_RAS_CLIENT_NAME					34
#define	RADIUS_MS_RAS_CLIENT_VERSION				35
#define	RADIUS_MS_NETWORK_ACCESS_SERVER_TYPE		47
#define	RADIUS_MS_RAS_CORRELATION					56

// EAP code
#define	EAP_CODE_REQUEST							1
#define	EAP_CODE_RESPONSE							2
#define	EAP_CODE_SUCCESS							3
#define	EAP_CODE_FAILURE							4

// EAP type
#define	EAP_TYPE_IDENTITY							1
#define	EAP_TYPE_LEGACY_NAK							3
#define	EAP_TYPE_PEAP								25
#define	EAP_TYPE_MS_AUTH							26

// MS-CHAPv2 opcodes
#define	EAP_MSCHAPV2_OP_CHALLENGE					1
#define	EAP_MSCHAPV2_OP_RESPONSE					2
#define	EAP_MSCHAPV2_OP_SUCCESS						3

// EAP-TLS flags
#define	EAP_TLS_FLAGS_LEN							0x80
#define	EAP_TLS_FLAGS_MORE_FRAGMENTS				0x40
#define	EAP_TLS_FLAGS_START							0x20


////////// Modern implementation

#ifdef	OS_WIN32
#pragma pack(push, 1)
#endif	// OS_WIN32

struct EAP_MESSAGE
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Data[1500];
} GCC_PACKED;

struct EAP_MSCHAPV2_GENERAL
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Chap_Opcode;
} GCC_PACKED;

struct EAP_MSCHAPV2_CHALLENGE
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Chap_Opcode;
	UCHAR Chap_Id;
	USHORT Chap_Len;
	UCHAR Chap_ValueSize;	// = 16
	UCHAR Chap_ChallengeValue[16];
	char Chap_Name[256];
} GCC_PACKED;

struct EAP_MSCHAPV2_RESPONSE
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Chap_Opcode;
	UCHAR Chap_Id;
	USHORT Chap_Len;
	UCHAR Chap_ValueSize;	// = 49
	UCHAR Chap_PeerChallange[16];
	UCHAR Chap_Reserved[8];
	UCHAR Chap_NtResponse[24];
	UCHAR Chap_Flags;
	char Chap_Name[256];
} GCC_PACKED;

struct EAP_MSCHAPV2_SUCCESS_SERVER
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Chap_Opcode;
	UCHAR Chap_Id;
	USHORT Chap_Len;
	char Message[256];
} GCC_PACKED;

struct EAP_MSCHAPV2_SUCCESS_CLIENT
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Chap_Opcode;
} GCC_PACKED;

struct EAP_PEAP
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR TlsFlags;
} GCC_PACKED;

#ifdef	OS_WIN32
#pragma pack(pop)
#endif	// OS_WIN32

struct RADIUS_PACKET
{
	UCHAR Code;
	UCHAR PacketId;
	LIST *AvpList;
	UCHAR Authenticator[16];

	UINT Parse_EapAuthMessagePos;
	UINT Parse_AuthenticatorPos;

	EAP_MESSAGE *Parse_EapMessage;
	UINT Parse_EapMessage_DataSize;

	UINT Parse_StateSize;
	UCHAR Parse_State[256];
};

struct RADIUS_AVP
{
	UCHAR Type;
	UINT VendorId;
	UCHAR VendorCode;
	UCHAR Padding[3];
	UCHAR DataSize;
	UCHAR Data[256];
};

struct EAP_CLIENT
{
	REF *Ref;

	SOCK *UdpSock;
	IP ServerIp;
	UINT ServerPort;
	char SharedSecret[MAX_SIZE];
	char ClientIpStr[256];
	char CalledStationStr[256];
	char Username[MAX_USERNAME_LEN + 1];
	UINT ResendTimeout;
	UINT GiveupTimeout;
	UCHAR TmpBuffer[4096];
	UCHAR NextEapId;
	UCHAR LastRecvEapId;

	bool PeapMode;

	UCHAR LastState[256];
	UINT LastStateSize;

	EAP_MSCHAPV2_CHALLENGE MsChapV2Challenge;
	EAP_MSCHAPV2_SUCCESS_SERVER MsChapV2Success;
	UCHAR ServerResponse[20];

	SSL_PIPE *SslPipe;
	UCHAR NextRadiusPacketId;

	BUF *PEAP_CurrentReceivingMsg;
	UINT PEAP_CurrentReceivingTotalSize;
	UCHAR RecvLastCode;

	UINT LastRecvVLanId;
};

void FreeRadiusPacket(RADIUS_PACKET *p);
BUF *GenerateRadiusPacket(RADIUS_PACKET *p, char *shared_secret);
RADIUS_PACKET *ParseRadiusPacket(void *data, UINT size);
RADIUS_PACKET *NewRadiusPacket(UCHAR code, UCHAR packet_id);
RADIUS_AVP *NewRadiusAvp(UCHAR type, UINT vendor_id, UCHAR vendor_code, void *data, UINT size);
RADIUS_AVP *GetRadiusAvp(RADIUS_PACKET *p, UCHAR type);
void RadiusTest();


EAP_CLIENT *NewEapClient(IP *server_ip, UINT server_port, char *shared_secret, UINT resend_timeout, UINT giveup_timeout, char *client_ip_str, char *username, char *hubname);
void ReleaseEapClient(EAP_CLIENT *e);
void CleanupEapClient(EAP_CLIENT *e);
bool EapClientSendMsChapv2AuthRequest(EAP_CLIENT *e);
bool EapClientSendMsChapv2AuthClientResponse(EAP_CLIENT *e, UCHAR *client_response, UCHAR *client_challenge);
void EapSetRadiusGeneralAttributes(RADIUS_PACKET *r, EAP_CLIENT *e);
bool EapSendPacket(EAP_CLIENT *e, RADIUS_PACKET *r);
RADIUS_PACKET *EapSendPacketAndRecvResponse(EAP_CLIENT *e, RADIUS_PACKET *r);

bool PeapClientSendMsChapv2AuthRequest(EAP_CLIENT *eap);
bool PeapClientSendMsChapv2AuthClientResponse(EAP_CLIENT *e, UCHAR *client_response, UCHAR *client_challenge);

bool StartPeapClient(EAP_CLIENT *e);
bool StartPeapSslClient(EAP_CLIENT *e);
bool SendPeapRawPacket(EAP_CLIENT *e, UCHAR *peap_data, UINT peap_size);
bool SendPeapPacket(EAP_CLIENT *e, void *msg, UINT msg_size);
bool GetRecvPeapMessage(EAP_CLIENT *e, EAP_MESSAGE *msg);


////////// Classical implementation
struct RADIUS_LOGIN_OPTION
{
	bool In_CheckVLanId;
	bool In_DenyNoVlanId;
	UINT Out_VLanId;
	bool Out_IsRadiusLogin;
	char NasId[RADIUS_MAX_NAS_ID_LEN + 1];	// NAS-Identifier
};

// Function prototype
bool RadiusLogin(CONNECTION *c, char *server, UINT port, UCHAR *secret, UINT secret_size, wchar_t *username, char *password, UINT interval, UCHAR *mschap_v2_server_response_20,
	RADIUS_LOGIN_OPTION *opt, char *hubname);
BUF *RadiusEncryptPassword(char *password, UCHAR *random, UCHAR *secret, UINT secret_size);
BUF *RadiusCreateUserName(wchar_t *username);
BUF *RadiusCreateUserPassword(void *data, UINT size);
BUF *RadiusCreateNasId(char *name);
void RadiusAddValue(BUF *b, UCHAR t, UINT v, UCHAR vt, void *data, UINT size);
LIST *RadiusParseOptions(BUF *b);


//////////////////////////////////////////////////////////////////////////
// Protocol.h


// The parameters that will be passed to the certificate confirmation thread
struct CHECK_CERT_THREAD_PROC
{
	CONNECTION *Connection;
	X *ServerX;
	CHECK_CERT_PROC *CheckCertProc;
	bool UserSelected;
	bool Exipred;
	bool Ok;
};

// The parameters that will be passed to the secure device signature thread
struct SECURE_SIGN_THREAD_PROC
{
	SECURE_SIGN_PROC *SecureSignProc;
	CONNECTION *Connection;
	SECURE_SIGN *SecureSign;
	bool UserFinished;
	bool Ok;
};

// Signature sending thread parameters
struct SEND_SIGNATURE_PARAM
{
	char Hostname[MAX_PATH];		// Host name
	UINT Port;						// Port number
	BUF *Buffer;					// Packet contents
};

// Software update client callback
typedef void (UPDATE_NOTIFY_PROC)(UPDATE_CLIENT *c, UINT latest_build, UINT64 latest_date, char *latest_ver, char *url, volatile bool *halt_flag, void *param);
typedef bool (UPDATE_ISFOREGROUND_PROC)(UPDATE_CLIENT *c, void *param);

// Configure the software update client
struct UPDATE_CLIENT_SETTING
{
	bool DisableCheck;				// Disable the update check
	UINT LatestIgnoreBuild;			// Ignore for earlier or identical to this build number
};

// Software update client
struct UPDATE_CLIENT
{
	char FamilyName[MAX_SIZE];		// Product family name
	char SoftwareName[MAX_SIZE];	// Software Name
	wchar_t SoftwareTitle[MAX_SIZE];	// Software display name
	char ClientId[128];				// Client ID
	UINT MyBuild;					// Build number of myself
	UINT64 MyDate;					// Build date of myself
	char MyLanguage[MAX_SIZE];		// My language
	UPDATE_CLIENT_SETTING Setting;	// Setting
	UINT LatestBuild;				// Latest build number that was successfully acquired
	volatile bool HaltFlag;			// Halting flag
	EVENT *HaltEvent;				// Halting event
	void *Param;					// Any parameters
	THREAD *Thread;					// Thread
	UPDATE_NOTIFY_PROC *Callback;	// Callback function
	UPDATE_ISFOREGROUND_PROC *IsForegroundCb;	// Callback function for retrieving whether foreground
};

//// Constant related to updating of the software

// Family
#define	UPDATE_FAMILY_NAME			_SS("PRODUCT_FAMILY_NAME")

// Software update server certificate hash
#define	UPDATE_SERVER_CERT_HASH		DDNS_CERT_HASH

// URL
#define	UPDATE_SERVER_URL_GLOBAL	"https://update-check.softether-network.net/update/update.aspx?family=%s&software=%s&mybuild=%u&lang=%s"
#define	UPDATE_SERVER_URL_CHINA		"https://update-check.uxcom.jp/update/update.aspx?family=%s&software=%s&mybuild=%u&lang=%s"

// Update check interval
#define	UPDATE_CHECK_INTERVAL_MIN		(12 * 3600 * 1000)
#define	UPDATE_CHECK_INTERVAL_MAX		(24 * 7200 * 1000)

// Connection parameters
#define	UPDATE_CONNECT_TIMEOUT			5000
#define	UPDATE_COMM_TIMEOUT				5000

// Dynamic root cert fetch function
#define	CERT_HTTP_DOWNLOAD_MAXSIZE	65536
#define	CERT_HTTP_DOWNLOAD_TIMEOUT	(10 * 1000)
#define	ROOT_CERTS_FILENAME			"|root_certs.dat"
#define	AUTO_DOWNLOAD_CERTS_PREFIX	L".autodownload_"
#define	FIND_CERT_CHAIN_MAX_DEPTH	16

#define	PROTO_SUPPRESS_CLIENT_UPDATE_NOTIFICATION_REGKEY	"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Client Update Notification"
#define	PROTO_SUPPRESS_CLIENT_UPDATE_NOTIFICATION_REGVALUE	"Suppress"

// Function prototype
UPDATE_CLIENT *NewUpdateClient(UPDATE_NOTIFY_PROC *cb, UPDATE_ISFOREGROUND_PROC *isforeground_cb, void *param, char *family_name, char *software_name, wchar_t *software_title, UINT my_build, UINT64 my_date, char *my_lang, UPDATE_CLIENT_SETTING *current_setting, char *client_id);
void FreeUpdateClient(UPDATE_CLIENT *c);
void UpdateClientThreadProc(THREAD *thread, void *param);
void UpdateClientThreadMain(UPDATE_CLIENT *c);
void UpdateClientThreadProcessResults(UPDATE_CLIENT *c, BUF *b);
void SetUpdateClientSetting(UPDATE_CLIENT *c, UPDATE_CLIENT_SETTING *s);
UINT64 ShortStrToDate64(char *str);


bool ServerAccept(CONNECTION *c);
bool ClientConnect(CONNECTION *c);
SOCK *ClientConnectToServer(CONNECTION *c);
SOCK *TcpIpConnect(char *hostname, UINT port, bool try_start_ssl, bool ssl_no_tls);
SOCK *TcpIpConnectEx(char *hostname, UINT port, bool *cancel_flag, void *hWnd, UINT *nat_t_error_code, bool no_nat_t, bool try_start_ssl, bool ssl_no_tls, IP *ret_ip);
bool ClientUploadSignature(SOCK *s);
bool ClientDownloadHello(CONNECTION *c, SOCK *s);
bool ServerDownloadSignature(CONNECTION *c, char **error_detail_str);
bool ServerUploadHello(CONNECTION *c);
bool ClientUploadAuth(CONNECTION *c);
SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect, bool no_tls);
SOCK *TcpConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, bool try_start_ssl, bool ssl_no_tls);
SOCK *TcpConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, bool no_nat_t, UINT *nat_t_error_code, bool try_start_ssl, bool ssl_no_tls, IP *ret_ip);

void InitProtocol();
void FreeProtocol();



POLICY *PackGetPolicy(PACK *p);
void PackAddPolicy(PACK *p, POLICY *y);
PACK *PackWelcome(SESSION *s);
PACK *PackHello(void *random, UINT ver, UINT build, char *server_str);
bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size);
PACK *PackLoginWithAnonymous(char *hubname, char *username);
PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password);
PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password);
PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size);
bool GetMethodFromPack(PACK *p, char *method, UINT size);
bool GetHubnameAndUsernameFromPack(PACK *p, char *username, UINT username_size,
	char *hubname, UINT hubname_size);
PACK *PackAdditionalConnect(UCHAR *session_key);
UINT GetAuthTypeFromPack(PACK *p);
UINT GetProtocolFromPack(PACK *p);
bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
	char *connection_name, UINT connection_name_size,
	POLICY **policy);


bool ClientAdditionalConnect(CONNECTION *c, THREAD *t);
SOCK *ClientAdditionalConnectToServer(CONNECTION *c);
bool ClientUploadAuth2(CONNECTION *c, SOCK *s);
bool GetSessionKeyFromPack(PACK *p, UCHAR *session_key, UINT *session_key_32);
void GenerateRC4KeyPair(RC4_KEY_PAIR *k);

SOCK *ProxyConnect(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
	char *server_host_name, UINT server_port,
	char *username, char *password, bool additional_connect);
SOCK *ProxyConnectEx(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
	char *server_host_name, UINT server_port,
	char *username, char *password, bool additional_connect,
	bool *cancel_flag, void *hWnd);
SOCK *ProxyConnectEx2(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
	char *server_host_name, UINT server_port,
	char *username, char *password, bool additional_connect,
	bool *cancel_flag, void *hWnd, UINT timeout);
SOCK *SocksConnect(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
	char *server_host_name, UINT server_port,
	char *username, bool additional_connect);
SOCK *SocksConnectEx(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
	char *server_host_name, UINT server_port,
	char *username, bool additional_connect,
	bool *cancel_flag, void *hWnd);
SOCK *SocksConnectEx2(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
	char *server_host_name, UINT server_port,
	char *username, bool additional_connect,
	bool *cancel_flag, void *hWnd, UINT timeout, IP *ret_ip);
bool SocksSendRequestPacket(CONNECTION *c, SOCK *s, UINT dest_port, IP *dest_ip, char *userid);
bool SocksRecvResponsePacket(CONNECTION *c, SOCK *s);
void CreateNodeInfo(NODE_INFO *info, CONNECTION *c);
UINT SecureSign(SECURE_SIGN *sign, UINT device_id, char *pin);
void ClientUploadNoop(CONNECTION *c);
bool ClientCheckServerCert(CONNECTION *c, bool *expired);
void ClientCheckServerCertThread(THREAD *thread, void *param);
bool ClientSecureSign(CONNECTION *c, UCHAR *sign, UCHAR *random, X **x);
void ClientSecureSignThread(THREAD *thread, void *param);
UINT SecureWrite(UINT device_id, char *cert_name, X *x, char *key_name, K *k, char *pin);
UINT SecureEnum(UINT device_id, char *pin, TOKEN_LIST **cert_list, TOKEN_LIST **key_list);
UINT SecureDelete(UINT device_id, char *pin, char *cert_name, char *key_name);
TOKEN_LIST *EnumHub(SESSION *s);
UINT ChangePasswordAccept(CONNECTION *c, PACK *p);
UINT ChangePassword(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, char *username, char *old_pass, char *new_pass);
void PackAddClientVersion(PACK *p, CONNECTION *c);
void NodeInfoToStr(wchar_t *str, UINT size, NODE_INFO *info);
void GenerateMachineUniqueHash(void *data);

LIST *NewCertList(bool load_root_and_chain);
void FreeCertList(LIST *o);
bool IsXInCertList(LIST *o, X *x);
void AddXToCertList(LIST *o, X *x);
void AddAllRootCertsToCertList(LIST *o);
void AddAllChainCertsToCertList(LIST *o);
X *DownloadCert(char *url);
X *FindCertIssuerFromCertList(LIST *o, X *x);
bool TryGetRootCertChain(LIST *o, X *x, bool auto_save, X **found_root_x);
bool TryGetParentCertFromCertList(LIST *o, X *x, LIST *found_chain);
bool DownloadAndSaveIntermediateCertificatesIfNecessary(X *x);


//////////////////////////////////////////////////////////////////////////
// Link.h


struct LINK
{
	bool Started;					// Running flag
	volatile bool Halting;			// Halting flag
	bool Offline;					// Offline
	bool NoOnline;					// Do not set to online flag
	REF *ref;						// Reference counter
	LOCK *lock;						// Lock
	CEDAR *Cedar;					// Cedar
	HUB *Hub;						// HUB
	SESSION *ClientSession;			// Client session
	SESSION *ServerSession;			// Server session
	CLIENT_OPTION *Option;			// Client Option
	CLIENT_AUTH *Auth;				// Authentication data
	POLICY *Policy;					// Policy
	QUEUE *SendPacketQueue;			// Transmission packet queue
	UINT CurrentSendPacketQueueSize;	// Current send packet queue size
	UINT LastError;					// Last error
	bool CheckServerCert;			// To check the server certificate
	X *ServerCert;					// Server certificate
	bool LockFlag;					// Lock flag
	bool *StopAllLinkFlag;			// Stop all link flag
	UINT LastServerConnectionReceivedBlocksNum;	// Last server connection recv queue num
	UINT Flag1;
};


PACKET_ADAPTER *LinkGetPacketAdapter();
bool LinkPaInit(SESSION *s);
CANCEL *LinkPaGetCancel(SESSION *s);
UINT LinkPaGetNextPacket(SESSION *s, void **data);
bool LinkPaPutPacket(SESSION *s, void *data, UINT size);
void LinkPaFree(SESSION *s);

void LinkServerSessionThread(THREAD *t, void *param);
LINK *NewLink(CEDAR *cedar, HUB *hub, CLIENT_OPTION *option, CLIENT_AUTH *auth, POLICY *policy);
void StartLink(LINK *k);
void StopLink(LINK *k);
void DelLink(HUB *hub, LINK *k);
void LockLink(LINK *k);
void UnlockLink(LINK *k);
void StopAllLink(HUB *h);
void StartAllLink(HUB *h);
void SetLinkOnline(LINK *k);
void SetLinkOffline(LINK *k);
void ReleaseLink(LINK *k);
void CleanupLink(LINK *k);
void ReleaseAllLink(HUB *h);
void NormalizeLinkPolicy(POLICY *p);


//////////////////////////////////////////////////////////////////////////
// Virtual.h



#define	NN_RAW_IP_PORT_START			61001
#define	NN_RAW_IP_PORT_END				65535

#define	VIRTUAL_TCP_SEND_TIMEOUT		(21 * 1000)

#define	NN_NEXT_WAIT_TIME_FOR_DEVICE_ENUM	(30 * 1000)
#define	NN_NEXT_WAIT_TIME_MAX_FAIL_COUNT	30

#define	NN_HOSTNAME_FORMAT				"securenat-%s"
#define	NN_HOSTNAME_STARTWITH			"securenat-"
#define	NN_HOSTNAME_STARTWITH2			"securenat_"
#define	NN_CHECK_CONNECTIVITY_TIMEOUT	(5 * 1000)
#define	NN_CHECK_CONNECTIVITY_INTERVAL	(1 * 1000)

#define	NN_POLL_CONNECTIVITY_TIMEOUT	(4 * 60 * 1000 + 10)
#define	NN_POLL_CONNECTIVITY_INTERVAL	(1 * 60 * 1000)

#define	NN_MAX_QUEUE_LENGTH				10000
#define	NN_NO_NATIVE_NAT_FILENAME		L"@no_native_nat_niclist.txt"

#define	NN_TIMEOUT_FOR_UNESTBALISHED_TCP	(10 * 1000)		// Time-out period of a TCP connection incomplete session

// Destination host name of the connectivity test for the Internet
// (Access the www.yahoo.com. Access the www.baidu.com from China. I am sorry.)
#define	NN_CHECK_HOSTNAME				(IsEmptyStr(secure_nat_target_hostname) ? (IsUseAlternativeHostname() ? "www.baidu.com" : "www.yahoo.com") : secure_nat_target_hostname)


// Native NAT entry
struct NATIVE_NAT_ENTRY
{
	UINT Id;						// ID
	UINT Status;					// Status
	UINT Protocol;					// Protocol
	UINT SrcIp;						// Source IP address
	UINT SrcPort;					// Source port number
	UINT DestIp;					// Destination IP address
	UINT DestPort;					// Destination port number
	UINT PublicIp;					// Public IP address
	UINT PublicPort;				// Public port number
	UINT64 CreatedTime;				// Connection time
	UINT64 LastCommTime;			// Last communication time
	UINT64 TotalSent;				// Total number of bytes sent
	UINT64 TotalRecv;				// Total number of bytes received
	UINT LastSeq;					// Last sequence number
	UINT LastAck;					// Last acknowledgment number
	UINT HashCodeForSend;			// Cached hash code (transmit direction)
	UINT HashCodeForRecv;			// Cached hash code (receive direction)
};

// Native NAT
struct NATIVE_NAT
{
	struct VH *v;					// Virtual machine
	bool Active;					// Whether currently available
	THREAD *Thread;					// Main thread
	bool Halt;						// Halting flag
	TUBE *HaltTube;					// Tube to be disconnected in order to stop
	TUBE *HaltTube2;				// Tube 2 to be disconnected in order to stop
	TUBE *HaltTube3;				// Tube 3 to be disconnected in order to stop
	LOCK *Lock;						// Lock
	EVENT *HaltEvent;				// Halting event
	UINT LastInterfaceIndex;		// Index number of the interface that is used for attempting last
	UINT LastInterfaceDeviceHash;	// Hash value of the device list at the time of the last attempted
	UINT NextWaitTimeForRetry;		// Time for waiting next time for the device list enumeration
	UINT FailedCount;				// The number of failed searching for the interface
	UINT LastHostAddressHash;		// Hash of the last host IP address
	DHCP_OPTION_LIST CurrentDhcpOptions;	// Current DHCP options
	QUEUE *SendQueue;				// Transmission queue
	QUEUE *RecvQueue;				// Reception queue
	CANCEL *Cancel;					// Cancel object (Hit if there is a received packet)
	LOCK *CancelLock;				// Lock of the cancel object
	HASH_LIST *NatTableForSend;		// Native NAT table (for transmission)
	HASH_LIST *NatTableForRecv;		// Native NAT table (for reception)
	UINT PublicIP;					// Public IP
	USHORT NextId;					// Next IP packet ID
	bool SendStateChanged;			// Transmission state changed
	LIST *IpCombine;				// IP combining list
	UINT CurrentIpQuota;			// Current IP combining quota
	UCHAR CurrentMacAddress[6];		// Current MAC address
	bool IsRawIpMode;				// Is RAW_IP mode
};

// ARP entry
struct ARP_ENTRY
{
	UINT IpAddress;					// IP address
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	UINT64 Created;					// Creation date and time
	UINT64 Expire;					// Expiration date
};

// ARP waiting list
struct ARP_WAIT
{
	UINT IpAddress;					// IP address trying to solve
	UINT NextTimeoutTimeValue;		// Next time before timing out
	UINT64 TimeoutTime;				// Current Time-out of transmission
	UINT64 GiveupTime;				// Time to give up the transmission
};

// IP waiting list
struct IP_WAIT
{
	UINT DestIP;					// Destination IP address
	UINT SrcIP;						// Source IP address
	UINT64 Expire;					// Storage life
	void *Data;						// Data
	UINT Size;						// Size
};

// IP partial list
struct IP_PART
{
	UINT Offset;					// Offset
	UINT Size;						// Size
};

// IP restore list
struct IP_COMBINE
{
	UINT DestIP;					// Destination IP address
	UINT SrcIP;						// Source IP address
	USHORT Id;						// IP packet ID
	UCHAR Ttl;						// TTL
	UINT64 Expire;					// Storage life
	void *Data;						// Packet data
	UINT DataReserved;				// Area reserved for data
	UINT Size;						// Packet size (Total)
	LIST *IpParts;					// IP partial list
	UCHAR Protocol;					// Protocol number
	bool MacBroadcast;				// Broadcast packets at the MAC level
	UCHAR *HeadIpHeaderData;		// Data of the IP header of the top
	UINT HeadIpHeaderDataSize;		// Data size of the IP header of the top
	bool SrcIsLocalMacAddr;			// Source MAC address is on the same machine
	UINT MaxL3Size;					// Largest L3 size
};

#define	IP_COMBINE_INITIAL_BUF_SIZE		(MAX_IP_DATA_SIZE)		// Initial buffer size

// NAT session table
struct NAT_ENTRY
{
	// TCP | UDP common items
	struct VH *v;					// Virtual machine
	UINT Id;						// ID
	LOCK *lock;						// Lock
	UINT Protocol;					// Protocol
	UINT SrcIp;						// Source IP address
	UINT SrcPort;					// Source port number
	UINT DestIp;					// Destination IP address
	UINT DestPort;					// Destination port number
	UINT PublicIp;					// Public IP address
	UINT PublicPort;				// Public port number
	UINT64 CreatedTime;				// Connection time
	UINT64 LastCommTime;			// Last communication time
	SOCK *Sock;						// Socket
	bool DisconnectNow;				// Flag to stop immediately
	UINT tag1;
	bool ProxyDns;					// DNS proxy
	UINT DestIpProxy;				// Proxy DNS address

									// ICMP NAT item (only for the calling ICMP API mode)
	THREAD *IcmpThread;				// ICMP query thread
	BLOCK *IcmpQueryBlock;			// Block that contains the ICMP query
	BLOCK *IcmpResponseBlock;		// Block that contains ICMP result
	bool IcmpTaskFinished;			// Flag indicating that the processing of ICMP has been completed
	UCHAR *IcmpOriginalCopy;		// Copy of the original ICMP packet
	UINT IcmpOriginalCopySize;		// The size of the copy of original ICMP packet

									// DNS NAT item
	THREAD *DnsThread;				// DNS query thread
	bool DnsGetIpFromHost;			// Reverse resolution flag
	char *DnsTargetHostName;		// Target host name
	IP DnsResponseIp;				// Response IP address
	char *DnsResponseHostName;		// Response host name
	UINT DnsTransactionId;			// DNS transaction ID
	bool DnsFinished;				// DNS query completion flag
	bool DnsOk;						// DNS success flag
	bool DnsPollingFlag;			// DNS polling completion flag

									// UDP item
	QUEUE *UdpSendQueue;			// UDP send queue
	QUEUE *UdpRecvQueue;			// UDP receive queue
	bool UdpSocketCreated;			// Whether an UDP socket was created

									// TCP items
	FIFO *SendFifo;					// Transmission FIFO
	FIFO *RecvFifo;					// Receive FIFO
	UINT TcpStatus;					// TCP state
	bool NatTcpCancelFlag;			// TCP connection cancel flag
	THREAD *NatTcpConnectThread;	// TCP socket connection thread
	bool TcpMakeConnectionFailed;	// Failed to connect with connection thread
	bool TcpMakeConnectionSucceed;	// Successfully connected by the connection thread
	UINT TcpSendMaxSegmentSize;		// Maximum transmission segment size
	UINT TcpRecvMaxSegmentSize;		// Maximum reception segment size
	UINT64 LastSynAckSentTime;		// Time which the SYN+ACK was sent last
	UINT SynAckSentCount;			// SYN + ACK transmission times
	UINT TcpSendWindowSize;			// Transmission window size
	UINT TcpSendCWnd;				// Transmission congestion window size (/mss)
	UINT TcpRecvWindowSize;			// Receive window size
	UINT TcpSendTimeoutSpan;		// Transmission time-out period
	UINT64 TcpLastSentTime;			// Time for the last transmitted over TCP
	UINT64 LastSentKeepAliveTime;	// Time which the keep-alive ACK was sent last
	FIFO *TcpRecvWindow;			// TCP receive window
	LIST *TcpRecvList;				// TCP reception list
	bool SendAckNext;				// Send an ACK at the time of the next transmission
	UINT LastSentWindowSize;		// My window size that sent the last
	UINT64 TcpLastRecvAckTime;		// Time that the other party has received the last data in TCP

	UINT64 SendSeqInit;				// Initial send sequence number
	UINT64 SendSeq;					// Send sequence number
	UINT64 RecvSeqInit;				// Initial receive sequence number
	UINT64 RecvSeq;					// Receive sequence number
	UINT FinSentSeq;				// Sequence number with the last FIN

	bool CurrentSendingMission;		// Burst transmission ongoing
	UINT SendMissionSize;			// Transmission size of this time
	bool RetransmissionUsedFlag;	// Retransmission using record flag

	UINT CurrentRTT;				// Current RTT value
	UINT64 CalcRTTStartTime;		// RTT measurement start time
	UINT64 CalcRTTStartValue;		// RTT measurement start value

	bool TcpFinished;				// Data communication end flag of TCP
	bool TcpDisconnected;			// TCP Disconnect flag
	bool TcpForceReset;				// TCP connection force reset flag
	UINT64 FinSentTime;				// Time which the FIN was sent last
	UINT FinSentCount;				// Number of FIN transmissions

	UINT64 test_TotalSent;
};


// TCP options
struct TCP_OPTION
{
	UINT MaxSegmentSize;			// Maximum segment size
	UINT WindowScaling;				// Window scaling
};

// Virtual host structure
struct VH
{
	REF *ref;						// Reference counter
	LOCK *lock;						// Lock
	SESSION *Session;				// Session
	CANCEL *Cancel;					// Cancel object
	QUEUE *SendQueue;				// Transmission queue
	bool Active;					// Active flag
	volatile bool HaltNat;			// NAT halting flag
	LIST *ArpTable;					// ARP table
	LIST *ArpWaitTable;				// ARP waiting table
	LIST *IpWaitTable;				// IP waiting table
	LIST *IpCombine;				// IP combining table
	UINT64 Now;						// Current time
	UINT64 NextArpTablePolling;		// Next time to poll the ARP table
	UINT Mtu;						// MTU value
	UINT IpMss;						// Maximum IP data size
	UINT TcpMss;					// TCP maximum data size
	UINT UdpMss;					// UDP maximum data size
	bool flag1;						// Flag 1
	bool flag2;						// Flag 2
	USHORT NextId;					// ID of the IP packet
	UINT CurrentIpQuota;			// IP packet memory quota
	LIST *NatTable;					// NAT table
	SOCK_EVENT *SockEvent;			// Socket event
	THREAD *NatThread;				// NAT thread
	void *TmpBuf;					// Buffer that can be used temporarily
	bool NatDoCancelFlag;			// Flag of whether to hit the cancel
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	UINT HostIP;					// Host IP
	UINT HostMask;					// Host subnet mask
	UINT NatTcpTimeout;				// NAT TCP timeout in seconds
	UINT NatUdpTimeout;				// NAT UDP timeout in seconds
	bool UseNat;					// NAT use flag
	bool UseDhcp;					// DHCP using flag
	UINT DhcpIpStart;				// Distribution start address
	UINT DhcpIpEnd;					// Distribution end address
	UINT DhcpMask;					// Subnet mask
	UINT DhcpExpire;				// Address distribution expiration date
	UINT DhcpGateway;				// Gateway address
	UINT DhcpDns;					// DNS server address 1
	UINT DhcpDns2;					// DNS server address 2
	char DhcpDomain[MAX_HOST_NAME_LEN + 1];	// Assigned domain name
	LIST *DhcpLeaseList;			// DHCP lease list
	UINT64 LastDhcpPolling;			// Time which the DHCP list polled last
	bool SaveLog;					// Save a log
	DHCP_CLASSLESS_ROUTE_TABLE PushRoute;	// Pushing routing table
	COUNTER *Counter;				// Session counter
	UINT DhcpId;					// DHCP ID
	UINT64 LastSendBeacon;			// Time which the beacon has been sent last
	LOG *Logger;					// Logger
	NAT *nat;						// A reference to the NAT object
	bool IcmpRawSocketOk;			// ICMP RAW SOCKET is available
	bool IcmpApiOk;					// ICMP API is available
	HUB_OPTION *HubOption;			// Pointer to the Virtual HUB options

	NATIVE_NAT *NativeNat;			// Native NAT
};

// Virtual host option
struct VH_OPTION
{
	char HubName[MAX_HUBNAME_LEN + 1];	// Target Virtual HUB name
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	IP Ip;							// IP address
	IP Mask;						// Subnet mask
	bool UseNat;					// Use flag of NAT function
	UINT Mtu;						// MTU value
	UINT NatTcpTimeout;				// NAT TCP timeout in seconds
	UINT NatUdpTimeout;				// NAT UDP timeout in seconds
	bool UseDhcp;					// Using flag of DHCP function
	IP DhcpLeaseIPStart;			// Start of IP address range for DHCP distribution
	IP DhcpLeaseIPEnd;				// End of IP address range for DHCP distribution
	IP DhcpSubnetMask;				// DHCP subnet mask
	UINT DhcpExpireTimeSpan;		// DHCP expiration date
	IP DhcpGatewayAddress;			// Assigned gateway address
	IP DhcpDnsServerAddress;		// Assigned DNS server address 1
	IP DhcpDnsServerAddress2;		// Assigned DNS server address 2
	char DhcpDomainName[MAX_HOST_NAME_LEN + 1];	// Assigned domain name
	bool SaveLog;					// Save a log
	bool ApplyDhcpPushRoutes;		// Apply flag for DhcpPushRoutes
	char DhcpPushRoutes[MAX_DHCP_CLASSLESS_ROUTE_TABLE_STR_SIZE];	// DHCP pushing routes
};

// DHCP lease entry
struct DHCP_LEASE
{
	UINT Id;						// ID
	UINT64 LeasedTime;				// Leased time
	UINT64 ExpireTime;				// Expiration date
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];				// Padding
	UINT IpAddress;					// IP address
	UINT Mask;						// Subnet mask
	char *Hostname;					// Host name
};

// DNS query
typedef struct NAT_DNS_QUERY
{
	REF *ref;						// Reference counter
	char Hostname[256];				// Host name
	bool Ok;						// Result success flag
	IP Ip;							// Result IP address
} NAT_DNS_QUERY;

// Parsed DNS query
struct DNS_PARSED_PACKET
{
	UINT TransactionId;
	char Hostname[128];
};


// Virtual LAN card of the virtual host
PACKET_ADAPTER *VirtualGetPacketAdapter();
bool VirtualPaInit(SESSION *s);
CANCEL *VirtualPaGetCancel(SESSION *s);
UINT VirtualPaGetNextPacket(SESSION *s, void **data);
bool VirtualPaPutPacket(SESSION *s, void *data, UINT size);
void VirtualPaFree(SESSION *s);

bool VirtualInit(VH *v);
UINT VirtualGetNextPacket(VH *v, void **data);
bool VirtualPutPacket(VH *v, void *data, UINT size);
void Virtual_Free(VH *v);

VH *NewVirtualHost(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, VH_OPTION *vh_option);
VH *NewVirtualHostEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, VH_OPTION *vh_option, NAT *nat);
void LockVirtual(VH *v);
void UnlockVirtual(VH *v);
void ReleaseVirtual(VH *v);
void CleanupVirtual(VH *v);
void StopVirtualHost(VH *v);
void SetVirtualHostOption(VH *v, VH_OPTION *vo);
void GenMacAddress(UCHAR *mac);
void GetVirtualHostOption(VH *v, VH_OPTION *o);

void VirtualLayer2(VH *v, PKT *packet);
bool VirtualLayer2Filter(VH *v, PKT *packet);
void VirtualArpReceived(VH *v, PKT *packet);
void VirtualArpResponseRequest(VH *v, PKT *packet);
void VirtualArpResponseReceived(VH *v, PKT *packet);
void VirtualArpSendResponse(VH *v, UCHAR *dest_mac, UINT dest_ip, UINT src_ip);
void VirtualArpSendRequest(VH *v, UINT dest_ip);
void VirtualIpSend(VH *v, UCHAR *dest_mac, void *data, UINT size);
void VirtualLayer2Send(VH *v, UCHAR *dest_mac, UCHAR *src_mac, USHORT protocol, void *data, UINT size);
void VirtualPolling(VH *v);
void InitArpTable(VH *v);
void FreeArpTable(VH *v);
int CompareArpTable(void *p1, void *p2);
ARP_ENTRY *SearchArpTable(VH *v, UINT ip);
void RefreshArpTable(VH *v);
void PollingArpTable(VH *v);
void InsertArpTable(VH *v, UCHAR *mac, UINT ip);
bool IsMacBroadcast(UCHAR *mac);
bool IsMacInvalid(UCHAR *mac);
void InitArpWaitTable(VH *v);
void FreeArpWaitTable(VH *v);
int CompareArpWaitTable(void *p1, void *p2);
ARP_WAIT *SearchArpWaitTable(VH *v, UINT ip);
void DeleteArpWaitTable(VH *v, UINT ip);
void SendArp(VH *v, UINT ip);
void InsertArpWaitTable(VH *v, ARP_WAIT *w);
void PollingArpWaitTable(VH *v);
void ArpIpWasKnown(VH *v, UINT ip, UCHAR *mac);
void InitIpWaitTable(VH *v);
void FreeIpWaitTable(VH *v);
void InsertIpWaitTable(VH *v, UINT dest_ip, UINT src_ip, void *data, UINT size);
void SendFragmentedIp(VH *v, UINT dest_ip, UINT src_ip, USHORT id, USHORT total_size, USHORT offset, UCHAR protocol, void *data, UINT size, UCHAR *dest_mac, UCHAR ttl);
void SendIp(VH *v, UINT dest_ip, UINT src_ip, UCHAR protocol, void *data, UINT size);
void SendIpEx(VH *v, UINT dest_ip, UINT src_ip, UCHAR protocol, void *data, UINT size, UCHAR ttl);
void PollingIpWaitTable(VH *v);
void DeleteOldIpWaitTable(VH *v);
void SendWaitingIp(VH *v, UCHAR *mac, UINT dest_ip);
void VirtualIpReceived(VH *v, PKT *packet);
void InitIpCombineList(VH *v);
void FreeIpCombineList(VH *v);
int CompareIpCombine(void *p1, void *p2);
void CombineIp(VH *v, IP_COMBINE *c, UINT offset, void *data, UINT size, bool last_packet, UCHAR *head_ip_header_data, UINT head_ip_header_size);
void IpReceived(VH *v, UINT src_ip, UINT dest_ip, UINT protocol, void *data, UINT size, bool mac_broadcast, UCHAR ttl, UCHAR *ip_header, UINT ip_header_size, bool is_local_mac, UINT max_l3_size);
void FreeIpCombine(VH *v, IP_COMBINE *c);
void PollingIpCombine(VH *v);
IP_COMBINE *InsertIpCombine(VH *v, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol, bool mac_broadcast, UCHAR ttl, bool src_is_localmac);
IP_COMBINE *SearchIpCombine(VH *v, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol);
void VirtualIcmpReceived(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size, UCHAR ttl, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size);
void VirtualIcmpEchoRequestReceived(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size, UCHAR ttl, void *icmp_data, UINT icmp_size, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size);
void VirtualIcmpEchoRequestReceivedRaw(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size, UCHAR ttl, void *icmp_data, UINT icmp_size, UCHAR *ip_header, UINT ip_header_size);
void VirtualIcmpEchoSendResponse(VH *v, UINT src_ip, UINT dst_ip, USHORT id, USHORT seq_no, void *data, UINT size);
void VirtualIcmpSend(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size);
void VirtualUdpReceived(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size, bool mac_broadcast, bool is_localmac, UINT max_l3_size);
void SendUdp(VH *v, UINT dest_ip, UINT dest_port, UINT src_ip, UINT src_port, void *data, UINT size);
UINT GetNetworkAddress(UINT addr, UINT mask);
UINT GetBroadcastAddress(UINT addr, UINT mask);
void GetBroadcastAddress4(IP *dst, IP *addr, IP *mask);
bool IsInNetwork(UINT uni_addr, UINT network_addr, UINT mask);
void UdpRecvForMe(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
void UdpRecvLlmnr(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
void UdpRecvForBroadcast(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
void UdpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, bool dns_proxy);
void UdpRecvForNetBiosBroadcast(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, bool dns_proxy, bool unicast);
bool IsNetbiosRegistrationPacket(UCHAR *buf, UINT size);
bool ProcessNetBiosNameQueryPacketForMyself(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
void EncodeNetBiosName(UCHAR *dst, char *src);
char *CharToNetBiosStr(char c);
void InitNat(VH *v);
void FreeNat(VH *v);
int CompareNat(void *p1, void *p2);
NAT_ENTRY *SearchNat(VH *v, NAT_ENTRY *target);
void SetNat(NAT_ENTRY *n, UINT protocol, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT public_ip, UINT public_port);
void DeleteNatTcp(VH *v, NAT_ENTRY *n);
void DeleteNatUdp(VH *v, NAT_ENTRY *n);
void DeleteNatIcmp(VH *v, NAT_ENTRY *n);
NAT_ENTRY *CreateNatUdp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT dns_proxy_ip);
NAT_ENTRY *CreateNatIcmp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UCHAR *original_copy, UINT original_copy_size);
void NatThread(THREAD *t, void *param);
void NatThreadMain(VH *v);
bool NatTransactUdp(VH *v, NAT_ENTRY *n);
bool NatTransactIcmp(VH *v, NAT_ENTRY *n);
void NatIcmpThreadProc(THREAD *thread, void *param);
void PoolingNat(VH *v);
void PoolingNatUdp(VH *v, NAT_ENTRY *n);
void PollingNatIcmp(VH *v, NAT_ENTRY *n);
void VirtualTcpReceived(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size, UINT max_l3_size);
void TcpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, TCP_HEADER *tcp, void *data, UINT size, UINT max_l3_size);
NAT_ENTRY *CreateNatTcp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port);
bool NatTransactTcp(VH *v, NAT_ENTRY *n);
void CreateNatTcpConnectThread(VH *v, NAT_ENTRY *n);
void NatTcpConnectThread(THREAD *t, void *p);
void PollingNatTcp(VH *v, NAT_ENTRY *n);
void ParseTcpOption(TCP_OPTION *o, void *data, UINT size);
void SendTcp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT seq, UINT ack, UINT flag, UINT window_size, UINT mss, void *data, UINT size);
void DnsProxy(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
bool ParseDnsPacket(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
bool ParseDnsPacketEx(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, DNS_PARSED_PACKET *parsed_result);
void SetDnsProxyVgsHostname(char *hostname);
bool NatTransactDns(VH *v, NAT_ENTRY *n);
void NatDnsThread(THREAD *t, void *param);
bool NatGetIP(IP *ip, char *hostname);
void NatGetIPThread(THREAD *t, void *param);
NAT_ENTRY *CreateNatDns(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port,
	UINT transaction_id, bool dns_get_ip_from_host, char *dns_target_host_name);
void PollingNatDns(VH *v, NAT_ENTRY *n);
void SendNatDnsResponse(VH *v, NAT_ENTRY *n);
void BuildDnsQueryPacket(BUF *b, char *hostname, bool ptr);
void BuildDnsResponsePacketA(BUF *b, IP *ip);
void BuildDnsResponsePacketPtr(BUF *b, char *hostname);
bool ArpaToIP(IP *ip, char *str);
BUF *BuildDnsHostName(char *hostname);
bool CanCreateNewNatEntry(VH *v);
void VirtualDhcpServer(VH *v, PKT *p);
void InitDhcpServer(VH *v);
void FreeDhcpServer(VH *v);
void PollingDhcpServer(VH *v);
int CompareDhcpLeaseList(void *p1, void *p2);
DHCP_LEASE *NewDhcpLease(UINT expire, UCHAR *mac_address, UINT ip, UINT mask, char *hostname);
void FreeDhcpLease(DHCP_LEASE *d);
DHCP_LEASE *SearchDhcpLeaseByMac(VH *v, UCHAR *mac);
DHCP_LEASE *SearchDhcpLeaseByIp(VH *v, UINT ip);
UINT ServeDhcpDiscover(VH *v, UCHAR *mac, UINT request_ip);
UINT GetFreeDhcpIpAddress(VH *v);
UINT GetFreeDhcpIpAddressByRandom(VH *v, UCHAR *mac);
UINT ServeDhcpRequest(VH *v, UCHAR *mac, UINT request_ip);
void VirtualDhcpSend(VH *v, UINT tran_id, UINT dest_ip, UINT dest_port,
	UINT new_ip, UCHAR *client_mac, BUF *b, UINT hw_type, UINT hw_addr_size);
void VLog(VH *v, char *str);
void SendBeacon(VH *v);
void PollingBeacon(VH *v);
HUB_OPTION *NatGetHubOption(VH *v);
UINT GetNumNatEntriesPerIp(VH *v, UINT ip, UINT protocol, bool tcp_syn_sent);
void NatSetHubOption(VH *v, HUB_OPTION *o);
NAT_ENTRY *GetOldestNatEntryOfIp(VH *v, UINT ip, UINT protocol);
void DisconnectNatEntryNow(VH *v, NAT_ENTRY *e);

NATIVE_NAT *NewNativeNat(VH *v);
void FreeNativeNat(NATIVE_NAT *t);
void NativeNatThread(THREAD *thread, void *param);
NATIVE_STACK *NnGetNextInterface(NATIVE_NAT *t);

bool NnTestConnectivity(NATIVE_STACK *a, TUBE *halt_tube);
void NnMainLoop(NATIVE_NAT *t, NATIVE_STACK *a);

BUF *NnBuildDnsQueryPacket(char *hostname, USHORT tran_id);
BUF *NnBuildUdpPacket(BUF *payload, UINT src_ip, USHORT src_port, UINT dst_ip, USHORT dst_port);
BUF *NnBuildTcpPacket(BUF *payload, UINT src_ip, USHORT src_port, UINT dst_ip, USHORT dst_port, UINT seq, UINT ack, UINT flag, UINT window_size, UINT mss);
BUF *NnBuildIpPacket(BUF *payload, UINT src_ip, UINT dst_ip, UCHAR protocol, UCHAR ttl);
UINT NnGenSrcPort(bool raw_ip_mode);
bool NnParseDnsResponsePacket(UCHAR *data, UINT size, IP *ret_ip);
BUF *NnReadDnsRecord(BUF *buf, bool answer, USHORT *ret_type, USHORT *ret_class);
bool NnReadDnsLabel(BUF *buf);
void NnClearQueue(NATIVE_NAT *t);

int CmpNativeNatTableForSend(void *p1, void *p2);
int CmpNativeNatTableForRecv(void *p1, void *p2);
UINT GetHashNativeNatTableForSend(void *p);
UINT GetHashNativeNatTableForRecv(void *p);
void NnSetNat(NATIVE_NAT_ENTRY *e, UINT protocol, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT pub_ip, UINT pub_port);

bool NnIsActive(VH *v);
bool NnIsActiveEx(VH *v, bool *is_ipraw_mode);
void NnUdpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, UINT max_l3_size);
void NnTcpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, TCP_HEADER *old_tcp, void *data, UINT size, UINT max_l3_size);
void NnIcmpEchoRecvForInternet(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, void *icmp_data, UINT icmp_size, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size);
UINT NnMapNewPublicPort(NATIVE_NAT *t, UINT protocol, UINT dest_ip, UINT dest_port, UINT public_ip);
void NnIpSendForInternet(NATIVE_NAT *t, UCHAR ip_protocol, UCHAR ttl, UINT src_ip, UINT dest_ip, void *data, UINT size, UINT max_l3_size);
void NnIpSendFragmentedForInternet(NATIVE_NAT *t, UCHAR ip_protocol, UINT src_ip, UINT dest_ip, USHORT id, USHORT total_size,
	USHORT offset, void *data, UINT size, UCHAR ttl);
void NnPoll(NATIVE_NAT *t);
void NnLayer2(NATIVE_NAT *t, PKT *packet);
void NnFragmentedIpReceived(NATIVE_NAT *t, PKT *packet);
void NnIpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, UINT protocol, void *data, UINT size,
	UCHAR ttl, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size);
void NnUdpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, UINT max_l3_size);
void NnTcpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, UINT max_l3_size);
void NnIcmpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, UINT max_l3_size);

void NnCombineIp(NATIVE_NAT *t, IP_COMBINE *c, UINT offset, void *data, UINT size, bool last_packet, UCHAR *head_ip_header_data, UINT head_ip_header_size);
void NnFreeIpCombine(NATIVE_NAT *t, IP_COMBINE *c);
IP_COMBINE *NnSearchIpCombine(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol);
IP_COMBINE *NnInsertIpCombine(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol, bool mac_broadcast, UCHAR ttl, bool src_is_localmac);
void NnInitIpCombineList(NATIVE_NAT *t);
void NnFreeIpCombineList(NATIVE_NAT *t);
void NnPollingIpCombine(NATIVE_NAT *t);
void NnDeleteOldSessions(NATIVE_NAT *t);
void NnDeleteSession(NATIVE_NAT *t, NATIVE_NAT_ENTRY *e);

NATIVE_NAT_ENTRY *NnGetOldestNatEntryOfIp(NATIVE_NAT *t, UINT ip, UINT protocol);
void NnDeleteOldestNatSession(NATIVE_NAT *t, UINT ip, UINT protocol);
UINT NnGetNumNatEntriesPerIp(NATIVE_NAT *t, UINT src_ip, UINT protocol);
void NnDeleteOldestNatSessionIfNecessary(NATIVE_NAT *t, UINT ip, UINT protocol);

void NnSetSecureNatTargetHostname(char *name);


//////////////////////////////////////////////////////////////////////////
// SecureNAT.h


struct SNAT
{
	LOCK *lock;						// Lock
	CEDAR *Cedar;					// Cedar
	HUB *Hub;						// HUB
	SESSION *Session;				// Session
	POLICY *Policy;					// Policy
	NAT *Nat;						// NAT
};


SNAT *SnNewSecureNAT(HUB *h, VH_OPTION *o);
void SnFreeSecureNAT(SNAT *s);
void SnSecureNATThread(THREAD *t, void *param);


//////////////////////////////////////////////////////////////////////////
// WaterMark.h

// Digital watermark
extern BYTE WaterMark[];
extern BYTE Saitama[];

UINT SizeOfWaterMark();
UINT SizeOfSaitama();

#define	MAX_WATERMARK_SIZE		(SizeOfWaterMark() + HTTP_PACK_RAND_SIZE_MAX * 2)


//////////////////////////////////////////////////////////////////////////
// Console.h


// Constant
#define	MAX_PROMPT_STRSIZE			65536
#define	WIN32_DEFAULT_CONSOLE_WIDTH	100

// Types of console
#define	CONSOLE_LOCAL				0	// Local console
#define	CONSOLE_CSV					1	// CSV output mode

// Parameters completion prompt function
typedef wchar_t *(PROMPT_PROC)(CONSOLE *c, void *param);

// Parameter validation prompt function
typedef bool (EVAL_PROC)(CONSOLE *c, wchar_t *str, void *param);

// Definition of the parameter item
struct PARAM
{
	char *Name;					// Parameter name
	PROMPT_PROC *PromptProc;	// Prompt function that automatically invoked if the parameter is not specified
								//  (This is not called in the case of NULL)
	void *PromptProcParam;		// Any pointers to pass to the prompt function
	EVAL_PROC *EvalProc;		// Parameter string validation function
	void *EvalProcParam;		// Any pointers to be passed to the validation function
	char *Tmp;					// Temporary variable
};

// Parameter value of the internal data
struct PARAM_VALUE
{
	char *Name;					// Name
	char *StrValue;				// String value
	wchar_t *UniStrValue;		// Unicode string value
	UINT IntValue;				// Integer value
};

// Console service structure
struct CONSOLE
{
	UINT ConsoleType;										// Type of console
	UINT RetCode;											// The last exit code
	void *Param;											// Data of any
	void(*Free)(CONSOLE *c);								// Release function
	wchar_t *(*ReadLine)(CONSOLE *c, wchar_t *prompt, bool nofile);		// Function to read one line
	char *(*ReadPassword)(CONSOLE *c, wchar_t *prompt);		// Function to read the password
	bool(*Write)(CONSOLE *c, wchar_t *str);				// Function to write a string
	UINT(*GetWidth)(CONSOLE *c);							// Get the width of the screen
	bool ProgrammingMode;									// Programming Mode
	LOCK *OutputLock;										// Output Lock
};

// Local console parameters
struct LOCAL_CONSOLE_PARAM
{
	IO *InFile;		// Input file
	BUF *InBuf;		// Input buffer
	IO *OutFile;	// Output file
	UINT Win32_OldConsoleWidth;	// Previous console size
};

// Command procedure
typedef UINT(COMMAND_PROC)(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);

// Definition of command
struct CMD
{
	char *Name;				// Command name
	COMMAND_PROC *Proc;		// Procedure function
};

// Evaluate the minimum / maximum value of the parameter
struct CMD_EVAL_MIN_MAX
{
	char *StrName;
	UINT MinValue, MaxValue;
};


// Function prototype
wchar_t *Prompt(wchar_t *prompt_str);
char *PromptA(wchar_t *prompt_str);
bool PasswordPrompt(char *password, UINT size);
void *SetConsoleRaw();
void RestoreConsole(void *p);
wchar_t *ParseCommandEx(wchar_t *str, wchar_t *name, TOKEN_LIST **param_list);
wchar_t *ParseCommand(wchar_t *str, wchar_t *name);
TOKEN_LIST *GetCommandNameList(wchar_t *str);
char *ParseCommandA(wchar_t *str, char *name);
LIST *NewParamValueList();
int CmpParamValue(void *p1, void *p2);
void FreeParamValueList(LIST *o);
PARAM_VALUE *FindParamValue(LIST *o, char *name);
char *GetParamStr(LIST *o, char *name);
wchar_t *GetParamUniStr(LIST *o, char *name);
UINT GetParamInt(LIST *o, char *name);
bool GetParamYes(LIST *o, char *name);
LIST *ParseCommandList(CONSOLE *c, char *cmd_name, wchar_t *command, PARAM param[], UINT num_param);
bool IsNameInRealName(char *input_name, char *real_name);
void GetOmissionName(char *dst, UINT size, char *src);
bool IsOmissionName(char *input_name, char *real_name);
TOKEN_LIST *GetRealnameCandidate(char *input_name, TOKEN_LIST *real_name_list);
bool SeparateCommandAndParam(wchar_t *src, char **cmd, wchar_t **param);
UINT GetConsoleWidth(CONSOLE *c);
bool DispatchNextCmd(CONSOLE *c, char *prompt, CMD cmd[], UINT num_cmd, void *param);
bool DispatchNextCmdEx(CONSOLE *c, wchar_t *exec_command, char *prompt, CMD cmd[], UINT num_cmd, void *param);
void PrintCandidateHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *candidate_list, UINT left_space);
UNI_TOKEN_LIST *SeparateStringByWidth(wchar_t *str, UINT width);
UINT GetNextWordWidth(wchar_t *str);
bool IsWordChar(wchar_t c);
void GetCommandHelpStr(char *command_name, wchar_t **description, wchar_t **args, wchar_t **help);
void GetCommandParamHelpStr(char *command_name, char *param_name, wchar_t **description);
bool CmdEvalMinMax(CONSOLE *c, wchar_t *str, void *param);
wchar_t *CmdPrompt(CONSOLE *c, void *param);
bool CmdEvalNotEmpty(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalInt1(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIsFile(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalSafe(CONSOLE *c, wchar_t *str, void *param);
void PrintCmdHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *param_list);
int CompareCandidateStr(void *p1, void *p2);
bool IsHelpStr(char *str);

CONSOLE *NewLocalConsole(wchar_t *infile, wchar_t *outfile);
void ConsoleLocalFree(CONSOLE *c);
wchar_t *ConsoleLocalReadLine(CONSOLE *c, wchar_t *prompt, bool nofile);
char *ConsoleLocalReadPassword(CONSOLE *c, wchar_t *prompt);
bool ConsoleLocalWrite(CONSOLE *c, wchar_t *str);
void ConsoleWriteOutFile(CONSOLE *c, wchar_t *str, bool add_last_crlf);
wchar_t *ConsoleReadNextFromInFile(CONSOLE *c);
UINT ConsoleLocalGetWidth(CONSOLE *c);



//////////////////////////////////////////////////////////////////////////
// Command.h


// Constants
#define	TRAFFIC_DEFAULT_PORT		9821
#define	TRAFFIC_NUMTCP_MAX			32
#define	TRAFFIC_NUMTCP_DEFAULT		32
#define	TRAFFIC_SPAN_DEFAULT		15
#define	TRAFFIC_TYPE_DOWNLOAD		1
#define	TRAFFIC_TYPE_UPLOAD			2
#define	TRAFFIC_TYPE_FULL			0
#define	TRAFFIC_BUF_SIZE			65535
#define	TRAFFIC_VER_STR_SIZE		16
#define	TRAFFIC_VER_STR				"TrafficServer\r\n"

// Constants for Win32
#define	VPNCMD_BOOTSTRAP_REG_KEYNAME	"Software\\" GC_REG_COMPANY_NAME "\\VPN Command Line Utility"
#define	VPNCMD_BOOTSTRAP_REG_VALUENAME_VER	"InstalledVersion"
#define	VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH	"InstalledPath"
#define	VPNCMD_BOOTSTRAP_FILENAME		"|vpncmdsys.exe"
#define	VPNCMD_BOOTSTRAP_FILENAME_X64	"|vpncmdsys_x64.exe"
#define	VPNCMD_BOOTSTRAP_FILENAME_IA64	"|vpncmdsys_ia64.exe"


// Traffic test results
struct TT_RESULT
{
	bool Raw;					// Whether raw data
	bool Double;				// Whether it is doubled
	UINT64 NumBytesUpload;		// Uploaded size
	UINT64 NumBytesDownload;	// Downloaded size
	UINT64 NumBytesTotal;		// Total size
	UINT64 Span;				// Period (in milliseconds)
	UINT64 BpsUpload;			// Upload throughput
	UINT64 BpsDownload;			// Download throughput
	UINT64 BpsTotal;			// Total throughput
};

// Text display function
typedef void (TT_PRINT_PROC)(void *param, wchar_t *str);

// Client side socket
struct TTC_SOCK
{
	SOCK *Sock;				// Socket
	UINT State;				// State
	UINT64 NumBytes;		// Transmitted bytes
	bool Download;			// Download socket
	bool ServerUploadReportReceived;	// Complete to receive the report of upload amount from the server
	UINT64 NextSendRequestReportTick;	// Time to request a next report
	UINT Id;
	bool HideErrMsg;
};

// Traffic test Client
struct TTC
{
	TT_PRINT_PROC *Print;	// Text display function
	void *Param;			// Any parameters
	bool Double;			// Double mode
	bool Raw;				// Raw data mode
	UINT Port;				// Port number
	char Host[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT NumTcp;			// Number of TCP connections
	UINT Type;				// Type
	UINT64 Span;			// Period
	UINT64 RealSpan;		// The actual span
	THREAD *Thread;			// Thread
	volatile bool Halt;		// Halting flag
	bool *Cancel;			// Halting flag 2
	LIST *ItcSockList;		// Client socket list
	TT_RESULT Result;		// Result
	UINT ErrorCode;			// Error code
	bool AbnormalTerminated;	// Abnormal termination
	EVENT *StartEvent;		// Start event
	EVENT *InitedEvent;		// Initialize completion notification event
	LIST *WorkerThreadList;	// List of worker threads

	UINT flag1, flag2;

	UINT64 session_id;
	UINT64 end_tick;
	UINT64 start_tick;
};

// Traffic test worker thread
struct TTC_WORKER
{
	THREAD *WorkerThread;
	TTC *Ttc;
	LIST *SockList;			// Client socket list
	SOCK_EVENT *SockEvent;	// Socket event
	EVENT *StartEvent;		// Start event
	bool Ok;				// The result
};

// Server side socket
struct TTS_SOCK
{
	SOCK *Sock;				// Socket
	UINT State;				// State
	UINT64 NumBytes;		// Transmitted bytes
	bool SockJoined;		// Whether it has been added to the event
	UINT Id;				// ID
	UINT64 LastWaitTick;	// Retry waiting time to notify the size information to the client
	UINT64 SessionId;		// Session ID
	bool NoMoreSendData;	// Flag not to send more data
	UINT64 FirstRecvTick;	// Time which the data has been received last
	UINT64 FirstSendTick;	// Time which the data has been sent last
	UINT64 Span;			// Period
	UINT64 GiveupSpan;
	UINT64 LastCommTime;
};

// Traffic test server
struct TTS
{
	TT_PRINT_PROC *Print;	// Text display function
	void *Param;			// Any parameters
	volatile bool Halt;		// Halting flag
	UINT Port;				// Port number
	THREAD *Thread;			// Thread
	THREAD *IPv6AcceptThread;	// IPv6 Accept thread
	SOCK *ListenSocket;		// Socket to wait
	SOCK *ListenSocketV6;	// Socket to wait (IPv6)
	UINT ErrorCode;			// Error code
	UINT IdSeed;			// ID value
	LIST *WorkerList;		// Worker threads list
};

// Traffic test worker thread
struct TTS_WORKER
{
	TTS *Tts;				// TTS
	THREAD *WorkThread;		// Worker thread
	SOCK_EVENT *SockEvent;	// Socket event
	LIST *TtsSockList;		// Server socket list
	bool NewSocketArrived;	// New socket has arrived
};

// VPN Tools context
struct PT
{
	CONSOLE *Console;	// Console
	UINT LastError;		// Last error
	wchar_t *CmdLine;	// Command line to execute
};

// Server management context
struct PS
{
	bool ConsoleForServer;	// Console for the server (always true)
	CONSOLE *Console;	// Console
	RPC *Rpc;			// RPC
	char *ServerName;	// Server name
	UINT ServerPort;	// Port number
	char *HubName;		// Virtual HUB name in the currently managed
	UINT LastError;		// Last error
	char *AdminHub;		// Virtual HUB to be managed by default
	wchar_t *CmdLine;	// Command line to execute
	CAPSLIST *CapsList;	// Caps list
};

// Client management context
struct PC
{
	bool ConsoleForServer;	// Console for the server (always false)
	CONSOLE *Console;	// Console
	REMOTE_CLIENT *RemoteClient;	// Remote client
	char *ServerName;	// Server name
	UINT LastError;		// Last error
	wchar_t *CmdLine;	// Command line
};

// A column of the table
struct CTC
{
	wchar_t *String;	// String
	bool Right;			// Right justification
};

// A row of the table
struct CTR
{
	wchar_t **Strings;	// String list
};

// Table for console
struct CT
{
	LIST *Columns;		// Column list
	LIST *Rows;			// Row list
};

UINT CommandMain(wchar_t *command_line);
UINT VpnCmdProc(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
bool ParseHostPort(char *src, char **host, UINT *port, UINT default_port);
bool ParseHostPortAtmark(char *src, char **host, UINT *port, UINT default_port);
CT *CtNew();
void CtFree(CT *ct, CONSOLE *c);
void CtFreeEx(CT *ct, CONSOLE *c, bool standard_view);
void CtInsertColumn(CT *ct, wchar_t *str, bool right);
CT *CtNewStandard();
CT *CtNewStandardEx();
void CtInsert(CT *ct, ...);
void CtPrint(CT *ct, CONSOLE *c);
void CtPrintStandard(CT *ct, CONSOLE *c);
void CtPrintRow(CONSOLE *c, UINT num, UINT *widths, wchar_t **strings, bool *rights, char separate_char);
void VpnCmdInitBootPath();
void OutRpcTtResult(PACK *p, TT_RESULT *t);
void InRpcTtResult(PACK *p, TT_RESULT *t);

void CmdPrintError(CONSOLE *c, UINT err);
void CmdPrintAbout(CONSOLE *c);
void CmdPrintRow(CONSOLE *c, wchar_t *title, wchar_t *tag, ...);
wchar_t *CmdPromptPort(CONSOLE *c, void *param);
wchar_t *CmdPromptChoosePassword(CONSOLE *c, void *param);
bool CmdEvalPort(CONSOLE *c, wchar_t *str, void *param);
void CmdInsertTrafficInfo(CT *ct, TRAFFIC *t);
wchar_t *GetHubTypeStr(UINT type);
wchar_t *GetServerTypeStr(UINT type);
char *CmdPasswordPrompt(CONSOLE *c);
bool CmdEvalIp(CONSOLE *c, wchar_t *str, void *param);
wchar_t *PsClusterSettingMemberPromptIp(CONSOLE *c, void *param);
bool CmdEvalHostAndPort(CONSOLE *c, wchar_t *str, void *param);
LIST *StrToPortList(char *str);
bool CmdEvalPortList(CONSOLE *c, wchar_t *str, void *param);
wchar_t *PsClusterSettingMemberPromptPorts(CONSOLE *c, void *param);
K *CmdLoadKey(CONSOLE *c, wchar_t *filename);
bool CmdLoadCertAndKey(CONSOLE *c, X **xx, K **kk, wchar_t *cert_filename, wchar_t *key_filename);
bool CmdEvalTcpOrUdp(CONSOLE *c, wchar_t *str, void *param);
wchar_t *GetConnectionTypeStr(UINT type);
bool CmdEvalHostAndSubnetMask4(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalNetworkAndSubnetMask4(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalNetworkAndSubnetMask6(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalNetworkAndSubnetMask46(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIpAndMask4(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIpAndMask6(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIpAndMask46(CONSOLE *c, wchar_t *str, void *param);
wchar_t *GetLogSwitchStr(UINT i);
wchar_t *GetPacketLogNameStr(UINT i);
UINT StrToLogSwitchType(char *str);
UINT StrToPacketLogType(char *str);
UINT StrToPacketLogSaveInfoType(char *str);
wchar_t *GetProxyTypeStr(UINT i);
wchar_t *GetClientAuthTypeStr(UINT i);
void PrintPolicyList(CONSOLE *c, char *name);
void PrintPolicy(CONSOLE *c, POLICY *pol, bool cascade_mode);
bool EditPolicy(CONSOLE *c, POLICY *pol, char *name, char *value, bool cascade_mode);
void CmdPrintStatusToListView(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s);
void CmdPrintStatusToListViewEx(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s, bool server_mode);
bool CmdEvalPassOrDiscard(CONSOLE *c, wchar_t *str, void *param);
bool StrToPassOrDiscard(char *str);
bool CmdEvalProtocol(CONSOLE *c, wchar_t *str, void *param);
UINT StrToProtocol(char *str);
bool CmdEvalPortRange(CONSOLE *c, wchar_t *str, void *param);
bool ParsePortRange(char *str, UINT *start, UINT *end);
wchar_t *GetAuthTypeStr(UINT id);
UINT64 StrToDateTime64(char *str);
bool CmdEvalDateTime(CONSOLE *c, wchar_t *str, void *param);
void CmdPrintNodeInfo(CT *ct, NODE_INFO *info);
wchar_t *GetProtocolName(UINT n);
void CmdGenerateImportName(REMOTE_CLIENT *r, wchar_t *name, UINT size, wchar_t *old_name);
bool CmdIsAccountName(REMOTE_CLIENT *r, wchar_t *name);
wchar_t *GetSyslogSettingName(UINT n);


void TtPrint(void *param, TT_PRINT_PROC *print_proc, wchar_t *str);
void TtGenerateRandomData(UCHAR **buf, UINT *size);
void TtsWorkerThread(THREAD *thread, void *param);
void TtsListenThread(THREAD *thread, void *param);
void TtsAcceptProc(TTS *tts, SOCK *listen_socket);
void TtsIPv6AcceptThread(THREAD *thread, void *param);
wchar_t *GetTtcTypeStr(UINT type);
void TtcPrintSummary(TTC *ttc);
void StopTtc(TTC *ttc);
void TtcGenerateResult(TTC *ttc);
void TtcThread(THREAD *thread, void *param);
TTC *NewTtcEx(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param, EVENT *start_event, bool *cancel);
TTC *NewTtc(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param);
UINT FreeTtc(TTC *ttc, TT_RESULT *result);
TTS *NewTts(UINT port, void *param, TT_PRINT_PROC *print_proc);
UINT FreeTts(TTS *tts);
void PtTrafficPrintProc(void *param, wchar_t *str);
void TtcPrintResult(CONSOLE *c, TT_RESULT *res);


bool SystemCheck();
bool CheckKernel();
bool CheckMemory();
bool CheckStrings();
bool CheckFileSystem();
bool CheckThread();
bool CheckNetwork();
void InputToNull(void *p);
UINT RetZero();

void Win32CmdDebug(bool is_uac);


UINT PtConnect(CONSOLE *c, wchar_t *cmdline);
PT *NewPt(CONSOLE *c, wchar_t *cmdline);
void FreePt(PT *pt);
void PtMain(PT *pt);
UINT PtMakeCert(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PtMakeCert2048(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PtTrafficClient(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PtTrafficServer(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PtCheck(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);


UINT PcConnect(CONSOLE *c, char *target, wchar_t *cmdline, char *password);
PC *NewPc(CONSOLE *c, REMOTE_CLIENT *remote_client, char *servername, wchar_t *cmdline);
void FreePc(PC *pc);
void PcMain(PC *pc);
UINT PcAbout(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcVersionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcPasswordGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcSecureList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcSecureSelect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcSecureGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicUpgrade(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicGetSetting(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicSetSetting(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountConnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountNicSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStatusShow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStatusHide(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountSecureCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountRetrySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStartupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStartupRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountExport(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountImport(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcRemoteEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcRemoteDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);


PS *NewPs(CONSOLE *c, RPC *rpc, char *servername, UINT serverport, char *hubname, char *adminhub, wchar_t *cmdline);
void FreePs(PS *ps);
UINT PsConnect(CONSOLE *c, char *host, UINT port, char *hub, char *adminhub, wchar_t *cmdline, char *password);
void PsMain(PS *ps);
UINT PsAbout(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingStandalone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingController(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingMember(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterMemberList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterMemberInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterMemberCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterConnectionStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrash(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsFlush(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDebug(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerKeyGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCipherGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCipherSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSyslogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSyslogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSyslogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConnectionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConnectionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConnectionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeDeviceList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCaps(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsReboot(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConfigGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConfigSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterStart(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterStop(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterIfList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterIfAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterIfDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterTableList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterTableAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterTableDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogFileList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogFileGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubCreateDynamic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubCreateStatic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubSetStatic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubSetDynamic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHub(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetMaxSession(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetHubPassword(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetEnumAllow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetEnumDeny(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOptionsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRadiusServerSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRadiusServerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRadiusServerGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogSwitchSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogPacketSaveType(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCAList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCAAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCADelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCAGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadePasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadePolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadePolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsPolicyList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAddEx(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAddEx6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserSignedSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserRadiusSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserNTLMSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserExpiresSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupJoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupUnjoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsMacTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsMacDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIpDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatHostGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatHostSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAdminOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAdminOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsExtOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsExtOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIPsecEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIPsecGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsEtherIpClientAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsEtherIpClientDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsEtherIpClientList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOpenVpnEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOpenVpnGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOpenVpnMakeConfig(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSstpEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSstpGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCertRegenerate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsVpnOverIcmpDnsEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsVpnOverIcmpDnsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDynamicDnsGetStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDynamicDnsSetHostname(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsVpnAzureSetEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsVpnAzureGetStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);



//////////////////////////////////////////////////////////////////////////
// Wpc.h


// Constant
#define WPC_HTTP_POST_NAME			"POST"		// POST
#define WPC_HTTP_GET_NAME			"GET"		// GET
#define WPC_USER_AGENT				DEFAULT_USER_AGENT	// User Agent
#define WPC_TIMEOUT					(15 * 1000)	// Time-out
#define WPC_RECV_BUF_SIZE			64000		// Receive buffer size
#define WPC_DATA_ENTRY_SIZE			4			// Data entry size
#define WPC_MAX_HTTP_DATASIZE		(134217728)	// Maximum HTTP data size

// Connection parameters
struct WPC_CONNECT
{
	char HostName[MAX_HOST_NAME_LEN + 1];		// Host name
	UINT Port;									// Port number
	UINT ProxyType;								// Type of proxy server
	char ProxyHostName[MAX_HOST_NAME_LEN + 1];	// Proxy server host name
	UINT ProxyPort;								// Proxy server port number
	char ProxyUsername[MAX_USERNAME_LEN + 1];	// Proxy server user name
	char ProxyPassword[MAX_USERNAME_LEN + 1];	// Proxy server password
	bool UseCompress;							// Use of compression
	bool DontCheckCert;							// Do not check the certificate
};

// Internet connection settings
struct INTERNET_SETTING
{
	UINT ProxyType;								// Type of proxy server
	char ProxyHostName[MAX_HOST_NAME_LEN + 1];	// Proxy server host name
	UINT ProxyPort;								// Proxy server port number
	char ProxyUsername[MAX_USERNAME_LEN + 1];	// Proxy server user name
	char ProxyPassword[MAX_USERNAME_LEN + 1];	// Proxy server password
};

// URL
struct URL_DATA
{
	bool Secure;							// Whether HTTPS
	char HostName[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT Port;								// Port number
	char HeaderHostName[MAX_HOST_NAME_LEN + 16];	// Host name on the header
	char Method[32];						// Method
	char Target[MAX_SIZE * 3];				// Target
	char Referer[MAX_SIZE * 3];				// Referer
	char AdditionalHeaderName[128];			// Additional header name
	char AdditionalHeaderValue[MAX_SIZE];	// Additional header value
	char SniString[MAX_SIZE];				// SNI String
};

// WPC entry
struct WPC_ENTRY
{
	char EntryName[WPC_DATA_ENTRY_SIZE];		// Entry name
	void *Data;									// Data
	UINT Size;									// Data size
};

// WPC packet
struct WPC_PACKET
{
	PACK *Pack;								// Pack (data body)
	UCHAR Hash[SHA1_SIZE];					// Data hash
	X *Cert;								// Certificate
	UCHAR Sign[128];						// Digital signature
};

// Reception callback
typedef bool (WPC_RECV_CALLBACK)(void *param, UINT total_size, UINT current_size, BUF *recv_buf);

// Function prototype
void EncodeSafe64(char *dst, void *src, UINT src_size);
UINT DecodeSafe64(void *dst, char *src, UINT src_strlen);
void Base64ToSafe64(char *str);
void Safe64ToBase64(char *str);
bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer);
void CreateUrl(char *url, UINT url_size, URL_DATA *data);
void GetSystemInternetSetting(INTERNET_SETTING *setting);
bool GetProxyServerNameAndPortFromIeProxyRegStr(char *name, UINT name_size, UINT *port, char *str, char *server_type);
BUF *HttpRequest(URL_DATA *data, INTERNET_SETTING *setting,
	UINT timeout_connect, UINT timeout_comm,
	UINT *error_code, bool check_ssl_trust, char *post_data,
	WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash);
BUF *HttpRequestEx(URL_DATA *data, INTERNET_SETTING *setting,
	UINT timeout_connect, UINT timeout_comm,
	UINT *error_code, bool check_ssl_trust, char *post_data,
	WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
	bool *cancel, UINT max_recv_size);
BUF *HttpRequestEx2(URL_DATA *data, INTERNET_SETTING *setting,
	UINT timeout_connect, UINT timeout_comm,
	UINT *error_code, bool check_ssl_trust, char *post_data,
	WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
	bool *cancel, UINT max_recv_size, char *header_name, char *header_value);
BUF *HttpRequestEx3(URL_DATA *data, INTERNET_SETTING *setting,
	UINT timeout_connect, UINT timeout_comm,
	UINT *error_code, bool check_ssl_trust, char *post_data,
	WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
	bool *cancel, UINT max_recv_size, char *header_name, char *header_value);
SOCK *WpcSockConnect(WPC_CONNECT *param, UINT *error_code, UINT timeout);
SOCK *WpcSockConnectEx(WPC_CONNECT *param, UINT *error_code, UINT timeout, bool *cancel);
SOCK *WpcSockConnect2(char *hostname, UINT port, INTERNET_SETTING *t, UINT *error_code, UINT timeout);
INTERNET_SETTING *GetNullInternetSetting();
void WpcAddDataEntry(BUF *b, char *name, void *data, UINT size);
void WpcAddDataEntryBin(BUF *b, char *name, void *data, UINT size);
void WpcFillEntryName(char *dst, char *name);
LIST *WpcParseDataEntry(BUF *b);
void WpcFreeDataEntryList(LIST *o);
WPC_ENTRY *WpcFindDataEntry(LIST *o, char *name);
BUF *WpcDataEntryToBuf(WPC_ENTRY *e);
BUF *WpcGeneratePacket(PACK *pack, X *cert, K *key);
bool WpcParsePacket(WPC_PACKET *packet, BUF *buf);
void WpcFreePacket(WPC_PACKET *packet);
PACK *WpcCall(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
	char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash);
PACK *WpcCallEx(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
	char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash, bool *cancel, UINT max_recv_size,
	char *additional_header_name, char *additional_header_value);
PACK *WpcCallEx2(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
	char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash, UINT num_hashes, bool *cancel, UINT max_recv_size,
	char *additional_header_name, char *additional_header_value, char *sni_string);
bool IsProxyPrivateIp(INTERNET_SETTING *s);


//////////////////////////////////////////////////////////////////////////
// IPsec.h


//// Constants

// UDP port number
#define	IPSEC_PORT_L2TP					1701		// L2TP
#define	IPSEC_PORT_IPSEC_ISAKMP			500			// ISAKMP
#define	IPSEC_PORT_IPSEC_ESP_UDP		4500		// IPsec ESP over UDP
#define	IPSEC_PORT_IPSEC_ESP_RAW		MAKE_SPECIAL_PORT(50)	// Raw mode ESP Protocol No: 50
#define	IPSEC_PORT_IPSEC_ESP_RAW_WPF	MAKE_SPECIAL_PORT(52)	// Raw mode ESP Protocol No: 52 (WPF)
#define	IPSEC_PORT_L2TPV3_VIRTUAL		1000001		// L2TPv3 virtual port

// IP protocol number
#define	IPSEC_IP_PROTO_ETHERIP			IP_PROTO_ETHERIP	// EtherIP
#define	IPSEC_IP_PROTO_L2TPV3			IP_PROTO_L2TPV3		// L2TPv3

// WFP tag
#define	WFP_ESP_PACKET_TAG_1		0x19841117
#define	WFP_ESP_PACKET_TAG_2		0x1accafe1

// Monitoring interval of OS service
#define	IPSEC_CHECK_OS_SERVICE_INTERVAL_INITIAL	1024
#define	IPSEC_CHECK_OS_SERVICE_INTERVAL_MAX		(5 * 60 * 1000)

// Default IPsec pre-shared key
#define	IPSEC_DEFAULT_SECRET			"vpn"


//// Type

// List of services provided by IPsec server
struct IPSEC_SERVICES
{
	bool L2TP_Raw;								// Raw L2TP
	bool L2TP_IPsec;							// L2TP over IPsec
	bool EtherIP_IPsec;							// EtherIP over IPsec

	char IPsec_Secret[MAX_SIZE];				// IPsec pre-shared key
	char L2TP_DefaultHub[MAX_SIZE];				// Default Virtual HUB name for L2TP connection
};

// EtherIP key list entry
struct ETHERIP_ID
{
	char Id[MAX_SIZE];							// ID
	char HubName[MAX_HUBNAME_LEN + 1];			// Virtual HUB name
	char UserName[MAX_USERNAME_LEN + 1];		// User name
	char Password[MAX_USERNAME_LEN + 1];		// Password
};

// IPsec server
struct IPSEC_SERVER
{
	CEDAR *Cedar;
	UDPLISTENER *UdpListener;
	bool Halt;
	bool NoMoreChangeSettings;
	LOCK *LockSettings;
	IPSEC_SERVICES Services;
	L2TP_SERVER *L2TP;							// L2TP server
	IKE_SERVER *Ike;							// IKE server
	LIST *EtherIPIdList;						// EtherIP setting list
	UINT EtherIPIdListSettingVerNo;				// EtherIP setting list version number
	THREAD *OsServiceCheckThread;				// OS Service monitoring thread
	EVENT *OsServiceCheckThreadEvent;			// Event for OS Service monitoring thread
	IPSEC_WIN7 *Win7;							// Helper module for Windows Vista / 7
	bool Check_LastEnabledStatus;
	bool HostIPAddressListChanged;
	bool OsServiceStoped;
};


//// Function prototype
IPSEC_SERVER *NewIPsecServer(CEDAR *cedar);
void FreeIPsecServer(IPSEC_SERVER *s);
void IPsecServerUdpPacketRecvProc(UDPLISTENER *u, LIST *packet_list);
void IPsecServerSetServices(IPSEC_SERVER *s, IPSEC_SERVICES *sl);
void IPsecNormalizeServiceSetting(IPSEC_SERVER *s);
void IPsecServerGetServices(IPSEC_SERVER *s, IPSEC_SERVICES *sl);
void IPsecProcPacket(IPSEC_SERVER *s, UDPPACKET *p);
int CmpEtherIPId(void *p1, void *p2);
bool SearchEtherIPId(IPSEC_SERVER *s, ETHERIP_ID *id, char *id_str);
void AddEtherIPId(IPSEC_SERVER *s, ETHERIP_ID *id);
bool DeleteEtherIPId(IPSEC_SERVER *s, char *id_str);
void IPsecOsServiceCheckThread(THREAD *t, void *p);
bool IPsecCheckOsService(IPSEC_SERVER *s);
void IPSecSetDisable(bool b);



//////////////////////////////////////////////////////////////////////////
// IPsec_L2TP.h


//// Macro

// Check the sequence number
#define	L2TP_SEQ_LT(a, b)			(((USHORT)(((USHORT)(a)) - ((USHORT)(b)))) & 0x8000)
#define	L2TP_SEQ_EQ(a, b)			((USHORT)(a) == (USHORT)(b))

//// Constants

// Client string
#define L2TP_IPC_CLIENT_NAME_TAG		"L2TP VPN Client - %s"
#define L2TP_IPC_CLIENT_NAME_NO_TAG		"L2TP VPN Client"
#define	L2TP_IPC_POSTFIX				"L2TP"

// L2TP vendor name
#define	L2TP_VENDOR_NAME				"L2TP"

// L2TP packet retransmission interval
#define	L2TP_PACKET_RESEND_INTERVAL		500

// Timeout for L2TP tunnel disconnecting completion
#define	L2TP_TUNNEL_DISCONNECT_TIMEOUT	3000

// Timeout for L2TP session disconnection completion
#define	L2TP_SESSION_DISCONNECT_TIMEOUT	3000

// Time-out interval of L2TP tunnel
#define	L2TP_TUNNEL_TIMEOUT				(60 * 1000)

// Transmission interval of L2TP Hello
#define	L2TP_HELLO_INTERVAL				(8801)

// Threshold number of registered items in the transmission queue for suppressing the L2TP Hello transmission
#define	L2TP_HELLO_SUPRESS_MAX_THRETHORD_NUM_SEND_QUEUE		32

// Quota
#define	L2TP_QUOTA_MAX_NUM_TUNNELS_PER_IP		1000			// Number of L2TP sessions per IP address
#define	L2TP_QUOTA_MAX_NUM_TUNNELS				30000			// Limit of the number of sessions
#define	L2TP_QUOTA_MAX_NUM_SESSIONS_PER_TUNNEL	1024		// Max sessions in a tunnel

// L2TP window size
#define	L2TP_WINDOW_SIZE				16

// L2TP packet header bit mask
#define	L2TP_HEADER_BIT_TYPE			0x80	// Type
#define	L2TP_HEADER_BIT_LENGTH			0x40	// Length
#define	L2TP_HEADER_BIT_SEQUENCE		0x08	// Sequence
#define	L2TP_HEADER_BIT_OFFSET			0x02	// Offset
#define	L2TP_HEADER_BIT_PRIORITY		0x01	// Priority
#define	L2TP_HEADER_BIT_VER				0x0F	// Version

// L2TP AVP header bit mask
#define	L2TP_AVP_BIT_MANDATORY			0x80	// Mandatory
#define	L2TP_AVP_BIT_HIDDEN				0x40	// Hidden
#define	L2TP_AVP_LENGTH					0x3FF	// Length

// AVP value
#define	L2TP_AVP_TYPE_MESSAGE_TYPE		0		// Message Type
#define	L2TP_AVP_TYPE_RESULT_CODE		1		// Result Code
#define	L2TP_AVP_TYPE_PROTOCOL_VERSION	2		// Protocol Version
#define	L2TP_AVP_TYPE_FRAME_CAP			3		// Framing Capabilities
#define	L2TP_AVP_TYPE_BEARER_CAP		4		// Bearer Capabilities
#define	L2TP_AVP_TYPE_TIE_BREAKER		5		// Tie Breaker
#define	L2TP_AVP_TYPE_HOST_NAME			7		// Host Name
#define	L2TP_AVP_TYPE_VENDOR_NAME		8		// Vendor Name
#define	L2TP_AVP_TYPE_ASSIGNED_TUNNEL	9		// Assigned Tunnel
#define	L2TP_AVP_TYPE_RECV_WINDOW_SIZE	10		// Receive Window Size
#define	L2TP_AVP_TYPE_ASSIGNED_SESSION	14		// Assigned Session ID
#define	L2TP_AVP_TYPE_CALL_SERIAL		15		// Call Serial Number
#define	L2TP_AVP_TYPE_PPP_DISCONNECT_CAUSE	46	// PPP Disconnect Cause Code
#define	L2TP_AVP_TYPE_V3_ROUTER_ID		60		// Router ID
#define	L2TP_AVP_TYPE_V3_TUNNEL_ID		61		// Assigned Control Connection ID
#define	L2TP_AVP_TYPE_V3_PW_CAP_LIST	62		// Pseudowire Capabilities List
#define	L2TP_AVP_TYPE_V3_SESSION_ID_LOCAL	63	// Local Session ID
#define	L2TP_AVP_TYPE_V3_SESSION_ID_REMOTE	64	// Remote Session ID
#define	L2TP_AVP_TYPE_V3_PW_TYPE		68		// Pseudowire Type
#define	L2TP_AVP_TYPE_V3_CIRCUIT_STATUS	71

// Message Type value
#define	L2TP_MESSAGE_TYPE_SCCRQ			1		// Start-Control-Connection-Request
#define	L2TP_MESSAGE_TYPE_SCCRP			2		// Start-Control-Connection-Reply
#define	L2TP_MESSAGE_TYPE_SCCCN			3		// Start-Control-Connection-Connected
#define	L2TP_MESSAGE_TYPE_STOPCCN		4		// Stop-Control-Connection-Notification
#define	L2TP_MESSAGE_TYPE_HELLO			6		// Hello
#define	L2TP_MESSAGE_TYPE_ICRQ			10		// Incoming-Call-Request
#define	L2TP_MESSAGE_TYPE_ICRP			11		// Incoming-Call-Reply
#define	L2TP_MESSAGE_TYPE_ICCN			12		// Incoming-Call-Connected
#define	L2TP_MESSAGE_TYPE_CDN			14		// Call-Disconnect-Notify

// Type of L2TPv3 virtual network
#define	L2TPV3_PW_TYPE_ETHERNET			5		// Ethernet
#define	L2TPV3_PW_TYPE_ETHERNET_VLAN	4		// Ethernet VLAN

// L2TPv3 vendor unique value
#define	L2TP_AVP_VENDOR_ID_CISCO		9		// Cisco Systems
#define	L2TPV3_CISCO_AVP_TUNNEL_ID		1		// Assigned Connection ID
#define	L2TPV3_CISCO_AVP_PW_CAP_LIST	2		// Pseudowire Capabilities List
#define	L2TPV3_CISCO_AVP_SESSION_ID_LOCAL	3	// Local Session ID
#define	L2TPV3_CISCO_AVP_SESSION_ID_REMOTE	4	// Remote Session ID
#define	L2TPV3_CISCO_AVP_PW_TYPE			7	// Pseudowire Type
#define	L2TPV3_CISCO_AVP_DRAFT_AVP_VERSION	10	// Draft AVP Version



//// Types

// L2TP queue
struct L2TP_QUEUE
{
	BUF *Buf;									// Data
	USHORT Ns;									// Sequence number
	UINT64 NextSendTick;						// Scheduled time to be sent next
	L2TP_PACKET *L2TPPacket;					// L2TP packet data
};

// L2TP AVP value
struct L2TP_AVP
{
	bool Mandatory;								// Force bit
	UINT Length;								// Overall length
	USHORT VendorID;							// Vendor ID
	USHORT Type;								// Type
	UINT DataSize;								// Data size
	void *Data;									// Data body
};

// L2TP packet
struct L2TP_PACKET
{
	bool IsControl;								// Whether it's a control message
	bool HasLength;								// Whether there is length bit
	bool HasSequence;							// Whether there is sequence bit
	bool HasOffset;								// Whether there is offset bit
	bool IsPriority;							// Whether priority packet
	bool IsZLB;									// Zero Length Bit
	bool IsYamahaV3;							// L2TPv3 on YAMAHA
	UINT Ver;									// Version
	UINT Length;								// Length
	UINT TunnelId;								// Tunnel ID
	UINT SessionId;								// Session ID
	USHORT Ns, Nr;								// Sequence number
	UINT OffsetSize;							// Offset size
	UINT DataSize;								// Data size
	void *Data;									// Data body
	LIST *AvpList;								// AVP list
	UINT MessageType;							// Message type
};

// L2TP session
struct L2TP_SESSION
{
	L2TP_TUNNEL *Tunnel;						// Parent L2TP tunnel
	bool IsV3;									// L2TPv3
	bool IsCiscoV3;								// L2TPv3 for Cisco
	UINT SessionId1;							// Session ID (server -> client direction)
	UINT SessionId2;							// Session ID (client -> server direction)
	bool Established;							// Established
	bool WantToDisconnect;						// Whether to want to disconnect
	bool Disconnecting;							// Whether disconnected
	UINT64 DisconnectTimeout;					// Disconnection completion time-out
	bool HasThread;								// Whether have a thread
	THREAD *Thread;								// Thread
	TUBE *TubeSend;								// Tube of PPP to L2TP direction
	TUBE *TubeRecv;								// Tube of L2TP to PPP direction
	UINT PseudowireType;						// Type of L2TPv3 virtual line
	ETHERIP_SERVER *EtherIP;					// EtherIP server
};

// L2TP tunnel
struct L2TP_TUNNEL
{
	bool IsV3;									// L2TPv3
	bool IsCiscoV3;								// L2TPv3 for Cisco
	bool IsYamahaV3;							// L2TPv3 for YAMAHA
	IP ClientIp;								// Client IP address
	UINT ClientPort;							// Client port number
	IP ServerIp;								// Server IP address
	UINT ServerPort;							// Server port number
	UINT TunnelId1;								// Tunnel ID (server -> client direction)
	UINT TunnelId2;								// Tunnel ID (client -> server direction)
	char HostName[MAX_SIZE];					// Destination host name
	char VendorName[MAX_SIZE];					// Destination vendor name
	LIST *SessionList;							// L2TP session list
	LIST *SendQueue;							// Transmission queue
	LIST *RecvQueue;							// Reception queue
	USHORT NextNs;								// Value of Ns of the packet to be sent next
	USHORT LastNr;								// Value of NR received in the last
	bool Established;							// Whether the tunnel is established
	bool StateChanged;							// Whether the state have changed
	bool WantToDisconnect;						// Whether to want to disconnect
	bool Disconnecting;							// Whether disconnected
	UINT64 DisconnectTimeout;					// Disconnection completion time-out
	UINT64 LastRecvTick;						// Time which the data has been received at last
	bool Timedout;								// Whether the time-out
	UINT64 LastHelloSent;						// Time which the data has been sent at last
};

// L2TP server
struct L2TP_SERVER
{
	CEDAR *Cedar;
	UINT64 Now;									// Current time
	LIST *SendPacketList;						// Transmission packet
	LIST *TunnelList;							// Tunnel list
	INTERRUPT_MANAGER *Interrupts;				// Interrupt manager
	SOCK_EVENT *SockEvent;						// SockEvent
	bool Halt;									// Start the shutdown
	bool Halting;								// During shutdown
	bool HaltCompleted;							// Shutdown is complete
	EVENT *HaltCompletedEvent;					// Stopping completion event
	LIST *ThreadList;							// Thread list
	char CryptName[MAX_SIZE];					// Cipher algorithm name
	IKE_SERVER *IkeServer;						// IKE server (Only if associated)
	IKE_CLIENT *IkeClient;						// IKE client (Only if associated)
	bool IsIPsecIPv6;							// Whether it's IPv6
	UINT CryptBlockSize;						// Cipher block size of the upper layer
	TUBE_FLUSH_LIST *FlushList;					// Tube Flush List
};


//// Function prototype
L2TP_SERVER *NewL2TPServer(CEDAR *cedar);
L2TP_SERVER *NewL2TPServerEx(CEDAR *cedar, IKE_SERVER *ike, bool is_ipv6, UINT crypt_block_size);
UINT GetNumL2TPTunnelsByClientIP(L2TP_SERVER *l2tp, IP *client_ip);
void SetL2TPServerSockEvent(L2TP_SERVER *l2tp, SOCK_EVENT *e);
void FreeL2TPServer(L2TP_SERVER *l2tp);
void StopL2TPServer(L2TP_SERVER *l2tp, bool no_wait);
void ProcL2TPPacketRecv(L2TP_SERVER *l2tp, UDPPACKET *p);
L2TP_PACKET *ParseL2TPPacket(UDPPACKET *p);
BUF *BuildL2TPPacketData(L2TP_PACKET *pp, L2TP_TUNNEL *t);
L2TP_AVP *GetAVPValue(L2TP_PACKET *p, UINT type);
L2TP_AVP *GetAVPValueEx(L2TP_PACKET *p, UINT type, UINT vendor_id);
L2TP_TUNNEL *NewL2TPTunnel(L2TP_SERVER *l2tp, L2TP_PACKET *p, UDPPACKET *udp);
UINT GenerateNewTunnelId(L2TP_SERVER *l2tp, IP *client_ip);
UINT GenerateNewTunnelIdEx(L2TP_SERVER *l2tp, IP *client_ip, bool is_32bit);
void FreeL2TPTunnel(L2TP_TUNNEL *t);
L2TP_TUNNEL *GetTunnelFromId(L2TP_SERVER *l2tp, IP *client_ip, UINT tunnel_id, bool is_v3);
L2TP_TUNNEL *GetTunnelFromIdOfAssignedByClient(L2TP_SERVER *l2tp, IP *client_ip, UINT tunnel_id);
L2TP_TUNNEL *GetTunnelFromIdOfAssignedByClientEx(L2TP_SERVER *l2tp, IP *client_ip, UINT tunnel_id, bool is_v3);
void SendL2TPControlPacket(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, UINT session_id, L2TP_PACKET *p);
void SendL2TPControlPacketMain(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_QUEUE *q);
void SendL2TPDataPacket(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s, void *data, UINT size);
void FreeL2TPQueue(L2TP_QUEUE *q);
void L2TPAddInterrupt(L2TP_SERVER *l2tp, UINT64 next_tick);
void L2TPSendUDP(L2TP_SERVER *l2tp, UDPPACKET *p);
void L2TPProcessInterrupts(L2TP_SERVER *l2tp);
L2TP_PACKET *NewL2TPControlPacket(UINT message_type, bool is_v3);
L2TP_AVP *NewAVP(USHORT type, bool mandatory, USHORT vendor_id, void *data, UINT data_size);
int CmpL2TPQueueForRecv(void *p1, void *p2);
void L2TPProcessRecvControlPacket(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_PACKET *p);
L2TP_SESSION *GetSessionFromId(L2TP_TUNNEL *t, UINT session_id);
L2TP_SESSION *GetSessionFromIdAssignedByClient(L2TP_TUNNEL *t, UINT session_id);
L2TP_SESSION *NewL2TPSession(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, UINT session_id_by_client);
UINT GenerateNewSessionId(L2TP_TUNNEL *t);
UINT GenerateNewSessionIdEx(L2TP_TUNNEL *t, bool is_32bit);
void FreeL2TPSession(L2TP_SESSION *s);
void DisconnectL2TPSession(L2TP_TUNNEL *t, L2TP_SESSION *s);
void DisconnectL2TPTunnel(L2TP_TUNNEL *t);
void StartL2TPThread(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s);
void StopL2TPThread(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s);
UINT CalcL2TPMss(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s);
UINT GenerateNewSessionIdForL2TPv3(L2TP_SERVER *l2tp);
L2TP_SESSION *SearchL2TPSessionById(L2TP_SERVER *l2tp, bool is_v3, UINT id);
void L2TPSessionManageEtherIPServer(L2TP_SERVER *l2tp, L2TP_SESSION *s);


//////////////////////////////////////////////////////////////////////////
// IPsec_PPP.h


//// Macro
#define	PPP_LCP_CODE_IS_NEGATIVE(c)			((c) == PPP_LCP_CODE_NAK || (c) == PPP_LCP_CODE_REJECT || (c) == PPP_LCP_CODE_CODE_REJECT || (c) == PPP_LCP_CODE_PROTOCOL_REJECT)
#define	PPP_LCP_CODE_IS_REQUEST(c)			((c) == PPP_LCP_CODE_REQ)
#define	PPP_LCP_CODE_IS_RESPONSE(c)			((c) == PPP_LCP_CODE_ACK || (c) == PPP_LCP_CODE_NAK || (c) == PPP_LCP_CODE_REJECT || (c) == PPP_LCP_CODE_PROTOCOL_REJECT)
#define	PPP_LCP_CODE_IS_WITH_OPTION_LIST(c)	((c) == PPP_LCP_CODE_REQ || (c) == PPP_LCP_CODE_ACK || (c) == PPP_LCP_CODE_NAK)

#define	PPP_PAP_CODE_IS_REQUEST(c)			((c) == PPP_PAP_CODE_REQ)
#define	PPP_PAP_CODE_IS_RESPONSE(c)			((c) == PPP_PAP_CODE_ACK || (c) == PPP_PAP_CODE_NAK)

#define	PPP_CODE_IS_RESPONSE(protocol, c)	((((protocol) == PPP_PROTOCOL_LCP || (protocol) == PPP_PROTOCOL_IPCP) && PPP_LCP_CODE_IS_RESPONSE(c)) || (((protocol) == PPP_PROTOCOL_PAP) && PPP_PAP_CODE_IS_RESPONSE(c)))
#define	PPP_CODE_IS_REQUEST(protocol, c)	((((protocol) == PPP_PROTOCOL_LCP || (protocol) == PPP_PROTOCOL_IPCP) && PPP_LCP_CODE_IS_REQUEST(c)) || (((protocol) == PPP_PROTOCOL_PAP) && PPP_PAP_CODE_IS_REQUEST(c)) || ((protocol) == PPP_PROTOCOL_CHAP))
#define	PPP_CODE_IS_WITH_OPTION_LIST(protocol, c) ((((protocol) == PPP_PROTOCOL_LCP || (protocol) == PPP_PROTOCOL_IPCP) && PPP_LCP_CODE_IS_WITH_OPTION_LIST(c)) || false)

#define	PPP_IS_SUPPORTED_PROTOCOL(p)		((p) == PPP_PROTOCOL_LCP || (p) == PPP_PROTOCOL_PAP || (p) == PPP_PROTOCOL_CHAP || (p) == PPP_PROTOCOL_IPCP || (p) == PPP_PROTOCOL_IP)


//// Constants

// Time-out value
#define	PPP_PACKET_RECV_TIMEOUT			10000		// Timeout until the next packet is received
#define	PPP_PACKET_RESEND_INTERVAL		1000		// Retransmission interval of the last packet
#define	PPP_TERMINATE_TIMEOUT			2000		// Timeout value to complete disconnection after requesting to disconnect in the PPP
#define	PPP_ECHO_SEND_INTERVAL			4792		// Transmission interval of PPP Echo Request
#define	PPP_DATA_TIMEOUT				(20 * 1000)	// Communication time-out

// MRU
#define	PPP_MRU_DEFAULT					1500		// Default value
#define	PPP_MRU_MIN						100			// Minimum value
#define	PPP_MRU_MAX						1500		// Maximum value

// PPP protocol (for control)
#define	PPP_PROTOCOL_LCP				0xc021
#define	PPP_PROTOCOL_PAP				0xc023
#define	PPP_PROTOCOL_IPCP				0x8021
#define	PPP_PROTOCOL_CHAP				0xc223

// PPP protocol (for transfer)
#define	PPP_PROTOCOL_IP					0x0021

// LCP code
#define	PPP_LCP_CODE_REQ				1
#define	PPP_LCP_CODE_ACK				2
#define	PPP_LCP_CODE_NAK				3
#define	PPP_LCP_CODE_REJECT				4
#define	PPP_LCP_CODE_TERMINATE_REQ		5
#define	PPP_LCP_CODE_TERMINATE_ACK		6
#define	PPP_LCP_CODE_CODE_REJECT		7
#define	PPP_LCP_CODE_PROTOCOL_REJECT	8
#define	PPP_LCP_CODE_ECHO_REQUEST		9
#define	PPP_LCP_CODE_ECHO_RESPONSE		10
#define	PPP_LCP_CODE_DROP				11
#define	PPP_LCP_CODE_IDENTIFICATION		12

// PAP Code
#define	PPP_PAP_CODE_REQ				1
#define	PPP_PAP_CODE_ACK				2
#define	PPP_PAP_CODE_NAK				3

// CHAP code
#define	PPP_CHAP_CODE_CHALLENGE			1
#define	PPP_CHAP_CODE_RESPONSE			2
#define	PPP_CHAP_CODE_SUCCESS			3
#define	PPP_CHAP_CODE_FAILURE			4

// LCP Option Type
#define	PPP_LCP_OPTION_MRU				1
#define	PPP_LCP_OPTION_AUTH				3

// IPCP option type
#define	PPP_IPCP_OPTION_IP				3
#define	PPP_IPCP_OPTION_DNS1			129
#define	PPP_IPCP_OPTION_DNS2			131
#define	PPP_IPCP_OPTION_WINS1			130
#define	PPP_IPCP_OPTION_WINS2			132

// Authentication protocol
#define	PPP_LCP_AUTH_PAP				PPP_PROTOCOL_PAP
#define	PPP_LCP_AUTH_CHAP				PPP_PROTOCOL_CHAP

// Algorithm of CHAP
#define	PPP_CHAP_ALG_MS_CHAP_V2			0x81


//// Type

// IP options used in the PPP
struct PPP_IPOPTION
{
	IP IpAddress;						// IP address
	IP DnsServer1, DnsServer2;			// DNS server address
	IP WinsServer1, WinsServer2;		// WINS server address
};

// PPP packet
struct PPP_PACKET
{
	USHORT Protocol;					// Protocol
	bool IsControl;						// Whether or not the control packet
	PPP_LCP *Lcp;						// LCP packet data
	UINT DataSize;						// Data size
	void *Data;							// Data body
};

// PPP LCP packet
struct PPP_LCP
{
	UCHAR Code;							// Code
	UCHAR Id;							// ID
	UCHAR MagicNumber[4];				// Magic number
	LIST *OptionList;					// PPP options list
	void *Data;							// Data
	UINT DataSize;						// Data size
};

// PPP Options
struct PPP_OPTION
{
	UCHAR Type;							// Type of option
	UINT DataSize;						// Data size
	UCHAR Data[254];					// Data
	bool IsSupported;					// Flag of whether it is supported
	bool IsAccepted;					// Flag for whether accepted
	UCHAR AltData[254];					// Alternate data when it isn't accepted
	UINT AltDataSize;					// Alternate data size
};

// PPP session
struct PPP_SESSION
{
	CEDAR *Cedar;						// Cedar
	IP ClientIP;						// Client IP address
	UINT ClientPort;					// Client port
	IP ServerIP;						// Server IP address
	UINT ServerPort;					// Server port
	TUBE *TubeSend;						// Sending tube
	TUBE *TubeRecv;						// Receiving tube
	UCHAR NextId;						// ID to be used next
	UINT Mru1;							// MRU (server -> client)
	UINT Mru2;							// MRU (client -> server)
	LIST *RecvPacketList;				// Received packet list
	PPP_PACKET *LastStoredPacket;		// Packet that is stored at the last
	bool IsTerminateReceived;			// Whether a Terminate has been received
	UINT DisconnectCauseCode;			// L2TP disconnect cause code
	UINT DisconnectCauseDirection;		// L2TP disconnect cause direction code
	IPC *Ipc;							// IPC
	bool ClientLCPOptionDetermined;		// LCP option from the client has been determined
	char Postfix[MAX_SIZE];				// Postfix of the session name
	char ClientHostname[MAX_SIZE];		// Client host name
	char ClientSoftwareName[MAX_SIZE];	// Client software name
	UINT64 NextEchoSendTime;			// Time to send Echo Request next
	UINT64 LastRecvTime;				// Time which the data has been received last
	DHCP_OPTION_LIST ClientAddressOption;	// Client address option
	bool DhcpIpAllocTried;				// Whether the request for an IP address is already attempted by DHCP
	bool DhcpIpInformTried;				// Whether the acquirement for an IP information is already attempted by DHCP
	bool DhcpAllocated;					// IP address is assigned by DHCP
	bool UseStaticIPAddress;			// Use a static IP address that is specified by the client
	UINT64 DhcpRenewInterval;			// DHCP update interval
	UINT64 DhcpNextRenewTime;			// DHCP renewal time of the next
	char CryptName[MAX_SIZE];			// Cipher algorithm name
	UINT AdjustMss;						// MSS value
	TUBE_FLUSH_LIST *FlushList;			// Tube Flush List
	bool EnableMSCHAPv2;				// Enable the MS-CHAP v2
	USHORT AuthProtocol;				// Authentication protocol
	bool AuthOk;						// Flag for whether the authentication was successful
	UCHAR MsChapV2_ServerChallenge[16];	// MS-CHAPv2 Server Challenge
	UCHAR MsChapV2_ClientChallenge[16];	// MS-CHAPv2 Client Challenge
	UCHAR MsChapV2_ClientResponse[24];	// MS-CHAPv2 Client Response
	UCHAR MsChapV2_ServerResponse[20];	// MS-CHAPv2 Server Response
	UINT MsChapV2_ErrorCode;			// Authentication failure error code of MS-CHAPv2

	bool MsChapV2_UseDoubleMsChapV2;	// Use the double-MSCHAPv2 technieue
	EAP_CLIENT *EapClient;				// EAP client
};

// Function prototype
THREAD *NewPPPSession(CEDAR *cedar, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, TUBE *send_tube, TUBE *recv_tube, char *postfix, char *client_software_name, char *client_hostname, char *crypt_name, UINT adjust_mss);
void PPPThread(THREAD *thread, void *param);
void FreePPPSession(PPP_SESSION *p);
void FreePPPOptionList(LIST *o);
void FreePPPLCP(PPP_LCP *c);
PPP_LCP *NewPPPLCP(UCHAR code, UCHAR id);
PPP_LCP *ParseLCP(USHORT protocol, void *data, UINT size);
BUF *BuildLCPData(PPP_LCP *c);
PPP_OPTION *GetOptionValue(PPP_LCP *c, UCHAR type);
PPP_PACKET *ParsePPPPacket(void *data, UINT size);
void FreePPPPacket(PPP_PACKET *pp);
void FreePPPPacketEx(PPP_PACKET *pp, bool no_free_struct);
BUF *BuildPPPPacketData(PPP_PACKET *pp);
PPP_OPTION *NewPPPOption(UCHAR type, void *data, UINT size);
bool PPPSendPacket(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPSendPacketEx(PPP_SESSION *p, PPP_PACKET *pp, bool no_flush);
PPP_PACKET *PPPRecvPacket(PPP_SESSION *p, bool async);
PPP_PACKET *PPPRecvPacketWithLowLayerProcessing(PPP_SESSION *p, bool async);
PPP_PACKET *PPPRecvPacketForCommunication(PPP_SESSION *p);
void PPPStoreLastPacket(PPP_SESSION *p, PPP_PACKET *pp);
void PPPCleanTerminate(PPP_SESSION *p);
bool PPPGetIPOptionFromLCP(PPP_IPOPTION *o, PPP_LCP *c);
bool PPPSetIPOptionToLCP(PPP_IPOPTION *o, PPP_LCP *c, bool only_modify);
bool PPPGetIPAddressValueFromLCP(PPP_LCP *c, UINT type, IP *ip);
bool PPPSetIPAddressValueToLCP(PPP_LCP *c, UINT type, IP *ip, bool only_modify);

bool PPPSendRequest(PPP_SESSION *p, USHORT protocol, PPP_LCP *c);
USHORT PPPContinueCurrentProtocolRequestListening(PPP_SESSION *p, USHORT protocol);
bool PPPContinueUntilFinishAllLCPOptionRequestsDetermined(PPP_SESSION *p);
PPP_PACKET *PPPRecvResponsePacket(PPP_SESSION *p, PPP_PACKET *req, USHORT expected_protocol, USHORT *received_protocol, bool finish_when_all_lcp_acked,
	bool return_mschapv2_response_with_no_processing);
PPP_PACKET *PPPProcessRequestPacket(PPP_SESSION *p, PPP_PACKET *req);
void PPPSendEchoRequest(PPP_SESSION *p);
bool PPPParseUsername(CEDAR *cedar, char *src, ETHERIP_ID *dst);
bool IsHubExistsWithLock(CEDAR *cedar, char *hubname);

void GenerateNtPasswordHash(UCHAR *dst, char *password);
void GenerateNtPasswordHashHash(UCHAR *dst_hash, UCHAR *src_hash);
void MsChapV2Server_GenerateChallenge(UCHAR *dst);
void MsChapV2Client_GenerateChallenge(UCHAR *dst);
void MsChapV2_GenerateChallenge8(UCHAR *dst, UCHAR *client_challenge, UCHAR *server_challenge, char *username);
void MsChapV2Client_GenerateResponse(UCHAR *dst, UCHAR *challenge8, UCHAR *nt_password_hash);
void MsChapV2Server_GenerateResponse(UCHAR *dst, UCHAR *nt_password_hash_hash, UCHAR *client_response, UCHAR *challenge8);
bool MsChapV2VerityPassword(IPC_MSCHAP_V2_AUTHINFO *d, char *password);
char *MsChapV2DoBruteForce(IPC_MSCHAP_V2_AUTHINFO *d, LIST *password_list);
void PPPFreeEapClient(PPP_SESSION *p);

//////////////////////////////////////////////////////////////////////////
// IPsec_IPC.h


// Constants
#define	IPC_ARP_LIFETIME				(3 * 60 * 1000)
#define	IPC_ARP_GIVEUPTIME				(1 * 1000)
#define	IPC_DHCP_TIMEOUT				(5 * 1000)
#define	IPC_DHCP_TIMEOUT_TOTAL_GIVEUP	(20 * 1000)
#define	IPC_DHCP_MIN_LEASE				5
#define	IPC_DHCP_DEFAULT_LEASE			3600

#define	IPC_MAX_PACKET_QUEUE_LEN		10000

#define	IPC_DHCP_VENDOR_ID				"MSFT 5.0"

#define	IPC_PASSWORD_MSCHAPV2_TAG		"xH7DiNlurDhcYV4a:"

// ARP table entry
struct IPC_ARP
{
	IP Ip;								// IP address
	bool Resolved;						// Whether the MAC address have been resolved
	UCHAR MacAddress[6];				// MAC address
	UINT64 GiveupTime;					// Time to give up (in the case of unresolved)
	UINT64 ExpireTime;					// Expiration date (If resolved)
	QUEUE *PacketQueue;					// Transmission packet queue
};

// DHCP release queue
struct IPC_DHCP_RELESAE_QUEUE
{
	DHCP_OPTION_LIST Req;
	UINT TranId;
	UCHAR MacAddress[6];
};

// IPC_PARAM
struct IPC_PARAM
{
	char ClientName[MAX_SIZE];
	char Postfix[MAX_SIZE];
	char HubName[MAX_HUBNAME_LEN + 1];
	char UserName[MAX_USERNAME_LEN + 1];
	char Password[MAX_PASSWORD_LEN + 1];
	IP ClientIp;
	UINT ClientPort;
	IP ServerIp;
	UINT ServerPort;
	char ClientHostname[MAX_SIZE];
	char CryptName[MAX_SIZE];
	bool BridgeMode;
	UINT Mss;
	bool IsL3Mode;
	bool IsOpenVPN;
};

// IPC_ASYNC object
struct IPC_ASYNC
{
	CEDAR *Cedar;						// Cedar
	IPC_PARAM Param;					// Parameters for creating IPC
	THREAD *Thread;						// Thread
	SOCK_EVENT *SockEvent;				// Socket events that is set when the connection is completed
	bool Done;							// Processing completion flag
	IPC *Ipc;							// IPC object (if it fails to connect, the value is NULL)
	TUBE *TubeForDisconnect;			// Tube for disconnection notification
	UINT ErrorCode;						// Error code in the case of failing to connect
	DHCP_OPTION_LIST L3ClientAddressOption;	// Client IP address option (Only in the case of L3 mode)
	UINT64 L3DhcpRenewInterval;			// DHCP update interval
	UINT64 L3NextDhcpRenewTick;			// DHCP renewal time of the next
	bool DhcpAllocFailed;				// Failed to get IP address from the DHCP server
};

// IPC object
struct IPC
{
	CEDAR *Cedar;
	char HubName[MAX_HUBNAME_LEN + 1];
	char UserName[MAX_USERNAME_LEN + 1];
	char Password[MAX_PASSWORD_LEN + 1];
	char ClientHostname[MAX_SIZE];
	UCHAR random[SHA1_SIZE];
	char SessionName[MAX_SESSION_NAME_LEN + 1];
	char ConnectionName[MAX_CONNECTION_NAME_LEN + 1];
	POLICY *Policy;
	SOCK *Sock;
	INTERRUPT_MANAGER *Interrupt;		// Interrupt manager
	IP ClientIPAddress;					// IP address of the client
	IP SubnetMask;						// Subnet mask of the client
	IP DefaultGateway;					// Default gateway address
	IP BroadcastAddress;				// Broadcast address
	UCHAR MacAddress[6];				// MAC address
	UCHAR Padding[2];
	LIST *ArpTable;						// ARP table
	QUEUE *IPv4RecviedQueue;			// IPv4 reception queue
	TUBE_FLUSH_LIST *FlushList;			// Tube Flush List
	UCHAR MsChapV2_ServerResponse[20];	// Server response
	DHCP_CLASSLESS_ROUTE_TABLE ClasslessRoute;	// Classless routing table
};

// MS-CHAPv2 authentication information
struct IPC_MSCHAP_V2_AUTHINFO
{
	char MsChapV2_PPPUsername[MAX_SIZE];	// MS-CHAPv2 Username
	UCHAR MsChapV2_ServerChallenge[16];	// MS-CHAPv2 Server Challenge
	UCHAR MsChapV2_ClientChallenge[16];	// MS-CHAPv2 Client Challenge
	UCHAR MsChapV2_ClientResponse[24];	// MS-CHAPv2 Client Response
	EAP_CLIENT *MsChapV2_EapClient;		// EAP client
};

IPC *NewIPC(CEDAR *cedar, char *client_name, char *postfix, char *hubname, char *username, char *password,
	UINT *error_code, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port,
	char *client_hostname, char *crypt_name,
	bool bridge_mode, UINT mss, EAP_CLIENT *eap_client);
IPC *NewIPCByParam(CEDAR *cedar, IPC_PARAM *param, UINT *error_code);
IPC *NewIPCBySock(CEDAR *cedar, SOCK *s, void *mac_address);
void FreeIPC(IPC *ipc);
bool IsIPCConnected(IPC *ipc);
void IPCSetSockEventWhenRecvL2Packet(IPC *ipc, SOCK_EVENT *e);
void IPCSendL2(IPC *ipc, void *data, UINT size);
void IPCSendIPv4(IPC *ipc, void *data, UINT size);
BLOCK *IPCRecvL2(IPC *ipc);
BLOCK *IPCRecvIPv4(IPC *ipc);
void IPCProcessInterrupts(IPC *ipc);
void IPCProcessL3Events(IPC *ipc);
void IPCProcessL3EventsEx(IPC *ipc, UINT64 now);
bool IPCSetIPv4Parameters(IPC *ipc, IP *ip, IP *subnet, IP *gw, DHCP_CLASSLESS_ROUTE_TABLE *rt);
IPC_ARP *IPCNewARP(IP *ip, UCHAR *mac_address);
void IPCFreeARP(IPC_ARP *a);
int IPCCmpArpTable(void *p1, void *p2);
void IPCSendIPv4Unicast(IPC *ipc, void *data, UINT size, IP *next_ip);
IPC_ARP *IPCSearchArpTable(IPC *ipc, IP *ip);
void IPCSendIPv4WithDestMacAddr(IPC *ipc, void *data, UINT size, UCHAR *dest_mac_addr);
void IPCFlushArpTable(IPC *ipc);
void IPCFlushArpTableEx(IPC *ipc, UINT64 now);
void IPCProcessArp(IPC *ipc, BLOCK *b);
void IPCAssociateOnArpTable(IPC *ipc, IP *ip, UCHAR *mac_address);
bool IsValidUnicastMacAddress(UCHAR *mac);
bool IsValidUnicastIPAddress4(IP *ip);
bool IsValidUnicastIPAddressUINT4(UINT ip);
DHCPV4_DATA *IPCSendDhcpRequest(IPC *ipc, IP *dest_ip, UINT tran_id, DHCP_OPTION_LIST *opt, UINT expecting_code, UINT timeout, TUBE *discon_poll_tube);
BUF *IPCBuildDhcpRequest(IPC *ipc, IP *dest_ip, UINT tran_id, DHCP_OPTION_LIST *opt);
BUF *IPCBuildDhcpRequestOptions(IPC *ipc, DHCP_OPTION_LIST *opt);
bool IPCDhcpAllocateIP(IPC *ipc, DHCP_OPTION_LIST *opt, TUBE *discon_poll_tube);
bool IPCDhcpAllocateIPEx(IPC *ipc, DHCP_OPTION_LIST *opt, TUBE *discon_poll_tube, bool openvpn_compatible);
bool IPCDhcpRequestInformIP(IPC *ipc, DHCP_OPTION_LIST *opt, TUBE *discon_poll_tube, IP *client_ip);
void IPCDhcpRenewIP(IPC *ipc, IP *dhcp_server);
void IPCDhcpFreeIP(IPC *ipc, IP *dhcp_server);
IPC_ASYNC *NewIPCAsync(CEDAR *cedar, IPC_PARAM *param, SOCK_EVENT *sock_event);
void IPCAsyncThreadProc(THREAD *thread, void *param);
void FreeIPCAsync(IPC_ASYNC *a);

bool ParseAndExtractMsChapV2InfoFromPassword(IPC_MSCHAP_V2_AUTHINFO *d, char *password);


//////////////////////////////////////////////////////////////////////////
// IPsec_IkePacket.h



// Constants
#ifdef	OS_WIN32
#pragma pack(push, 1)
#endif	// OS_WIN32

// Maximum hash size
#define	IKE_MAX_HASH_SIZE				64		// Size of SHA-2-512 is the maximum for now

// Maximum block size
#define	IKE_MAX_BLOCK_SIZE				16		// Size of AES is maximum at the moment

// Maximum key size
#define	IKE_MAX_KEY_SIZE				32		// Size of AES-256 is the maximum for now

// IKE version
#define IKE_VERSION						0x10	// 1.0

// IKE payload type
#define	IKE_PAYLOAD_NONE				0		// No payload
#define IKE_PAYLOAD_SA					1		// SA payload
#define IKE_PAYLOAD_PROPOSAL			2		// Proposal payload
#define IKE_PAYLOAD_TRANSFORM			3		// Transform payload
#define IKE_PAYLOAD_KEY_EXCHANGE		4		// Key exchange payload
#define IKE_PAYLOAD_ID					5		// ID payload
#define IKE_PAYLOAD_CERT				6		// Certificate payload
#define IKE_PAYLOAD_CERT_REQUEST		7		// Certificate request payload
#define IKE_PAYLOAD_HASH				8		// Hash payload
#define IKE_PAYLOAD_SIGN				9		// Signature payload
#define IKE_PAYLOAD_RAND				10		// Random number payload
#define IKE_PAYLOAD_NOTICE				11		// Notification Payload
#define IKE_PAYLOAD_DELETE				12		// Deletion payload
#define IKE_PAYLOAD_VENDOR_ID			13		// Vendor ID payload
#define	IKE_PAYLOAD_NAT_D				20		// NAT-D payload
#define	IKE_PAYLOAD_NAT_OA				21		// NAT-OA payload
#define	IKE_PAYLOAD_NAT_D_DRAFT			130		// NAT-D payload draft
#define	IKE_PAYLOAD_NAT_OA_DRAFT		16		// NAT-OA payload draft
#define	IKE_PAYLOAD_NAT_OA_DRAFT_2		131		// NAT-OA payload draft 2

// Macro to check whether the payload type is supported
#define IKE_IS_SUPPORTED_PAYLOAD_TYPE(i) ((((i) >= IKE_PAYLOAD_SA) && ((i) <= IKE_PAYLOAD_VENDOR_ID)) || ((i) == IKE_PAYLOAD_NAT_D) || ((i) == IKE_PAYLOAD_NAT_OA) || ((i) == IKE_PAYLOAD_NAT_OA_DRAFT) || ((i) == IKE_PAYLOAD_NAT_OA_DRAFT_2) || ((i) == IKE_PAYLOAD_NAT_D_DRAFT))

// IKE header flag
#define IKE_HEADER_FLAG_ENCRYPTED			1	// Encryption
#define IKE_HEADER_FLAG_COMMIT				2	// Commit
#define IKE_HEADER_FLAG_AUTH_ONLY			4	// Only authentication

// IKE payload common header
struct IKE_COMMON_HEADER
{
	UCHAR NextPayload;
	UCHAR Reserved;
	USHORT PayloadSize;
} GCC_PACKED;

// IKE SA payload header
struct IKE_SA_HEADER
{
	UINT DoI;									// DOI value
	UINT Situation;								// Situation value
} GCC_PACKED;

// DOI value in the IKE SA payload
#define IKE_SA_DOI_IPSEC				1		// IPsec

// Situation value in the IKE SA payload
#define IKE_SA_SITUATION_IDENTITY		1		// Only authentication

// IKE proposal payload header
struct IKE_PROPOSAL_HEADER
{
	UCHAR Number;								// Number
	UCHAR ProtocolId;							// Protocol ID
	UCHAR SpiSize;								// Length of SPI
	UCHAR NumTransforms;						// Transform number
} GCC_PACKED;

// Protocol ID in the IKE proposal payload header
#define IKE_PROTOCOL_ID_IKE				1		// IKE
#define IKE_PROTOCOL_ID_IPSEC_AH		2		// AH
#define IKE_PROTOCOL_ID_IPSEC_ESP		3		// ESP
#define	IKE_PROTOCOL_ID_IPV4			4		// IP
#define	IKE_PROTOCOL_ID_IPV6			41		// IPv6

// IKE transform payload header
struct IKE_TRANSFORM_HEADER
{
	UCHAR Number;								// Number
	UCHAR TransformId;							// Transform ID
	USHORT Reserved;							// Reserved
} GCC_PACKED;

// Transform ID (Phase 1) in IKE transform payload header
#define IKE_TRANSFORM_ID_P1_KEY_IKE				1	// IKE

// Transform ID (Phase 2) in IKE transform payload header
#define IKE_TRANSFORM_ID_P2_ESP_DES				2	// DES-CBC
#define IKE_TRANSFORM_ID_P2_ESP_3DES			3	// 3DES-CBC
#define IKE_TRANSFORM_ID_P2_ESP_CAST			6	// CAST
#define IKE_TRANSFORM_ID_P2_ESP_BLOWFISH		7	// BLOWFISH
#define IKE_TRANSFORM_ID_P2_ESP_AES				12	// AES

// IKE transform value (fixed length)
struct IKE_TRANSFORM_VALUE
{
	UCHAR AfBit;								// AF bit (0: Fixed length, 1: Variable length)
	UCHAR Type;									// Type
	USHORT Value;								// Value data (16bit)
} GCC_PACKED;

// The Type value in IKE transform value (Phase 1)
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_TRANSFORM_VALUE_P1_CRYPTO			1	// Encryption algorithm
#define IKE_TRANSFORM_VALUE_P1_HASH				2	// Hash algorithm
#define IKE_TRANSFORM_VALUE_P1_AUTH_METHOD		3	// Authentication method
#define IKE_TRANSFORM_VALUE_P1_DH_GROUP			4	// DH group number
#define IKE_TRANSFORM_VALUE_P1_LIFE_TYPE		11	// Expiration date type
#define IKE_TRANSFORM_VALUE_P1_LIFE_VALUE		12	// Expiration date
#define IKE_TRANSFORM_VALUE_P1_KET_SIZE			14	// Key size

// The Type value in IKE transform values (Phase 2)
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_TRANSFORM_VALUE_P2_LIFE_TYPE	1	// Expiration date type
#define IKE_TRANSFORM_VALUE_P2_LIFE_VALUE	2	// Expiration date
#define IKE_TRANSFORM_VALUE_P2_DH_GROUP		3	// DH group number
#define IKE_TRANSFORM_VALUE_P2_CAPSULE		4	// Encapsulation mode
#define IKE_TRANSFORM_VALUE_P2_HMAC			5	// HMAC algorithm
#define IKE_TRANSFORM_VALUE_P2_KEY_SIZE		6	// Key size

// Phase 1: The encryption algorithm in the IKE transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P1_CRYPTO_DES_CBC				1
#define IKE_P1_CRYPTO_BLOWFISH				3
#define IKE_P1_CRYPTO_3DES_CBC				5
#define IKE_P1_CRYPTO_CAST_CBC				6
#define IKE_P1_CRYPTO_AES_CBC				7

// Phase 1: The hash algorithm in IKE transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define	IKE_P1_HASH_MD5						1
#define IKE_P1_HASH_SHA1					2
#define IKE_P1_HASH_SHA2_256				4
#define IKE_P1_HASH_SHA2_384				5
#define IKE_P1_HASH_SHA2_512				6

// Phase 1: The authentication method in the IKE transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P1_AUTH_METHOD_PRESHAREDKEY		1
#define IKE_P1_AUTH_METHOD_RSA_SIGN			3

// Phase 1: The DH group number in the IKE transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P1_DH_GROUP_768_MODP			1
#define IKE_P1_DH_GROUP_1024_MODP			2
#define IKE_P1_DH_GROUP_1536_MODP			5
#define IKE_P1_DH_GROUP_2048_MODP			14
#define IKE_P1_DH_GROUP_3072_MODP			15
#define IKE_P1_DH_GROUP_4096_MODP			16

// Phase 1: The expiration date type in IKE transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P1_LIFE_TYPE_SECONDS			1
#define IKE_P1_LIFE_TYPE_KILOBYTES			2

// Phase 2: The HMAC algorithm in IPsec transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P2_HMAC_MD5_96					1
#define IKE_P2_HMAC_SHA1_96					2

// Phase 2: The DH group number in the IPsec transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P2_DH_GROUP_768_MODP			1
#define IKE_P2_DH_GROUP_1024_MODP			2
#define IKE_P2_DH_GROUP_1536_MODP			5
#define IKE_P2_DH_GROUP_2048_MODP			14
#define IKE_P2_DH_GROUP_3072_MODP			15
#define IKE_P2_DH_GROUP_4096_MODP			16

// Phase 2: The encapsulation mode in IPsec transform value
#define IKE_P2_CAPSULE_TUNNEL				1
#define IKE_P2_CAPSULE_TRANSPORT			2
#define IKE_P2_CAPSULE_NAT_TUNNEL_1			3
#define IKE_P2_CAPSULE_NAT_TUNNEL_2			61443
#define IKE_P2_CAPSULE_NAT_TRANSPORT_1		4
#define IKE_P2_CAPSULE_NAT_TRANSPORT_2		61444

// Phase 2: The expiration date type in IPsec transform value
#define IKE_P2_LIFE_TYPE_SECONDS			1
#define IKE_P2_LIFE_TYPE_KILOBYTES			2


// IKE ID payload header
struct IKE_ID_HEADER
{
	UCHAR IdType;								// Type of ID
	UCHAR ProtocolId;							// Protocol ID
	USHORT Port;								// Port
} GCC_PACKED;

// Type of ID in the IKE ID payload header
#define IKE_ID_IPV4_ADDR				1		// IPv4 address (32 bit)
#define IKE_ID_FQDN						2		// FQDN
#define IKE_ID_USER_FQDN				3		// User FQDN
#define IKE_ID_IPV4_ADDR_SUBNET			4		// IPv4 + subnet (64 bit)
#define IKE_ID_IPV6_ADDR				5		// IPv6 address (128 bit)
#define IKE_ID_IPV6_ADDR_SUBNET			6		// IPv6 + subnet (256 bit)
#define IKE_ID_DER_ASN1_DN				9		// X.500 Distinguished Name
#define IKE_ID_DER_ASN1_GN				10		// X.500 General Name
#define IKE_ID_KEY_ID					11		// Key

// The protocol ID in the IKE ID payload
#define IKE_ID_PROTOCOL_UDP			IP_PROTO_UDP	// UDP

// IKE certificate payload header
struct IKE_CERT_HEADER
{
	UCHAR CertType;								// Certificate Type
} GCC_PACKED;

// The certificate type in IKE certificate payload header
#define IKE_CERT_TYPE_X509				4		// X.509 certificate (for digital signature)

// IKE certificate payload header
struct IKE_CERT_REQUEST_HEADER
{
	UCHAR CertType;								// Certificate Type
} GCC_PACKED;

// IKE notification payload header
struct IKE_NOTICE_HEADER
{
	UINT DoI;									// DOI value
	UCHAR ProtocolId;							// Protocol ID
												// Same to the protocol ID in the IKE proposal payload header
	UCHAR SpiSize;								// SPI size
	USHORT MessageType;							// Message type
} GCC_PACKED;

// IKE Deletion payload header
struct IKE_DELETE_HEADER
{
	UINT DoI;									// DOI value
	UCHAR ProtocolId;							// Protocol ID
												// Same to the protocol ID in the IKE proposal payload header
	UCHAR SpiSize;								// SPI size
	USHORT NumSpis;								// SPI number
} GCC_PACKED;

// IKE NAT-OA payload header
struct IKE_NAT_OA_HEADER
{
	UCHAR IdType;								// Type of ID
	UCHAR Reserved1;
	USHORT Reserved2;
} GCC_PACKED;


#ifdef	OS_WIN32
#pragma pack(pop)
#endif	// OS_WIN32



//
// IKE internal data structure
//

// IKE packet SA payload
struct IKE_PACKET_SA_PAYLOAD
{
	LIST *PayloadList;						// Proposal payload list
};

// IKE proposal packet payload
struct IKE_PACKET_PROPOSAL_PAYLOAD
{
	UCHAR Number;							// Number
	UCHAR ProtocolId;						// Protocol ID
	BUF *Spi;								// SPI data

	LIST *PayloadList;						// Payload list
};

// IKE packet transform payload
struct IKE_PACKET_TRANSFORM_PAYLOAD
{
	UCHAR Number;								// Number
	UCHAR TransformId;							// Transform ID

	LIST *ValueList;							// Value list
};

// IKE packet transform value
struct IKE_PACKET_TRANSFORM_VALUE
{
	UCHAR Type;									// Type
	UINT Value;									// Value
};

// IKE generic data payload
struct IKE_PACKET_DATA_PAYLOAD
{
	BUF *Data;									// Generic data
};

// IKE packet ID payload
struct IKE_PACKET_ID_PAYLOAD
{
	UCHAR Type;									// Type
	UCHAR ProtocolId;							// Protocol ID
	USHORT Port;								// Port number
	BUF *IdData;								// ID data
	char StrData[128];							// Data of the result of converting to a string
};

// IKE packet certificate payload
struct IKE_PACKET_CERT_PAYLOAD
{
	UCHAR CertType;								// Certificate type
	BUF *CertData;								// Certificate data
};

// IKE packet certificate request payload
struct IKE_PACKET_CERT_REQUEST_PAYLOAD
{
	UCHAR CertType;								// Certificate type
	BUF *Data;									// Request data
};

// IKE packet notification payload
struct IKE_PACKET_NOTICE_PAYLOAD
{
	UCHAR ProtocolId;							// Protocol ID
	USHORT MessageType;							// Message type
	BUF *Spi;									// SPI data
	BUF *MessageData;							// Message data
};

// IKE notification message type
// Error
#define	IKE_NOTICE_ERROR_INVALID_COOKIE			4	// Invalid cookie
#define	IKE_NOTICE_ERROR_INVALID_EXCHANGE_TYPE	7	// Invalid exchange type
#define	IKE_NOTICE_ERROR_INVALID_SPI			11	// Invalid SPI
#define	IKE_NOTICE_ERROR_NO_PROPOSAL_CHOSEN		14	// There is nothing worth mentioning in the presented proposal

// DPD
#define	IKE_NOTICE_DPD_REQUEST					36136	// R-U-THERE
#define	IKE_NOTICE_DPD_RESPONSE					36137	// R-U-THERE-ACK


// IKE packet deletion payload
struct IKE_PACKET_DELETE_PAYLOAD
{
	UCHAR ProtocolId;							// Protocol ID
	LIST *SpiList;								// SPI list
};

// IKE NAT-OA payload
struct IKE_PACKET_NAT_OA_PAYLOAD
{
	IP IpAddress;								// IP address
};

// IKE packet payload
struct IKE_PACKET_PAYLOAD
{
	UCHAR PayloadType;							// Payload type
	UCHAR Padding[3];
	BUF *BitArray;								// Bit array

	union
	{
		IKE_PACKET_SA_PAYLOAD Sa;				// SA payload
		IKE_PACKET_PROPOSAL_PAYLOAD Proposal;	// Proposal payload
		IKE_PACKET_TRANSFORM_PAYLOAD Transform;	// Transform payload
		IKE_PACKET_DATA_PAYLOAD KeyExchange;	// Key exchange payload
		IKE_PACKET_ID_PAYLOAD Id;				// ID payload
		IKE_PACKET_CERT_PAYLOAD Cert;			// Certificate payload
		IKE_PACKET_CERT_REQUEST_PAYLOAD CertRequest;	// Certificate request payload
		IKE_PACKET_DATA_PAYLOAD Hash;			// Hash payload
		IKE_PACKET_DATA_PAYLOAD Sign;			// Signature payload
		IKE_PACKET_DATA_PAYLOAD Rand;			// Random number payload
		IKE_PACKET_NOTICE_PAYLOAD Notice;		// Notification Payload
		IKE_PACKET_DELETE_PAYLOAD Delete;		// Deletion payload
		IKE_PACKET_DATA_PAYLOAD VendorId;		// Vendor ID payload
		IKE_PACKET_NAT_OA_PAYLOAD NatOa;		// NAT-OA payload
		IKE_PACKET_DATA_PAYLOAD GeneralData;	// Generic data payload
	} Payload;
};

struct IKE_PACKET
{
	UINT64 InitiatorCookie;						// Initiator cookie
	UINT64 ResponderCookie;						// Responder cookie
	UCHAR ExchangeType;							// Exchange type
	bool FlagEncrypted;							// Encryption flag
	bool FlagCommit;							// Commit flag
	bool FlagAuthOnly;							// Flag only authentication
	UINT MessageId;								// Message ID
	LIST *PayloadList;							// Payload list
	BUF *DecryptedPayload;						// Decrypted payload
	UINT MessageSize;							// Original size
};

// IKE P1 key set
struct IKE_P1_KEYSET
{
	BUF *SKEYID_d;									// IPsec SA key
	BUF *SKEYID_a;									// IKE SA authentication key
	BUF *SKEYID_e;									// IKE SA encryption key
};

// Number and name of the encryption algorithm for IKE
#define	IKE_CRYPTO_DES_ID						0
#define	IKE_CRYPTO_DES_STRING					"DES-CBC"

#define	IKE_CRYPTO_3DES_ID						1
#define	IKE_CRYPTO_3DES_STRING					"3DES-CBC"

#define	IKE_CRYPTO_AES_ID						2
#define	IKE_CRYPTO_AES_STRING					"AES-CBC"

#define	IKE_CRYPTO_BLOWFISH_ID					3
#define	IKE_CRYPTO_BLOWFISH_STRING				"Blowfish-CBC"

#define	IKE_CRYPTO_CAST_ID						4
#define	IKE_CRYPTO_CAST_STRING					"CAST-128-CBC"

// Number and name of the IKE hash algorithm
#define	IKE_HASH_MD5_ID							0
#define	IKE_HASH_MD5_STRING						"MD5"

#define	IKE_HASH_SHA1_ID						1
#define	IKE_HASH_SHA1_STRING					"SHA-1"

#define	IKE_HASH_SHA2_256_ID					2
#define	IKE_HASH_SHA2_256_STRING				"SHA-2-256"

#define	IKE_HASH_SHA2_384_ID					3
#define	IKE_HASH_SHA2_384_STRING				"SHA-2-384"

#define	IKE_HASH_SHA2_512_ID					4
#define	IKE_HASH_SHA2_512_STRING				"SHA-2-512"

// Number and name of DH algorithm for IKE
#define	IKE_DH_1_ID								0
#define	IKE_DH_1_STRING							"MODP 768 (Group 1)"

#define	IKE_DH_2_ID								1
#define	IKE_DH_2_STRING							"MODP 1024 (Group 2)"

#define	IKE_DH_5_ID								2
#define	IKE_DH_5_STRING							"MODP 1536 (Group 5)"

#define IKE_DH_2048_ID							14
#define IKE_DH_2048_STRING						"MODP 2048 (Group 14)"

#define IKE_DH_3072_ID							15
#define IKE_DH_3072_STRING						"MODP 3072 (Group 15)"

#define IKE_DH_4096_ID							16
#define IKE_DH_4096_STRING						"MODP 4096 (Group 16)"


// Encryption algorithm for IKE
struct IKE_CRYPTO
{
	UINT CryptoId;								// ID
	char *Name;									// Name
	UINT KeySizes[16];							// Key size candidate
	UINT BlockSize;								// Block size
	bool VariableKeySize;						// Whether the key size is variable
};

// IKE encryption key
struct IKE_CRYPTO_KEY
{
	IKE_CRYPTO *Crypto;
	void *Data;									// Key data
	UINT Size;									// Key size

	DES_KEY_VALUE *DesKey1, *DesKey2, *DesKey3;	// DES key
	AES_KEY_VALUE *AesKey;						// AES key
};

// IKE hash algorithm
struct IKE_HASH
{
	UINT HashId;								// ID
	char *Name;									// Name
	UINT HashSize;								// Output size
};

// DH algorithm for IKE
struct IKE_DH
{
	UINT DhId;									// ID
	char *Name;									// Name
	UINT KeySize;								// Key size
};

#define	MAX_IKE_ENGINE_ELEMENTS					64

// Encryption engine for IKE
struct IKE_ENGINE
{
	IKE_CRYPTO *IkeCryptos[MAX_IKE_ENGINE_ELEMENTS];	// Encryption algorithm list that is used in the IKE
	IKE_HASH *IkeHashes[MAX_IKE_ENGINE_ELEMENTS];		// Hash algorithm list that is used in the IKE
	IKE_DH *IkeDhs[MAX_IKE_ENGINE_ELEMENTS];			// DH algorithm list that is used in the IKE

	IKE_CRYPTO *EspCryptos[MAX_IKE_ENGINE_ELEMENTS];	// Encryption algorithm list that is used by ESP
	IKE_HASH *EspHashes[MAX_IKE_ENGINE_ELEMENTS];		// Hash algorithm list that is used by ESP
	IKE_DH *EspDhs[MAX_IKE_ENGINE_ELEMENTS];			// DH algorithm list that is used by ESP

	LIST *CryptosList;
	LIST *HashesList;
	LIST *DhsList;
};

// IKE encryption parameters
struct IKE_CRYPTO_PARAM
{
	IKE_CRYPTO_KEY *Key;						// Key
	UCHAR Iv[IKE_MAX_BLOCK_SIZE];				// IV
	UCHAR NextIv[IKE_MAX_BLOCK_SIZE];			// IV to be used next
};


// Function prototype
IKE_PACKET *IkeParseHeader(void *data, UINT size, IKE_CRYPTO_PARAM *cparam);
IKE_PACKET *IkeParse(void *data, UINT size, IKE_CRYPTO_PARAM *cparam);
IKE_PACKET *IkeParseEx(void *data, UINT size, IKE_CRYPTO_PARAM *cparam, bool header_only);
void IkeFree(IKE_PACKET *p);
IKE_PACKET *IkeNew(UINT64 init_cookie, UINT64 resp_cookie, UCHAR exchange_type,
	bool encrypted, bool commit, bool auth_only, UINT msg_id,
	LIST *payload_list);

void IkeDebugPrintPayloads(LIST *o, UINT depth);
void IkeDebugUdpSendRawPacket(IKE_PACKET *p);

BUF *IkeEncrypt(void *data, UINT size, IKE_CRYPTO_PARAM *cparam);
BUF *IkeEncryptWithPadding(void *data, UINT size, IKE_CRYPTO_PARAM *cparam);
BUF *IkeDecrypt(void *data, UINT size, IKE_CRYPTO_PARAM *cparam);

LIST *IkeParsePayloadList(void *data, UINT size, UCHAR first_payload);
LIST *IkeParsePayloadListEx(void *data, UINT size, UCHAR first_payload, UINT *total_read_size);
void IkeFreePayloadList(LIST *o);
UINT IkeGetPayloadNum(LIST *o, UINT payload_type);
IKE_PACKET_PAYLOAD *IkeGetPayload(LIST *o, UINT payload_type, UINT index);

IKE_PACKET_PAYLOAD *IkeParsePayload(UINT payload_type, BUF *b);
void IkeFreePayload(IKE_PACKET_PAYLOAD *p);
bool IkeParseDataPayload(IKE_PACKET_DATA_PAYLOAD *t, BUF *b);
void IkeFreeDataPayload(IKE_PACKET_DATA_PAYLOAD *t);
bool IkeParseSaPayload(IKE_PACKET_SA_PAYLOAD *t, BUF *b);
void IkeFreeSaPayload(IKE_PACKET_SA_PAYLOAD *t);
bool IkeParseProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t, BUF *b);
void IkeFreeProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t);
bool IkeParseTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t, BUF *b);
void IkeFreeTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t);
LIST *IkeParseTransformValueList(BUF *b);
void IkeFreeTransformValueList(LIST *o);
bool IkeParseIdPayload(IKE_PACKET_ID_PAYLOAD *t, BUF *b);
void IkeFreeIdPayload(IKE_PACKET_ID_PAYLOAD *t);
bool IkeParseCertPayload(IKE_PACKET_CERT_PAYLOAD *t, BUF *b);
void IkeFreeCertPayload(IKE_PACKET_CERT_PAYLOAD *t);
bool IkeParseCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t, BUF *b);
void IkeFreeCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t);
bool IkeParseNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t, BUF *b);
void IkeFreeNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t);
bool IkeParseDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t, BUF *b);
void IkeFreeDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t);
bool IkeParseNatOaPayload(IKE_PACKET_NAT_OA_PAYLOAD *t, BUF *b);


bool IkeCompareHash(IKE_PACKET_PAYLOAD *hash_payload, void *hash_data, UINT hash_size);

IKE_PACKET_PAYLOAD *IkeNewPayload(UINT payload_type);
IKE_PACKET_PAYLOAD *IkeNewDataPayload(UCHAR payload_type, void *data, UINT size);
IKE_PACKET_PAYLOAD *IkeNewNatOaPayload(UCHAR payload_type, IP *ip);
IKE_PACKET_PAYLOAD *IkeNewSaPayload(LIST *payload_list);
IKE_PACKET_PAYLOAD *IkeNewProposalPayload(UCHAR number, UCHAR protocol_id, void *spi, UINT spi_size, LIST *payload_list);
IKE_PACKET_PAYLOAD *IkeNewTransformPayload(UCHAR number, UCHAR transform_id, LIST *value_list);
IKE_PACKET_TRANSFORM_VALUE *IkeNewTransformValue(UCHAR type, UINT value);
IKE_PACKET_PAYLOAD *IkeNewIdPayload(UCHAR id_type, UCHAR protocol_id, USHORT port, void *id_data, UINT id_size);
IKE_PACKET_PAYLOAD *IkeNewCertPayload(UCHAR cert_type, void *cert_data, UINT cert_size);
IKE_PACKET_PAYLOAD *IkeNewCertRequestPayload(UCHAR cert_type, void *data, UINT size);
IKE_PACKET_PAYLOAD *IkeNewNoticePayload(UCHAR protocol_id, USHORT message_type,
	void *spi, UINT spi_size,
	void *message, UINT message_size);
IKE_PACKET_PAYLOAD *IkeNewDeletePayload(UCHAR protocol_id, LIST *spi_list);

IKE_PACKET_PAYLOAD *IkeNewNoticeErrorInvalidCookiePayload(UINT64 init_cookie, UINT64 resp_cookie);
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorInvalidExchangeTypePayload(UINT64 init_cookie, UINT64 resp_cookie, UCHAR exchange_type);
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorInvalidSpiPayload(UINT spi);
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorNoProposalChosenPayload(bool quick_mode, UINT64 init_cookie, UINT64 resp_cookie);
IKE_PACKET_PAYLOAD *IkeNewNoticeDpdPayload(bool ack, UINT64 init_cookie, UINT64 resp_cookie, UINT seq_no);

UCHAR IkeGetFirstPayloadType(LIST *o);
BUF *IkeBuild(IKE_PACKET *p, IKE_CRYPTO_PARAM *cparam);
BUF *IkeBuildEx(IKE_PACKET *p, IKE_CRYPTO_PARAM *cparam, bool use_original_decrypted);
BUF *IkeBuildPayloadList(LIST *o);
BUF *IkeBuildPayload(IKE_PACKET_PAYLOAD *p);
BUF *IkeBuildDataPayload(IKE_PACKET_DATA_PAYLOAD *t);
BUF *IkeBuildSaPayload(IKE_PACKET_SA_PAYLOAD *t);
BUF *IkeBuildProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t);
BUF *IkeBuildTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t);
BUF *IkeBuildTransformValue(IKE_PACKET_TRANSFORM_VALUE *v);
BUF *IkeBuildTransformValueList(LIST *o);
BUF *IkeBuildIdPayload(IKE_PACKET_ID_PAYLOAD *t);
BUF *IkeBuildCertPayload(IKE_PACKET_CERT_PAYLOAD *t);
BUF *IkeBuildCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t);
BUF *IkeBuildNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t);
BUF *IkeBuildDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t);

BUF *IkeBuildTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t);
UINT IkeGetTransformValue(IKE_PACKET_TRANSFORM_PAYLOAD *t, UINT type, UINT index);
UINT IkeGetTransformValueNum(IKE_PACKET_TRANSFORM_PAYLOAD *t, UINT type);

UCHAR IkeStrToPhase1CryptId(char *name);
UCHAR IkeStrToPhase1HashId(char *name);
UCHAR IkeStrToPhase2CryptId(char *name);
UCHAR IkeStrToPhase2HashId(char *name);
BUF *IkeStrToPassword(char *str);
UINT IkePhase1CryptIdToKeySize(UCHAR id);
UINT IkePhase2CryptIdToKeySize(UCHAR id);

UINT IkeNewSpi();

IKE_ENGINE *NewIkeEngine();
IKE_CRYPTO *NewIkeCrypto(IKE_ENGINE *e, UINT crypto_id, char *name, UINT *key_sizes, UINT num_key_sizes, UINT block_size);
IKE_HASH *NewIkeHash(IKE_ENGINE *e, UINT hash_id, char *name, UINT size);
IKE_DH *NewIkeDh(IKE_ENGINE *e, UINT dh_id, char *name, UINT key_size);
void FreeIkeEngine(IKE_ENGINE *e);
void FreeIkeCrypto(IKE_CRYPTO *c);
void FreeIkeHash(IKE_HASH *h);
void FreeIkeDh(IKE_DH *d);
IKE_CRYPTO *GetIkeCrypto(IKE_ENGINE *e, bool for_esp, UINT i);
IKE_HASH *GetIkeHash(IKE_ENGINE *e, bool for_esp, UINT i);
IKE_DH *GetIkeDh(IKE_ENGINE *e, bool for_esp, UINT i);

void IkeHash(IKE_HASH *h, void *dst, void *src, UINT size);
void IkeHMac(IKE_HASH *h, void *dst, void *key, UINT key_size, void *data, UINT data_size);
void IkeHMacBuf(IKE_HASH *h, void *dst, BUF *key, BUF *data);

IKE_CRYPTO_KEY *IkeNewKey(IKE_CRYPTO *c, void *data, UINT size);
bool IkeCheckKeySize(IKE_CRYPTO *c, UINT size);
void IkeFreeKey(IKE_CRYPTO_KEY *k);
void IkeCryptoEncrypt(IKE_CRYPTO_KEY *k, void *dst, void *src, UINT size, void *ivec);
void IkeCryptoDecrypt(IKE_CRYPTO_KEY *k, void *dst, void *src, UINT size, void *ivec);

DH_CTX *IkeDhNewCtx(IKE_DH *d);
void IkeDhFreeCtx(DH_CTX *dh);


//////////////////////////////////////////////////////////////////////////
// IPsec_IKE.h



//// Macro

//// Constants

// State
#define	IKE_SA_MAIN_MODE					0	// Main mode
#define	IKE_SA_AGRESSIVE_MODE				1	// Aggressive mode

#define	IKE_SA_MM_STATE_1_SA				0	// Main mode state 1 (SA exchange is complete. Wait for key exchange)
#define	IKE_SA_MM_STATE_2_KEY				1	// Main mode state 2 (Key exchange is complete. Wait for exchange ID)
#define	IKE_SA_MM_STATE_3_ESTABLISHED		2	// Main mode state 3 (ID exchange is complete. Established)

#define	IKE_SA_AM_STATE_1_SA				0	// Aggressive mode state 1 (SA exchange is completed. Wait for hash)
#define	IKE_SA_AM_STATE_2_ESTABLISHED		1	// Aggressive mode state 2 (Hash exchange is completed. Established)

#define	IKE_SA_RESEND_INTERVAL				(2 * 1000)	// IKE SA packet retransmission interval
#define	IKE_SA_RAND_SIZE					16	// Size of the random number

// ESP
#define	IKE_ESP_HASH_SIZE					12	// The hash size for the ESP packet

// Type of UDP packet
#define	IKE_UDP_TYPE_ISAKMP					0	// ISAKMP packet (destination 500)
#define	IKE_UDP_TYPE_ESP					1	// ESP packet (destination 4500)
#define	IKE_UDP_KEEPALIVE					2	// KeepAlive packet
#define	IKE_UDP_SPECIAL						3	// Special packet

// String for Vendor ID
#define	IKE_VENDOR_ID_RFC3947_NAT_T			"0x4a131c81070358455c5728f20e95452f"
#define	IKE_VENDOR_ID_IPSEC_NAT_T_IKE_03	"0x7d9419a65310ca6f2c179d9215529d56"
#define	IKE_VENDOR_ID_IPSEC_NAT_T_IKE_02	"0x90cb80913ebb696e086381b5ec427b1f"
#define	IKE_VENDOR_ID_IPSEC_NAT_T_IKE_02_2	"0xcd60464335df21f87cfdb2fc68b6a448"
#define	IKE_VENDOR_ID_IPSEC_NAT_T_IKE_00	"0x4485152d18b6bbcd0be8a8469579ddcc"
#define	IKE_VENDOR_ID_RFC3706_DPD			"0xafcad71368a1f1c96b8696fc77570100"
#define	IKE_VENDOR_ID_MICROSOFT_L2TP		"0x4048b7d56ebce88525e7de7f00d6c2d3"
#define	IKE_VENDOR_ID_MS_NT5_ISAKMPOAKLEY	"0x1e2b516905991c7d7c96fcbfb587e461"
#define	IKE_VENDOR_ID_MS_VID_INITIALCONTACT	"0x26244d38eddb61b3172a36e3d0cfb819"

// Quota
#define	IKE_QUOTA_MAX_NUM_CLIENTS_PER_IP	1000			// The number of IKE_CLIENT per IP address
#define	IKE_QUOTA_MAX_NUM_CLIENTS			30000			// Limit number of IKE_CLIENT
#define	IKE_QUOTA_MAX_SA_PER_CLIENT			100				// The limit number of SA for each IKE_CLIENT

// Time-out
#define	IKE_TIMEOUT_FOR_IKE_CLIENT			150000			// IKE_CLIENT non-communication disconnect time
#define	IKE_TIMEOUT_FOR_IKE_CLIENT_FOR_NOT_ESTABLISHED		10000 // IKE_CLIENT non-communication disconnect time (connection incomplete)
#define	IKE_INTERVAL_UDP_KEEPALIVE			5000			// UDP KeepAlive transmission interval
#define	IKE_QUICKMODE_START_INTERVAL		2000			// QuickMode start interval
#define	IKE_QUICKMODE_FAILED_TIMEOUT		10000			// Maximum time to tolerant that to fail to establish a QuickMode
#define	IKE_INTERVAL_DPD_KEEPALIVE			10000			// DPD KeepAlive transmission interval

// Expiration margin
#define	IKE_SOFT_EXPIRES_MARGIN				1000			// Expiration margin


//// Type

// IKE SA transform data
struct IKE_SA_TRANSFORM_SETTING
{
	IKE_CRYPTO *Crypto;
	UINT CryptoKeySize;
	IKE_HASH *Hash;
	IKE_DH *Dh;
	UINT CryptoId;
	UINT HashId;
	UINT DhId;
	UINT LifeKilobytes;
	UINT LifeSeconds;
};

// IPsec SA transforms data
struct IPSEC_SA_TRANSFORM_SETTING
{
	IKE_CRYPTO *Crypto;
	UINT CryptoKeySize;
	IKE_HASH *Hash;
	IKE_DH *Dh;
	UINT CryptoId;
	UINT HashId;
	UINT DhId;
	UINT LifeKilobytes;
	UINT LifeSeconds;
	UINT SpiServerToClient;
	UINT CapsuleMode;
	bool OnlyCapsuleModeIsInvalid;
};

// Function support information
struct IKE_CAPS
{
	// Support Information
	bool NatTraversalRfc3947;		// RFC 3947 Negotiation of NAT-Traversal in the IKE
	bool NatTraversalDraftIetf;		// draft-ietf-ipsec-nat-t-ike
	bool DpdRfc3706;				// RFC 3706 A Traffic-Based Method of Detecting Dead Internet Key Exchange (IKE) Peers
	bool MS_L2TPIPSecVPNClient;		// Vendor ID: Microsoft L2TP/IPSec VPN Client
	bool MS_NT5_ISAKMP_OAKLEY;		// Vendor ID: MS NT5 ISAKMPOAKLEY
	bool MS_Vid_InitialContact;		// Vendor ID: Microsoft Vid-Initial-Contact

									// Use information
	bool UsingNatTraversalRfc3947;
	bool UsingNatTraversalDraftIetf;
};

// IKE / IPsec client
struct IKE_CLIENT
{
	UINT Id;
	IP ClientIP;
	UINT ClientPort;
	IP ServerIP;
	UINT ServerPort;
	IKE_SA *CurrentIkeSa;						// IKE SA to be used currently
	IPSECSA *CurrentIpSecSaRecv;				// IPsec SA to be used currently (receive direction)
	IPSECSA *CurrentIpSecSaSend;				// IPsec SA to be currently in use (transmit direction)
	UINT64 FirstCommTick;						// Time the first data communication
	UINT64 LastCommTick;						// Time that made the last communication (received data) time
	bool Deleting;								// Deleting
	UINT64 NextKeepAliveSendTick;				// Time to send the next KeepAlive
	UINT64 NextDpdSendTick;						// Time to send the next DPD
	UINT DpdSeqNo;								// DPD sequence number
	char ClientId[128];							// ID presented by the client
	char Secret[MAX_SIZE];						// Secret value of the authentication is successful

	bool IsMicrosoft;							// Whether the client is Microsoft's

	IPSEC_SA_TRANSFORM_SETTING CachedTransformSetting;	// Cached transform attribute value
	UINT64 CurrentExpiresSoftTick_StoC;			// The maximum value of the flexible expiration date of the current (server -> client)
	UINT64 CurrentExpiresSoftTick_CtoS;			// The maximum value of the flexible expiration date of the current (client -> server)
	UINT CurrentNumEstablishedIPsecSA_StoC;		// The number of IPsec SA currently active (server -> client)
	UINT CurrentNumEstablishedIPsecSA_CtoS;		// The number of IPsec SA currently active (client -> server)
	UINT CurrentNumHealtyIPsecSA_CtoS;			// The number of currently available IPsec SA which expiration well within (client -> server)
	UINT CurrentNumHealtyIPsecSA_StoC;			// The number of currently available IPsec SA which expiration well within (server -> client)
	bool SendID1andID2;							// Whether to send the ID in QM
	UCHAR SendID1_Type, SendID2_Type;
	UCHAR SendID1_Protocol, SendID2_Protocol;
	USHORT SendID1_Port, SendID2_Port;
	BUF *SendID1_Buf, *SendID2_Buf;
	bool SendNatOaDraft1, SendNatOaDraft2, SendNatOaRfc;	// Whether to send the NAT-OA in QM
	bool StartQuickModeAsSoon;					// Flag to indicate to the start of the Quick Mode as soon as possible
	UINT64 LastQuickModeStartTick;				// Time which the last QuickMode started
	UINT64 NeedQmBeginTick;						// Time which a start-up of QuickMode is required

												// L2TP related
	L2TP_SERVER *L2TP;							// L2TP server
	UINT L2TPClientPort;						// Client-side port number of L2TP
	IP L2TPServerIP, L2TPClientIP;				// IP address used by the L2TP processing
	bool IsL2TPOnIPsecTunnelMode;				// Whether the L2TP is working on IPsec tunnel mode

												// EtherIP related
	ETHERIP_SERVER *EtherIP;					// EtherIP server
	bool IsEtherIPOnIPsecTunnelMode;			// Whether the EtherIP is working on IPsec tunnel mode

												// Transport mode related
	IP TransportModeServerIP;
	IP TransportModeClientIP;
	bool ShouldCalcChecksumForUDP;				// Flag to calculate the checksum for the UDP packet

												// Tunnel mode related
	IP TunnelModeServerIP;						// Server-side internal IP address
	IP TunnelModeClientIP;						// Client-side internal IP address
	USHORT TunnelSendIpId;						// ID of the transmission IP header
};

// IKE SA
struct IKE_SA
{
	UINT Id;
	IKE_CLIENT *IkeClient;						// Pointer to the IKE client
	UINT64 InitiatorCookie, ResponderCookie;	// Cookie
	UINT Mode;									// Mode
	UINT State;									// State
	BUF *SendBuffer;							// Buffer during transmission
	UINT64 NextSendTick;						// Next transmission time
	UINT64 FirstCommTick;						// Time that the first data communication
	UINT64 EstablishedTick;						// Time that the SA has been established
	UINT64 LastCommTick;						// Time that made the last communication (received data) time
	IKE_SA_TRANSFORM_SETTING TransformSetting;	// Transform Configuration
	IKE_CAPS Caps;								// IKE Caps
	BUF *InitiatorRand, *ResponderRand;			// Random number
	BUF *DhSharedKey;							// DH common key
	BUF *GXi, *GXr;								// DH exchange data
	BUF *SAi_b;									// Data needed for authentication
	BUF *YourIDPayloadForAM;					// Copy the ID payload of the client-side
	UCHAR SKEYID[IKE_MAX_HASH_SIZE];			// Key set
	UCHAR SKEYID_d[IKE_MAX_HASH_SIZE];
	UCHAR SKEYID_a[IKE_MAX_HASH_SIZE];
	UCHAR SKEYID_e[IKE_MAX_HASH_SIZE];
	UCHAR InitiatorHashForAM[IKE_MAX_HASH_SIZE];
	IKE_CRYPTO_KEY *CryptoKey;					// Common encryption key
	UINT HashSize;								// Hash size
	UINT KeySize;								// Key size
	UINT BlockSize;								// Block size
	UCHAR Iv[IKE_MAX_BLOCK_SIZE];				// IV
	bool IsIvExisting;							// Whether an IV exists
	bool Established;							// Established flag
	bool Deleting;								// Deleting
	UINT NumResends;							// The number of retransmissions
	char Secret[MAX_SIZE];						// Secret value of the authentication is successful
};

// IPsec SA
struct IPSECSA
{
	UINT Id;
	IKE_CLIENT *IkeClient;						// Pointer to the IKE client
	IKE_SA *IkeSa;								// Pointer to IKE_SA to use for transmission
	UCHAR Iv[IKE_MAX_BLOCK_SIZE];				// IV used in the Quick Mode exchange
	bool IsIvExisting;							// Whether the IV exists
	UINT MessageId;								// Message ID used in Quick Mode exchange
	UINT Spi;									// SPI
	UINT CurrentSeqNo;							// Send sequence number
	BUF *SendBuffer;							// Buffer during transmission
	UINT NumResends;							// The number of retransmissions
	UINT64 NextSendTick;						// Next transmission date and time
	UINT64 FirstCommTick;						// Time the last data sent
	UINT64 EstablishedTick;						// Time that the SA has been established
	UINT64 LastCommTick;						// Time that made the last communication (received data) time
	UINT64 ExpiresHardTick;						// Exact expiration time
	UINT64 ExpiresSoftTick;						// Flexible expiration time
	UINT64 TotalSize;							// Size sent to and received
	IPSEC_SA_TRANSFORM_SETTING TransformSetting;	// Transform Configuration
	bool ServerToClient;						// Whether is upload direction
	IPSECSA *PairIPsecSa;						// IPsec SA that are paired
	bool Established;							// Established flag
	BUF *InitiatorRand, *ResponderRand;			// Random number
	BUF *SharedKey;								// PFS shared key
	UCHAR Hash3[IKE_MAX_HASH_SIZE];				// Hash 3
	UCHAR KeyMat[IKE_MAX_KEY_SIZE + IKE_MAX_HASH_SIZE];	// Encryption key
	UCHAR HashKey[IKE_MAX_HASH_SIZE];			// Hash key
	IKE_CRYPTO_KEY *CryptoKey;					// Key data
	bool Deleting;								// Deleting
	UCHAR EspIv[IKE_MAX_BLOCK_SIZE];			// IV for ESP communication
	bool Initiated;								// The server-side is initiator
	DH_CTX *Dh;									// DH (only if the server-side is initiator)
	bool StartQM_FlagSet;						// Whether the flag to indicate to do the QM is set to the IKE_CLIENT
	UCHAR SKEYID_d[IKE_MAX_HASH_SIZE];
	UCHAR SKEYID_a[IKE_MAX_HASH_SIZE];
	IKE_HASH *SKEYID_Hash;
};

// IKE server
struct IKE_SERVER
{
	CEDAR *Cedar;
	IPSEC_SERVER *IPsec;
	UINT64 Now;									// Current time
	LIST *SendPacketList;						// Transmission packet
	INTERRUPT_MANAGER *Interrupts;				// Interrupt manager
	SOCK_EVENT *SockEvent;						// SockEvent
	IKE_ENGINE *Engine;							// Encryption engine
	LIST *ClientList;							// Client list
	LIST *IkeSaList;							// SA list
	LIST *IPsecSaList;							// IPsec SA list
	LIST *ThreadList;							// L2TP thread list
	bool StateHasChanged;						// Flag whether the state has changed
	UINT CurrentIkeSaId, CurrentIPsecSaId, CurrentIkeClientId, CurrentEtherId;	// Serial number ID

																				// Setting data
	char Secret[MAX_SIZE];						// Pre-shared key
};


//// Function prototype
IKE_SERVER *NewIKEServer(CEDAR *cedar, IPSEC_SERVER *ipsec);
void FreeIKEServer(IKE_SERVER *ike);
void SetIKEServerSockEvent(IKE_SERVER *ike, SOCK_EVENT *e);
void ProcIKEPacketRecv(IKE_SERVER *ike, UDPPACKET *p);
void StopIKEServer(IKE_SERVER *ike);
void ProcessIKEInterrupts(IKE_SERVER *ike);
IKE_PACKET *ParseIKEPacketHeader(UDPPACKET *p);
void ProcIkeMainModePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header);
void ProcIkeQuickModePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header);
void ProcIkeAggressiveModePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header);
void ProcIkeInformationalExchangePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header);
void FreeIkeSa(IKE_SA *sa);
void FreeIkeClient(IKE_SERVER *ike, IKE_CLIENT *c);
UINT64 GenerateNewResponserCookie(IKE_SERVER *ike);
bool GetBestTransformSettingForIkeSa(IKE_SERVER *ike, IKE_PACKET *pr, IKE_SA_TRANSFORM_SETTING *setting);
bool TransformPayloadToTransformSettingForIkeSa(IKE_SERVER *ike, IKE_PACKET_TRANSFORM_PAYLOAD *transform, IKE_SA_TRANSFORM_SETTING *setting);
IKE_CLIENT *SearchIkeClientForIkePacket(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, IKE_PACKET *pr);
IKE_CLIENT *SearchOrCreateNewIkeClientForIkePacket(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, IKE_PACKET *pr);
UINT GetNumberOfIkeClientsFromIP(IKE_SERVER *ike, IP *client_ip);
UINT GetNumberOfIPsecSaOfIkeClient(IKE_SERVER *ike, IKE_CLIENT *c);
UINT GetNumberOfIkeSaOfIkeClient(IKE_SERVER *ike, IKE_CLIENT *c);
int CmpIkeClient(void *p1, void *p2);
int CmpIkeSa(void *p1, void *p2);
int CmpIPsecSa(void *p1, void *p2);
IKE_SA *FindIkeSaByEndPointAndInitiatorCookie(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, UINT64 init_cookie, UINT mode);
IKE_SA *FindIkeSaByResponderCookie(IKE_SERVER *ike, UINT64 responder_cookie);
IKE_SA *FindIkeSaByResponderCookieAndClient(IKE_SERVER *ike, UINT64 responder_cookie, IKE_CLIENT *c);
IKE_CLIENT *NewIkeClient(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port);
IKE_CLIENT *SetIkeClientEndpoint(IKE_SERVER *ike, IKE_CLIENT *c, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port);
IKE_SA *NewIkeSa(IKE_SERVER *ike, IKE_CLIENT *c, UINT64 init_cookie, UINT mode, IKE_SA_TRANSFORM_SETTING *setting);
IKE_PACKET_PAYLOAD *TransformSettingToTransformPayloadForIke(IKE_SERVER *ike, IKE_SA_TRANSFORM_SETTING *setting);
void IkeSaSendPacket(IKE_SERVER *ike, IKE_SA *sa, IKE_PACKET *p);
IKE_PACKET *IkeSaRecvPacket(IKE_SERVER *ike, IKE_SA *sa, void *data, UINT size);
void IkeSendUdpPacket(IKE_SERVER *ike, UINT type, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, void *data, UINT size);
void IkeAddVendorIdPayloads(IKE_PACKET *p);
BUF *IkeStrToVendorId(char *str);
void IkeAddVendorId(IKE_PACKET *p, char *str);
bool IkeIsVendorIdExists(IKE_PACKET *p, char *str);
void IkeCheckCaps(IKE_CAPS *caps, IKE_PACKET *p);
BUF *IkeCalcNatDetectHash(IKE_SERVER *ike, IKE_HASH *hash, UINT64 initiator_cookie, UINT64 responder_cookie, IP *ip, UINT port);
void IkeCalcSaKeySet(IKE_SERVER *ike, IKE_SA *sa, char *secret);
IKE_CRYPTO_KEY *IkeNewCryptoKeyFromK(IKE_SERVER *ike, void *k, UINT k_size, IKE_HASH *h, IKE_CRYPTO *c, UINT crypto_key_size);
BUF *IkeExpandKeySize(IKE_HASH *h, void *k, UINT k_size, UINT target_size);
void IkeSaUpdateIv(IKE_SA *sa, void *iv, UINT iv_size);
IPSECSA *NewIPsecSa(IKE_SERVER *ike, IKE_CLIENT *c, IKE_SA *ike_sa, bool initiate, UINT message_id, bool server_to_client, void *iv, UINT spi, void *init_rand_data, UINT init_rand_size, void *res_rand_data, UINT res_rand_size, IPSEC_SA_TRANSFORM_SETTING *setting, void *shared_key_data, UINT shared_key_size);
void IkeCalcPhase2InitialIv(void *iv, IKE_SA *sa, UINT message_id);
bool GetBestTransformSettingForIPsecSa(IKE_SERVER *ike, IKE_PACKET *pr, IPSEC_SA_TRANSFORM_SETTING *setting, IP *server_ip);
bool TransformPayloadToTransformSettingForIPsecSa(IKE_SERVER *ike, IKE_PACKET_TRANSFORM_PAYLOAD *transform, IPSEC_SA_TRANSFORM_SETTING *setting, IP *server_ip);
IKE_PACKET_PAYLOAD *TransformSettingToTransformPayloadForIPsec(IKE_SERVER *ike, IPSEC_SA_TRANSFORM_SETTING *setting);
UINT GenerateNewIPsecSaSpi(IKE_SERVER *ike, UINT counterpart_spi);
IPSECSA *SearchClientToServerIPsecSaBySpi(IKE_SERVER *ike, UINT spi);
IPSECSA *SearchIPsecSaBySpi(IKE_SERVER *ike, IKE_CLIENT *c, UINT spi);
IPSECSA *SearchIPsecSaByMessageId(IKE_SERVER *ike, IKE_CLIENT *c, UINT message_id);
void IPsecSaSendPacket(IKE_SERVER *ike, IPSECSA *sa, IKE_PACKET *p);
IKE_PACKET *IPsecSaRecvPacket(IKE_SERVER *ike, IPSECSA *sa, void *data, UINT size);
void IPsecSaUpdateIv(IPSECSA *sa, void *iv, UINT iv_size);
void ProcDeletePayload(IKE_SERVER *ike, IKE_CLIENT *c, IKE_PACKET_DELETE_PAYLOAD *d);
void MarkIPsecSaAsDeleted(IKE_SERVER *ike, IPSECSA *sa);
void MarkIkeSaAsDeleted(IKE_SERVER *ike, IKE_SA *sa);
void PurgeDeletingSAsAndClients(IKE_SERVER *ike);
void PurgeIPsecSa(IKE_SERVER *ike, IPSECSA *sa);
void PurgeIkeSa(IKE_SERVER *ike, IKE_SA *sa);
void PurgeIkeClient(IKE_SERVER *ike, IKE_CLIENT *c);
void FreeIPsecSa(IPSECSA *sa);
void MarkIkeClientAsDeleted(IKE_SERVER *ike, IKE_CLIENT *c);
IKE_SA *GetOtherLatestIkeSa(IKE_SERVER *ike, IKE_SA *sa);
IPSECSA *GetOtherLatestIPsecSa(IKE_SERVER *ike, IPSECSA *sa);
void SendInformationalExchangePacket(IKE_SERVER *ike, IKE_CLIENT *c, IKE_PACKET_PAYLOAD *payload);
void SendInformationalExchangePacketEx(IKE_SERVER *ike, IKE_CLIENT *c, IKE_PACKET_PAYLOAD *payload, bool force_plain, UINT64 init_cookie, UINT64 resp_cookie);
void SendDeleteIkeSaPacket(IKE_SERVER *ike, IKE_CLIENT *c, UINT64 init_cookie, UINT64 resp_cookie);
void SendDeleteIPsecSaPacket(IKE_SERVER *ike, IKE_CLIENT *c, UINT spi);
void IPsecCalcKeymat(IKE_SERVER *ike, IKE_HASH *h, void *dst, UINT dst_size, void *skeyid_d_data, UINT skeyid_d_size, UCHAR protocol, UINT spi, void *rand_init_data, UINT rand_init_size,
	void *rand_resp_data, UINT rand_resp_size, void *df_key_data, UINT df_key_size);

void ProcIPsecEspPacketRecv(IKE_SERVER *ike, UDPPACKET *p);
void ProcIPsecUdpPacketRecv(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size);
void IPsecSendPacketByIPsecSa(IKE_SERVER *ike, IPSECSA *sa, UCHAR *data, UINT data_size, UCHAR protocol_id);
void IPsecSendPacketByIPsecSaInner(IKE_SERVER *ike, IPSECSA *sa, UCHAR *data, UINT data_size, UCHAR protocol_id);
void IPsecSendPacketByIkeClient(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size, UCHAR protocol_id);
void IPsecSendUdpPacket(IKE_SERVER *ike, IKE_CLIENT *c, UINT src_port, UINT dst_port, UCHAR *data, UINT data_size);
void IPsecIkeClientManageL2TPServer(IKE_SERVER *ike, IKE_CLIENT *c);
void IPsecIkeClientSendL2TPPackets(IKE_SERVER *ike, IKE_CLIENT *c, L2TP_SERVER *l2tp);
void IPsecIkeSendUdpForDebug(UINT dst_port, UINT dst_ip, void *data, UINT size);
void StartQuickMode(IKE_SERVER *ike, IKE_CLIENT *c);
UINT GenerateNewMessageId(IKE_SERVER *ike);

void IPsecIkeClientManageEtherIPServer(IKE_SERVER *ike, IKE_CLIENT *c);
void IPsecIkeClientSendEtherIPPackets(IKE_SERVER *ike, IKE_CLIENT *c, ETHERIP_SERVER *s);
void ProcIPsecEtherIPPacketRecv(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size, bool is_tunnel_mode);
bool IsIPsecSaTunnelMode(IPSECSA *sa);
void ProcL2TPv3PacketRecv(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size, bool is_tunnel_mode);

IKE_SA *SearchIkeSaByCookie(IKE_SERVER *ike, UINT64 init_cookie, UINT64 resp_cookie);


//////////////////////////////////////////////////////////////////////////
// IPsec_Win7.h


// Constants
#define	IPSEC_WIN7_SRC_SYS_X86	"|pxwfp_x86.sys"
#define	IPSEC_WIN7_SRC_SYS_X64	"|pxwfp_x64.sys"
#define	IPSEC_WIN7_DST_SYS		"%s\\drivers\\pxwfp.sys"

#define	IPSEC_WIN7_DRIVER_NAME			"pxwfp"
#define	IPSEC_WIN7_DRIVER_TITLE			L"SoftEther PacketiX VPN IPsec WFP Callout Driver"
#define	IPSEC_WIN7_DRIVER_TITLE_V4		L"SoftEther PacketiX VPN IPsec WFP Callout for IPv4"
#define	IPSEC_WIN7_DRIVER_TITLE_V6		L"SoftEther PacketiX VPN IPsec WFP Callout for IPv6"
#define	IPSEC_WIN7_FILTER_TITLE_V4		CEDAR_PRODUCT_STR_W L" VPN IPsec Filter for IPv4"
#define	IPSEC_WIN7_FILTER_TITLE_V6		CEDAR_PRODUCT_STR_W L" VPN IPsec Filter for IPv6"
#define	IPSEC_WIN7_DRIVER_REGKEY		"SYSTEM\\CurrentControlSet\\services\\pxwfp"
#define	IPSEC_WIN7_DRIVER_BUILDNUMBER	"CurrentInstalledBuild"
#define	IPSEC_WIN7_DRIVER_BUILDNUMBER_WIN10	"CurrentInstalledBuild_Win10"


// Function prototype
IPSEC_WIN7 *IPsecWin7Init();
void IPsecWin7Free(IPSEC_WIN7 *w);
void IPsecWin7UpdateHostIPAddressList(IPSEC_WIN7 *w);

bool IPsecWin7InitDriver();
bool IPsecWin7InitDriverInner();
UINT GetCurrentIPsecWin7DriverBuild();
void SetCurrentIPsecWin7DriverBuild();
bool IPsecWin7InitApi();




//////////////////////////////////////////////////////////////////////////
// IPsec_EtherIP.h


//// Macro


//// Constants
#define	ETHERIP_VPN_CONNECT_RETRY_INTERVAL		(15 * 1000)	// VPN connection retry interval
#define	ETHERIP_CLIENT_NAME						"EtherIP Client"
#define	ETHERIP_POSTFIX							"ETHERIP"
#define	ETHERIP_L2TPV3_CLIENT_NAME				"L2TPv3 Client"
#define	ETHERIP_L2TPV3_CLIENT_NAME_EX			"L2TPv3 Client - %s"
#define	ETHERIP_L2TPV3_POSTFIX					"L2TPV3"

//// Type

// EtherIP server
struct ETHERIP_SERVER
{
	REF *Ref;
	CEDAR *Cedar;
	IPSEC_SERVER *IPsec;
	LOCK *Lock;
	UINT Id;
	IKE_SERVER *Ike;
	UINT64 Now;									// Current time
	INTERRUPT_MANAGER *Interrupts;				// Interrupt manager
	SOCK_EVENT *SockEvent;						// SockEvent
	char CryptName[MAX_SIZE];					// Cipher algorithm name
	LIST *SendPacketList;						// Transmission packet list
	UINT64 LastConnectFailedTick;				// Time that it fails to connect at the last
	IPC *Ipc;									// IPC
	THREAD *IpcConnectThread;					// IPC connection thread
	IPSEC_SERVICES CurrentIPSecServiceSetting;	// Copy of the current IPsec service settings
	IP ClientIP, ServerIP;
	UINT ClientPort, ServerPort;
	bool IsTunnelMode;							// Whether the IPsec is in the tunnel mode
	UINT CryptBlockSize;						// Encryption block size of IPsec
	char ClientId[MAX_SIZE];					// Client ID has been presented by the IPsec connection
	UINT LastEtherIPSettingVerNo;				// Version number of EtherIP settings last checked
	ETHERIP_ID CurrentEtherIPIdSetting;			// Current EtherIP ID settings
	bool L2TPv3;								// L2TPv3 mode
	char VendorName[MAX_SIZE];					// Vendor name
};


//// Function prototype
ETHERIP_SERVER *NewEtherIPServer(CEDAR *cedar, IPSEC_SERVER *ipsec, IKE_SERVER *ike,
	IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, char *crypt_name,
	bool is_tunnel_mode, UINT crypt_block_size,
	char *client_id, UINT id);
void ReleaseEtherIPServer(ETHERIP_SERVER *s);
void CleanupEtherIPServer(ETHERIP_SERVER *s);
void SetEtherIPServerSockEvent(ETHERIP_SERVER *s, SOCK_EVENT *e);
void EtherIPProcInterrupts(ETHERIP_SERVER *s);
void EtherIPProcRecvPackets(ETHERIP_SERVER *s, BLOCK *b);
void EtherIPIpcConnectThread(THREAD *t, void *p);
UINT CalcEtherIPTcpMss(ETHERIP_SERVER *s);



//////////////////////////////////////////////////////////////////////////
// Interop_SSTP.h



//// Constants
#define	SSTP_URI				"/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"		// SSTP HTTPS URI
#define	SSTP_VERSION_1			0x10							// SSTP Version 1.0
#define	MAX_SSTP_PACKET_SIZE	4096							// Maximum packet size
#define SSTP_IPC_CLIENT_NAME			"Microsoft SSTP VPN Client"
#define	SSTP_IPC_POSTFIX				"SSTP"
#define	SSTP_ECHO_SEND_INTERVAL_MIN		2500					// Transmission interval of Echo Request (minimum)
#define	SSTP_ECHO_SEND_INTERVAL_MAX		4792					// Transmission interval of Echo Request (maximum)
#define	SSTP_TIMEOUT					10000					// Communication time-out of SSTP

// SSTP Message Type
#define	SSTP_MSG_CALL_CONNECT_REQUEST				0x0001
#define	SSTP_MSG_CALL_CONNECT_ACK					0x0002
#define	SSTP_MSG_CALL_CONNECT_NAK					0x0003
#define	SSTP_MSG_CALL_CONNECTED						0x0004
#define	SSTP_MSG_CALL_ABORT							0x0005
#define	SSTP_MSG_CALL_DISCONNECT					0x0006
#define	SSTP_MSG_CALL_DISCONNECT_ACK				0x0007
#define	SSTP_MSG_ECHO_REQUEST						0x0008
#define	SSTP_MSG_ECHO_RESPONSE						0x0009

// SSTP Attribute ID
#define	SSTP_ATTRIB_NO_ERROR						0x00
#define	SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID		0x01
#define	SSTP_ATTRIB_STATUS_INFO						0x02
#define	SSTP_ATTRIB_CRYPTO_BINDING					0x03
#define	SSTP_ATTRIB_CRYPTO_BINDING_REQ				0x04

// Protocol ID
#define	SSTP_ENCAPSULATED_PROTOCOL_PPP				0x0001

// Hash Protocol Bitmask
#define	CERT_HASH_PROTOCOL_SHA1						0x01
#define	CERT_HASH_PROTOCOL_SHA256					0x02

// Status
#define	ATTRIB_STATUS_NO_ERROR						0x00000000
#define	ATTRIB_STATUS_DUPLICATE_ATTRIBUTE			0x00000001
#define	ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE		0x00000002
#define	ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH	0x00000003
#define	ATTRIB_STATUS_VALUE_NOT_SUPPORTED			0x00000004
#define	ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED		0x00000005
#define	ATTRIB_STATUS_RETRY_COUNT_EXCEEDED			0x00000006
#define	ATTRIB_STATUS_INVALID_FRAME_RECEIVED		0x00000007
#define	ATTRIB_STATUS_NEGOTIATION_TIMEOUT			0x00000008
#define	ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG	0x00000009
#define	ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING	0x0000000A
#define	ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG	0x0000000B

// State of SSTP Server
#define	SSTP_SERVER_STATUS_REQUEST_PENGING			0	// Connection incomplete
#define	SSTP_SERVER_STATUS_CONNECTED_PENDING		1	// Connection completed. Authentication incomplete
#define	SSTP_SERVER_STATUS_ESTABLISHED				2	// Connection completed. Communication available

// Length of Nonce
#define	SSTP_NONCE_SIZE								32	// 256 bits


//// Type

// SSTP Attibute
struct SSTP_ATTRIBUTE
{
	UCHAR AttributeId;
	UCHAR *Data;
	UINT DataSize;
	UINT TotalLength;
};

// SSTP Packet
struct SSTP_PACKET
{
	UCHAR Version;
	bool IsControl;
	UCHAR *Data;
	UINT DataSize;
	USHORT MessageType;
	LIST *AttibuteList;
};

// SSTP Server
struct SSTP_SERVER
{
	CEDAR *Cedar;
	UINT64 Now;
	IP ClientIp, ServerIp;
	UINT ClientPort, ServerPort;
	char ClientHostName[MAX_HOST_NAME_LEN + 1];
	char ClientCipherName[MAX_SIZE];
	SOCK_EVENT *SockEvent;
	QUEUE *RecvQueue;						// Receive queue
	QUEUE *SendQueue;						// Transmission queue
	INTERRUPT_MANAGER *Interrupt;			// Interrupt manager
	bool Aborting;							// Forced disconnection flag
	bool AbortSent;							// Flag of whether to send the Abort
	bool AbortReceived;						// Flag of whether the Abort has been received
	bool Disconnecting;						// Disconnecting flag
	bool DisconnectSent;					// Flag of whether to send a Disconnect
	bool DisconnectRecved;					// Flag of whether a Disconnect has been received
	bool Disconnected;						// Flag as to disconnect
	UINT Status;							// State
	UCHAR SentNonce[SSTP_NONCE_SIZE];		// Random data sent
	TUBE *TubeRecv, *TubeSend;				// Delivery tube of packets to PPP module
	THREAD *PPPThread;						// PPP module thread
	UINT64 NextSendEchoRequestTick;			// Time to send the next Echo Request
	UINT64 LastRecvTick;					// Tick when some data has received at the end
	bool FlushRecvTube;						// Flag whether to flush the reception tube
	UINT EstablishedCount;					// Number of session establishment
};


//// Function prototype
bool AcceptSstp(CONNECTION *c);
bool ProcessSstpHttps(CEDAR *cedar, SOCK *s, SOCK_EVENT *se);

SSTP_SERVER *NewSstpServer(CEDAR *cedar, IP *client_ip, UINT client_port, IP *server_ip,
	UINT server_port, SOCK_EVENT *se,
	char *client_host_name, char *crypt_name);
void FreeSstpServer(SSTP_SERVER *s);
void SstpProcessInterrupt(SSTP_SERVER *s);
SSTP_PACKET *SstpParsePacket(UCHAR *data, UINT size);
LIST *SstpParseAttributeList(UCHAR *data, UINT size, SSTP_PACKET *p);
SSTP_ATTRIBUTE *SstpParseAttribute(UCHAR *data, UINT size);
void SstpFreeAttribute(SSTP_ATTRIBUTE *a);
void SstpFreeAttributeList(LIST *o);
void SstpFreePacket(SSTP_PACKET *p);
BUF *SstpBuildPacket(SSTP_PACKET *p);
BUF *SstpBuildAttributeList(LIST *o, USHORT message_type);
BUF *SstpBuildAttribute(SSTP_ATTRIBUTE *a);
void SstpAbort(SSTP_SERVER *s);
void SstpDisconnect(SSTP_SERVER *s);
void SstpProcessPacket(SSTP_SERVER *s, SSTP_PACKET *p);
void SstpProcessControlPacket(SSTP_SERVER *s, SSTP_PACKET *p);
void SstpProcessDataPacket(SSTP_SERVER *s, SSTP_PACKET *p);
SSTP_ATTRIBUTE *SstpFindAttribute(SSTP_PACKET *p, UCHAR attribute_id);
SSTP_ATTRIBUTE *SstpNewAttribute(UCHAR attribute_id, UCHAR *data, UINT data_size);
SSTP_ATTRIBUTE *SstpNewStatusInfoAttribute(UCHAR attrib_id, UINT status);
SSTP_ATTRIBUTE *SstpNewCryptoBindingRequestAttribute(UCHAR hash_protocol_bitmask, UCHAR *nonce_32bytes);
SSTP_PACKET *SstpNewDataPacket(UCHAR *data, UINT size);
SSTP_PACKET *SstpNewControlPacket(USHORT message_type);
SSTP_PACKET *SstpNewControlPacketWithAnAttribute(USHORT message_type, SSTP_ATTRIBUTE *a);
void SstpSendPacket(SSTP_SERVER *s, SSTP_PACKET *p);
bool GetNoSstp();
void SetNoSstp(bool b);


//////////////////////////////////////////////////////////////////////////
// Interop_OpenVPN.h


//// Constants
#define	OPENVPN_UDP_PORT						1194	// OpenVPN default UDP port number
#define	OPENVPN_UDP_PORT_INCLUDE				1195	// OpenVPN default UDP port number (Operating within the client)

#define	OPENVPN_MAX_NUMACK						4		// The maximum number of ACKs
#define	OPENVPN_NUM_CHANNELS					8		// Maximum number of channels during a session
#define	OPENVPN_CONTROL_PACKET_RESEND_INTERVAL	500		// Control packet retransmission interval
#define	OPENVPN_CONTROL_PACKET_MAX_DATASIZE		1200	// Maximum data size that can be stored in one control packet

#define	OPENVPN_MAX_SSL_RECV_BUF_SIZE			(256 * 1024)	// SSL receive buffer maximum length

#define	OPENVPN_MAX_KEY_SIZE					64		// Maximum key size

#define	OPENVPN_TMP_BUFFER_SIZE					(65536 + 256)	// Temporary buffer size

#define	OPENVPN_PING_SEND_INTERVAL				3000	// Transmission interval of Ping
#define	OPENVPN_RECV_TIMEOUT					10000	// Communication time-out
#define	OPENVPN_NEW_SESSION_DEADLINE_TIMEOUT	30000	// Grace time to complete new VPN session connection since it was created

#define	OPENVPN_MAX_PACKET_ID_FOR_TRIGGER_REKEY	0xFF000000	// Packet ID that is a trigger to start the re-key
#define	OPENVPN_TCP_MAX_PACKET_SIZE				2000	// The maximum packet size allowed in TCP mode


// The default algorithm
#define	OPENVPN_DEFAULT_CIPHER					"AES-128-CBC"
#define	OPENVPN_DEFAULT_MD						"SHA1"

// Encryption related
#define	OPENVPN_PREMASTER_LABEL					"OpenVPN master secret"
#define	OPENVPN_EXPANSION_LABEL					"OpenVPN key expansion"

// IPC related
#define	OPENVPN_IPC_CLIENT_NAME					"OpenVPN Client"
#define	OPENVPN_IPC_POSTFIX_L2					"OPENVPN_L2"
#define	OPENVPN_IPC_POSTFIX_L3					"OPENVPN_L3"

// List of supported encryption algorithms
#define	OPENVPN_CIPHER_LIST						"[NULL-CIPHER] NULL AES-128-CBC AES-192-CBC AES-256-CBC BF-CBC CAST-CBC CAST5-CBC DES-CBC DES-EDE-CBC DES-EDE3-CBC DESX-CBC RC2-40-CBC RC2-64-CBC RC2-CBC CAMELLIA-128-CBC CAMELLIA-192-CBC CAMELLIA-256-CBC"

// List of the supported hash algorithm
#define	OPENVPN_MD_LIST							"SHA SHA1 SHA256 SHA384 SHA512 MD5 MD4 RMD160"

// MTU
#define	OPENVPN_MTU_LINK						1514	// Ethernet MTU
#define	OPENVPN_MTU_TUN							1500	// Tun MTU

// Protocol
#define	OPENVPN_PROTOCOL_UDP					0		// UDP
#define	OPENVPN_PROTOCOL_TCP					1		// TCP

// Op-code
#define	OPENVPN_P_CONTROL_SOFT_RESET_V1			3		// Soft reset request
#define	OPENVPN_P_CONTROL_V1					4		// SSL negotiation packet
#define	OPENVPN_P_ACK_V1						5		// Acknowledgment
#define	OPENVPN_P_DATA_V1						6		// Data packet
#define	OPENVPN_P_CONTROL_HARD_RESET_CLIENT_V2	7		// Connection request from client
#define	OPENVPN_P_CONTROL_HARD_RESET_SERVER_V2	8		// Connection response from server

// State of OpenVPN channel
#define	OPENVPN_CHANNEL_STATUS_INIT					0	// Initialization phase
#define	OPENVPN_CHANNEL_STATUS_TLS_WAIT_CLIENT_KEY	1	// Waiting for the key information from the client
#define	OPENVPN_CHANNEL_STATUS_TLS_WAIT_CLIENT_PUSH_REQUEST	2	// Waiting for PUSH_REQUEST from the client
#define	OPENVPN_CHANNEL_STATUS_TLS_VPN_CONNECTING	3	// VPN connecting process is running
#define	OPENVPN_CHANNEL_STATUS_ESTABLISHED			4	// VPN connection established
#define	OPENVPN_CHANNEL_STATUS_DISCONNECTED			5	// Disconnected

// Quota
#define	OPENVPN_QUOTA_MAX_NUM_SESSIONS_PER_IP	1000			// Number of OpenVPN sessions per IP address
#define	OPENVPN_QUOTA_MAX_NUM_SESSIONS			30000			// Limit of the number of sessions

// Mode
#define	OPENVPN_MODE_UNKNOWN					0		// Unknown
#define	OPENVPN_MODE_L2							1		// TAP (Ethernet)
#define	OPENVPN_MODE_L3							2		// TUN (IP)


//// Type

// Data of OpenVPN Key Method 2
struct OPENVPN_KEY_METHOD_2
{
	UCHAR PreMasterSecret[48];							// Pre Master Secret (client only)
	UCHAR Random1[32];									// Random 1
	UCHAR Random2[32];									// Random 2
	char OptionString[512];								// Option string
	char Username[512];									// User name
	char Password[512];									// Password
	char PeerInfo[1536];								// PeerInfo
};

// OpenVPN sending control packet
struct OPENVPN_CONTROL_PACKET
{
	UCHAR OpCode;										// Op-code
	UINT PacketId;										// Packet ID
	UINT DataSize;										// Data size
	UCHAR *Data;										// Data body
	UINT64 NextSendTime;								// Scheduled next transmission time
};

// OpenVPN packet
struct OPENVPN_PACKET
{
	UCHAR OpCode;										// Op-code
	UCHAR KeyId;										// Key ID
	UINT64 MySessionId;									// Channel ID of the sender
	UCHAR NumAck;										// Number of ACK
	UINT AckPacketId[OPENVPN_MAX_NUMACK];				// ACK packet ID list
	UINT64 YourSessionId;								// Destination Channel ID (If there are one or more ACK)
	UINT PacketId;										// Packet ID
	UINT DataSize;										// Data size
	UCHAR *Data;										// Data body
};

// OpenVPN channel
struct OPENVPN_CHANNEL
{
	OPENVPN_SERVER *Server;
	OPENVPN_SESSION *Session;
	UINT Status;										// State
	LIST *AckReplyList;									// Response ACK list
	UINT MaxRecvPacketId;								// The maximum value of the arrived packet ID
	UINT NextSendPacketId;								// The value of a packet ID to be transmitted next
	LIST *SendControlPacketList;						// Sending control packet list
	SSL_PIPE *SslPipe;									// SSL pipe
	OPENVPN_KEY_METHOD_2 ClientKey;						// Key sent from the client
	OPENVPN_KEY_METHOD_2 ServerKey;						// Key sent from the server
	char Proto[64];										// Protocol
	CIPHER *CipherEncrypt;								// Encryption algorithm
	CIPHER *CipherDecrypt;								// Decryption algorithm
	MD *MdSend;											// Transmission MD algorithm
	MD *MdRecv;											// Reception MD algorithm
	UCHAR MasterSecret[48];								// Master Secret
	UCHAR ExpansionKey[256];							// Expansion Key
	UCHAR NextIv[64];									// Next IV
	UINT LastDataPacketId;								// Previous Data Packet ID
	UINT64 EstablishedTick;								// Established time
	UCHAR KeyId;										// KEY ID
	bool IsRekeyChannel;								// Whether it is a channel for key update
	bool IsInitiatorServer;								// Whether the channel was started from the server side
	bool RekeyInitiated;								// Whether re-keying has already started
	UINT64 NextRekey;
};

// OpenVPN session
struct OPENVPN_SESSION
{
	UINT Id;											// ID
	OPENVPN_SERVER *Server;
	UINT64 ServerSessionId;								// The session ID of the server-side
	UINT64 ClientSessionId;								// Session ID of the client side
	UINT Protocol;										// Protocol
	IP ClientIp;										// Client IP address
	UINT ClientPort;									// Client port number
	IP ServerIp;										// Server IP address
	UINT ServerPort;									// Server port number
	OPENVPN_CHANNEL *Channels[OPENVPN_NUM_CHANNELS];	// Channels (up to 8)
	UINT LastCreatedChannelIndex;						// Channel number that is created in the last
	UINT Mode;											// Mode (L3 or L2)
	UINT LinkMtu;										// link-mtu
	UINT TunMtu;										// tun-mtu
	IPC_ASYNC *IpcAsync;								// Asynchronous IPC connection
	IPC *Ipc;											// Connected IPC connection
	char PushReplyStr[MAX_SIZE];						// PUSH_REPLY string
	UINT64 NextPingSendTick;							// Next time to send a Ping
	bool Established;									// VPN communication established flag
	UINT64 CreatedTick;									// Creation date and time
	UINT64 LastCommTick;								// Last communication date and time
};

// OpenVPN server
struct OPENVPN_SERVER
{
	CEDAR *Cedar;
	INTERRUPT_MANAGER *Interrupt;						// Interrupt manager
	LIST *SendPacketList;								// Transmission packet list
	LIST *SessionList;									// Session list
	UINT64 Now;											// Current time
	SOCK_EVENT *SockEvent;								// Socket event
	UCHAR TmpBuf[OPENVPN_TMP_BUFFER_SIZE];				// Temporary buffer
	UINT DisconnectCount;								// The number of session lost that have occurred so far
	bool SupressSendPacket;								// Packet transmission suppression flag
	UINT NextSessionId;									// Next session ID
	DH_CTX *Dh;											// DH key
	UINT SessionEstablishedCount;						// Number of session establishment
};

// OpenVPN server (UDP mode)
struct OPENVPN_SERVER_UDP
{
	CEDAR *Cedar;
	UDPLISTENER *UdpListener;							// UDP listener
	OPENVPN_SERVER *OpenVpnServer;						// OpenVPN server
	UINT64 VgsNextGetPublicPortsTick;
};

// OpenVPN Default Client Option String
#define	OVPN_DEF_CLIENT_OPTION_STRING	"dev-type tun,link-mtu 1500,tun-mtu 1500,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client"


//// Function prototype
OPENVPN_SERVER_UDP *NewOpenVpnServerUdp(CEDAR *cedar);
void FreeOpenVpnServerUdp(OPENVPN_SERVER_UDP *u);
void OpenVpnServerUdpListenerProc(UDPLISTENER *u, LIST *packet_list);
void OvsApplyUdpPortList(OPENVPN_SERVER_UDP *u, char *port_list);

OPENVPN_SERVER *NewOpenVpnServer(CEDAR *cedar, INTERRUPT_MANAGER *interrupt, SOCK_EVENT *sock_event);
void FreeOpenVpnServer(OPENVPN_SERVER *s);
void OvsRecvPacket(OPENVPN_SERVER *s, LIST *recv_packet_list, UINT protocol);
void OvsProceccRecvPacket(OPENVPN_SERVER *s, UDPPACKET *p, UINT protocol);
int OvsCompareSessionList(void *p1, void *p2);
OPENVPN_SESSION *OvsSearchSession(OPENVPN_SERVER *s, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, UINT protocol);
OPENVPN_SESSION *OvsNewSession(OPENVPN_SERVER *s, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, UINT protocol);
OPENVPN_SESSION *OvsFindOrCreateSession(OPENVPN_SERVER *s, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, UINT protocol);
void OvsFreeSession(OPENVPN_SESSION *se);
UINT OvsGetNumSessionByClientIp(OPENVPN_SERVER *s, IP *ip);

OPENVPN_PACKET *OvsParsePacket(UCHAR *data, UINT size);
void OvsFreePacket(OPENVPN_PACKET *p);
BUF *OvsBuildPacket(OPENVPN_PACKET *p);
OPENVPN_PACKET *OvsNewControlPacket(UCHAR opcode, UCHAR key_id, UINT64 my_channel_id, UINT num_ack,
	UINT *ack_packet_ids, UINT64 your_channel_id, UINT packet_id,
	UINT data_size, UCHAR *data);
void OvsSendDataPacket(OPENVPN_CHANNEL *c, UCHAR key_id, UINT data_packet_id, void *data, UINT data_size);


OPENVPN_CHANNEL *OvsNewChannel(OPENVPN_SESSION *se, UCHAR key_id);
void OvsFreeChannel(OPENVPN_CHANNEL *c);
UINT64 OvsNewServerSessionId(OPENVPN_SERVER *s);
UINT OvsGetAckReplyList(OPENVPN_CHANNEL *c, UINT *ret);

void OvsSendPacketNow(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_PACKET *p);
void OvsSendPacketRawNow(OPENVPN_SERVER *s, OPENVPN_SESSION *se, void *data, UINT size);

void OvsProcessRecvControlPacket(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c, OPENVPN_PACKET *p);
void OvsSendControlPacket(OPENVPN_CHANNEL *c, UCHAR opcode, UCHAR *data, UINT data_size);
void OvsSendControlPacketWithAutoSplit(OPENVPN_CHANNEL *c, UCHAR opcode, UCHAR *data, UINT data_size);
void OvsFreeControlPacket(OPENVPN_CONTROL_PACKET *p);
void OvsDeleteFromSendingControlPacketList(OPENVPN_CHANNEL *c, UINT num_acks, UINT *acks);
UINT OvsParseKeyMethod2(OPENVPN_KEY_METHOD_2 *ret, UCHAR *data, UINT size, bool client_mode);
bool OvsReadStringFromBuf(BUF *b, char *str, UINT str_size);
void OvsSetupSessionParameters(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c, OPENVPN_KEY_METHOD_2 *data);
BUF *OvsBuildKeyMethod2(OPENVPN_KEY_METHOD_2 *d);
void OvsWriteStringToBuf(BUF *b, char *str, UINT max_size);

LIST *OvsParseOptions(char *str);
void OvsFreeOptions(LIST *o);
LIST *OvsNewOptions();
void OvsAddOption(LIST *o, char *key, char *value);
bool OvsHasOption(LIST *o, char *key);
UINT OvsPeekStringFromFifo(FIFO *f, char *str, UINT str_size);
void OvsBeginIPCAsyncConnectionIfEmpty(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c);
bool OvsIsCompatibleL3IP(UINT ip);
UINT OvsGetCompatibleL3IPNext(UINT ip);
UINT OvsCalcTcpMss(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c);

CIPHER *OvsGetCipher(char *name);
MD *OvsGetMd(char *name);
bool OvsCheckTcpRecvBufIfOpenVPNProtocol(UCHAR *buf, UINT size);

bool OvsPerformTcpServer(CEDAR *cedar, SOCK *sock);

void OvsSetReplyForVgsPollEnable(bool b);

void OvsSetNoOpenVpnTcp(bool b);
bool OvsGetNoOpenVpnTcp();

void OvsSetNoOpenVpnUdp(bool b);



//////////////////////////////////////////////////////////////////////////
// UdpAccel.h


// Constants
#define	UDP_ACCELERATION_COMMON_KEY_SIZE	20			// Common key size
#define	UDP_ACCELERATION_PACKET_KEY_SIZE	20			// Key size for the packet
#define	UDP_ACCELERATION_PACKET_IV_SIZE		20			// IV size for the packet
#define	UDP_ACCELERATION_TMP_BUF_SIZE		2048		// Temporary buffer size
#define	UDP_ACCELERATION_WINDOW_SIZE_MSEC	(30 * 1000)	// Receive window size (in milliseconds)

#define	UDP_ACCELERATION_SUPPORTED_MAX_PAYLOAD_SIZE	1600	// Maximum supported payload size
#define	UDP_ACCELERATION_MAX_PADDING_SIZE	32			// Maximum padding size

#define	UDP_ACCELERATION_REQUIRE_CONTINUOUS	(10 * 1000)	// Not to use if stable communication is not continued at least for this time

// Time constant for Build 8534 or earlier
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN	(1 * 1000)	// Keep Alive Interval (minimum)
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX	(3 * 1000)	// Keep Alive Interval (maximum)
#define	UDP_ACCELERATION_KEEPALIVE_TIMEOUT		(9 * 1000)	// Time to disconnect time by non-communication

// Time constant for Build 8535 or later
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST	(500)	// Keep Alive Interval (minimum)
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX_FAST	(1000)	// Keep Alive Interval (maximum)
#define	UDP_ACCELERATION_KEEPALIVE_TIMEOUT_FAST			(2100)	// Time to disconnect time by non-communication

// Range of port numbers
#define	UDP_SERVER_PORT_LOWER				40000		// Minimum port
#define	UDP_SERVER_PORT_HIGHER				44999		// Maximum port

// NAT-T port signature to be embedded in the Keep Alive of the session
#define	UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE			"NATT_MY_PORT"

// UDP Acceleration Mode
struct UDP_ACCEL
{
	CEDAR *Cedar;										// Cedar
	bool NoNatT;										// Not to communicate with the NAT-T server (To communicate with the query server instead)
	bool ClientMode;									// Whether client mode
	bool IsInCedarPortList;								// Whether included in the port list of the Cedar
	UINT64 Now;											// Current time
	UCHAR MyKey[UDP_ACCELERATION_COMMON_KEY_SIZE];		// Submit-direction common key
	UCHAR YourKey[UDP_ACCELERATION_COMMON_KEY_SIZE];	// Receiving-direction common key
	SOCK *UdpSock;										// UDP socket
	UINT MyPort;										// My port number
	UINT YourPort;										// Port number of the other party
	IP MyIp;											// My IP address
	IP YourIp;											// IP address of the other party
	IP YourIp2;											// IP address of the other party (second)
	bool IsIPv6;										// Whether it's an IPv6
	UCHAR TmpBuf[UDP_ACCELERATION_TMP_BUF_SIZE];		// Temporary buffer
	UINT64 LastRecvYourTick;							// Opponent's tick value of the last reception
	UINT64 LastRecvMyTick;								// My tick value of the last reception
	QUEUE *RecvBlockQueue;								// Reception block queue
	bool UseHMac;										// Flag to use the HMAC
	bool PlainTextMode;									// No encryption
	UINT64 LastSetSrcIpAndPortTick;						// Opponent's tick ??value at the time of storing the IP address and port number of the opponent at the end
	UINT64 LastRecvTick;								// Tick when data has received at the end
	UINT64 NextSendKeepAlive;							// Next time to send a KeepAlive packet
	UCHAR NextIv[UDP_ACCELERATION_PACKET_IV_SIZE];		// IV to be used next
	UINT MyCookie;										// My cookie
	UINT YourCookie;									// Cookie of the other party
	bool Inited;										// Initialized flag
	UINT Mss;											// Optimal MSS
	UINT MaxUdpPacketSize;								// Get the maximum transmittable UDP size
	LOCK *NatT_Lock;									// Lock the IP address field of NAT-T server
	IP NatT_IP;											// IP address of the NAT-T server
	THREAD *NatT_GetIpThread;							// IP address acquisition thread of NAT-T server
	bool NatT_Halt;										// Halting flag of IP address acquisition thread of NAT-T server
	EVENT *NatT_HaltEvent;								// Halting event of IP address acquisition thread of NAT-T server
	UINT64 NextPerformNatTTick;							// Time to communicate with NAT-T server next time
	UINT CommToNatT_NumFail;							// Number of failures to communicate with NAT-T server
	UINT MyPortByNatTServer;							// Self port number which is received from the NAT-T server
	bool MyPortByNatTServerChanged;						// The self port number which is received from the NAT-T server changes
	UINT YourPortByNatTServer;							// Port number of the opponent that was found via the NAT-T server
	bool YourPortByNatTServerChanged;					// Port number of the opponent that was found via the NAT-T server has been changed
	bool FatalError;									// A fatal error occurred
	bool NatT_IP_Changed;								// IP address of the NAT-T server has changed
	UINT64 NatT_TranId;									// Transaction ID to be exchanged with the NAT-T server
	bool IsReachedOnce;									// It is true if it succeeds in mutual transmission and reception of packets at least once
	UINT64 CreatedTick;									// Object creation time
	bool FastDetect;									// Fast disconnection detection mode
	UINT64 FirstStableReceiveTick;						// Start time of current stable continued receivable period
	bool UseSuperRelayQuery;							// Use the super relay query
	bool UseUdpIpQuery;									// Use the self IP address query by UDP
	IP UdpIpQueryHost;									// Host for the self IP address query by UDP
	UINT UdpIpQueryPort;								// Port number for self IP address for query by UDP
	UCHAR UdpIpQueryPacketData[16];						// Query packet data (final transmission)
	UINT UdpIpQueryPacketSize;							// Query packet data size (final transmission)
	UCHAR UdpHostUniqueKey[SHA1_SIZE];					// Unique key for UDP self endpoint query
};

// Function prototype
UDP_ACCEL *NewUdpAccel(CEDAR *cedar, IP *ip, bool client_mode, bool random_port, bool no_nat_t);
void FreeUdpAccel(UDP_ACCEL *a);
bool UdpAccelInitClient(UDP_ACCEL *a, UCHAR *server_key, IP *server_ip, UINT server_port, UINT server_cookie, UINT client_cookie, IP *server_ip_2);
bool UdpAccelInitServer(UDP_ACCEL *a, UCHAR *client_key, IP *client_ip, UINT client_port, IP *client_ip_2);
void UdpAccelPoll(UDP_ACCEL *a);
void UdpAccelSetTick(UDP_ACCEL *a, UINT64 tick64);
BLOCK *UdpAccelProcessRecvPacket(UDP_ACCEL *a, UCHAR *buf, UINT size, IP *src_ip, UINT src_port);
void UdpAccelCalcKey(UCHAR *key, UCHAR *common_key, UCHAR *iv);
bool UdpAccelIsSendReady(UDP_ACCEL *a, bool check_keepalive);
void UdpAccelSend(UDP_ACCEL *a, UCHAR *data, UINT data_size, bool compressed, UINT max_size, bool high_priority);
void UdpAccelSendBlock(UDP_ACCEL *a, BLOCK *b);
UINT UdpAccelCalcMss(UDP_ACCEL *a);
void NatT_GetIpThread(THREAD *thread, void *param);




//////////////////////////////////////////////////////////////////////////
// DDNS.h



// Certificate hash
#define	DDNS_CERT_HASH		"78BF0499A99396907C9F49DD13571C81FE26E6F5" \
							"439BAFA75A6EE5671FC9F9A02D34FF29881761A0" \
							"EFAC5FA0CDD14E0F864EED58A73C35D7E33B62F3" \
							"74DF99D4B1B5F0488A388B50D347D26013DC67A5" \
							"6EBB39AFCA8C900635CFC11218CF293A612457E4"

#define	DDNS_SNI_VER_STRING		"DDNS"


// Destination URL
#define	DDNS_URL_V4_GLOBAL	"https://x%c.x%c.servers.ddns.softether-network.net/ddns/ddns.aspx"
#define	DDNS_URL_V6_GLOBAL	"https://x%c.x%c.servers-v6.ddns.softether-network.net/ddns/ddns.aspx"
#define	DDNS_URL2_V4_GLOBAL	"http://get-my-ip.ddns.softether-network.net/ddns/getmyip.ashx"
#define	DDNS_URL2_V6_GLOBAL	"http://get-my-ip-v6.ddns.softether-network.net/ddns/getmyip.ashx"

#define	DDNS_REPLACE_URL_FOR_EAST_BFLETS	"https://senet-flets.v6.softether.co.jp/ddns/ddns.aspx"
#define	DDNS_REPLACE_URL_FOR_EAST_NGN		"https://senet.aoi.flets-east.jp/ddns/ddns.aspx"
#define	DDNS_REPLACE_URL_FOR_WEST_NGN		"https://senet.p-ns.flets-west.jp/ddns/ddns.aspx"

#define	DDNS_REPLACE_URL2_FOR_EAST_BFLETS	"http://senet-flets.v6.softether.co.jp/ddns/getmyip.ashx"
#define	DDNS_REPLACE_URL2_FOR_EAST_NGN		"http://senet.aoi.flets-east.jp/ddns/getmyip.ashx"
#define	DDNS_REPLACE_URL2_FOR_WEST_NGN		"http://senet.p-ns.flets-west.jp/ddns/getmyip.ashx"

// For China: Free version
#define	DDNS_URL_V4_ALT		"https://x%c.x%c.servers.ddns.uxcom.jp/ddns/ddns.aspx"
#define	DDNS_URL_V6_ALT		"https://x%c.x%c.servers-v6.ddns.uxcom.jp/ddns/ddns.aspx"
#define	DDNS_URL2_V4_ALT	"http://get-my-ip.ddns.uxcom.jp/ddns/getmyip.ashx"
#define	DDNS_URL2_V6_ALT	"http://get-my-ip-v6.ddns.uxcom.jp/ddns/getmyip.ashx"

#define	DDNS_RPC_MAX_RECV_SIZE				DYN32(DDNS_RPC_MAX_RECV_SIZE, (128 * 1024 * 1024))

// Connection Timeout
#define	DDNS_CONNECT_TIMEOUT		DYN32(DDNS_CONNECT_TIMEOUT, (15 * 1000))

// Communication time-out
#define	DDNS_COMM_TIMEOUT			DYN32(DDNS_COMM_TIMEOUT, (60 * 1000))

// Maximum length of the host name 
#define	DDNS_MAX_HOSTNAME			31

// DDNS Version
#define	DDNS_VERSION				1

// Period until the next registration in case of success
#define	DDNS_REGISTER_INTERVAL_OK_MIN		DYN32(DDNS_REGISTER_INTERVAL_OK_MIN, (1 * 60 * 60 * 1000))
#define	DDNS_REGISTER_INTERVAL_OK_MAX		DYN32(DDNS_REGISTER_INTERVAL_OK_MAX, (2 * 60 * 60 * 1000))

// Period until the next registration in case of failure
#define	DDNS_REGISTER_INTERVAL_NG_MIN		DYN32(DDNS_REGISTER_INTERVAL_NG_MIN, (1 * 60 * 1000))
#define	DDNS_REGISTER_INTERVAL_NG_MAX		DYN32(DDNS_REGISTER_INTERVAL_NG_MAX, (5 * 60 * 1000))

// The self IP address acquisition interval (If last trial succeeded)
#define	DDNS_GETMYIP_INTERVAL_OK_MIN		DYN32(DDNS_GETMYIP_INTERVAL_OK_MIN, (10 * 60 * 1000))
#define	DDNS_GETMYIP_INTERVAL_OK_MAX		DYN32(DDNS_GETMYIP_INTERVAL_OK_MAX, (20 * 60 * 1000))

// The self IP address acquisition interval (If last trial failed)
#define	DDNS_GETMYIP_INTERVAL_NG_MIN		DYN32(DDNS_GETMYIP_INTERVAL_NG_MIN, (1 * 60 * 1000))
#define	DDNS_GETMYIP_INTERVAL_NG_MAX		DYN32(DDNS_GETMYIP_INTERVAL_NG_MAX, (5 * 60 * 1000))

// Time difference to communicate with the DDNS server after a predetermined time has elapsed since the VPN Azure is disconnected
#define	DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF	DYN32(DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF, (120 * 1000))
#define	DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF_MAX	DYN32(DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF_MAX, (10 * 60 * 1000))

// DDNS Client
struct DDNS_CLIENT
{
	CEDAR *Cedar;							// Cedar
	THREAD *Thread;							// Thread
	UCHAR Key[SHA1_SIZE];					// Key
	LOCK *Lock;								// Lock
	volatile bool Halt;						// Halt flag
	EVENT *Event;							// Halt event
	char CurrentHostName[DDNS_MAX_HOSTNAME + 1];	// Current host name
	char CurrentFqdn[MAX_SIZE];				// Current FQDN
	char DnsSuffix[MAX_SIZE];				// DNS suffix
	char CurrentIPv4[MAX_SIZE];				// Current IPv4 address
	char CurrentIPv6[MAX_SIZE];				// Current IPv6 address
	UINT Err_IPv4, Err_IPv6;				// Last error
	UINT Err_IPv4_GetMyIp, Err_IPv6_GetMyIp;	// Last error (obtaining self IP address)
	bool KeyChanged;						// Flag to indicate that the key has been changed
	char LastMyIPv4[MAX_SIZE];				// Self IPv4 address that were acquired on last
	char LastMyIPv6[MAX_SIZE];				// Self IPv6 address that were acquired on last
	char CurrentAzureIp[MAX_SIZE];			// IP address of Azure Server to be used
	UINT64 CurrentAzureTimestamp;			// Time stamp to be presented to the Azure Server
	char CurrentAzureSignature[MAX_SIZE];	// Signature to be presented to the Azure Server
	char AzureCertHash[MAX_SIZE];			// Azure Server certificate hash
	INTERNET_SETTING InternetSetting;		// Internet connection settings

	UINT64 NextRegisterTick_IPv4, NextRegisterTick_IPv6;		// Next register time
	UINT64 NextGetMyIpTick_IPv4, NextGetMyIpTick_IPv6;			// Next self IP acquisition time
};

// DDNS Register Param
struct DDNS_REGISTER_PARAM
{
	char NewHostname[DDNS_MAX_HOSTNAME + 1];	// Host name after the change
};

// The current status of the DDNS
struct DDNS_CLIENT_STATUS
{
	UINT Err_IPv4, Err_IPv6;				// Last error
	char CurrentHostName[DDNS_MAX_HOSTNAME + 1];	// Current host name
	char CurrentFqdn[MAX_SIZE];				// Current FQDN
	char DnsSuffix[MAX_SIZE];				// DNS suffix
	char CurrentIPv4[MAX_SIZE];				// Current IPv4 address
	char CurrentIPv6[MAX_SIZE];				// Current IPv6 address
	char CurrentAzureIp[MAX_SIZE];			// IP address of Azure Server to be used
	UINT64 CurrentAzureTimestamp;			// Time stamp to be presented to the Azure Server
	char CurrentAzureSignature[MAX_SIZE];	// Signature to be presented to the Azure Server
	char AzureCertHash[MAX_SIZE];			// Azure Server certificate hash
	INTERNET_SETTING InternetSetting;		// Internet settings
};

// Function prototype
DDNS_CLIENT *NewDDNSClient(CEDAR *cedar, UCHAR *key, INTERNET_SETTING *t);
void FreeDDNSClient(DDNS_CLIENT *c);
void DCGenNewKey(UCHAR *key);
void DCThread(THREAD *thread, void *param);
UINT DCRegister(DDNS_CLIENT *c, bool ipv6, DDNS_REGISTER_PARAM *p, char *replace_v6);
UINT DCGetMyIpMain(DDNS_CLIENT *c, bool ipv6, char *dst, UINT dst_size, bool use_ssl, char *replace_v6);
UINT DCGetMyIp(DDNS_CLIENT *c, bool ipv6, char *dst, UINT dst_size, char *replace_v6);
void DCUpdateNow(DDNS_CLIENT *c);
void DCGetStatus(DDNS_CLIENT *c, DDNS_CLIENT_STATUS *st);
UINT DCChangeHostName(DDNS_CLIENT *c, char *hostname);
void DCSetInternetSetting(DDNS_CLIENT *c, INTERNET_SETTING *t);
void DCGetInternetSetting(DDNS_CLIENT *c, INTERNET_SETTING *t);


//////////////////////////////////////////////////////////////////////////
// AzureClient.h


// Constants
#define	AZURE_SERVER_PORT					443
#define AZURE_PROTOCOL_CONTROL_SIGNATURE	"ACTL"
#define	AZURE_PROTOCOL_DATA_SIANGTURE		"AZURE_CONNECT_SIGNATURE!"
#define	AZURE_PROTOCOL_CONTROL_TIMEOUT_DEFAULT	(5 * 1000)			// Default timeout
#define	AZURE_CONNECT_INITIAL_RETRY_INTERVAL	(1 * 1000)			// Initial re-connection interval (15 * 1000)
#define	AZURE_CONNECT_MAX_RETRY_INTERVAL		(60 * 60 * 1000)	// Maximum re-connection interval

#define	AZURE_DOMAIN_SUFFIX					".vpnazure.net"

#define	AZURE_SERVER_MAX_KEEPALIVE			(5 * 60 * 1000)
#define	AZURE_SERVER_MAX_TIMEOUT			(10 * 60 * 1000)

#define	AZURE_VIA_PROXY_TIMEOUT				5000


// Communications parameter
struct AZURE_PARAM
{
	UINT ControlKeepAlive;
	UINT ControlTimeout;
	UINT DataTimeout;
	UINT SslTimeout;
};

// VPN Azure Client
struct AZURE_CLIENT
{
	CEDAR *Cedar;
	SERVER *Server;
	LOCK *Lock;
	DDNS_CLIENT_STATUS DDnsStatus;
	volatile bool IsEnabled;
	EVENT *Event;
	volatile bool Halt;
	THREAD *MainThread;
	volatile UINT IpStatusRevision;
	DDNS_CLIENT_STATUS DDnsStatusCopy;
	SOCK *CurrentSock;
	char ConnectingAzureIp[MAX_SIZE];
	AZURE_PARAM AzureParam;
	volatile UINT DDnsTriggerInt;
	volatile bool IsConnected;
};


// Function prototype
AZURE_CLIENT *NewAzureClient(CEDAR *cedar, SERVER *server);
void FreeAzureClient(AZURE_CLIENT *ac);
void AcApplyCurrentConfig(AZURE_CLIENT *ac, DDNS_CLIENT_STATUS *ddns_status);
void AcMainThread(THREAD *thread, void *param);
void AcSetEnable(AZURE_CLIENT *ac, bool enabled);
bool AcGetEnable(AZURE_CLIENT *ac);
void AcWaitForRequest(AZURE_CLIENT *ac, SOCK *s, AZURE_PARAM *param);



//////////////////////////////////////////////////////////////////////////
// NativeStack.h


//// Constants
#define	NS_MAC_ADDRESS_BYTE_1		0xDA		// First byte of the MAC address

#define	NS_CHECK_IPTABLES_INTERVAL_INIT	(1 * 1000)

#define	NS_CHECK_IPTABLES_INTERVAL_MAX	(5 * 60 * 1000)

//// Type
struct NATIVE_STACK
{
	CEDAR *Cedar;
	IPC *Ipc;						// IPC object
	char DeviceName[MAX_SIZE];		// Ethernet device name
	THREAD *MainThread;				// Main thread
	bool Halt;						// Halting flag
	CANCEL *Cancel;					// Cancel
	UCHAR MacAddress[6];			// MAC address of the virtual host
	ETH *Eth;						// Eth device
	SOCK *Sock1;					// Sock1 (To be used in the bridge side)
	SOCK *Sock2;					// Sock2 (Used in the IPC side)
	DHCP_OPTION_LIST CurrentDhcpOptionList;	// Current DHCP options list
	IP DnsServerIP;					// IP address of the DNS server
	IP DnsServerIP2;				// IP address of the DNS server #2
	bool IsIpRawMode;
	IP MyIP_InCaseOfIpRawMode;		// My IP

	THREAD *IpTablesThread;
	EVENT *IpTablesHaltEvent;
	bool IpTablesHalt;
	bool IpTablesInitOk;
};

struct IPTABLES_ENTRY
{
	char Chain[64];
	UINT LineNumber;
	char ConditionAndArgs[MAX_SIZE];
	IP DummySrcIp, DummyDestIP;
	UINT DummyMark;
};

struct IPTABLES_STATE
{
	UCHAR SeedHash[SHA1_SIZE];
	LIST *EntryList;
	bool HasError;
};


//// Function prototype
NATIVE_STACK *NewNativeStack(CEDAR *cedar, char *device_name, char *mac_address_seed);
void FreeNativeStack(NATIVE_STACK *a);

void NsGenMacAddress(void *dest, char *mac_address_seed, char *device_name);
void NsMainThread(THREAD *thread, void *param);
void NsGenMacAddressSignatureForMachine(UCHAR *dst_last_2, UCHAR *src_mac_addr_4);
bool NsIsMacAddressOnLocalhost(UCHAR *mac);

bool NsStartIpTablesTracking(NATIVE_STACK *a);
void NsStopIpTablesTracking(NATIVE_STACK *a);
void NsIpTablesThread(THREAD *thread, void *param);

IPTABLES_STATE *GetCurrentIpTables();
void FreeIpTablesState(IPTABLES_STATE *s);
bool IsIpTablesSupported();
IPTABLES_ENTRY *SearchIpTables(IPTABLES_STATE *s, char *chain, IP *src_ip, IP *dest_ip, UINT mark);
UINT GetCurrentIpTableLineNumber(char *chain, IP *src_ip, IP *dest_ip, UINT mark);

IPTABLES_STATE *StartAddIpTablesEntryForNativeStack(void *seed, UINT seed_size);
void EndAddIpTablesEntryForNativeStack(IPTABLES_STATE *s);
bool MaintainAddIpTablesEntryForNativeStack(IPTABLES_STATE *s);

void GenerateDummyIpAndMark(void *hash_seed, IPTABLES_ENTRY *e, UINT id);
UINT GenerateDummyMark(PRAND *p);
void GenerateDummyIp(PRAND *p, IP *ip);


#ifdef	OS_WIN32

//////////////////////////////////////////////////////////////////////////
// Neo.h



// Identification string (NDIS)
#define	NDIS_NEO_HARDWARE_ID				"VPN Client Adapter - %s"
#define	NDIS_NEO_DEVICE_NAME				"\\Device\\NEO_%s_DEVICE"
#define	NDIS_NEO_DEVICE_NAME_WIN32			"\\DosDevices\\NEO_%s_DEVICE"
#define	NDIS_NEO_DEVICE_FILE_NAME			"\\\\.\\NEO_NEOADAPTER_%s_DEVICE"
#define	NDIS_NEO_EVENT_NAME					"\\BaseNamedObjects\\NEO_EVENT_%s"
#define	NDIS_NEO_EVENT_NAME_WIN32			"Global\\NEO_EVENT_NEOADAPTER_%s"

// Constant
#define	NEO_MAX_PACKET_SIZE			1600
#define	NEO_MAX_PACKET_SIZE_ANNOUNCE	1514
#define	NEO_MIN_PACKET_SIZE			14
#define	NEO_PACKET_HEADER_SIZE		14
#define	NEO_MAX_FRAME_SIZE			(NEO_MAX_PACKET_SIZE - NEO_MIN_PACKET_SIZE)
#define	NEO_MAX_SPEED_DEFAULT		1000000
#define	NEO_MAC_ADDRESS_SIZE		6
#define	NEO_MAX_MULTICASE			32


// IOCTL constant
#define	NEO_IOCTL_SET_EVENT			CTL_CODE(0x8000, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	NEO_IOCTL_PUT_PACKET		CTL_CODE(0x8000, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	NEO_IOCTL_GET_PACKET		CTL_CODE(0x8000, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)


// Packet data exchange related
#define	NEO_MAX_PACKET_EXCHANGE		256			// Number of packets that can be exchanged at a time
#define	NEO_MAX_PACKET_QUEUED		4096		// Maximum number of packets that can be queued
#define	NEO_EX_SIZEOF_NUM_PACKET	4			// Packet count data (UINT)
#define	NEO_EX_SIZEOF_LENGTH_PACKET	4			// Length data of the packet data (UINT)
#define	NEO_EX_SIZEOF_LEFT_FLAG		4			// Flag to indicate that the packet is still
#define	NEO_EX_SIZEOF_ONE_PACKET	1600		// Data area occupied by a packet data
#define	NEO_EXCHANGE_BUFFER_SIZE	(NEO_EX_SIZEOF_NUM_PACKET + NEO_EX_SIZEOF_LEFT_FLAG +	\
	(NEO_EX_SIZEOF_LENGTH_PACKET + NEO_EX_SIZEOF_ONE_PACKET) * (NEO_MAX_PACKET_EXCHANGE + 1))
#define	NEO_NUM_PACKET(buf)			(*((UINT *)((UCHAR *)buf + 0)))
#define	NEO_SIZE_OF_PACKET(buf, i)	(*((UINT *)((UCHAR *)buf + NEO_EX_SIZEOF_NUM_PACKET + \
									(i * (NEO_EX_SIZEOF_LENGTH_PACKET + NEO_EX_SIZEOF_ONE_PACKET)))))
#define	NEO_ADDR_OF_PACKET(buf, i)	(((UINT *)((UCHAR *)buf + NEO_EX_SIZEOF_NUM_PACKET + \
									NEO_EX_SIZEOF_LENGTH_PACKET +	\
									(i * (NEO_EX_SIZEOF_LENGTH_PACKET + NEO_EX_SIZEOF_ONE_PACKET)))))
#define	NEO_LEFT_FLAG(buf)			NEO_SIZE_OF_PACKET(buf, NEO_MAX_PACKET_EXCHANGE)


//////////////////////////////////////////////////////////////////////////
// SeLowUser.h

#define	SL_VER						48

// Constants
#define	SL_MAX_PACKET_SIZE			1600
#define	SL_MAX_PACKET_SIZE_ANNOUNCE	1514
#define	SL_MIN_PACKET_SIZE			14
#define	SL_PACKET_HEADER_SIZE		14
#define	SL_MAX_FRAME_SIZE			(SL_MAX_PACKET_SIZE - SL_MIN_PACKET_SIZE)

#define	SL_PROTOCOL_NAME			"SeLow"
#define	SL_EVENT_NAME_SIZE			128

#define	SL_ENUM_COMPLETE_GIVEUP_TICK	(15 * 1000)

// IOCTL
#define	SL_IOCTL_GET_EVENT_NAME		CTL_CODE(0x8000, 1, METHOD_NEITHER, FILE_ANY_ACCESS)

// IOCTL data structure
typedef struct SL_IOCTL_EVENT_NAME
{
	char EventNameWin32[SL_EVENT_NAME_SIZE];		// Event name
} SL_IOCTL_EVENT_NAME;

// Device ID
#define	SL_BASIC_DEVICE_NAME			"\\Device\\SELOW_BASIC_DEVICE"
#define	SL_BASIC_DEVICE_NAME_SYMBOLIC	"\\DosDevices\\Global\\SELOW_BASIC_DEVICE"
#define	SL_BASIC_DEVICE_FILENAME_WIN32	"\\\\.\\SELOW_BASIC_DEVICE"
#define	SL_ADAPTER_ID_PREFIX			"SELOW_A_"
#define	SL_ADAPTER_ID_PREFIX_W			L"SELOW_A_"
#define	SL_ADAPTER_DEVICE_NAME			"\\Device\\SELOW_A_{00000000-0000-0000-0000-000000000000}"
#define	SL_ADAPTER_DEVICE_NAME_SYMBOLIC	"\\DosDevices\\Global\\SELOW_A_{00000000-0000-0000-0000-000000000000}"
#define	SL_ADAPTER_DEVICE_FILENAME_WIN32	"\\\\.\\%s"

// Event name
#define	SL_EVENT_NAME					"\\BaseNamedObjects\\SELOW_EVENT_%u_%u"
#define	SL_EVENT_NAME_WIN32				"Global\\SELOW_EVENT_%u_%u"

// Registry key
#define	SL_REG_KEY_NAME					"SYSTEM\\CurrentControlSet\\services\\SeLow"
#define	SL_REG_VER_VALUE				"SlVersion"
#define	SL_REG_VER_VALUE_WIN10			"SlVersion_Win10"

// Adapter data
#define	SL_ADAPTER_ID_LEN				64
typedef struct SL_ADAPTER_INFO
{
	wchar_t AdapterId[SL_ADAPTER_ID_LEN];	// Adapter ID
	UCHAR MacAddress[6];				// MAC address
	UCHAR Padding1[2];
	UINT MtuSize;						// MTU size
	char FriendlyName[256];				// Display name
	UINT SupportsVLanHw;				// Supports VLAN by HW
	UCHAR Reserved[256 - sizeof(UINT)];	// Reserved area
} SL_ADAPTER_INFO;

#define	SL_MAX_ADAPTER_INFO_LIST_ENTRY	256
#define	SL_SIGNATURE					0xDEADBEEF

typedef struct SL_ADAPTER_INFO_LIST
{
	UINT Signature;													// Signature
	UINT SeLowVersion;												// Version of SeLow
	UINT EnumCompleted;												// Enumeration completion flag
	UINT NumAdapters;												// The total number of adapter
	SL_ADAPTER_INFO Adapters[SL_MAX_ADAPTER_INFO_LIST_ENTRY];		// Array of adapter
} SL_ADAPTER_INFO_LIST;


// Packet data exchange related
#define	SL_MAX_PACKET_EXCHANGE		256			// Number of packets that can be exchanged at a time
#define	SL_MAX_PACKET_QUEUED		4096		// Maximum number of packets that can be queued
#define	SL_EX_SIZEOF_NUM_PACKET	4			// Packet count data (UINT)
#define	SL_EX_SIZEOF_LENGTH_PACKET	4			// Length data of the packet data (UINT)
#define	SL_EX_SIZEOF_LEFT_FLAG		4			// Flag to indicate that the packet is left
#define	SL_EX_SIZEOF_ONE_PACKET	1600		// Data area occupied by a packet data
#define	SL_EXCHANGE_BUFFER_SIZE	(SL_EX_SIZEOF_NUM_PACKET + SL_EX_SIZEOF_LEFT_FLAG +	\
	(SL_EX_SIZEOF_LENGTH_PACKET + SL_EX_SIZEOF_ONE_PACKET) * (SL_MAX_PACKET_EXCHANGE + 1))
#define	SL_NUM_PACKET(buf)			(*((UINT *)((UCHAR *)buf + 0)))
#define	SL_SIZE_OF_PACKET(buf, i)	(*((UINT *)((UCHAR *)buf + SL_EX_SIZEOF_NUM_PACKET + \
	(i * (SL_EX_SIZEOF_LENGTH_PACKET + SL_EX_SIZEOF_ONE_PACKET)))))
#define	SL_ADDR_OF_PACKET(buf, i)	(((UINT *)((UCHAR *)buf + SL_EX_SIZEOF_NUM_PACKET + \
	SL_EX_SIZEOF_LENGTH_PACKET +	\
	(i * (SL_EX_SIZEOF_LENGTH_PACKET + SL_EX_SIZEOF_ONE_PACKET)))))
#define	SL_LEFT_FLAG(buf)			SL_SIZE_OF_PACKET(buf, SL_MAX_PACKET_EXCHANGE)


//// Macro
#define	SL_USER_INSTALL_LOCK_TIMEOUT		60000		// Lock acquisition timeout
#define	SL_USER_AUTO_PUSH_TIMER				60000		// Timer to start the installation automatically

//// Type

// SU
struct SU
{
	void *hFile;							// File handle
	SL_ADAPTER_INFO_LIST AdapterInfoList;	// Adapter list cache
};

// Adapter
struct SU_ADAPTER
{
	char AdapterId[MAX_PATH];				// Adapter ID
	char DeviceName[MAX_PATH];				// Device name
	void *hFile;							// File handle
	void *hEvent;							// Event handle
	bool Halt;
	UINT CurrentPacketCount;
	UCHAR GetBuffer[SL_EXCHANGE_BUFFER_SIZE];	// Read buffer
	UCHAR PutBuffer[SL_EXCHANGE_BUFFER_SIZE];	// Write buffer
};

// Adapter list items
struct SU_ADAPTER_LIST
{
	SL_ADAPTER_INFO Info;					// Adapter information
	char Guid[128];							// GUID
	char Name[MAX_SIZE];					// Name
	char SortKey[MAX_SIZE];					// Sort key
};


//// Function prototype
SU *SuInit();
SU *SuInitEx(UINT wait_for_bind_complete_tick);
void SuFree(SU *u);
TOKEN_LIST *SuEnumAdapters(SU *u);
SU_ADAPTER *SuOpenAdapter(SU *u, char *adapter_id);
void SuCloseAdapter(SU_ADAPTER *a);
void SuCloseAdapterHandleInner(SU_ADAPTER *a);
bool SuGetPacketsFromDriver(SU_ADAPTER *a);
bool SuGetNextPacket(SU_ADAPTER *a, void **buf, UINT *size);
bool SuPutPacketsToDriver(SU_ADAPTER *a);
bool SuPutPacket(SU_ADAPTER *a, void *buf, UINT size);

SU_ADAPTER_LIST *SuAdapterInfoToAdapterList(SL_ADAPTER_INFO *info);
LIST *SuGetAdapterList(SU *u);
void SuFreeAdapterList(LIST *o);
int SuCmpAdaterList(void *p1, void *p2);

bool SuInstallDriver(bool force);
bool SuInstallDriverInner(bool force);
bool SuIsSupportedOs(bool on_install);
bool SuCopySysFile(wchar_t *src, wchar_t *dst);

void SuDeleteGarbageInfs();
void SuDeleteGarbageInfsInner();
bool SuLoadDriversHive();
bool SuUnloadDriversHive();




#endif	// OS_WIN32



//////////////////////////////////////////////////////////////////////////
// VLan.h


// Parameters related to VLAN
struct VLAN_PARAM
{
	UCHAR MacAddress[6];
	UCHAR Padding[2];
};

#ifdef	OS_WIN32

// Begin Win32


// Routing table tracking timer
#define	TRACKING_INTERVAL_INITIAL		444		// Initial
#define	TRACKING_INTERVAL_ADD			444		// Adding value
#define	TRACKING_INTERVAL_MAX			12345	// Maximum value
#define	TRACKING_INTERVAL_MAX_RC		87654	// Maximum value (OS which change detection mechanism enabled)


typedef void *HANDLE;

// Routing tracking state machine
struct ROUTE_TRACKING
{
	UINT VLanInterfaceId;
	ROUTE_ENTRY *RouteToServer;
	bool RouteToServerAlreadyExists;
	ROUTE_ENTRY *DefaultGatewayByVLan;
	ROUTE_ENTRY *VistaDefaultGateway1, *VistaDefaultGateway2, *VistaOldDefaultGatewayByVLan;
	ROUTE_ENTRY *RouteToDefaultDns;
	ROUTE_ENTRY *RouteToEight;
	ROUTE_ENTRY *RouteToNatTServer;
	ROUTE_ENTRY *RouteToRealServerGlobal;
	UINT64 NextTrackingTime;
	UINT64 NextTrackingTimeAdd;
	UINT64 NextRouteChangeCheckTime;
	UINT LastRoutingTableHash;
	QUEUE *DeletedDefaultGateway;
	UINT OldDefaultGatewayMetric;
	IP OldDnsServer;
	bool VistaAndUsingPPP;
	ROUTE_CHANGE *RouteChange;
};

// VLAN structure
struct VLAN
{
	volatile bool Halt;			// Halting flag
	bool Win9xMode;				// Windows 9x
	char *InstanceName;			// Instance name
	char *DeviceNameWin32;		// Win32 device name
	char *EventNameWin32;		// Win32 event name
	HANDLE Handle;				// Device driver file
	HANDLE Event;				// Handle of the event
	void *GetBuffer;			// Sent packet capturing buffer
	UINT CurrentPacketCount;	// Packet number to be read next
	void *PutBuffer;			// Buffer for writing received packet
	ROUTE_TRACKING *RouteState;	// Routing tracking state machine
};

// Instance list
struct INSTANCE_LIST
{
	UINT NumInstance;
	char **InstanceName;
};


// Function prototype
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param);
void FreeVLan(VLAN *v);
CANCEL *VLanGetCancel(VLAN *v);
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size);
bool VLanGetPacketsFromDriver(VLAN *v);
bool VLanPutPacketsToDriver(VLAN *v);
bool VLanPutPacket(VLAN *v, void *buf, UINT size);

PACKET_ADAPTER *VLanGetPacketAdapter();
bool VLanPaInit(SESSION *s);
CANCEL *VLanPaGetCancel(SESSION *s);
UINT VLanPaGetNextPacket(SESSION *s, void **data);
bool VLanPaPutPacket(SESSION *s, void *data, UINT size);
void VLanPaFree(SESSION *s);

INSTANCE_LIST *GetInstanceList();
void FreeInstanceList(INSTANCE_LIST *n);
UINT GetInstanceId(char *name);

void RouteTrackingStart(SESSION *s);
void RouteTrackingStop(SESSION *s, ROUTE_TRACKING *t);
void RouteTrackingMain(SESSION *s);
void Win32ReleaseAllDhcp9x(bool wait);

void Win32GetWinVer(RPC_WINVER *v);


// End Win32

#else	// OS_WIN32

// Begin UNIX


// Constant
#define	TAP_READ_BUF_SIZE			1600

#ifndef	NO_VLAN

// VLAN structure
struct VLAN
{
	volatile bool Halt;			// Halt flag
	char *InstanceName;			// Instance name
	int fd;						// File
};

// Function prototype
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param);
VLAN *NewTap(char *name, char *mac_address);
void FreeVLan(VLAN *v);
CANCEL *VLanGetCancel(VLAN *v);
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size);
bool VLanPutPacket(VLAN *v, void *buf, UINT size);

PACKET_ADAPTER *VLanGetPacketAdapter();
bool VLanPaInit(SESSION *s);
CANCEL *VLanPaGetCancel(SESSION *s);
UINT VLanPaGetNextPacket(SESSION *s, void **data);
bool VLanPaPutPacket(SESSION *s, void *data, UINT size);
void VLanPaFree(SESSION *s);

#else	// NO_VLAN

#define	VLanGetPacketAdapter	NullGetPacketAdapter

#endif	// NO_VLAN

struct UNIX_VLAN_LIST
{
	char Name[MAX_SIZE];		// Device name
	int fd;						// fd
};

int UnixCreateTapDevice(char *name, UCHAR *mac_address);
int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address);
void UnixCloseTapDevice(int fd);
void UnixVLanInit();
void UnixVLanFree();
bool UnixVLanCreate(char *name, UCHAR *mac_address);
bool UnixVLanCreateEx(char *name, char *prefix, UCHAR *mac_address);
TOKEN_LIST *UnixVLanEnum();
void UnixVLanDelete(char *name);
int UnixVLanGet(char *name);
int UnixCompareVLan(void *p1, void *p2);

// End UNIX

#endif	// OS_WIN32





//////////////////////////////////////////////////////////////////////////
// Bridge.h

#ifdef	OS_WIN32

// Begin Win32


#define	BRIDGE_WIN32_PACKET_DLL		"Packet.dll"
#define	BRIDGE_WIN32_PCD_DLL		"|see.dll"
#define	BRIDGE_WIN32_PCD_SYS		"|DriverPackages\\See\\x86\\See_x86.sys"
#define	BRIDGE_WIN32_PCD_DLL_X64	"|see_x64.dll"
#define	BRIDGE_WIN32_PCD_SYS_X64	"|DriverPackages\\See\\x64\\See_x64.sys"
#define	BRIDGE_WIN32_PCD_REGKEY		"SYSTEM\\CurrentControlSet\\services\\SEE"
#define	BRIDGE_WIN32_PCD_BUILDVALUE	"CurrentInstalledBuild"

#define	BRIDGE_WIN32_ETH_BUFFER		(1048576)


typedef void *HANDLE;

#ifdef	SECLIB_INTERNAL

/*
* Copyright (c) 1999 - 2003
* NetGroup, Politecnico di Torino (Italy)
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
* 3. Neither the name of the Politecnico di Torino nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

/** @ingroup packetapi
*  @{
*/

/** @defgroup packet32h Packet.dll definitions and data structures
*  Packet32.h contains the data structures and the definitions used by packet.dll.
*  The file is used both by the Win9x and the WinNTx versions of packet.dll, and can be included
*  by the applications that use the functions of this library
*  @{
*/

#ifndef __PACKET32
#define __PACKET32

#include <winsock2.h>
#include "devioctl.h"
#ifdef HAVE_DAG_API
#include <dagc.h>
#endif /* HAVE_DAG_API */

// Working modes
#define PACKET_MODE_CAPT 0x0 ///< Capture mode
#define PACKET_MODE_STAT 0x1 ///< Statistical mode
#define PACKET_MODE_MON 0x2 ///< Monitoring mode
#define PACKET_MODE_DUMP 0x10 ///< Dump mode
#define PACKET_MODE_STAT_DUMP MODE_DUMP | MODE_STAT ///< Statistical dump Mode

// ioctls
#define FILE_DEVICE_PROTOCOL        0x8000

#define IOCTL_PROTOCOL_STATISTICS   CTL_CODE(FILE_DEVICE_PROTOCOL, 2 , METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTOCOL_RESET        CTL_CODE(FILE_DEVICE_PROTOCOL, 3 , METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTOCOL_READ         CTL_CODE(FILE_DEVICE_PROTOCOL, 4 , METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTOCOL_WRITE        CTL_CODE(FILE_DEVICE_PROTOCOL, 5 , METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTOCOL_MACNAME      CTL_CODE(FILE_DEVICE_PROTOCOL, 6 , METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OPEN                  CTL_CODE(FILE_DEVICE_PROTOCOL, 7 , METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLOSE                 CTL_CODE(FILE_DEVICE_PROTOCOL, 8 , METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	 pBIOCSETBUFFERSIZE 9592		///< IOCTL code: set kernel buffer size.
#define	 pBIOCSETF 9030					///< IOCTL code: set packet filtering program.
#define  pBIOCGSTATS 9031				///< IOCTL code: get the capture stats.
#define	 pBIOCSRTIMEOUT 7416			///< IOCTL code: set the read timeout.
#define	 pBIOCSMODE 7412				///< IOCTL code: set working mode.
#define	 pBIOCSWRITEREP 7413			///< IOCTL code: set number of physical repetions of every packet written by the app.
#define	 pBIOCSMINTOCOPY 7414			///< IOCTL code: set minimum amount of data in the kernel buffer that unlocks a read call.
#define	 pBIOCSETOID 2147483648			///< IOCTL code: set an OID value.
#define	 pBIOCQUERYOID 2147483652		///< IOCTL code: get an OID value.
#define	 pATTACHPROCESS 7117			///< IOCTL code: attach a process to the driver. Used in Win9x only.
#define	 pDETACHPROCESS 7118			///< IOCTL code: detach a process from the driver. Used in Win9x only.
#define  pBIOCSETDUMPFILENAME 9029		///< IOCTL code: set the name of a the file used by kernel dump mode.
#define  pBIOCEVNAME 7415				///< IOCTL code: get the name of the event that the driver signals when some data is present in the buffer.
#define  pBIOCSENDPACKETSNOSYNC 9032	///< IOCTL code: Send a buffer containing multiple packets to the network, ignoring the timestamps associated with the packets.
#define  pBIOCSENDPACKETSSYNC 9033		///< IOCTL code: Send a buffer containing multiple packets to the network, respecting the timestamps associated with the packets.
#define  pBIOCSETDUMPLIMITS 9034		///< IOCTL code: Set the dump file limits. See the PacketSetDumpLimits() function.
#define  pBIOCISDUMPENDED 7411			///< IOCTL code: Get the status of the kernel dump process. See the PacketIsDumpEnded() function.

#define  pBIOCSTIMEZONE 7471			///< IOCTL code: set time zone. Used in Win9x only.


/// Alignment macro. Defines the alignment size.
#define Packet_ALIGNMENT sizeof(int)
/// Alignment macro. Rounds up to the next even multiple of Packet_ALIGNMENT. 
#define Packet_WORDALIGN(x) (((x)+(Packet_ALIGNMENT-1))&~(Packet_ALIGNMENT-1))


#define NdisMediumNull	-1		// Custom linktype: NDIS doesn't provide an equivalent
#define NdisMediumCHDLC	-2		// Custom linktype: NDIS doesn't provide an equivalent
#define NdisMediumPPPSerial	-3	// Custom linktype: NDIS doesn't provide an equivalent

/*!
\brief Network type structure.

This structure is used by the PacketGetNetType() function to return information on the current adapter's type and speed.
*/
typedef struct NetType
{
	UINT LinkType;	///< The MAC of the current network adapter (see function PacketGetNetType() for more information)
	ULONGLONG LinkSpeed;	///< The speed of the network in bits per second
}NetType;


//some definitions stolen from libpcap

#ifndef BPF_MAJOR_VERSION

/*!
\brief A BPF pseudo-assembly program.

The program will be injected in the kernel by the PacketSetBPF() function and applied to every incoming packet.
*/
struct bpf_program
{
	UINT bf_len;				///< Indicates the number of instructions of the program, i.e. the number of struct bpf_insn that will follow.
	struct bpf_insn *bf_insns;	///< A pointer to the first instruction of the program.
};

/*!
\brief A single BPF pseudo-instruction.

bpf_insn contains a single instruction for the BPF register-machine. It is used to send a filter program to the driver.
*/
struct bpf_insn
{
	USHORT	code;		///< Instruction type and addressing mode.
	UCHAR 	jt;			///< Jump if true
	UCHAR 	jf;			///< Jump if false
	int k;				///< Generic field used for various purposes.
};

/*!
\brief Structure that contains a couple of statistics values on the current capture.

It is used by packet.dll to return statistics about a capture session.
*/
struct bpf_stat
{
	UINT bs_recv;		///< Number of packets that the driver received from the network adapter 
						///< from the beginning of the current capture. This value includes the packets 
						///< lost by the driver.
	UINT bs_drop;		///< number of packets that the driver lost from the beginning of a capture. 
						///< Basically, a packet is lost when the the buffer of the driver is full. 
						///< In this situation the packet cannot be stored and the driver rejects it.
	UINT ps_ifdrop;		///< drops by interface. XXX not yet supported
	UINT bs_capt;		///< number of packets that pass the filter, find place in the kernel buffer and
						///< thus reach the application.
};

/*!
\brief Packet header.

This structure defines the header associated with every packet delivered to the application.
*/
struct bpf_hdr
{
	struct timeval	bh_tstamp;	///< The timestamp associated with the captured packet. 
								///< It is stored in a TimeVal structure.
	UINT	bh_caplen;			///< Length of captured portion. The captured portion <b>can be different</b>
								///< from the original packet, because it is possible (with a proper filter)
								///< to instruct the driver to capture only a portion of the packets.
	UINT	bh_datalen;			///< Original length of packet
	USHORT		bh_hdrlen;		///< Length of bpf header (this struct plus alignment padding). In some cases,
								///< a padding could be added between the end of this structure and the packet
								///< data for performance reasons. This filed can be used to retrieve the actual data 
								///< of the packet.
};

/*!
\brief Dump packet header.

This structure defines the header associated with the packets in a buffer to be used with PacketSendPackets().
It is simpler than the bpf_hdr, because it corresponds to the header associated by WinPcap and libpcap to a
packet in a dump file. This makes straightforward sending WinPcap dump files to the network.
*/
struct dump_bpf_hdr {
	struct timeval	ts;			///< Time stamp of the packet
	UINT			caplen;		///< Length of captured portion. The captured portion can smaller than the 
								///< the original packet, because it is possible (with a proper filter) to 
								///< instruct the driver to capture only a portion of the packets. 
	UINT			len;		///< Length of the original packet (off wire).
};


#endif

#define        DOSNAMEPREFIX   TEXT("Packet_")	///< Prefix added to the adapters device names to create the WinPcap devices
#define        MAX_LINK_NAME_LENGTH	64			//< Maximum length of the devices symbolic links
#define        NMAX_PACKET 65535

/*!
\brief Addresses of a network adapter.

This structure is used by the PacketGetNetInfoEx() function to return the IP addresses associated with
an adapter.
*/
typedef struct npf_if_addr {
	struct sockaddr_storage IPAddress;	///< IP address.
	struct sockaddr_storage SubnetMask;	///< Netmask for that address.
	struct sockaddr_storage Broadcast;	///< Broadcast address.
}npf_if_addr;


#define ADAPTER_NAME_LENGTH 256 + 12	///<  Maximum length for the name of an adapter. The value is the same used by the IP Helper API.
#define ADAPTER_DESC_LENGTH 128			///<  Maximum length for the description of an adapter. The value is the same used by the IP Helper API.
#define MAX_MAC_ADDR_LENGTH 8			///<  Maximum length for the link layer address of an adapter. The value is the same used by the IP Helper API.
#define MAX_NETWORK_ADDRESSES 16		///<  Maximum length for the link layer address of an adapter. The value is the same used by the IP Helper API.


typedef struct WAN_ADAPTER_INT WAN_ADAPTER; ///< Describes an opened wan (dialup, VPN...) network adapter using the NetMon API
typedef WAN_ADAPTER *PWAN_ADAPTER; ///< Describes an opened wan (dialup, VPN...) network adapter using the NetMon API

#define INFO_FLAG_NDIS_ADAPTER		0	///< Flag for ADAPTER_INFO: this is a traditional ndis adapter
#define INFO_FLAG_NDISWAN_ADAPTER	1	///< Flag for ADAPTER_INFO: this is a NdisWan adapter
#define INFO_FLAG_DAG_CARD			2	///< Flag for ADAPTER_INFO: this is a DAG card
#define INFO_FLAG_DAG_FILE			6	///< Flag for ADAPTER_INFO: this is a DAG file
#define INFO_FLAG_DONT_EXPORT		8	///< Flag for ADAPTER_INFO: when this flag is set, the adapter will not be listed or openend by winpcap. This allows to prevent exporting broken network adapters, like for example FireWire ones.

								   /*!
								   \brief Contains comprehensive information about a network adapter.

								   This structure is filled with all the accessory information that the user can need about an adapter installed
								   on his system.
								   */
typedef struct _ADAPTER_INFO
{
	struct _ADAPTER_INFO *Next;				///< Pointer to the next adapter in the list.
	CHAR Name[ADAPTER_NAME_LENGTH + 1];		///< Name of the device representing the adapter.
	CHAR Description[ADAPTER_DESC_LENGTH + 1];	///< Human understandable description of the adapter
	UINT MacAddressLen;						///< Length of the link layer address.
	UCHAR MacAddress[MAX_MAC_ADDR_LENGTH];	///< Link layer address.
	NetType LinkLayer;						///< Physical characteristics of this adapter. This NetType structure contains the link type and the speed of the adapter.
	INT NNetworkAddresses;					///< Number of network layer addresses of this adapter.
	npf_if_addr *NetworkAddresses;			///< Pointer to an array of npf_if_addr, each of which specifies a network address of this adapter.
	UINT Flags;								///< Adapter's flags. Tell if this adapter must be treated in a different way, using the Netmon API or the dagc API.
}
ADAPTER_INFO, *PADAPTER_INFO;

/*!
\brief Describes an opened network adapter.

This structure is the most important for the functioning of packet.dll, but the great part of its fields
should be ignored by the user, since the library offers functions that avoid to cope with low-level parameters
*/
typedef struct _ADAPTER {
	HANDLE hFile;				///< \internal Handle to an open instance of the NPF driver.
	CHAR  SymbolicLink[MAX_LINK_NAME_LENGTH]; ///< \internal A string containing the name of the network adapter currently opened.
	int NumWrites;				///< \internal Number of times a packets written on this adapter will be repeated 
								///< on the wire.
	HANDLE ReadEvent;			///< A notification event associated with the read calls on the adapter.
								///< It can be passed to standard Win32 functions (like WaitForSingleObject
								///< or WaitForMultipleObjects) to wait until the driver's buffer contains some 
								///< data. It is particularly useful in GUI applications that need to wait 
								///< concurrently on several events. In Windows NT/2000 the PacketSetMinToCopy()
								///< function can be used to define the minimum amount of data in the kernel buffer
								///< that will cause the event to be signalled. 

	UINT ReadTimeOut;			///< \internal The amount of time after which a read on the driver will be released and 
								///< ReadEvent will be signaled, also if no packets were captured
	CHAR Name[ADAPTER_NAME_LENGTH];
	PWAN_ADAPTER pWanAdapter;
	UINT Flags;					///< Adapter's flags. Tell if this adapter must be treated in a different way, using the Netmon API or the dagc API.
#ifdef HAVE_DAG_API
	dagc_t *pDagCard;			///< Pointer to the dagc API adapter descriptor for this adapter
	PCHAR DagBuffer;			///< Pointer to the buffer with the packets that is received from the DAG card
	struct timeval DagReadTimeout;	///< Read timeout. The dagc API requires a timeval structure
	unsigned DagFcsLen;			///< Length of the frame check sequence attached to any packet by the card. Obtained from the registry
	DWORD DagFastProcess;		///< True if the user requests fast capture processing on this card. Higher level applications can use this value to provide a faster but possibly unprecise capture (for example, libpcap doesn't convert the timestamps).
#endif // HAVE_DAG_API
}  ADAPTER, *LPADAPTER;

/*!
\brief Structure that contains a group of packets coming from the driver.

This structure defines the header associated with every packet delivered to the application.
*/
typedef struct _PACKET {
	HANDLE       hEvent;		///< \deprecated Still present for compatibility with old applications.
	OVERLAPPED   OverLapped;	///< \deprecated Still present for compatibility with old applications.
	PVOID        Buffer;		///< Buffer with containing the packets. See the PacketReceivePacket() for
								///< details about the organization of the data in this buffer
	UINT         Length;		///< Length of the buffer
	DWORD        ulBytesReceived;	///< Number of valid bytes present in the buffer, i.e. amount of data
									///< received by the last call to PacketReceivePacket()
	BOOLEAN      bIoComplete;	///< \deprecated Still present for compatibility with old applications.
}  PACKET, *LPPACKET;

/*!
\brief Structure containing an OID request.

It is used by the PacketRequest() function to send an OID to the interface card driver.
It can be used, for example, to retrieve the status of the error counters on the adapter, its MAC address,
the list of the multicast groups defined on it, and so on.
*/
struct _PACKET_OID_DATA {
	ULONG Oid;					///< OID code. See the Microsoft DDK documentation or the file ntddndis.h
								///< for a complete list of valid codes.
	ULONG Length;				///< Length of the data field
	UCHAR Data[1];				///< variable-lenght field that contains the information passed to or received 
								///< from the adapter.
};
typedef struct _PACKET_OID_DATA PACKET_OID_DATA, *PPACKET_OID_DATA;


#if _DBG
#define ODS(_x) OutputDebugString(TEXT(_x))
#define ODSEx(_x, _y)
#else
#ifdef _DEBUG_TO_FILE
/*!
\brief Macro to print a debug string. The behavior differs depending on the debug level
*/
#define ODS(_x) { \
	FILE *f; \
	f = fopen("winpcap_debug.txt", "a"); \
	fprintf(f, "%s", _x); \
	fclose(f); \
}
/*!
\brief Macro to print debug data with the printf convention. The behavior differs depending on
the debug level
*/
#define ODSEx(_x, _y) { \
	FILE *f; \
	f = fopen("winpcap_debug.txt", "a"); \
	fprintf(f, _x, _y); \
	fclose(f); \
}



LONG PacketDumpRegistryKey(PCHAR KeyName, PCHAR FileName);
#else
#define ODS(_x)		
#define ODSEx(_x, _y)
#endif
#endif

/* We load dinamically the dag library in order link it only when it's present on the system */
#ifdef HAVE_DAG_API
typedef dagc_t* (*dagc_open_handler)(const char *source, unsigned flags, char *ebuf);	///< prototype used to dynamically load the dag dll
typedef void(*dagc_close_handler)(dagc_t *dagcfd);										///< prototype used to dynamically load the dag dll
typedef int(*dagc_getlinktype_handler)(dagc_t *dagcfd);								///< prototype used to dynamically load the dag dll
typedef int(*dagc_getlinkspeed_handler)(dagc_t *dagcfd);								///< prototype used to dynamically load the dag dll
typedef int(*dagc_setsnaplen_handler)(dagc_t *dagcfd, unsigned snaplen);				///< prototype used to dynamically load the dag dll
typedef unsigned(*dagc_getfcslen_handler)(dagc_t *dagcfd);								///< prototype used to dynamically load the dag dll
typedef int(*dagc_receive_handler)(dagc_t *dagcfd, u_char **buffer, u_int *bufsize);	///< prototype used to dynamically load the dag dll
typedef int(*dagc_stats_handler)(dagc_t *dagcfd, dagc_stats_t *ps);					///< prototype used to dynamically load the dag dll
typedef int(*dagc_wait_handler)(dagc_t *dagcfd, struct timeval *timeout);				///< prototype used to dynamically load the dag dll
typedef int(*dagc_finddevs_handler)(dagc_if_t **alldevsp, char *ebuf);					///< prototype used to dynamically load the dag dll
typedef int(*dagc_freedevs_handler)(dagc_if_t *alldevsp);								///< prototype used to dynamically load the dag dll
#endif // HAVE_DAG_API

#ifdef __cplusplus
extern "C" {
#endif

	/**
	*  @}
	*/

	// The following is used to check the adapter name in PacketOpenAdapterNPF and prevent 
	// opening of firewire adapters 
#define FIREWIRE_SUBSTR L"1394"

	void PacketPopulateAdaptersInfoList();
	PWCHAR SChar2WChar(PCHAR string);
	PCHAR WChar2SChar(PWCHAR string);
	BOOL PacketGetFileVersion(LPTSTR FileName, PCHAR VersionBuff, UINT VersionBuffLen);
	PADAPTER_INFO PacketFindAdInfo(PCHAR AdapterName);
	BOOLEAN PacketUpdateAdInfo(PCHAR AdapterName);
	BOOLEAN IsFireWire(TCHAR *AdapterDesc);


	//---------------------------------------------------------------------------
	// EXPORTED FUNCTIONS
	//---------------------------------------------------------------------------

	PCHAR PacketGetVersion();
	PCHAR PacketGetDriverVersion();
	BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject, int nbytes);
	BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject, int nwrites);
	BOOLEAN PacketSetMode(LPADAPTER AdapterObject, int mode);
	BOOLEAN PacketSetReadTimeout(LPADAPTER AdapterObject, int timeout);
	BOOLEAN PacketSetBpf(LPADAPTER AdapterObject, struct bpf_program *fp);
	INT PacketSetSnapLen(LPADAPTER AdapterObject, int snaplen);
	BOOLEAN PacketGetStats(LPADAPTER AdapterObject, struct bpf_stat *s);
	BOOLEAN PacketGetStatsEx(LPADAPTER AdapterObject, struct bpf_stat *s);
	BOOLEAN PacketSetBuff(LPADAPTER AdapterObject, int dim);
	BOOLEAN PacketGetNetType(LPADAPTER AdapterObject, NetType *type);
	LPADAPTER PacketOpenAdapter(PCHAR AdapterName);
	BOOLEAN PacketSendPacket(LPADAPTER AdapterObject, LPPACKET pPacket, BOOLEAN Sync);
	INT PacketSendPackets(LPADAPTER AdapterObject, PVOID PacketBuff, ULONG Size, BOOLEAN Sync);
	LPPACKET PacketAllocatePacket(void);
	VOID PacketInitPacket(LPPACKET lpPacket, PVOID  Buffer, UINT  Length);
	VOID PacketFreePacket(LPPACKET lpPacket);
	BOOLEAN PacketReceivePacket(LPADAPTER AdapterObject, LPPACKET lpPacket, BOOLEAN Sync);
	BOOLEAN PacketSetHwFilter(LPADAPTER AdapterObject, ULONG Filter);
	BOOLEAN PacketGetAdapterNames(PTSTR pStr, PULONG  BufferSize);
	BOOLEAN PacketGetNetInfoEx(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries);
	BOOLEAN PacketRequest(LPADAPTER  AdapterObject, BOOLEAN Set, PPACKET_OID_DATA  OidData);
	HANDLE PacketGetReadEvent(LPADAPTER AdapterObject);
	BOOLEAN PacketSetDumpName(LPADAPTER AdapterObject, void *name, int len);
	BOOLEAN PacketSetDumpLimits(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks);
	BOOLEAN PacketIsDumpEnded(LPADAPTER AdapterObject, BOOLEAN sync);
	BOOL PacketStopDriver();
	VOID PacketCloseAdapter(LPADAPTER lpAdapter);

#ifdef __cplusplus
}
#endif 

#endif //__PACKET32


// Header for Internal function (for BridgeWin32.c)
typedef struct WP
{
	bool Inited;
	HINSTANCE hPacketDll;
	PCHAR(*PacketGetVersion)();
	PCHAR(*PacketGetDriverVersion)();
	BOOLEAN(*PacketSetMinToCopy)(LPADAPTER AdapterObject, int nbytes);
	BOOLEAN(*PacketSetNumWrites)(LPADAPTER AdapterObject, int nwrites);
	BOOLEAN(*PacketSetMode)(LPADAPTER AdapterObject, int mode);
	BOOLEAN(*PacketSetReadTimeout)(LPADAPTER AdapterObject, int timeout);
	BOOLEAN(*PacketSetBpf)(LPADAPTER AdapterObject, struct bpf_program *fp);
	INT(*PacketSetSnapLen)(LPADAPTER AdapterObject, int snaplen);
	BOOLEAN(*PacketGetStats)(LPADAPTER AdapterObject, struct bpf_stat *s);
	BOOLEAN(*PacketGetStatsEx)(LPADAPTER AdapterObject, struct bpf_stat *s);
	BOOLEAN(*PacketSetBuff)(LPADAPTER AdapterObject, int dim);
	BOOLEAN(*PacketGetNetType)(LPADAPTER AdapterObject, NetType *type);
	LPADAPTER(*PacketOpenAdapter)(PCHAR AdapterName);
	BOOLEAN(*PacketSendPacket)(LPADAPTER AdapterObject, LPPACKET pPacket, BOOLEAN Sync);
	INT(*PacketSendPackets)(LPADAPTER AdapterObject, PVOID PacketBuff, ULONG Size, BOOLEAN Sync);
	LPPACKET(*PacketAllocatePacket)(void);
	VOID(*PacketInitPacket)(LPPACKET lpPacket, PVOID  Buffer, UINT  Length);
	VOID(*PacketFreePacket)(LPPACKET lpPacket);
	BOOLEAN(*PacketReceivePacket)(LPADAPTER AdapterObject, LPPACKET lpPacket, BOOLEAN Sync);
	BOOLEAN(*PacketSetHwFilter)(LPADAPTER AdapterObject, ULONG Filter);
	BOOLEAN(*PacketGetAdapterNames)(PTSTR pStr, PULONG  BufferSize);
	BOOLEAN(*PacketGetNetInfoEx)(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries);
	BOOLEAN(*PacketRequest)(LPADAPTER  AdapterObject, BOOLEAN Set, PPACKET_OID_DATA  OidData);
	HANDLE(*PacketGetReadEvent)(LPADAPTER AdapterObject);
	BOOLEAN(*PacketSetDumpName)(LPADAPTER AdapterObject, void *name, int len);
	BOOLEAN(*PacketSetDumpLimits)(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks);
	BOOLEAN(*PacketIsDumpEnded)(LPADAPTER AdapterObject, BOOLEAN sync);
	BOOL(*PacketStopDriver)();
	VOID(*PacketCloseAdapter)(LPADAPTER lpAdapter);
	BOOLEAN(*PacketSetLoopbackBehavior)(LPADAPTER AdapterObject, UINT LoopbackBehavior);
} WP;

// Adapter list
typedef struct WP_ADAPTER
{
	char Name[MAX_SIZE];
	char Title[MAX_SIZE];
	char Guid[MAX_SIZE];
	UINT Id;
} WP_ADAPTER;

// Internal function prototype
void InitEthAdaptersList();
void FreeEthAdaptersList();
int CompareWpAdapter(void *p1, void *p2);
LIST *GetEthAdapterList();
LIST *GetEthAdapterListInternal();
bool InitWpWithLoadLibrary(WP *wp, HINSTANCE h);
bool IsPcdSupported();
HINSTANCE InstallPcdDriver();
HINSTANCE InstallPcdDriverInternal();
UINT LoadPcdDriverBuild();
void SavePcdDriverBuild(UINT build);

#endif	// SECLIB_INTERNAL

typedef struct _ADAPTER ADAPTER;
typedef struct _PACKET PACKET;

// ETH structure
struct ETH
{
	char *Name;					// Adapter name
	char *Title;				// Adapter title
	ADAPTER *Adapter;			// Adapter
	CANCEL *Cancel;				// Cancel object
	UCHAR *Buffer;				// Buffer
	UINT BufferSize;			// Buffer size
	PACKET *Packet;				// Packet
	PACKET *PutPacket;			// Write packet
	QUEUE *PacketQueue;			// Packet queue
	UINT64 LastSetSingleCpu;	// Date and time set to a single CPU to last
	bool LoopbackBlock;			// Whether to block the loop back packet
	bool Empty;					// It is empty
	UCHAR MacAddress[6];		// MAC address
	bool HasFatalError;			// A fatal error occurred on the transmission side

	SU *Su;						// SeLow handle
	SU_ADAPTER *SuAdapter;		// SeLow adapter handle

								// Unused
	bool IsRawIpMode;			// RAW IP mode
	UCHAR RawIpMyMacAddr[6];
	UCHAR RawIpYourMacAddr[6];
	IP MyPhysicalIPForce;
};

// Function prototype
void InitEth();
void FreeEth();
bool IsEthSupported();
bool IsEthSupportedInner();
TOKEN_LIST *GetEthList();
TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden, bool enum_normal, bool enum_rawip);
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthInternal(char *name, bool local, bool tapmode, char *tapaddr);
void CloseEth(ETH *e);
CANCEL *EthGetCancel(ETH *e);
UINT EthGetPacket(ETH *e, void **data);
void EthPutPacket(ETH *e, void *data, UINT size);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
void GetEthNetworkConnectionName(wchar_t *dst, UINT size, char *device_name);
bool IsWin32BridgeWithSee();
UINT EthGetMtu(ETH *e);
bool EthSetMtu(ETH *e, UINT mtu);
bool EthIsChangeMtuSupported(ETH *e);

bool Win32EthIsSuSupported();

void Win32EthSetShowAllIf(bool b);
bool Win32EthGetShowAllIf();

bool EnumEthVLanWin32(RPC_ENUM_ETH_VLAN *t);
bool GetClassRegKeyWin32(char *key, UINT key_size, char *short_key, UINT short_key_size, char *guid);
int CmpRpcEnumEthVLan(void *p1, void *p2);
void GetVLanSupportStatus(RPC_ENUM_ETH_VLAN_ITEM *e);
void GetVLanEnableStatus(RPC_ENUM_ETH_VLAN_ITEM *e);
bool SetVLanEnableStatus(char *title, bool enable);
RPC_ENUM_ETH_VLAN_ITEM *FindEthVLanItem(RPC_ENUM_ETH_VLAN *t, char *name);
char *SearchDeviceInstanceIdFromShortKey(char *short_key);
void Win32EthMakeCombinedName(char *dst, UINT dst_size, char *nicname, char *guid);
UINT Win32EthGenIdFromGuid(char *guid);
UINT Win32EthGetNameAndIdFromCombinedName(char *name, UINT name_size, char *str);

struct WP_ADAPTER *Win32EthSearch(char *name);
bool Win32IsUsingSeLow();
void Win32SetEnableSeLow(bool b);
bool Win32GetEnableSeLow();

// End Win32

#else

// Begin UNIX


// Macro
#ifndef SOL_PACKET
#define	SOL_PACKET	263
#endif
#ifndef ifr_newname
#define ifr_newname     ifr_ifru.ifru_slave
#endif

// Constants
#define	UNIX_ETH_TMP_BUFFER_SIZE		(2000)
#define	SOLARIS_MAXDLBUF				(32768)
#define BRIDGE_MAX_QUEUE_SIZE			(4096*1500)

// ETH structure
struct ETH
{
	char *Name;					// Adapter name
	char *Title;				// Adapter title
	CANCEL *Cancel;				// Cancel object
	int IfIndex;				// Index
	int Socket;					// Socket
	UINT InitialMtu;			// Initial MTU value
	UINT CurrentMtu;			// Current MTU value
	int SocketBsdIf;			// BSD interface operation socket
	UCHAR MacAddress[6];		// MAC address

#ifdef BRIDGE_PCAP
	void *Pcap;					// Pcap descriptor
	QUEUE *Queue;				// Queue of the relay thread
	UINT QueueSize;				// Number of bytes in Queue
	THREAD *CaptureThread;			// Pcap relay thread
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
	UINT BufSize;				// Buffer size to read the BPF (error for other)
#ifdef BRIDGE_BPF_THREAD
	QUEUE *Queue;				// Queue of the relay thread
	UINT QueueSize;				// Number of bytes in Queue
	THREAD *CaptureThread;			// BPF relay thread
#else // BRIDGE_BPF_THREAD
	UCHAR *Buffer;				// Buffer to read the BPF
	UCHAR *Next;
	int Rest;
#endif // BRIDGE_BPF_THREAD
#endif // BRIDGE_BPF

	VLAN *Tap;					// tap
	bool Linux_IsAuxDataSupported;	// Is PACKET_AUXDATA supported

	bool IsRawIpMode;			// RAW IP mode
	SOCK *RawTcp, *RawUdp, *RawIcmp;	// RAW sockets
	bool RawIp_HasError;
	UCHAR RawIpMyMacAddr[6];
	UCHAR RawIpYourMacAddr[6];
	IP MyIP;
	IP YourIP;
	QUEUE *RawIpSendQueue;
	IP MyPhysicalIP;
	IP MyPhysicalIPForce;
	UCHAR *RawIP_TmpBuffer;
	UINT RawIP_TmpBufferSize;
};

#if defined( BRIDGE_BPF ) || defined( BRIDGE_PCAP )
struct CAPTUREBLOCK {
	UINT Size;
	UCHAR *Buf;
};
#endif // BRIDGE_BPF


// Function prototype
void InitEth();
void FreeEth();
bool IsEthSupported();
bool IsEthSupportedLinux();
bool IsEthSupportedSolaris();
bool IsEthSupportedPcap();
TOKEN_LIST *GetEthList();
TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden, bool enum_normal, bool enum_rawip);
TOKEN_LIST *GetEthListLinux(bool enum_normal, bool enum_rawip);
TOKEN_LIST *GetEthListSolaris();
TOKEN_LIST *GetEthListPcap();
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthLinux(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthSolaris(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthPcap(char *name, bool local, bool tapmode, char *tapaddr);
bool ParseUnixEthDeviceName(char *dst_devname, UINT dst_devname_size, UINT *dst_devid, char *src_name);
void CloseEth(ETH *e);
CANCEL *EthGetCancel(ETH *e);
UINT EthGetPacket(ETH *e, void **data);
UINT EthGetPacketLinux(ETH *e, void **data);
UINT EthGetPacketSolaris(ETH *e, void **data);
UINT EthGetPacketPcap(ETH *e, void **data);
UINT EthGetPacketBpf(ETH *e, void **data);
void EthPutPacket(ETH *e, void *data, UINT size);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
UINT EthGetMtu(ETH *e);
bool EthSetMtu(ETH *e, UINT mtu);
bool EthIsChangeMtuSupported(ETH *e);
bool EthGetInterfaceDescriptionUnix(char *name, char *str, UINT size);
bool EthIsInterfaceDescriptionSupportedUnix();

ETH *OpenEthLinuxIpRaw();
void CloseEthLinuxIpRaw(ETH *e);
UINT EthGetPacketLinuxIpRaw(ETH *e, void **data);
UINT EthGetPacketLinuxIpRawForSock(ETH *e, void **data, SOCK *s, UINT proto);
void EthPutPacketLinuxIpRaw(ETH *e, void *data, UINT size);
bool EthProcessIpPacketInnerIpRaw(ETH *e, PKT *p);
void EthSendIpPacketInnerIpRaw(ETH *e, void *data, UINT size, USHORT protocol);

#ifdef	UNIX_SOLARIS
// Function prototype for Solaris
bool DlipAttatchRequest(int fd, UINT devid);
bool DlipReceiveAck(int fd);
bool DlipPromiscuous(int fd, UINT level);
bool DlipBindRequest(int fd);
#endif	// OS_SOLARIS

int UnixEthOpenRawSocket();

// End UNIX


#endif


// Constants
#define	BRIDGE_SPECIAL_IPRAW_NAME		"ipv4_rawsocket_virtual_router"

// Bridge
struct BRIDGE
{
	bool Active;			// Status
	CEDAR *Cedar;			// Cedar
	HUB *Hub;				// HUB
	SESSION *Session;		// Session
	POLICY *Policy;			// Policy
	ETH *Eth;				// Ethernet
	char Name[MAX_SIZE];	// Device name
	UINT64 LastBridgeTry;	// Time to try to bridge at last
	bool Local;				// Local mode
	bool Monitor;			// Monitor mode
	bool TapMode;			// Tap mode
	bool LimitBroadcast;	// Broadcasts limiting mode
	UCHAR TapMacAddress[6];	// MAC address of the tap
	UINT LastNumDevice;		// Number of device (Number of last checked)
	UINT64 LastNumDeviceCheck;	// Time at which to check the number of devices at last
	UINT64 LastChangeMtuError;	// Time that recorded the error to change the MTU at last
	LOCALBRIDGE *ParentLocalBridge;	// Parent Local Bridge
};

// Local bridge
struct LOCALBRIDGE
{
	char HubName[MAX_HUBNAME_LEN + 1];			// Virtual HUB name
	char DeviceName[MAX_SIZE];					// Device name
	bool Local;									// Local mode
	bool Monitor;								// Monitor mode
	bool TapMode;								// Tap mode
	bool LimitBroadcast;						// Broadcast packets limiting mode
	UCHAR TapMacAddress[6];						// MAC address of the tap
	BRIDGE *Bridge;								// Bridge
};

BRIDGE *BrNewBridge(HUB *h, char *name, POLICY *p, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast, LOCALBRIDGE *parent_local_bridge);
void BrBridgeThread(THREAD *thread, void *param);
void BrFreeBridge(BRIDGE *b);
void InitLocalBridgeList(CEDAR *c);
void FreeLocalBridgeList(CEDAR *c);
void AddLocalBridge(CEDAR *c, char *hubname, char *devicename, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast);
bool DeleteLocalBridge(CEDAR *c, char *hubname, char *devicename);
bool IsBridgeSupported();
bool IsNeedWinPcap();
UINT GetEthDeviceHash();
bool IsRawIpBridgeSupported();




//////////////////////////////////////////////////////////////////////////
// Layer3.h


// Constants
#define	L3_USERNAME					"L3SW_"


// L3 ARP table entry
struct L3ARPENTRY
{
	UINT IpAddress;					// IP address
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	UINT64 Expire;					// Expiration date
};

// L3 ARP resolution waiting list entry
struct L3ARPWAIT
{
	UINT IpAddress;					// IP address
	UINT64 LastSentTime;			// Time which the data has been sent last
	UINT64 Expire;					// Expiration date
};

// L3 IP packet table
struct L3PACKET
{
	PKT *Packet;					// Packet data body
	UINT64 Expire;					// Expiration date
	UINT NextHopIp;					// Local delivery destination IP address
};

// L3 routing table definition
struct L3TABLE
{
	UINT NetworkAddress;			// Network address
	UINT SubnetMask;				// Subnet mask
	UINT GatewayAddress;			// Gateway address
	UINT Metric;					// Metric
};

// L3 interface definition
struct L3IF
{
	L3SW *Switch;					// Layer-3 switch
	char HubName[MAX_HUBNAME_LEN + 1];	// Virtual HUB name
	UINT IpAddress;					// IP address
	UINT SubnetMask;				// Subnet mask

	HUB *Hub;						// Virtual HUB
	SESSION *Session;				// Session
	LIST *ArpTable;					// ARP table
	LIST *ArpWaitTable;				// ARP waiting table
	QUEUE *IpPacketQueue;			// IP packet queue (for reception from other interfaces)
	LIST *IpWaitList;				// IP waiting list
	QUEUE *SendQueue;				// Transmission queue
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	UINT64 LastDeleteOldArpTable;	// Time that old ARP table entries are cleared
	LIST *CancelList;				// Cancellation list
	UINT64 LastBeaconSent;			// Time which the beacon has been sent last
};

// L3 switch definition
struct L3SW
{
	char Name[MAX_HUBNAME_LEN + 1];	// Name
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	CEDAR *Cedar;					// Cedar
	bool Active;					// During operation flag
	bool Online;					// Online flag
	volatile bool Halt;				// Halting flag
	LIST *IfList;					// Interface list
	LIST *TableList;				// Routing table list
	THREAD *Thread;					// Thread
};



// Function prototype
int CmpL3Sw(void *p1, void *p2);
int CmpL3ArpEntry(void *p1, void *p2);
int CmpL3ArpWaitTable(void *p1, void *p2);
int CmpL3Table(void *p1, void *p2);
int CmpL3If(void *p1, void *p2);
void InitCedarLayer3(CEDAR *c);
void FreeCedarLayer3(CEDAR *c);
L3SW *NewL3Sw(CEDAR *c, char *name);
void ReleaseL3Sw(L3SW *s);
void CleanupL3Sw(L3SW *s);
bool L3AddIf(L3SW *s, char *hubname, UINT ip, UINT subnet);
bool L3DelIf(L3SW *s, char *hubname);
bool L3AddTable(L3SW *s, L3TABLE *tbl);
bool L3DelTable(L3SW *s, L3TABLE *tbl);
L3IF *L3SearchIf(L3SW *s, char *hubname);
L3SW *L3GetSw(CEDAR *c, char *name);
L3SW *L3AddSw(CEDAR *c, char *name);
bool L3DelSw(CEDAR *c, char *name);
void L3FreeAllSw(CEDAR *c);
void L3SwStart(L3SW *s);
void L3SwStop(L3SW *s);
void L3SwThread(THREAD *t, void *param);
void L3Test(SERVER *s);
void L3InitAllInterfaces(L3SW *s);
void L3FreeAllInterfaces(L3SW *s);
void L3IfThread(THREAD *t, void *param);
void L3InitInterface(L3IF *f);
void L3FreeInterface(L3IF *f);
L3IF *L3GetNextIf(L3SW *s, UINT ip, UINT *next_hop);
L3TABLE *L3GetBestRoute(L3SW *s, UINT ip);
UINT L3GetNextPacket(L3IF *f, void **data);
void L3Polling(L3IF *f);
void L3PollingBeacon(L3IF *f);
void L3DeleteOldArpTable(L3IF *f);
void L3DeleteOldIpWaitList(L3IF *f);
void L3PollingArpWaitTable(L3IF *f);
void L3SendL2Now(L3IF *f, UCHAR *dest_mac, UCHAR *src_mac, USHORT protocol, void *data, UINT size);
void L3SendArpRequestNow(L3IF *f, UINT dest_ip);
void L3SendArpResponseNow(L3IF *f, UCHAR *dest_mac, UINT dest_ip, UINT src_ip);
void L3GenerateMacAddress(L3IF *f);
L3ARPENTRY *L3SearchArpTable(L3IF *f, UINT ip);
void L3SendIpNow(L3IF *f, L3ARPENTRY *a, L3PACKET *p);
void L3SendIp(L3IF *f, L3PACKET *p);
void L3RecvArp(L3IF *f, PKT *p);
void L3RecvArpRequest(L3IF *f, PKT *p);
void L3RecvArpResponse(L3IF *f, PKT *p);
void L3KnownArp(L3IF *f, UINT ip, UCHAR *mac);
void L3SendArp(L3IF *f, UINT ip);
void L3InsertArpTable(L3IF *f, UINT ip, UCHAR *mac);
void L3SendWaitingIp(L3IF *f, UCHAR *mac, UINT ip, L3ARPENTRY *a);
void L3PutPacket(L3IF *f, void *data, UINT size);
void L3RecvL2(L3IF *f, PKT *p);
void L3StoreIpPacketToIf(L3IF *src_if, L3IF *dst_if, L3PACKET *p);
void L3RecvIp(L3IF *f, PKT *p, bool self);
void L3PollingIpQueue(L3IF *f);


//////////////////////////////////////////////////////////////////////////
// NullLan.h


#define	NULL_PACKET_GENERATE_INTERVAL		100000000		// Packet generation interval

// NULL device structure
struct NULL_LAN
{
	THREAD *PacketGeneratorThread;
	CANCEL *Cancel;
	QUEUE *PacketQueue;
	volatile bool Halt;
	EVENT *Event;
	UCHAR MacAddr[6];
	UCHAR Padding[2];
	UINT Id;
};

PACKET_ADAPTER *NullGetPacketAdapter();
bool NullPaInit(SESSION *s);
CANCEL *NullPaGetCancel(SESSION *s);
UINT NullPaGetNextPacket(SESSION *s, void **data);
bool NullPaPutPacket(SESSION *s, void *data, UINT size);
void NullPaFree(SESSION *s);
void NullPacketGenerateThread(THREAD *t, void *param);
void NullGenerateMacAddress(UCHAR *mac, UINT id, UINT seq);



//////////////////////////////////////////////////////////////////////////
// Client.h



#define	CLIENT_CONFIG_PORT					GC_CLIENT_CONFIG_PORT		// Client port number
#define	CLIENT_NOTIFY_PORT					GC_CLIENT_NOTIFY_PORT		// Client notification port number
#define CLIENT_WAIT_CN_READY_TIMEOUT		(10 * 1000)	// Standby time to start the client notification service


// Check whether the client can run on the specified OS_TYPE
#define	IS_CLIENT_SUPPORTED_OS(t)			\
	((OS_IS_WINDOWS_NT(t) && GET_KETA(t, 100) >= 2) || (OS_IS_WINDOWS_9X(t)))


// Constants
#define	CLIENT_CONFIG_FILE_NAME				"@vpn_client.config"
#define	CLIENT_DEFAULT_KEEPALIVE_HOST		"keepalive.softether.org"
#define	CLIENT_DEFAULT_KEEPALIVE_PORT		80
#define	CLIENT_DEFAULT_KEEPALIVE_INTERVAL	KEEP_INTERVAL_DEFAULT

#define	CLIENT_RPC_MODE_NOTIFY				0
#define	CLIENT_RPC_MODE_MANAGEMENT			1
#define	CLIENT_RPC_MODE_SHORTCUT			2
#define	CLIENT_RPC_MODE_SHORTCUT_DISCONNECT	3

#define	CLIENT_MACOS_TAP_NAME				"tap0"

#define	CLIENT_SAVER_INTERVAL				(30 * 1000)

#define	CLIENT_NOTIFY_SERVICE_INSTANCENAME	GC_SW_SOFTETHER_PREFIX "vpnclient_uihelper"

#define	CLIENT_WIN32_EXE_FILENAME			"vpnclient.exe"
#define	CLIENT_WIN32_EXE_FILENAME_X64		"vpnclient_x64.exe"
#define	CLIENT_WIN32_EXE_FILENAME_IA64		"vpnclient_ia64.exe"

#define CLIENT_CUSTOM_INI_FILENAME			"@custom.ini"

#define	CLIENT_GLOBAL_PULSE_NAME			"clientglobalpulse"

#define	CLIENT_WIN32_REGKEYNAME				"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Client"
#define	CLIENT_WIN32_REGVALUE_PORT			"RpcPort"
#define	CLIENT_WIN32_REGVALUE_PID			"RpcPid"


// List of virtual LAN cards in UNIX
struct UNIX_VLAN
{
	bool Enabled;							// Enable flag
	char Name[MAX_SIZE];					// Name
	UCHAR MacAddress[6];					// MAC address
	UCHAR Padding[2];
};

// Account
struct ACCOUNT
{
	// Static data
	CLIENT_OPTION *ClientOption;			// Client Option
	CLIENT_AUTH *ClientAuth;				// Client authentication data
	bool CheckServerCert;					// Check the server certificate
	X *ServerCert;							// Server certificate
	bool StartupAccount;					// Start-up account
	UCHAR ShortcutKey[SHA1_SIZE];			// Key
	UINT64 CreateDateTime;					// Creation date and time
	UINT64 UpdateDateTime;					// Updating date
	UINT64 LastConnectDateTime;				// Last connection date and time

											// Dynamic data
	LOCK *lock;								// Lock
	SESSION *ClientSession;					// Client session
	CLIENT_STATUS_PRINTER *StatusPrinter;	// Status indicator

	SOCK *StatusWindow;						// Status window
};

// Client Settings
struct CLIENT_CONFIG
{
	bool AllowRemoteConfig;					// Allow the remote configuration
	bool UseKeepConnect;					// Keep connected to the Internet
	char KeepConnectHost[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT KeepConnectPort;					// Port number
	UINT KeepConnectProtocol;				// Protocol
	UINT KeepConnectInterval;				// Interval
	bool NoChangeWcmNetworkSettingOnWindows8;	// Don't change the WCM network settings on Windows 8
};

// Version acquisition
struct RPC_CLIENT_VERSION
{
	char ClientProductName[128];		// Client product name
	char ClientVersionString[128];		// Client version string
	char ClientBuildInfoString[128];	// Build client information string
	UINT ClientVerInt;					// Client version integer value
	UINT ClientBuildInt;				// Client build number integer value
	UINT ProcessId;						// Process ID
	UINT OsType;						// OS type
	bool IsVLanNameRegulated;			// Whether a virtual LAN card name must be "VLAN" + number
	bool IsVgcSupported;				// Whether the VPN Gate Client is supported
	bool ShowVgcLink;					// Display a VPN Gate Client link
	char ClientId[128];					// Client OD
};

// Password Setting
struct RPC_CLIENT_PASSWORD
{
	char Password[MAX_PASSWORD_LEN + 1];	// Password
	bool PasswordRemoteOnly;				// The password is required only remote access
};

// Get the password setting
struct RPC_CLIENT_PASSWORD_SETTING
{
	bool IsPasswordPresented;				// Password exists
	bool PasswordRemoteOnly;				// The password is required only remote access
};

// Certificate enumeration item
struct RPC_CLIENT_ENUM_CA_ITEM
{
	UINT Key;								// Certificate key
	wchar_t SubjectName[MAX_SIZE];			// Issued to
	wchar_t IssuerName[MAX_SIZE];			// Issuer
	UINT64 Expires;							// Expiration date
};

// Certificate enumeration
struct RPC_CLIENT_ENUM_CA
{
	UINT NumItem;							// Number of items
	RPC_CLIENT_ENUM_CA_ITEM **Items;		// Item
};

// Certificate item
struct RPC_CERT
{
	X *x;									// Certificate
};

// Delete the certificate
struct RPC_CLIENT_DELETE_CA
{
	UINT Key;								// Certificate key
};

// Get the certificate
struct RPC_GET_CA
{
	UINT Key;								// Certificate key
	X *x;									// Certificate
};

// Get the issuer
struct RPC_GET_ISSUER
{
	X *x;									// Certificate
	X *issuer_x;							// Issuer
};

// Secure device enumeration item
struct RPC_CLIENT_ENUM_SECURE_ITEM
{
	UINT DeviceId;							// Device ID
	UINT Type;								// Type
	char DeviceName[MAX_SIZE];				// Device name
	char Manufacturer[MAX_SIZE];			// Manufacturer
};

// Enumeration of secure devices
struct RPC_CLIENT_ENUM_SECURE
{
	UINT NumItem;							// Number of items
	RPC_CLIENT_ENUM_SECURE_ITEM **Items;	// Item
};

// Specify a secure device
struct RPC_USE_SECURE
{
	UINT DeviceId;							// Device ID
};

// Enumerate objects in the secure device
struct RPC_ENUM_OBJECT_IN_SECURE
{
	UINT hWnd;								// Window handle
	UINT NumItem;							// Number of items
	char **ItemName;						// Item name
	bool *ItemType;							// Type (true = secret key, false = public key)
};

// Create a virtual LAN
struct RPC_CLIENT_CREATE_VLAN
{
	char DeviceName[MAX_SIZE];				// Device name
};

// Get a Virtual LAN information
struct RPC_CLIENT_GET_VLAN
{
	char DeviceName[MAX_SIZE];				// Device name
	bool Enabled;							// Flag of whether it works or not
	char MacAddress[MAX_SIZE];				// MAC address
	char Version[MAX_SIZE];					// Version
	char FileName[MAX_SIZE];				// Driver file name
	char Guid[MAX_SIZE];					// GUID
};

// Set the virtual LAN information
struct RPC_CLIENT_SET_VLAN
{
	char DeviceName[MAX_SIZE];				// Device name
	char MacAddress[MAX_SIZE];				// MAC address
};

// Virtual LAN enumeration item
struct RPC_CLIENT_ENUM_VLAN_ITEM
{
	char DeviceName[MAX_SIZE];				// Device name
	bool Enabled;							// Operation flag
	char MacAddress[MAX_SIZE];				// MAC address
	char Version[MAX_SIZE];					// Version
};

// Enumerate the virtual LANs
struct RPC_CLIENT_ENUM_VLAN
{
	UINT NumItem;							// Item count
	RPC_CLIENT_ENUM_VLAN_ITEM **Items;		// Item
};

// Create an account
struct RPC_CLIENT_CREATE_ACCOUNT
{
	CLIENT_OPTION *ClientOption;			// Client Option
	CLIENT_AUTH *ClientAuth;				// Client authentication data
	bool StartupAccount;					// Startup account
	bool CheckServerCert;					// Checking of the server certificate
	X *ServerCert;							// Server certificate
	UCHAR ShortcutKey[SHA1_SIZE];			// Shortcut Key
};

// Enumeration item of account
struct RPC_CLIENT_ENUM_ACCOUNT_ITEM
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	char UserName[MAX_USERNAME_LEN + 1];	//  User name
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	char DeviceName[MAX_DEVICE_NAME_LEN + 1];	// Device name
	UINT ProxyType;							// Type of proxy connection
	char ProxyName[MAX_HOST_NAME_LEN + 1];	// Host name
	bool Active;							// Operation flag
	bool Connected;							// Connection completion flag
	bool StartupAccount;					// Startup account
	UINT Port;								// Port number (Ver 3.0 or later)
	char HubName[MAX_HUBNAME_LEN + 1];		// Virtual HUB name (Ver 3.0 or later)
	UINT64 CreateDateTime;					// Creation date and time (Ver 3.0 or later)
	UINT64 UpdateDateTime;					// Modified date (Ver 3.0 or later)
	UINT64 LastConnectDateTime;				// Last connection date and time (Ver 3.0 or later)
	UINT tmp1;								// Temporary data
};

// Enumeration of accounts
struct RPC_CLIENT_ENUM_ACCOUNT
{
	UINT NumItem;							// Item count
	RPC_CLIENT_ENUM_ACCOUNT_ITEM **Items;	// Items
};

// Delete the Account
struct RPC_CLIENT_DELETE_ACCOUNT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
};

// Change the account name
struct RPC_RENAME_ACCOUNT
{
	wchar_t OldName[MAX_ACCOUNT_NAME_LEN + 1];		// Old name
	wchar_t NewName[MAX_ACCOUNT_NAME_LEN + 1];		// New Name
};

// Get the account
struct RPC_CLIENT_GET_ACCOUNT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	CLIENT_OPTION *ClientOption;			// Client Option
	CLIENT_AUTH *ClientAuth;				// Client authentication data
	bool StartupAccount;					// Startup account
	bool CheckServerCert;					// Check the server certificate
	X *ServerCert;							// Server certificate
	UCHAR ShortcutKey[SHA1_SIZE];			// Shortcut Key
	UINT64 CreateDateTime;					// Creation date and time (Ver 3.0 or later)
	UINT64 UpdateDateTime;					// Modified date (Ver 3.0 or later)
	UINT64 LastConnectDateTime;				// Last connection date and time (Ver 3.0 or later)
};

// Connection
struct RPC_CLIENT_CONNECT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
};

// Get the Connection status
struct RPC_CLIENT_GET_CONNECTION_STATUS
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	bool Active;							// Operation flag
	bool Connected;							// Connected flag
	UINT SessionStatus;						// Session status
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT ServerPort;						// Port number of the server
	char ServerProductName[MAX_SIZE];		// Server product name
	UINT ServerProductVer;					// Server product version
	UINT ServerProductBuild;				// Server product build number
	X *ServerX;								// Server certificate
	X *ClientX;								// Client certificate
	UINT64 StartTime;						// Connection start time
	UINT64 FirstConnectionEstablisiedTime;	// Connection completion time of the first connection
	UINT64 CurrentConnectionEstablishTime;	// Connection completion time of this connection
	UINT NumConnectionsEatablished;			// Number of connections have been established so far
	bool HalfConnection;					// Half-connection
	bool QoS;								// VoIP / QoS
	UINT MaxTcpConnections;					// Maximum number of the TCP connections
	UINT NumTcpConnections;					// Number of current TCP connections
	UINT NumTcpConnectionsUpload;			// Number of inbound connections
	UINT NumTcpConnectionsDownload;			// Number of outbound connections
	bool UseEncrypt;						// Use of encryption
	char CipherName[32];					// Cipher algorithm name
	char ProtocolName[64];					// Protocol name
	bool UseCompress;						// Use of compression
	bool IsRUDPSession;						// R-UDP session
	char UnderlayProtocol[64];				// Physical communication protocol
	bool IsUdpAccelerationEnabled;			// The UDP acceleration is enabled
	bool IsUsingUdpAcceleration;			// Using the UDP acceleration function
	char SessionName[MAX_SESSION_NAME_LEN + 1];	// Session name
	char ConnectionName[MAX_CONNECTION_NAME_LEN + 1];	// Connection name
	UCHAR SessionKey[SHA1_SIZE];			// Session key
	POLICY Policy;							// Policy
	UINT64 TotalSendSize;					// Total transmitted data size
	UINT64 TotalRecvSize;					// Total received data size
	UINT64 TotalSendSizeReal;				// Total transmitted data size (no compression)
	UINT64 TotalRecvSizeReal;				// Total received data size (no compression)
	TRAFFIC Traffic;						// Traffic data
	bool IsBridgeMode;						// Bridge Mode
	bool IsMonitorMode;						// Monitor mode
	UINT VLanId;							// VLAN ID
};


// RPC connection
struct CLIENT_RPC_CONNECTION
{
	struct CLIENT *Client;					// Client
	bool RpcMode;							// True: RPC mode, false: notification mode
	THREAD *Thread;							// Processing thread
	SOCK *Sock;								// Socket
};

// Client object
struct CLIENT
{
	LOCK *lock;								// Lock
	LOCK *lockForConnect;					// Lock to be used in the CtConnect
	REF *ref;								// Reference counter
	CEDAR *Cedar;							// Cedar
	volatile bool Halt;						// Halting flag
	UINT Err;								// Error code
	CFG_RW *CfgRw;							// Configuration file R/W
	LIST *AccountList;						// Account list
	UCHAR EncryptedPassword[SHA1_SIZE];		// Password
	bool PasswordRemoteOnly;				// Password is required only remote access
	UINT UseSecureDeviceId;					// Secure device ID to be used
	CLIENT_CONFIG Config;					// Client Settings
	LIST *RpcConnectionList;				// RPC connection list
	SOCK *RpcListener;						// RPC listener
	THREAD *RpcThread;						// RPC thread
	LOCK *HelperLock;						// Auxiliary lock
	THREAD *SaverThread;					// Saver thread
	EVENT *SaverHalter;						// The event to stop the Saver thread
	LIST *NotifyCancelList;					// Notification event list
	KEEP *Keep;								// Keep Connection
	LIST *UnixVLanList;						// List of virtual LAN cards in UNIX
	LOG *Logger;							// Logger
	bool DontSavePassword;					// Flag for not to save the password
	ERASER *Eraser;							// Eraser
	SOCKLIST *SockList;						// Socket list
	CM_SETTING *CmSetting;					// CM configuration
	void *GlobalPulse;						// Global pulse
	THREAD *PulseRecvThread;				// Pulse reception thread
	volatile bool HaltPulseThread;			// Stop flag for the pulse reception thread
	bool NoSaveLog;							// Do not save the log
	bool NoSaveConfig;						// Do not save the settings
	INTERNET_SETTING CommonProxySetting;	// Common proxy settings
	void *MsSuspendHandler;					// MS suspend handler

};

// Notification to the remote client
struct RPC_CLIENT_NOTIFY
{
	UINT NotifyCode;						// Code
};

// Type of notification
#define	CLIENT_NOTIFY_ACCOUNT_CHANGED	1	// Account change notification
#define	CLIENT_NOTIFY_VLAN_CHANGED		2	// Virtual LAN card change notification

// Remote client
struct REMOTE_CLIENT
{
	RPC *Rpc;
	UINT OsType;
	bool Unix;
	bool Win9x;
	UINT ProcessId;
	UINT ClientBuildInt;
	bool IsVgcSupported;
	bool ShowVgcLink;
	char ClientId[128];
};

// Notification client
struct NOTIFY_CLIENT
{
	SOCK *Sock;
};

// CM configuration
struct CM_SETTING
{
	bool EasyMode;							// Simple mode
	bool LockMode;							// Setting lock mode
	UCHAR HashedPassword[SHA1_SIZE];		// Password
};




// Function prototype
REMOTE_CLIENT *CcConnectRpc(char *server_name, char *password, bool *bad_pass, bool *no_remote, UINT wait_retry);
REMOTE_CLIENT *CcConnectRpcEx(char *server_name, char *password, bool *bad_pass, bool *no_remote, UCHAR *key, UINT *key_error_code, bool shortcut_disconnect, UINT wait_retry);
UINT CcShortcut(UCHAR *key);
UINT CcShortcutDisconnect(UCHAR *key);
void CcDisconnectRpc(REMOTE_CLIENT *rc);
NOTIFY_CLIENT *CcConnectNotify(REMOTE_CLIENT *rc);
void CcDisconnectNotify(NOTIFY_CLIENT *n);
void CcStopNotify(NOTIFY_CLIENT *n);
bool CcWaitNotify(NOTIFY_CLIENT *n);
UINT CcGetClientVersion(REMOTE_CLIENT *r, RPC_CLIENT_VERSION *a);
UINT CcSetCmSetting(REMOTE_CLIENT *r, CM_SETTING *a);
UINT CcGetCmSetting(REMOTE_CLIENT *r, CM_SETTING *a);
UINT CcSetPassword(REMOTE_CLIENT *r, RPC_CLIENT_PASSWORD *pass);
UINT CcGetPasswordSetting(REMOTE_CLIENT *r, RPC_CLIENT_PASSWORD_SETTING *a);
UINT CcEnumCa(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_CA *e);
UINT CcAddCa(REMOTE_CLIENT *r, RPC_CERT *cert);
UINT CcDeleteCa(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_CA *p);
UINT CcGetCa(REMOTE_CLIENT *r, RPC_GET_CA *get);
UINT CcEnumSecure(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_SECURE *e);
UINT CcUseSecure(REMOTE_CLIENT *r, RPC_USE_SECURE *sec);
UINT CcGetUseSecure(REMOTE_CLIENT *r, RPC_USE_SECURE *sec);
UINT CcEnumObjectInSecure(REMOTE_CLIENT *r, RPC_ENUM_OBJECT_IN_SECURE *e);
UINT CcCreateVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *create);
UINT CcUpgradeVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *create);
UINT CcGetVLan(REMOTE_CLIENT *r, RPC_CLIENT_GET_VLAN *get);
UINT CcSetVLan(REMOTE_CLIENT *r, RPC_CLIENT_SET_VLAN *set);
UINT CcEnumVLan(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_VLAN *e);
UINT CcDeleteVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *d);
UINT CcEnableVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *vlan);
UINT CcDisableVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *vlan);
UINT CcCreateAccount(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_ACCOUNT *a);
UINT CcEnumAccount(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_ACCOUNT *e);
UINT CcDeleteAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a);
UINT CcSetAccount(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_ACCOUNT *a);
UINT CcGetAccount(REMOTE_CLIENT *r, RPC_CLIENT_GET_ACCOUNT *a);
UINT CcRenameAccount(REMOTE_CLIENT *r, RPC_RENAME_ACCOUNT *rename);
UINT CcSetClientConfig(REMOTE_CLIENT *r, CLIENT_CONFIG *o);
UINT CcGetClientConfig(REMOTE_CLIENT *r, CLIENT_CONFIG *o);
UINT CcConnect(REMOTE_CLIENT *r, RPC_CLIENT_CONNECT *connect);
UINT CcDisconnect(REMOTE_CLIENT *r, RPC_CLIENT_CONNECT *connect);
UINT CcGetAccountStatus(REMOTE_CLIENT *r, RPC_CLIENT_GET_CONNECTION_STATUS *st);
UINT CcSetStartupAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a);
UINT CcRemoveStartupAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a);
UINT CcGetIssuer(REMOTE_CLIENT *r, RPC_GET_ISSUER *a);
UINT CcGetCommonProxySetting(REMOTE_CLIENT *r, INTERNET_SETTING *a);
UINT CcSetCommonProxySetting(REMOTE_CLIENT *r, INTERNET_SETTING *a);


void CcSetServiceToForegroundProcess(REMOTE_CLIENT *r);
char *CiGetFirstVLan(CLIENT *c);
void CiNormalizeAccountVLan(CLIENT *c);

bool CompareInternetSetting(INTERNET_SETTING *s1, INTERNET_SETTING *s2);


void CnStart();
void CnListenerProc(THREAD *thread, void *param);

void CnReleaseSocket(SOCK *s, PACK *p);

void CnStatusPrinter(SOCK *s, PACK *p);
void Win32CnStatusPrinter(SOCK *s, PACK *p);

void CnConnectErrorDlg(SOCK *s, PACK *p);
void Win32CnConnectErrorDlg(SOCK *s, PACK *p);
void Win32CnConnectErrorDlgThreadProc(THREAD *thread, void *param);

void CnPasswordDlg(SOCK *s, PACK *p);
void Win32CnPasswordDlg(SOCK *s, PACK *p);
void Win32CnPasswordDlgThreadProc(THREAD *thread, void *param);

void CnMsgDlg(SOCK *s, PACK *p);
void Win32CnMsgDlg(SOCK *s, PACK *p);
void Win32CnMsgDlgThreadProc(THREAD *thread, void *param);

void CnNicInfo(SOCK *s, PACK *p);
void Win32CnNicInfo(SOCK *s, PACK *p);
void Win32CnNicInfoThreadProc(THREAD *thread, void *param);

void CnCheckCert(SOCK *s, PACK *p);
void Win32CnCheckCert(SOCK *s, PACK *p);
void Win32CnCheckCertThreadProc(THREAD *thread, void *param);

void CnExecDriverInstaller(SOCK *s, PACK *p);
void Win32CnExecDriverInstaller(SOCK *s, PACK *p);

bool CnCheckAlreadyExists(bool lock);
bool CnIsCnServiceReady();
void CnWaitForCnServiceReady();

void CnSecureSign(SOCK *s, PACK *p);

SOCK *CncConnect();
SOCK *CncConnectEx(UINT timeout);
void CncReleaseSocket();
void CncExit();
UINT CncGetSessionId();
bool CncExecDriverInstaller(char *arg);
SOCK *CncStatusPrinterWindowStart(SESSION *s);
void CncStatusPrinterWindowPrint(SOCK *s, wchar_t *str);
void CncStatusPrinterWindowStop(SOCK *s);
void CncStatusPrinterWindowThreadProc(THREAD *thread, void *param);
bool CncConnectErrorDlg(SESSION *session, UI_CONNECTERROR_DLG *dlg);
void CncConnectErrorDlgHaltThread(THREAD *thread, void *param);
bool CncPasswordDlg(SESSION *session, UI_PASSWORD_DLG *dlg);
void CncPasswordDlgHaltThread(THREAD *thread, void *param);
void CncCheckCert(SESSION *session, UI_CHECKCERT *dlg);
void CncCheckCertHaltThread(THREAD *thread, void *param);
bool CncSecureSignDlg(SECURE_SIGN *sign);
SOCK *CncMsgDlg(UI_MSG_DLG *dlg);
void CndMsgDlgFree(SOCK *s);
SOCK *CncNicInfo(UI_NICINFO *info);
void CncNicInfoFree(SOCK *s);

void CtStartClient();
void CtStopClient();
CLIENT *CtGetClient();
void CtReleaseClient(CLIENT *c);
bool CtGetClientVersion(CLIENT *c, RPC_CLIENT_VERSION *ver);
bool CtGetCmSetting(CLIENT *c, CM_SETTING *s);
bool CtSetCmSetting(CLIENT *c, CM_SETTING *s);
bool CtSetPassword(CLIENT *c, RPC_CLIENT_PASSWORD *pass);
bool CtGetPasswordSetting(CLIENT *c, RPC_CLIENT_PASSWORD_SETTING *a);
bool CtEnumCa(CLIENT *c, RPC_CLIENT_ENUM_CA *e);
bool CtAddCa(CLIENT *c, RPC_CERT *cert);
bool CtDeleteCa(CLIENT *c, RPC_CLIENT_DELETE_CA *p);
bool CtGetCa(CLIENT *c, RPC_GET_CA *get);
bool CtEnumSecure(CLIENT *c, RPC_CLIENT_ENUM_SECURE *e);
bool CtUseSecure(CLIENT *c, RPC_USE_SECURE *sec);
bool CtGetUseSecure(CLIENT *c, RPC_USE_SECURE *sec);
bool CtEnumObjectInSecure(CLIENT *c, RPC_ENUM_OBJECT_IN_SECURE *e);
bool CtCreateVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *create);
bool CtUpgradeVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *create);
bool CtGetVLan(CLIENT *c, RPC_CLIENT_GET_VLAN *get);
bool CtSetVLan(CLIENT *c, RPC_CLIENT_SET_VLAN *set);
bool CtEnumVLan(CLIENT *c, RPC_CLIENT_ENUM_VLAN *e);
bool CtDeleteVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *d);
bool CtEnableVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *vlan);
bool CtDisableVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *vlan);
bool CtCreateAccount(CLIENT *c, RPC_CLIENT_CREATE_ACCOUNT *a, bool inner);
bool CtEnumAccount(CLIENT *c, RPC_CLIENT_ENUM_ACCOUNT *e);
bool CtDeleteAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a, bool inner);
bool CtSetAccount(CLIENT *c, RPC_CLIENT_CREATE_ACCOUNT *a, bool inner);
bool CtGetAccount(CLIENT *c, RPC_CLIENT_GET_ACCOUNT *a);
bool CtRenameAccount(CLIENT *c, RPC_RENAME_ACCOUNT *rename, bool inner);
bool CtSetClientConfig(CLIENT *c, CLIENT_CONFIG *o);
bool CtGetClientConfig(CLIENT *c, CLIENT_CONFIG *o);
bool CtConnect(CLIENT *c, RPC_CLIENT_CONNECT *connect);
bool CtDisconnect(CLIENT *c, RPC_CLIENT_CONNECT *connect, bool inner);
bool CtGetAccountStatus(CLIENT *c, RPC_CLIENT_GET_CONNECTION_STATUS *st);
bool CtSetStartupAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a, bool inner);
bool CtRemoveStartupAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a);
bool CtGetIssuer(CLIENT *c, RPC_GET_ISSUER *a);
bool CtGetCommonProxySetting(CLIENT *c, INTERNET_SETTING *a);
bool CtSetCommonProxySetting(CLIENT *c, INTERNET_SETTING *a);


// Internal function prototype
void CiSendGlobalPulse(CLIENT *c);
void CiPulseRecvThread(THREAD *thread, void *param);
char *CiGetVpnClientExeFileName();
void CiServerThread(THREAD *t, void *param);
void CiInitSaver(CLIENT *c);
void CiFreeSaver(CLIENT *c);
void CiGetSessionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st, SESSION *s);
PACK *CiRpcDispatch(RPC *rpc, char *name, PACK *p);
void CiRpcAccepted(CLIENT *c, SOCK *s);
void CiNotifyMain(CLIENT *c, SOCK *s);
void CiRpcAcceptThread(THREAD *thread, void *param);
void CiRpcServerThread(THREAD *thread, void *param);
void CiStartRpcServer(CLIENT *c);
void CiStopRpcServer(CLIENT *c);
CLIENT_OPTION *CiLoadClientOption(FOLDER *f);
CLIENT_AUTH *CiLoadClientAuth(FOLDER *f);
ACCOUNT *CiLoadClientAccount(FOLDER *f);
void CiLoadClientConfig(CLIENT_CONFIG *c, FOLDER *f);
void CiLoadAccountDatabase(CLIENT *c, FOLDER *f);
void CiLoadCAList(CLIENT *c, FOLDER *f);
void CiLoadCACert(CLIENT *c, FOLDER *f);
void CiLoadVLanList(CLIENT *c, FOLDER *f);
void CiLoadVLan(CLIENT *c, FOLDER *f);
bool CiReadSettingFromCfg(CLIENT *c, FOLDER *root);
void CiWriteAccountDatabase(CLIENT *c, FOLDER *f);
void CiWriteAccountData(FOLDER *f, ACCOUNT *a);
void CiWriteClientOption(FOLDER *f, CLIENT_OPTION *o);
void CiWriteClientAuth(FOLDER *f, CLIENT_AUTH *a);
void CiWriteClientConfig(FOLDER *cc, CLIENT_CONFIG *config);
void CiWriteSettingToCfg(CLIENT *c, FOLDER *root);
void CiWriteCAList(CLIENT *c, FOLDER *f);
void CiWriteCACert(CLIENT *c, FOLDER *f, X *x);
void CiWriteVLanList(CLIENT *c, FOLDER *f);
void CiWriteVLan(CLIENT *c, FOLDER *f, UNIX_VLAN *v);
void CiFreeClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st);
bool CiCheckCertProc(SESSION *s, CONNECTION *c, X *server_x, bool *expired);
bool CiSecureSignProc(SESSION *s, CONNECTION *c, SECURE_SIGN *sign);
bool Win32CiSecureSign(SECURE_SIGN *sign);
void CiFreeClientAuth(CLIENT_AUTH *auth);
void CiFreeClientCreateAccount(RPC_CLIENT_CREATE_ACCOUNT *a);
void CiFreeClientGetAccount(RPC_CLIENT_GET_ACCOUNT *a);
void CiFreeClientEnumVLan(RPC_CLIENT_ENUM_VLAN *e);
void CiFreeClientEnumSecure(RPC_CLIENT_ENUM_SECURE *e);
void CiFreeClientEnumCa(RPC_CLIENT_ENUM_CA *e);
void CiFreeEnumObjectInSecure(RPC_ENUM_OBJECT_IN_SECURE *a);
void CiFreeGetCa(RPC_GET_CA *a);
void CiFreeGetIssuer(RPC_GET_ISSUER *a);
void CiFreeClientEnumAccount(RPC_CLIENT_ENUM_ACCOUNT *a);
void CiSetError(CLIENT *c, UINT err);
void CiCheckOs();
CLIENT *CiNewClient();
void CiCleanupClient(CLIENT *c);
bool CiLoadConfigurationFile(CLIENT *c);
void CiSaveConfigurationFile(CLIENT *c);
void CiInitConfiguration(CLIENT *c);
void CiSetVLanToDefault(CLIENT *c);
bool CiIsVLan(CLIENT *c, char *name);
void CiFreeConfiguration(CLIENT *c);
int CiCompareAccount(void *p1, void *p2);
void CiFreeAccount(ACCOUNT *a);
void CiNotify(CLIENT *c);
void CiNotifyInternal(CLIENT *c);
void CiClientStatusPrinter(SESSION *s, wchar_t *status);
void CiInitKeep(CLIENT *c);
void CiFreeKeep(CLIENT *c);
int CiCompareUnixVLan(void *p1, void *p2);
BUF *CiAccountToCfg(RPC_CLIENT_CREATE_ACCOUNT *t);
RPC_CLIENT_CREATE_ACCOUNT *CiCfgToAccount(BUF *b);
void CiChangeAllVLanMacAddressIfCleared(CLIENT *c);
void CiChangeAllVLanMacAddress(CLIENT *c);
void CiChangeAllVLanMacAddressIfMachineChanged(CLIENT *c);
bool CiReadLastMachineHash(void *data);
bool CiWriteLastMachineHash(void *data);
void CiGetCurrentMachineHash(void *data);
void CiGetCurrentMachineHashOld(void *data);
void CiGetCurrentMachineHashNew(void *data);
LIST *CiLoadIni();
void CiFreeIni(LIST *o);
void CiLoadIniSettings(CLIENT *c);
bool CiLoadConfigFilePathFromIni(char *path, UINT size);
int CiCompareClientAccountEnumItemByLastConnectDateTime(void *p1, void *p2);
bool CiIsValidVLanRegulatedName(char *name);
void CiGenerateVLanRegulatedName(char *name, UINT size, UINT i);
bool CiGetNextRecommendedVLanName(REMOTE_CLIENT *r, char *name, UINT size);
void CiDisableWcmNetworkMinimize(CLIENT *c);
bool CiTryToParseAccount(BUF *b);
bool CiTryToParseAccountFile(wchar_t *name);
bool CiEraseSensitiveInAccount(BUF *b);
bool CiHasAccountSensitiveInformation(BUF *b);
bool CiHasAccountSensitiveInformationFile(wchar_t *name);
void CiApplyInnerVPNServerConfig(CLIENT *c);
SERVER *CiNewInnerVPNServer(CLIENT *c, bool relay_server);
void CiFreeInnerVPNServer(CLIENT *c, SERVER *s);
void CiIncrementNumActiveSessions();
void CiDecrementNumActiveSessions();
UINT CiGetNumActiveSessions();

BUF *EncryptPassword(char *password);
BUF *EncryptPassword2(char *password);
char *DecryptPassword(BUF *b);
char *DecryptPassword2(BUF *b);

void InRpcGetIssuer(RPC_GET_ISSUER *c, PACK *p);
void OutRpcGetIssuer(PACK *p, RPC_GET_ISSUER *c);
void InRpcClientVersion(RPC_CLIENT_VERSION *ver, PACK *p);
void OutRpcClientVersion(PACK *p, RPC_CLIENT_VERSION *ver);
void InRpcClientPassword(RPC_CLIENT_PASSWORD *pw, PACK *p);
void OutRpcClientPassword(PACK *p, RPC_CLIENT_PASSWORD *pw);
void InRpcClientEnumCa(RPC_CLIENT_ENUM_CA *e, PACK *p);
void OutRpcClientEnumCa(PACK *p, RPC_CLIENT_ENUM_CA *e);
void InRpcCert(RPC_CERT *c, PACK *p);
void OutRpcCert(PACK *p, RPC_CERT *c);
void InRpcClientDeleteCa(RPC_CLIENT_DELETE_CA *c, PACK *p);
void OutRpcClientDeleteCa(PACK *p, RPC_CLIENT_DELETE_CA *c);
void InRpcGetCa(RPC_GET_CA *c, PACK *p);
void OutRpcGetCa(PACK *p, RPC_GET_CA *c);
void InRpcClientEnumSecure(RPC_CLIENT_ENUM_SECURE *e, PACK *p);
void OutRpcClientEnumSecure(PACK *p, RPC_CLIENT_ENUM_SECURE *e);
void InRpcUseSecure(RPC_USE_SECURE *u, PACK *p);
void OutRpcUseSecure(PACK *p, RPC_USE_SECURE *u);
void InRpcEnumObjectInSecure(RPC_ENUM_OBJECT_IN_SECURE *e, PACK *p);
void OutRpcEnumObjectInSecure(PACK *p, RPC_ENUM_OBJECT_IN_SECURE *e);
void InRpcCreateVLan(RPC_CLIENT_CREATE_VLAN *v, PACK *p);
void OutRpcCreateVLan(PACK *p, RPC_CLIENT_CREATE_VLAN *v);
void InRpcClientGetVLan(RPC_CLIENT_GET_VLAN *v, PACK *p);
void OutRpcClientGetVLan(PACK *p, RPC_CLIENT_GET_VLAN *v);
void InRpcClientSetVLan(RPC_CLIENT_SET_VLAN *v, PACK *p);
void OutRpcClientSetVLan(PACK *p, RPC_CLIENT_SET_VLAN *v);
void InRpcClientEnumVLan(RPC_CLIENT_ENUM_VLAN *v, PACK *p);
void OutRpcClientEnumVLan(PACK *p, RPC_CLIENT_ENUM_VLAN *v);
void InRpcClientOption(CLIENT_OPTION *c, PACK *p);
void OutRpcClientOption(PACK *p, CLIENT_OPTION *c);
void InRpcClientAuth(CLIENT_AUTH *c, PACK *p);
void OutRpcClientAuth(PACK *p, CLIENT_AUTH *c);
void InRpcClientCreateAccount(RPC_CLIENT_CREATE_ACCOUNT *c, PACK *p);
void OutRpcClientCreateAccount(PACK *p, RPC_CLIENT_CREATE_ACCOUNT *c);
void InRpcClientEnumAccount(RPC_CLIENT_ENUM_ACCOUNT *e, PACK *p);
void OutRpcClientEnumAccount(PACK *p, RPC_CLIENT_ENUM_ACCOUNT *e);
void InRpcClientDeleteAccount(RPC_CLIENT_DELETE_ACCOUNT *a, PACK *p);
void OutRpcClientDeleteAccount(PACK *p, RPC_CLIENT_DELETE_ACCOUNT *a);
void InRpcRenameAccount(RPC_RENAME_ACCOUNT *a, PACK *p);
void OutRpcRenameAccount(PACK *p, RPC_RENAME_ACCOUNT *a);
void InRpcClientGetAccount(RPC_CLIENT_GET_ACCOUNT *c, PACK *p);
void OutRpcClientGetAccount(PACK *p, RPC_CLIENT_GET_ACCOUNT *c);
void InRpcClientConnect(RPC_CLIENT_CONNECT *c, PACK *p);
void OutRpcClientConnect(PACK *p, RPC_CLIENT_CONNECT *c);
void InRpcPolicy(POLICY *o, PACK *p);
void OutRpcPolicy(PACK *p, POLICY *o);
void InRpcClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *s, PACK *p);
void OutRpcClientGetConnectionStatus(PACK *p, RPC_CLIENT_GET_CONNECTION_STATUS *c);
void InRpcClientNotify(RPC_CLIENT_NOTIFY *n, PACK *p);
void OutRpcClientNotify(PACK *p, RPC_CLIENT_NOTIFY *n);
void InRpcClientConfig(CLIENT_CONFIG *c, PACK *p);
void OutRpcClientConfig(PACK *p, CLIENT_CONFIG *c);
void InRpcClientPasswordSetting(RPC_CLIENT_PASSWORD_SETTING *a, PACK *p);
void OutRpcClientPasswordSetting(PACK *p, RPC_CLIENT_PASSWORD_SETTING *a);
void InRpcTraffic(TRAFFIC *t, PACK *p);
void OutRpcTraffic(PACK *p, TRAFFIC *t);
void InRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i);
void OutRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i, UINT num);
void OutRpcCmSetting(PACK *p, CM_SETTING *c);
void InRpcCmSetting(CM_SETTING *c, PACK *p);


#ifdef	OS_WIN32
void CiInitDriverVerStruct(MS_DRIVER_VER *ver);
#endif	// OS_EIN32



//////////////////////////////////////////////////////////////////////////
// Server.h


// Default ports
#define	SERVER_DEF_PORTS_1				443
#define	SERVER_DEF_PORTS_2				992
#define	SERVER_DEF_PORTS_3				1194
#define	SERVER_DEF_PORTS_4				GC_DEFAULT_PORT

#define	SERVER_DEF_PORTS_INCLIENT_1		995
#define	SERVER_DEF_PORTS_INCLIENT_2		465
#define	SERVER_DEF_PORTS_INCLIENT_3		9008	// for admin (in client)
#define	SERVER_DEF_PORTS_INCLIENT_4		1195

#define	SERVER_DEF_PORTS_INCLIENT_DYN_MIN	1201
#define	SERVER_DEF_PORTS_INCLIENT_DYN_MAX	1999

extern char *SERVER_CONFIG_FILE_NAME;
#define	SERVER_DEFAULT_CIPHER_NAME		"AES128-SHA"
#define	SERVER_DEFAULT_CERT_DAYS		(365 * 10)
#define	SERVER_DEFAULT_HUB_NAME			"DEFAULT"
#define	SERVER_DEFAULT_BRIDGE_NAME		"BRIDGE"
#define	SERVER_CONTROL_TCP_TIMEOUT		(60 * 1000)
#define	SERVER_FARM_CONTROL_INTERVAL	(10 * 1000)

#define	SERVER_FILE_SAVE_INTERVAL_DEFAULT	(5 * 60 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_MIN		(5 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_MAX		(3600 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_USERMODE	(1 * 60 * 1000)

#define	SERVER_LICENSE_VIOLATION_SPAN	(SERVER_FARM_CONTROL_INTERVAL * 2)


#define SERVER_DEADLOCK_CHECK_SPAN		(2 * 60 * 1000)
#define SERVER_DEADLOCK_CHECK_TIMEOUT	(10 * 60 * 1000)


#define	RETRY_CONNECT_TO_CONTROLLER_INTERVAL	(1 * 1000)

#define	MAX_PUBLIC_PORT_NUM				128

#define	MEMBER_SELECTOR_TXT_FILENAME	"@member_selector.config"
#define	MEMBER_SELECTOR_CONNECT_TIMEOUT	2000
#define	MEMBER_SELECTOR_DATA_TIMEOUT	5000


// Virtual HUB list hosted by each farm member
struct HUB_LIST
{
	struct FARM_MEMBER *FarmMember;		// Farm member
	bool DynamicHub;					// Dynamic HUB
	char Name[MAX_HUBNAME_LEN + 1];		// HUB Name
	UINT NumSessions;					// Number of sessions
	UINT NumSessionsClient;				// Number of client sessions
	UINT NumSessionsBridge;				// Number of bridge sessions
	UINT NumMacTables;					// Number of MAC table entries
	UINT NumIpTables;					// Number of IP table entries
};

// Task
struct FARM_TASK
{
	EVENT *CompleteEvent;				// Completion notice
	PACK *Request;						// Request
	PACK *Response;						// Response
	FARM_MEMBER *FarmMember;			// Destination farm member
	char TaskName[MAX_PATH];			// Task name
	char HostName[MAX_PATH];			// Host name
};

// Farm member
struct FARM_MEMBER
{
	CEDAR *Cedar;						// Cedar
	UINT64 ConnectedTime;				// Connection date and time
	UINT Me;							// Myself
	UINT Ip;							// IP address
	UINT NumPort;						// Number of port numbers
	UINT *Ports;						// Port number
	char hostname[MAX_HOST_NAME_LEN + 1];	// Host name
	X *ServerCert;						// Server certificate
	LIST *HubList;						// Virtual HUB list
	QUEUE *TaskQueue;					// Task queue
	EVENT *TaskPostEvent;				// Task queuing event
	UINT Point;							// Point
	volatile bool Halting;				// Stopped
	UINT NumSessions;					// Number of sessions
	UINT MaxSessions;					// Maximum number of sessions
	UINT NumTcpConnections;				// Number of TCP connections
	TRAFFIC Traffic;					// Traffic information
	UINT AssignedClientLicense;			// Number of assigned client licenses
	UINT AssignedBridgeLicense;			// Number of assigned bridge licenses
	UINT Weight;						// Performance ratio
	UCHAR RandomKey[SHA1_SIZE];			// Random number key (license check)
	UINT64 SystemId;					// System ID (license check)
};

// Connection to the farm controller
struct FARM_CONTROLLER
{
	LOCK *lock;							// Lock
	struct SERVER *Server;				// Server
	THREAD *Thread;						// Thread
	SOCK *Sock;							// Socket
	SESSION *Session;					// Session
	volatile bool Halt;					// Halting flag
	EVENT *HaltEvent;					// Halting event
	UINT LastError;						// Last error
	bool Online;						// Online flag
	UINT64 StartedTime;					// Connection start time
	UINT64 CurrentConnectedTime;		// Connection time of this time
	UINT64 FirstConnectedTime;			// First connection time
	UINT NumConnected;					// Number of connection count
	UINT NumTry;						// Number of trials
	UINT NumFailed;						// Connection failure count
	bool IsConnected;					// Whether it's connected
};

// Server listener
struct SERVER_LISTENER
{
	UINT Port;							// Port number
	bool Enabled;						// Active flag
	LISTENER *Listener;					// Listener object
	bool DisableDos;					// Disable the DoS detection
};

// Syslog configuration
struct SYSLOG_SETTING
{
	UINT SaveType;							// Save type
	char Hostname[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT Port;								// Port number
};

// Setting of SSTP and OpenVPN
struct OPENVPN_SSTP_CONFIG
{
	bool EnableOpenVPN;						// OpenVPN is enabled
	char OpenVPNPortList[MAX_SIZE];			// OpenVPN UDP port number list
	bool EnableSSTP;						// SSTP is enabled
};

// Server object
struct SERVER
{
	UINT ServerType;					// Type of server
	UINT UpdatedServerType;				// Type of updated server
	LIST *ServerListenerList;			// Server listener list
	UCHAR HashedPassword[SHA1_SIZE];	// Password
	char ControllerName[MAX_HOST_NAME_LEN + 1];		// Controller name
	UINT ControllerPort;				// Controller port
	UINT Weight;						// Performance ratio
	bool ControllerOnly;				// Only controller function
	UCHAR MemberPassword[SHA1_SIZE];	// Password for farm members
	UINT PublicIp;						// Public IP 
	UINT NumPublicPort;					// Number of public ports
	UINT *PublicPorts;					// Public port array
	UINT64 StartTime;					// Start-up time
	UINT AutoSaveConfigSpan;			// Auto save interval
	UINT AutoSaveConfigSpanSaved;		// Auto save interval (stored value)
	bool DontBackupConfig;				// Do not save a backup of the configuration automatically
	bool BackupConfigOnlyWhenModified;	// Save a backup of the configuration only if there is a modification
	UINT ConfigRevision;				// Configuration file revision
	bool DisableDosProction;			// Disable the DoS attack protection
	UCHAR MyRandomKey[SHA1_SIZE];		// Their own random key
	bool FarmControllerInited;			// Initialization of farm controller has been completed
	bool DisableDeadLockCheck;			// Disable the deadlock check
	bool UseWebUI;						// Use the WebUI
	bool SaveDebugLog;					// Save the debug log
	bool NoSendSignature;				// Let the client not to send a signature
	bool UseWebTimePage;				// Use WebTimePage
	bool NoLinuxArpFilter;				// Not to set arp_filter in Linux
	bool NoHighPriorityProcess;			// Not to raise the priority of the process
	bool NoDebugDump;					// Not to output the debug dump
	bool DisableSSTPServer;				// Disable the SSTP server function
	bool DisableOpenVPNServer;			// Disable the OpenVPN server function
	bool DisableNatTraversal;			// Disable the NAT-traversal feature
	bool EnableVpnOverIcmp;				// VPN over ICMP is enabled
	bool EnableVpnOverDns;				// VPN over DNS is enabled
	bool DisableIntelAesAcceleration;	// Disable the Intel AES acceleration
	bool NoMoreSave;					// Do not save any more
	bool EnableConditionalAccept;		// Apply the Conditional Accept the Listener
	bool EnableLegacySSL;				// Enable Legacy SSL

	volatile bool Halt;					// Halting flag
	LOCK *lock;							// Lock
	REF *ref;							// Reference counter
	CEDAR *Cedar;						// Cedar
	CFG_RW *CfgRw;						// Configuration file R/W
	LOCK *SaveCfgLock;					// Settings saving lock
	EVENT *SaveHaltEvent;				// Saving thread halting event
	THREAD *SaveThread;					// Settings saving thread
	FARM_CONTROLLER *FarmController;	// Farm controller
	LOCK *TasksFromFarmControllerLock;	// Lock while processing tasks from farm controller
	LIST *FarmMemberList;				// Farm members list
	FARM_MEMBER *Me;					// Register myself as a farm member
	THREAD *FarmControlThread;			// Farm control thread
	EVENT *FarmControlThreadHaltEvent;	// Farm control thread halting event
	LIST *HubCreateHistoryList;			// Virtual HUB creation history list

	KEEP *Keep;							// Maintaining connections
	LOG *Logger;						// Server logger
	ERASER *Eraser;						// Eraser

	bool Led;							// Use the LED display board
	bool LedSpecial;					// LED Special

	UINT CurrentTotalNumSessionsOnFarm;	// Total number of sessions in this server farm
	UINT CurrentAssignedClientLicense;	// Current number of assigned client licenses
	UINT CurrentAssignedBridgeLicense;	// Current number of assigned bridge license


	LOCK *SyslogLock;					// The lock of the syslog configuration
	SYSLOG_SETTING SyslogSetting;		// Syslog configuration
	SLOG *Syslog;						// Syslog object

	LOCK *CapsCacheLock;				// Lock for Caps cache
	CAPSLIST *CapsListCache;			// Caps cache
	UINT LicenseHash;					// Hash value of the license list

	bool SnapshotInited;
	EVENT *SnapshotHaltEvent;			// Snapshot halting event
	volatile bool HaltSnapshot;			// Snapshot halting flag
	THREAD *SnapshotThread;				// Snapshot thread
	LOG *SnapshotLogger;				// Snapshot logger
	UINT64 LastSnapshotTime;			// Time that the last snapshot created

	THREAD *DeadLockCheckThread;		// Deadlock check thread
	volatile bool HaltDeadLockThread;	// Halting flag
	EVENT *DeadLockWaitEvent;			// Waiting Event

	IPSEC_SERVER *IPsecServer;			// IPsec server function
	OPENVPN_SERVER_UDP *OpenVpnServerUdp;	// OpenVPN server function
	char OpenVpnServerUdpPorts[MAX_SIZE];	// UDP port list string
	DDNS_CLIENT *DDnsClient;			// DDNS client feature
	LOCK *OpenVpnSstpConfigLock;		// Lock OpenVPN and SSTP configuration

	AZURE_CLIENT *AzureClient;			// VPN Azure client
	bool EnableVpnAzure;				// Flag whether VPN Azure client is enabled

	bool DisableGetHostNameWhenAcceptTcp;	// Disable GetHostName when accepting TCP
	bool DisableCoreDumpOnUnix;			// Disable core dump on UNIX

	TINY_LOG *DebugLog;					// Debug log

	DYNAMIC_LISTENER *DynListenerIcmp;	// VPN over ICMP listener
	DYNAMIC_LISTENER *DynListenerDns;	// VPN over DNS listener

	bool IPsecMessageDisplayed;			// Flag for whether the message about IPsec is displayed

	bool IsInVm;						// Whether I'm within the VM



	volatile UINT NatTGlobalUdpPort;	// NAT-T global UDP port

	bool StrictSyslogDatetimeFormat;	// Make syslog datetime format strict RFC3164
};


// Enumerate sessions *
struct RPC_ENUM_SESSION
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumSession;								// Number of sessions
	struct RPC_ENUM_SESSION_ITEM *Sessions;			// Session list
};

// Session status *
struct RPC_SESSION_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	char Name[MAX_SESSION_NAME_LEN + 1];			// Session name
	char Username[MAX_USERNAME_LEN + 1];			// User name
	char RealUsername[MAX_USERNAME_LEN + 1];		// Real user name
	char GroupName[MAX_USERNAME_LEN + 1];			// Group name
	bool LinkMode;									// Link mode
	RPC_CLIENT_GET_CONNECTION_STATUS Status;		// Status
	UINT ClientIp;									// Client IP address
	UCHAR ClientIp6[16];							// Client IPv6 address
	char ClientHostName[MAX_HOST_NAME_LEN + 1];		// Client host name
	NODE_INFO NodeInfo;								// Node information
};


// Type of server
#define	SERVER_TYPE_STANDALONE			0		// Stand-alone server
#define	SERVER_TYPE_FARM_CONTROLLER		1		// Farm controller server
#define	SERVER_TYPE_FARM_MEMBER			2		// Farm member server


// Caps related
struct CAPS
{
	char *Name;							// Name
	UINT Value;							// Value
};
struct CAPSLIST
{
	LIST *CapsList;						// Caps list
};

// Log file
struct LOG_FILE
{
	char Path[MAX_PATH];				// Path name
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT FileSize;						// File size
	UINT64 UpdatedTime;					// Updating date
};


// Global server flags
#define	NUM_GLOBAL_SERVER_FLAGS			128
#define	GSF_DISABLE_PUSH_ROUTE			1
#define	GSF_DISABLE_RADIUS_AUTH			2
#define	GSF_DISABLE_CERT_AUTH			3
#define	GSF_DISABLE_DEEP_LOGGING		4
#define	GSF_DISABLE_AC					5
#define	GSF_DISABLE_SYSLOG				6
#define	GSF_SHOW_OSS_MSG				7
#define	GSF_LOCALBRIDGE_NO_DISABLE_OFFLOAD	8
#define	GSF_DISABLE_SESSION_RECONNECT	9

// Global parameters
#define	NUM_GLOBAL_PARAMS					128
#define	GP_MAX_SEND_SOCKET_QUEUE_SIZE		1
#define	GP_MIN_SEND_SOCKET_QUEUE_SIZE		2
#define	GP_MAX_SEND_SOCKET_QUEUE_NUM		3
#define	GP_SELECT_TIME						4
#define	GP_SELECT_TIME_FOR_NAT				5
#define	GP_MAX_STORED_QUEUE_NUM				6
#define	GP_MAX_BUFFERING_PACKET_SIZE		7
#define	GP_HUB_ARP_SEND_INTERVAL			8
#define	GP_MAC_TABLE_EXPIRE_TIME			9
#define	GP_IP_TABLE_EXPIRE_TIME				10
#define	GP_IP_TABLE_EXPIRE_TIME_DHCP		11
#define	GP_STORM_CHECK_SPAN					12
#define	GP_STORM_DISCARD_VALUE_START		13
#define	GP_STORM_DISCARD_VALUE_END			14
#define	GP_MAX_MAC_TABLES					15
#define	GP_MAX_IP_TABLES					16
#define	GP_MAX_HUB_LINKS					17
#define	GP_MEM_FIFO_REALLOC_MEM_SIZE		18
#define	GP_QUEUE_BUDGET						19
#define	GP_FIFO_BUDGET						20

extern UINT vpn_global_parameters[NUM_GLOBAL_PARAMS];

#define	VPN_GP(id, default_value)	((UINT)(vpn_global_parameters[(id)] != 0 ? vpn_global_parameters[(id)] : (default_value)))



// Virtual HUB creation history
struct SERVER_HUB_CREATE_HISTORY
{
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT64 CreatedTime;
};

// Function prototype declaration
SERVER *SiNewServer(bool bridge);
SERVER *SiNewServerEx(bool bridge, bool in_client_inner_server, bool relay_server);
void SiReleaseServer(SERVER *s);
void SiCleanupServer(SERVER *s);
void StStartServer(bool bridge);
void StStopServer();
void SiInitConfiguration(SERVER *s);
void SiFreeConfiguration(SERVER *s);
UINT SiWriteConfigurationFile(SERVER *s);
void SiLoadInitialConfiguration(SERVER *s);
bool SiLoadConfigurationFile(SERVER *s);
bool SiLoadConfigurationFileMain(SERVER *s, FOLDER *root);
void SiInitDefaultServerCert(SERVER *s);
void SiInitCipherName(SERVER *s);
void SiGenerateDefaultCert(X **server_x, K **server_k);
void SiGenerateDefaultCertEx(X **server_x, K **server_k, char *common_name);
void SiInitListenerList(SERVER *s);
void SiLockListenerList(SERVER *s);
void SiUnlockListenerList(SERVER *s);
bool SiAddListener(SERVER *s, UINT port, bool enabled);
bool SiAddListenerEx(SERVER *s, UINT port, bool enabled, bool disable_dos);
bool SiEnableListener(SERVER *s, UINT port);
bool SiDisableListener(SERVER *s, UINT port);
bool SiDeleteListener(SERVER *s, UINT port);
SERVER_LISTENER *SiGetListener(SERVER *s, UINT port);
int CompareServerListener(void *p1, void *p2);
void SiStopAllListener(SERVER *s);
void SiInitDefaultHubList(SERVER *s);
void SiSetDefaultHubOption(HUB_OPTION *o);
void SiInitBridge(SERVER *s);
void SiTest(SERVER *s);
FOLDER *SiWriteConfigurationToCfg(SERVER *s);
bool SiLoadConfigurationCfg(SERVER *s, FOLDER *root);
void SiWriteLocalBridges(FOLDER *f, SERVER *s);
void SiLoadLocalBridges(SERVER *s, FOLDER *f);
void SiWriteLocalBridgeCfg(FOLDER *f, LOCALBRIDGE *br);
void SiLoadLocalBridgeCfg(SERVER *s, FOLDER *f);
void SiWriteListeners(FOLDER *f, SERVER *s);
void SiLoadListeners(SERVER *s, FOLDER *f);
void SiWriteListenerCfg(FOLDER *f, SERVER_LISTENER *r);
void SiLoadListenerCfg(SERVER *s, FOLDER *f);
void SiWriteServerCfg(FOLDER *f, SERVER *s);
void SiLoadServerCfg(SERVER *s, FOLDER *f);
void SiWriteGlobalParamsCfg(FOLDER *f);
void SiLoadGlobalParamsCfg(FOLDER *f);
void SiLoadGlobalParamItem(UINT id, UINT value);
void SiWriteTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiWriteTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiSaverThread(THREAD *thread, void *param);
void SiLoadLicenseManager(SERVER *s, FOLDER *f);
void SiWriteLicenseManager(FOLDER *f, SERVER *s);
void SiLoadL3Switchs(SERVER *s, FOLDER *f);
void SiLoadL3SwitchCfg(L3SW *sw, FOLDER *f);
void SiWriteL3Switchs(FOLDER *f, SERVER *s);
void SiWriteL3SwitchCfg(FOLDER *f, L3SW *sw);
void SiLoadIPsec(SERVER *s, FOLDER *f);
void SiWriteIPsec(FOLDER *f, SERVER *s);
void SiWriteHubs(FOLDER *f, SERVER *s);
void SiLoadHubs(SERVER *s, FOLDER *f);
void SiWriteHubCfg(FOLDER *f, HUB *h);
void SiLoadHubCfg(SERVER *s, FOLDER *f, char *name);
void SiLoadHubLogCfg(HUB_LOG *g, FOLDER *f);
void SiWriteHubOptionCfg(FOLDER *f, HUB_OPTION *o);
void SiWriteHubLogCfg(FOLDER *f, HUB_LOG *g);
void SiWriteHubLogCfgEx(FOLDER *f, HUB_LOG *g, bool el_mode);
void SiLoadHubOptionCfg(FOLDER *f, HUB_OPTION *o);
void SiWriteHubLinks(FOLDER *f, HUB *h);
void SiLoadHubLinks(HUB *h, FOLDER *f);
void SiWriteHubAdminOptions(FOLDER *f, HUB *h);
void SiLoadHubAdminOptions(HUB *h, FOLDER *f);
void SiWriteHubLinkCfg(FOLDER *f, LINK *k);
void SiLoadHubLinkCfg(FOLDER *f, HUB *h);
void SiWriteHubAccessLists(FOLDER *f, HUB *h);
void SiLoadHubAccessLists(HUB *h, FOLDER *f);
void SiWriteHubAccessCfg(FOLDER *f, ACCESS *a);
void SiLoadHubAccessCfg(HUB *h, FOLDER *f);
void SiWriteHubDb(FOLDER *f, HUBDB *db, bool no_save_ac_list);
void SiLoadHubDb(HUB *h, FOLDER *f);
void SiWriteUserList(FOLDER *f, LIST *o);
void SiLoadUserList(HUB *h, FOLDER *f);
void SiWriteUserCfg(FOLDER *f, USER *u);
void SiLoadUserCfg(HUB *h, FOLDER *f);
void SiWriteGroupList(FOLDER *f, LIST *o);
void SiLoadGroupList(HUB *h, FOLDER *f);
void SiWriteGroupCfg(FOLDER *f, USERGROUP *g);
void SiLoadGroupCfg(HUB *h, FOLDER *f);
void SiWriteCertList(FOLDER *f, LIST *o);
void SiLoadCertList(LIST *o, FOLDER *f);
void SiWriteCrlList(FOLDER *f, LIST *o);
void SiLoadCrlList(LIST *o, FOLDER *f);
void SiWriteAcList(FOLDER *f, LIST *o);
void SiLoadAcList(LIST *o, FOLDER *f);
void SiWritePolicyCfg(FOLDER *f, POLICY *p, bool cascade_mode);
void SiLoadPolicyCfg(POLICY *p, FOLDER *f);
void SiLoadSecureNAT(HUB *h, FOLDER *f);
void SiWriteSecureNAT(HUB *h, FOLDER *f);
void SiRebootServerEx(bool bridge, bool reset_setting);
void SiRebootServer(bool bridge);
void SiRebootServerThread(THREAD *thread, void *param);
void StInit();
void StFree();
SERVER *StGetServer();
void SiSetServerType(SERVER *s, UINT type,
	UINT ip, UINT num_port, UINT *ports,
	char *controller_name, UINT controller_port, UCHAR *password, UINT weight, bool controller_only);
FARM_CONTROLLER *SiStartConnectToController(SERVER *s);
void SiStopConnectToController(FARM_CONTROLLER *f);
void SiFarmServ(SERVER *server, SOCK *sock, X *cert, UINT ip, UINT num_port, UINT *ports, char *hostname, UINT point, UINT weight, UINT max_sessions);
int CompareHubList(void *p1, void *p2);
void SiFarmServMain(SERVER *server, SOCK *sock, FARM_MEMBER *f);
FARM_TASK *SiFarmServPostTask(FARM_MEMBER *f, PACK *request);
PACK *SiFarmServWaitTask(FARM_TASK *t);
PACK *SiExecTask(FARM_MEMBER *f, PACK *p);
PACK *SiCallTask(FARM_MEMBER *f, PACK *p, char *taskname);
FARM_TASK *SiCallTaskAsyncBegin(FARM_MEMBER *f, PACK *p, char *taskname);
PACK *SiCallTaskAsyncEnd(CEDAR *c, FARM_TASK *t);
void SiAcceptTasksFromController(FARM_CONTROLLER *f, SOCK *sock);
void SiAcceptTasksFromControllerMain(FARM_CONTROLLER *f, SOCK *sock);
PACK *SiCalledTask(FARM_CONTROLLER *f, PACK *p, char *taskname);
void SiHubOnlineProc(HUB *h);
void SiHubOfflineProc(HUB *h);
FARM_MEMBER *SiGetNextFarmMember(SERVER *s, CONNECTION *c, HUB *h);
bool SiGetMemberSelectorUrl(char *url, UINT url_size);
void SiCallCreateHub(SERVER *s, FARM_MEMBER *f, HUB *h);
void SiCallUpdateHub(SERVER *s, FARM_MEMBER *f, HUB *h);
void SiCallDeleteHub(SERVER *s, FARM_MEMBER *f, HUB *h);
void SiCallEnumSession(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_SESSION *t);
void SiCallEnumNat(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_NAT *t);
void SiCallEnumDhcp(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_DHCP *t);
void SiCallGetNatStatus(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_NAT_STATUS *t);
void SiCallEnumMacTable(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_MAC_TABLE *t);
void SiCallEnumIpTable(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_IP_TABLE *t);
void SiCallDeleteSession(SERVER *s, FARM_MEMBER *f, char *hubname, char *session_name);
void SiCallCreateTicket(SERVER *s, FARM_MEMBER *f, char *hubname, char *username, char *realusername, POLICY *policy, UCHAR *ticket, UINT counter, char *groupname);
void SiCallDeleteMacTable(SERVER *s, FARM_MEMBER *f, char *hubname, UINT key);
void SiCallDeleteIpTable(SERVER *s, FARM_MEMBER *f, char *hubname, UINT key);
void SiCalledCreateHub(SERVER *s, PACK *p);
void SiCalledUpdateHub(SERVER *s, PACK *p);
void SiCalledDeleteHub(SERVER *s, PACK *p);
void SiCalledDeleteSession(SERVER *s, PACK *p);
void SiCalledDeleteMacTable(SERVER *s, PACK *p);
void SiCalledDeleteIpTable(SERVER *s, PACK *p);
PACK *SiCalledCreateTicket(SERVER *s, PACK *p);
PACK *SiCalledEnumSession(SERVER *s, PACK *p);
PACK *SiCalledEnumNat(SERVER *s, PACK *p);
PACK *SiCalledEnumDhcp(SERVER *s, PACK *p);
PACK *SiCalledGetNatStatus(SERVER *s, PACK *p);
PACK *SiCalledEnumMacTable(SERVER *s, PACK *p);
PACK *SiCalledEnumIpTable(SERVER *s, PACK *p);
void SiCalledEnumHub(SERVER *s, PACK *p, PACK *req);
void SiPackAddCreateHub(PACK *p, HUB *h);
FARM_MEMBER *SiGetHubHostingMember(SERVER *s, HUB *h, bool admin_mode, CONNECTION *c);
void SiCallEnumHub(SERVER *s, FARM_MEMBER *f);
void SiCallEnumHubBegin(SERVER *s, FARM_MEMBER *f);
void SiCallEnumHubEnd(SERVER *s, FARM_MEMBER *f);
void SiStartFarmControl(SERVER *s);
void SiStopFarmControl(SERVER *s);
void SiFarmControlThread(THREAD *thread, void *param);
void SiAccessListToPack(PACK *p, LIST *o);
void SiAccessToPack(PACK *p, ACCESS *a, UINT i, UINT total);
ACCESS *SiPackToAccess(PACK *p, UINT i);
UINT SiNumAccessFromPack(PACK *p);
void SiHubUpdateProc(HUB *h);
bool SiCheckTicket(HUB *h, UCHAR *ticket, char *username, UINT username_size, char *usernamereal, UINT usernamereal_size, POLICY *policy, char *sessionname, UINT sessionname_size, char *groupname, UINT groupname_size);
UINT SiGetPoint(SERVER *s);
UINT SiCalcPoint(SERVER *s, UINT num, UINT weight);
bool SiCallGetSessionStatus(SERVER *s, FARM_MEMBER *f, RPC_SESSION_STATUS *t);
PACK *SiCalledGetSessionStatus(SERVER *s, PACK *p);
bool SiCallEnumLogFileList(SERVER *s, FARM_MEMBER *f, RPC_ENUM_LOG_FILE *t, char *hubname);
PACK *SiCalledEnumLogFileList(SERVER *s, PACK *p);
bool SiCallReadLogFile(SERVER *s, FARM_MEMBER *f, RPC_READ_LOG_FILE *t);
PACK *SiCalledReadLogFile(SERVER *s, PACK *p);
int CmpLogFile(void *p1, void *p2);
LIST *EnumLogFile(char *hubname);
void EnumLogFileDir(LIST *o, char *dirname);
void FreeEnumLogFile(LIST *o);
bool CheckLogFileNameFromEnumList(LIST *o, char *name, char *server_name);
void AdjoinEnumLogFile(LIST *o, LIST *src);
void IncrementServerConfigRevision(SERVER *s);
void GetServerProductName(SERVER *s, char *name, UINT size);
void GetServerProductNameInternal(SERVER *s, char *name, UINT size);


void SiSetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiGetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiWriteSysLog(SERVER *s, char *typestr, char *hubname, wchar_t *message);
UINT SiGetSysLogSaveStatus(SERVER *s);
void SiInitDeadLockCheck(SERVER *s);
void SiFreeDeadLockCheck(SERVER *s);
void SiDeadLockCheckThread(THREAD *t, void *param);
void SiCheckDeadLockMain(SERVER *s, UINT timeout);
void SiDebugLog(SERVER *s, char *msg);
UINT SiDebug(SERVER *s, RPC_TEST *ret, UINT i, char *str);
UINT SiDebugProcHelloWorld(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcExit(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcDump(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcRestorePriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcSetHighPriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetExeFileName(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcCrash(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetIPsecMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcSetIPsecMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetVgsMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcSetVgsMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetCurrentTcpSendQueueLength(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetCurrentGetIPThreadCount(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);

typedef UINT(SI_DEBUG_PROC)(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);

CAPS *NewCaps(char *name, UINT value);
void FreeCaps(CAPS *c);
CAPSLIST *NewCapsList();
int CompareCaps(void *p1, void *p2);
void AddCaps(CAPSLIST *caps, CAPS *c);
CAPS *GetCaps(CAPSLIST *caps, char *name);
void FreeCapsList(CAPSLIST *caps);
bool GetCapsBool(CAPSLIST *caps, char *name);
UINT GetCapsInt(CAPSLIST *caps, char *name);
void AddCapsBool(CAPSLIST *caps, char *name, bool b);
void AddCapsInt(CAPSLIST *caps, char *name, UINT i);
void InRpcCapsList(CAPSLIST *t, PACK *p);
void OutRpcCapsList(PACK *p, CAPSLIST *t);
void FreeRpcCapsList(CAPSLIST *t);
void InitCapsList(CAPSLIST *t);
void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p);
void OutRpcSysLogSetting(PACK *p, SYSLOG_SETTING *t);

void GetServerCaps(SERVER *s, CAPSLIST *t);
void FlushServerCaps(SERVER *s);
bool GetServerCapsBool(SERVER *s, char *name);
UINT GetServerCapsInt(SERVER *s, char *name);
void GetServerCapsMain(SERVER *s, CAPSLIST *t);
void InitServerCapsCache(SERVER *s);
void FreeServerCapsCache(SERVER *s);
void DestroyServerCapsCache(SERVER *s);

void SetGlobalServerFlag(UINT index, UINT value);
UINT GetGlobalServerFlag(UINT index);
void UpdateGlobalServerFlags(SERVER *s, CAPSLIST *t);


bool IsAdminPackSupportedServerProduct(char *name);

void SiInitHubCreateHistory(SERVER *s);
void SiFreeHubCreateHistory(SERVER *s);
void SiDeleteOldHubCreateHistory(SERVER *s);
void SiAddHubCreateHistory(SERVER *s, char *name);
void SiDelHubCreateHistory(SERVER *s, char *name);
bool SiIsHubRegistedOnCreateHistory(SERVER *s, char *name);

UINT SiGetServerNumUserObjects(SERVER *s);
bool SiTooManyUserObjectsInServer(SERVER *s, bool oneMore);

void SiGetOpenVPNAndSSTPConfig(SERVER *s, OPENVPN_SSTP_CONFIG *c);
void SiSetOpenVPNAndSSTPConfig(SERVER *s, OPENVPN_SSTP_CONFIG *c);

bool SiCanOpenVpnOverDnsPort();
bool SiCanOpenVpnOverIcmpPort();
void SiApplySpecialListenerStatus(SERVER *s);

bool SiIsAzureEnabled(SERVER *s);
bool SiIsAzureSupported(SERVER *s);
void SiApplyAzureConfig(SERVER *s, DDNS_CLIENT_STATUS *ddns_status);
void SiSetAzureEnable(SERVER *s, bool enabled);
bool SiGetAzureEnable(SERVER *s);

void SiUpdateCurrentRegion(CEDAR *c, char *region, bool force_update);
void SiGetCurrentRegion(CEDAR *c, char *region, UINT region_size);
bool SiIsEnterpriseFunctionsRestrictedOnOpenSource(CEDAR *c);
bool SiCheckCurrentRegion(CEDAR *c, char *r);



//////////////////////////////////////////////////////////////////////////
// Database.h


wchar_t *LiGetLicenseStatusStr(UINT i);
bool LiIsLicenseKey(char *str);
bool LiStrToKeyBit(UCHAR *keybit, char *keystr);


//////////////////////////////////////////////////////////////////////////
// EtherLog.h


// Whether this is a beta version
#define	ELOG_IS_BETA						true

// Beta expiration date
#define	ELOG_BETA_EXPIRES_YEAR				2008
#define	ELOG_BETA_EXPIRES_MONTH				12
#define ELOG_BETA_EXPIRES_DAY				2

// Version information
//#define	EL_VER							201
//#define	EL_BUILD						1600
//#define	EL_BETA							1
#define MAX_LOGGING_QUEUE_LEN 100000

// RPC related
struct RPC_ADD_DEVICE
{
	char DeviceName[MAX_SIZE];			// Device name
	HUB_LOG LogSetting;					// Log settings
	bool NoPromiscus;					// Without promiscuous mode
};

struct RPC_DELETE_DEVICE
{
	char DeviceName[MAX_SIZE];			// Device name
};

struct RPC_ENUM_DEVICE_ITEM
{
	char DeviceName[MAX_SIZE];			// Device name
	bool Active;						// Running flag
};

struct RPC_ENUM_DEVICE
{
	UINT NumItem;						// Number of items
	RPC_ENUM_DEVICE_ITEM *Items;		// Items
	bool IsLicenseSupported;			// Whether the license system is supported
};

// License status of the service
struct RPC_EL_LICENSE_STATUS
{
	BOOL Valid;								// Enable flag
	UINT64 SystemId;						// System ID
	UINT64 SystemExpires;					// System expiration date
};

// Device
struct EL_DEVICE
{
	EL *el;								// EL
	char DeviceName[MAX_SIZE];			// Device name
	HUB_LOG LogSetting;					// Log settings
	THREAD *Thread;						// Thread
	CANCEL *Cancel1;					// Cancel 1
	CANCEL *Cancel2;					// Cancel 2
	volatile bool Halt;					// Halting flag
	bool Active;						// Running flag
	bool NoPromiscus;					// Without promiscuous mode
	LOG *Logger;						// Logger
};

// License status
struct EL_LICENSE_STATUS
{
	BOOL Valid;				// Enable flag
	UINT64 SystemId;		// System ID
	UINT64 Expires;			// Expiration date
};

// EtherLogger
struct EL
{
	LOCK *lock;							// Lock
	REF *ref;							// Reference counter
	CEDAR *Cedar;						// Cedar
	LIST *DeviceList;					// Device list
	CFG_RW *CfgRw;						// Config R/W
	UINT Port;							// Port number
	LISTENER *Listener;					// Listener
	UCHAR HashedPassword[SHA1_SIZE];	// Password
	LIST *AdminThreadList;				// Management thread list
	LIST *AdminSockList;				// Management socket list
	LICENSE_SYSTEM *LicenseSystem;		// License system
	EL_LICENSE_STATUS *LicenseStatus;	// License status
	UINT64 AutoDeleteCheckDiskFreeSpaceMin;	// Minimum free disk space
	ERASER *Eraser;						// Eraser
};

// Function prototype
void ElInit();
void ElFree();
void ElStart();
void ElStop();
EL *NewEl();
void ReleaseEl(EL *e);
void CleanupEl(EL *e);
void ElInitConfig(EL *e);
void ElFreeConfig(EL *e);
bool ElLoadConfig(EL *e);
void ElLoadConfigFromFolder(EL *e, FOLDER *root);
void ElSaveConfig(EL *e);
void ElSaveConfigToFolder(EL *e, FOLDER *root);
int ElCompareDevice(void *p1, void *p2);
bool ElAddCaptureDevice(EL *e, char *name, HUB_LOG *log, bool no_promiscus);
bool ElDeleteCaptureDevice(EL *e, char *name);
bool ElSetCaptureDeviceLogSetting(EL *e, char *name, HUB_LOG *log);
void ElCaptureThread(THREAD *thread, void *param);
void ElStartListener(EL *e);
void ElStopListener(EL *e);
void ElListenerProc(THREAD *thread, void *param);
PACK *ElRpcServer(RPC *r, char *name, PACK *p);
void ElCheckLicense(EL_LICENSE_STATUS *st, LICENSE *e);
void ElParseCurrentLicenseStatus(LICENSE_SYSTEM *s, EL_LICENSE_STATUS *st);
bool ElIsBetaExpired();


UINT EtAddDevice(EL *e, RPC_ADD_DEVICE *t);
UINT EtDelDevice(EL *e, RPC_DELETE_DEVICE *t);
UINT EtSetDevice(EL *e, RPC_ADD_DEVICE *t);
UINT EtGetDevice(EL *e, RPC_ADD_DEVICE *t);
UINT EtEnumDevice(EL *e, RPC_ENUM_DEVICE *t);
UINT EtEnumAllDevice(EL *e, RPC_ENUM_DEVICE *t);
UINT EtSetPassword(EL *e, RPC_SET_PASSWORD *t);
UINT EtAddLicenseKey(EL *a, RPC_TEST *t);
UINT EtDelLicenseKey(EL *a, RPC_TEST *t);
UINT EtEnumLicenseKey(EL *a, RPC_ENUM_LICENSE_KEY *t);
UINT EtGetLicenseStatus(EL *a, RPC_EL_LICENSE_STATUS *t);
UINT EtGetBridgeSupport(EL *a, RPC_BRIDGE_SUPPORT *t);
UINT EtRebootServer(EL *a, RPC_TEST *t);

UINT EcAddDevice(RPC *r, RPC_ADD_DEVICE *t);
UINT EcDelDevice(RPC *r, RPC_DELETE_DEVICE *t);
UINT EcSetDevice(RPC *r, RPC_ADD_DEVICE *t);
UINT EcGetDevice(RPC *r, RPC_ADD_DEVICE *t);
UINT EcEnumDevice(RPC *r, RPC_ENUM_DEVICE *t);
UINT EcEnumAllDevice(RPC *r, RPC_ENUM_DEVICE *t);
UINT EcSetPassword(RPC *r, RPC_SET_PASSWORD *t);
UINT EcAddLicenseKey(RPC *r, RPC_TEST *t);
UINT EcDelLicenseKey(RPC *r, RPC_TEST *t);
UINT EcEnumLicenseKey(RPC *r, RPC_ENUM_LICENSE_KEY *t);
UINT EcGetLicenseStatus(RPC *r, RPC_EL_LICENSE_STATUS *t);
UINT EcGetBridgeSupport(RPC *r, RPC_BRIDGE_SUPPORT *t);
UINT EcRebootServer(RPC *r, RPC_TEST *t);

UINT EcConnect(char *host, UINT port, char *password, RPC **rpc);
void EcDisconnect(RPC *rpc);

void InRpcAddDevice(RPC_ADD_DEVICE *t, PACK *p);
void OutRpcAddDevice(PACK *p, RPC_ADD_DEVICE *t);
void InRpcDeleteDevice(RPC_DELETE_DEVICE *t, PACK *p);
void OutRpcDeleteDevice(PACK *p, RPC_DELETE_DEVICE *t);
void InRpcEnumDevice(RPC_ENUM_DEVICE *t, PACK *p);
void OutRpcEnumDevice(PACK *p, RPC_ENUM_DEVICE *t);
void FreeRpcEnumDevice(RPC_ENUM_DEVICE *t);
void InRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t, PACK *p);
void OutRpcEnumLicenseKey(PACK *p, RPC_ENUM_LICENSE_KEY *t);
void FreeRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t);
void InRpcElLicenseStatus(RPC_EL_LICENSE_STATUS *t, PACK *p);
void OutRpcElLicenseStatus(PACK *p, RPC_EL_LICENSE_STATUS *t);


//////////////////////////////////////////////////////////////////////////
// Admin.h



// Windows version
struct RPC_WINVER
{
	bool IsWindows;
	bool IsNT;
	bool IsServer;
	bool IsBeta;
	UINT VerMajor;
	UINT VerMinor;
	UINT Build;
	UINT ServicePack;
	char Title[128];
};

// Server-side structure
struct ADMIN
{
	SERVER *Server;				// Server
	bool ServerAdmin;			// Server Administrator
	char *HubName;				// HUB name that can be managed
	RPC *Rpc;					// RPC
	LIST *LogFileList;			// Accessible log file list
	UINT ClientBuild;			// Build number of the client
	RPC_WINVER ClientWinVer;	// Windows version of client
};

// Test
struct RPC_TEST
{
	UINT IntValue;
	UINT64 Int64Value;
	char StrValue[1024];
	wchar_t UniStrValue[1024];
};

// Server Information *
struct RPC_SERVER_INFO
{
	char ServerProductName[128];		// Server product name
	char ServerVersionString[128];		// Server version string
	char ServerBuildInfoString[128];	// Server build information string
	UINT ServerVerInt;					// Server version integer value
	UINT ServerBuildInt;				// Server build number integer value
	char ServerHostName[MAX_HOST_NAME_LEN + 1];	// Server host name
	UINT ServerType;					// Type of server
	UINT64 ServerBuildDate;				// Build date and time of the server
	char ServerFamilyName[128];			// Family name
	OS_INFO OsInfo;						// OS information
};

// Server status
struct RPC_SERVER_STATUS
{
	UINT ServerType;					// Type of server
	UINT NumTcpConnections;				// Total number of TCP connections
	UINT NumTcpConnectionsLocal;		// Number of Local TCP connections
	UINT NumTcpConnectionsRemote;		// Number of remote TCP connections
	UINT NumHubTotal;					// Total number of HUBs
	UINT NumHubStandalone;				// Nymber of stand-alone HUB
	UINT NumHubStatic;					// Number of static HUBs
	UINT NumHubDynamic;					// Number of Dynamic HUBs
	UINT NumSessionsTotal;				// Total number of sessions
	UINT NumSessionsLocal;				// Number of Local sessions (only controller)
	UINT NumSessionsRemote;				// The number of remote sessions (other than the controller)
	UINT NumMacTables;					// Number of MAC table entries
	UINT NumIpTables;					// Number of IP table entries
	UINT NumUsers;						// Number of users
	UINT NumGroups;						// Number of groups
	UINT AssignedBridgeLicenses;		// Number of assigned bridge licenses
	UINT AssignedClientLicenses;		// Number of assigned client licenses
	UINT AssignedBridgeLicensesTotal;	// Number of Assigned bridge license (cluster-wide)
	UINT AssignedClientLicensesTotal;	// Number of assigned client licenses (cluster-wide)
	TRAFFIC Traffic;					// Traffic information
	UINT64 CurrentTime;					// Current time
	UINT64 CurrentTick;					// Current tick
	UINT64 StartTime;					// Start-up time
	MEMINFO MemInfo;					// Memory information
};

// Listener
struct RPC_LISTENER
{
	UINT Port;							// Port number
	bool Enable;						// Active state
};

// List of listeners *
struct RPC_LISTENER_LIST
{
	UINT NumPort;						// Number of ports
	UINT *Ports;						// Port List
	bool *Enables;						// Effective state
	bool *Errors;						// An error occurred
};

// String *
struct RPC_STR
{
	char *String;						// String
};

// Integer
struct RPC_INT
{
	UINT IntValue;						// Integer
};

// Set Password
struct RPC_SET_PASSWORD
{
	UCHAR HashedPassword[SHA1_SIZE];	// Hashed password
};

// Server farm configuration *
struct RPC_FARM
{
	UINT ServerType;					// Type of server
	UINT NumPort;						// Number of public ports
	UINT *Ports;						// Public port list
	UINT PublicIp;						// Public IP
	char ControllerName[MAX_HOST_NAME_LEN + 1];	// Controller name
	UINT ControllerPort;				// Controller port
	UCHAR MemberPassword[SHA1_SIZE];	// Member password
	UINT Weight;						// Performance ratio
	bool ControllerOnly;				// Only controller function
};

// HUB item of each farm member
struct RPC_FARM_HUB
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	bool DynamicHub;					// Dynamic HUB
};

// Server farm member information acquisition *
struct RPC_FARM_INFO
{
	UINT Id;							// ID
	bool Controller;					// Controller
	UINT64 ConnectedTime;				// Connection time
	UINT Ip;							// IP address
	char Hostname[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT Point;							// Point
	UINT NumPort;						// Number of ports
	UINT *Ports;						// Port
	X *ServerCert;						// Server certificate
	UINT NumFarmHub;					// Number of farm HUB
	RPC_FARM_HUB *FarmHubs;				// Farm HUB
	UINT NumSessions;					// Number of sessions
	UINT NumTcpConnections;				// Number of TCP connections
	UINT Weight;						// Performance ratio
};

// Server farm members enumeration items
struct RPC_ENUM_FARM_ITEM
{
	UINT Id;							// ID
	bool Controller;					// Controller
	UINT64 ConnectedTime;				// Connection time
	UINT Ip;							// IP address
	char Hostname[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT Point;							// Point
	UINT NumSessions;					// Number of sessions
	UINT NumTcpConnections;				// Number of TCP connections
	UINT NumHubs;						// Number of HUBs
	UINT AssignedClientLicense;			// Number of assigned client licenses
	UINT AssignedBridgeLicense;			// Number of assigned bridge licenses
};

// Server farm member enumeration *
struct RPC_ENUM_FARM
{
	UINT NumFarm;						// Number of farm members
	RPC_ENUM_FARM_ITEM *Farms;			// Farm member list
};

// Connection state to the controller
struct RPC_FARM_CONNECTION_STATUS
{
	UINT Ip;							// IP address
	UINT Port;							// Port number
	bool Online;						// Online state
	UINT LastError;						// Last error
	UINT64 StartedTime;					// Connection start time
	UINT64 FirstConnectedTime;			// First connection time
	UINT64 CurrentConnectedTime;		// Connection time of this time
	UINT NumTry;						// Number of trials
	UINT NumConnected;					// Number of connection count
	UINT NumFailed;						// Connection failure count
};

// Key pair
struct RPC_KEY_PAIR
{
	X *Cert;							// Certificate
	K *Key;								// Secret key
	UINT Flag1;							// Flag1
};

// HUB option
struct RPC_HUB_OPTION
{
	UINT MaxSession;					// Maximum number of sessions
	bool NoEnum;						// Not listed
};

// Radius server options
struct RPC_RADIUS
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	char RadiusServerName[MAX_HOST_NAME_LEN + 1];	// Radius server name
	UINT RadiusPort;					// Radius port number
	char RadiusSecret[MAX_PASSWORD_LEN + 1];	// Secret key
	UINT RadiusRetryInterval;			// Radius retry interval
};

// Specify the HUB
struct RPC_HUB
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
};

// Create a HUB
struct RPC_CREATE_HUB
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	UCHAR HashedPassword[SHA1_SIZE];	// Administrative password
	UCHAR SecurePassword[SHA1_SIZE];	// Administrator password
	bool Online;						// Online flag
	RPC_HUB_OPTION HubOption;			// HUB options
	UINT HubType;						// Type of HUB
};

// Enumeration items of HUB
struct RPC_ENUM_HUB_ITEM
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	bool Online;						// Online
	UINT HubType;						// Type of HUB
	UINT NumUsers;						// Number of users
	UINT NumGroups;						// Number of groups
	UINT NumSessions;					// Number of sessions
	UINT NumMacTables;					// Number of MAC table entries
	UINT NumIpTables;					// Number of IP table entries
	UINT64 LastCommTime;				// Last communication date and time
	UINT64 LastLoginTime;				// Last login date and time
	UINT64 CreatedTime;					// Creation date and time
	UINT NumLogin;						// Number of logins
	bool IsTrafficFilled;				// Whether the traffic information exists
	TRAFFIC Traffic;					// Traffic
};

// Enumeration of HUB
struct RPC_ENUM_HUB
{
	UINT NumHub;						// Number of HUBs
	RPC_ENUM_HUB_ITEM *Hubs;			// HUB
};

// Delete the HUB
struct RPC_DELETE_HUB
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
};

// Connection enumeration items
struct RPC_ENUM_CONNECTION_ITEM
{
	char Name[MAX_SIZE];				// Connection name
	char Hostname[MAX_SIZE];			// Host name
	UINT Ip;							// IP address
	UINT Port;							// Port number
	UINT64 ConnectedTime;				// Connected time
	UINT Type;							// Type
};

// Connection enumeration
struct RPC_ENUM_CONNECTION
{
	UINT NumConnection;					// Number of connections
	RPC_ENUM_CONNECTION_ITEM *Connections;	// Connection list
};

// Disconnection
struct RPC_DISCONNECT_CONNECTION
{
	char Name[MAX_SIZE];				// Connection name
};

// Connection information
struct RPC_CONNECTION_INFO
{
	char Name[MAX_SIZE];				// Connection name
	UINT Type;							// Type
	char Hostname[MAX_SIZE];			// Host name
	UINT Ip;							// IP address
	UINT Port;							// Port number
	UINT64 ConnectedTime;				// Connected time
	char ServerStr[MAX_SERVER_STR_LEN + 1];	// Server string
	UINT ServerVer;						// Server version
	UINT ServerBuild;					// Server build number
	char ClientStr[MAX_CLIENT_STR_LEN + 1];	// Client string
	UINT ClientVer;						// Client version
	UINT ClientBuild;					// Client build number
};

// Online or offline the HUB
struct RPC_SET_HUB_ONLINE
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	bool Online;						// Online / offline flag
};

// Get the state HUB
struct RPC_HUB_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	bool Online;						// Online
	UINT HubType;						// Type of HUB
	UINT NumSessions;					// Number of sessions
	UINT NumSessionsClient;				// Number of sessions (client)
	UINT NumSessionsBridge;				// Number of sessions (bridge)
	UINT NumAccessLists;				// Number of Access list entries
	UINT NumUsers;						// Number of users
	UINT NumGroups;						// Number of groups
	UINT NumMacTables;					// Number of MAC table entries
	UINT NumIpTables;					// Number of IP table entries
	TRAFFIC Traffic;					// Traffic
	bool SecureNATEnabled;				// Whether SecureNAT is enabled
	UINT64 LastCommTime;				// Last communication date and time
	UINT64 LastLoginTime;				// Last login date and time
	UINT64 CreatedTime;					// Creation date and time
	UINT NumLogin;						// Number of logins
};

// HUB log settings
struct RPC_HUB_LOG
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	HUB_LOG LogSetting;					// Log Settings
};

// Add CA to HUB *
struct RPC_HUB_ADD_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	X *Cert;							// Certificate
};

// CA enumeration items of HUB
struct RPC_HUB_ENUM_CA_ITEM
{
	UINT Key;								// Certificate key
	wchar_t SubjectName[MAX_SIZE];			// Issued to
	wchar_t IssuerName[MAX_SIZE];			// Issuer
	UINT64 Expires;							// Expiration date
};

// CA enumeration of HUB *
struct RPC_HUB_ENUM_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	UINT NumCa;								// CA number
	RPC_HUB_ENUM_CA_ITEM *Ca;				// CA
};

// Get the CA of HUB *
struct RPC_HUB_GET_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	UINT Key;							// Certificate key
	X *Cert;							// Certificate
};

// Delete the CA of HUB
struct RPC_HUB_DELETE_CA
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	UINT Key;							// Certificate key to be deleted
};

// Create and set of link *
struct RPC_CREATE_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB Name
	bool Online;						// Online flag
	CLIENT_OPTION *ClientOption;		// Client Option
	CLIENT_AUTH *ClientAuth;			// Client authentication data
	POLICY Policy;						// Policy
	bool CheckServerCert;				// Validate the server certificate
	X *ServerCert;						// Server certificate
};

// Enumeration items of link
struct RPC_ENUM_LINK_ITEM
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	bool Online;									// Online flag
	bool Connected;									// Connection completion flag
	UINT LastError;									// The error that last occurred
	UINT64 ConnectedTime;							// Connection completion time
	char Hostname[MAX_HOST_NAME_LEN + 1];			// Host name
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
};

// Enumeration of the link *
struct RPC_ENUM_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumLink;									// Number of links
	RPC_ENUM_LINK_ITEM *Links;						// Link List
};

// Get the link state *
struct RPC_LINK_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	RPC_CLIENT_GET_CONNECTION_STATUS Status;		// Status
};

// Specify the Link
struct RPC_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
};

// Rename link
struct RPC_RENAME_LINK
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	wchar_t OldAccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Old account name
	wchar_t NewAccountName[MAX_ACCOUNT_NAME_LEN + 1];	// New account name
};

// Enumeration of the access list *
struct RPC_ENUM_ACCESS_LIST
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumAccess;									// Number of Access list entries
	ACCESS *Accesses;								// Access list
};

// Add to Access List
struct RPC_ADD_ACCESS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	ACCESS Access;									// Access list
};

// Delete the access list
struct RPC_DELETE_ACCESS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT Id;										// ID
};

// Create, configure, and get the user *
struct RPC_SET_USER
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	char Name[MAX_USERNAME_LEN + 1];				// User name
	char GroupName[MAX_USERNAME_LEN + 1];			// Group name
	wchar_t Realname[MAX_SIZE];						// Real name
	wchar_t Note[MAX_SIZE];							// Note
	UINT64 CreatedTime;								// Creation date and time
	UINT64 UpdatedTime;								// Updating date
	UINT64 ExpireTime;								// Expiration date
	UINT AuthType;									// Authentication method
	void *AuthData;									// Authentication data
	UINT NumLogin;									// Number of logins
	TRAFFIC Traffic;								// Traffic data
	POLICY *Policy;									// Policy
};

// Enumeration item of user
struct RPC_ENUM_USER_ITEM
{
	char Name[MAX_USERNAME_LEN + 1];				// User name
	char GroupName[MAX_USERNAME_LEN + 1];			// Group name
	wchar_t Realname[MAX_SIZE];						// Real name
	wchar_t Note[MAX_SIZE];							// Note
	UINT AuthType;									// Authentication method
	UINT NumLogin;									// Number of logins
	UINT64 LastLoginTime;							// Last login date and time
	bool DenyAccess;								// Access denied
	bool IsTrafficFilled;							// Flag of whether the traffic variable is set
	TRAFFIC Traffic;								// Traffic
	bool IsExpiresFilled;							// Flag of whether expiration date variable is set
	UINT64 Expires;									// Expiration date
};

// Enumeration of user
struct RPC_ENUM_USER
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumUser;									// Number of users
	RPC_ENUM_USER_ITEM *Users;						// User
};

// Create, configure, and get the group *
struct RPC_SET_GROUP
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	char Name[MAX_USERNAME_LEN + 1];				// User name
	wchar_t Realname[MAX_SIZE];						// Real name
	wchar_t Note[MAX_SIZE];							// Note
	TRAFFIC Traffic;								// Traffic data
	POLICY *Policy;									// Policy
};

// Enumeration items in the group
struct RPC_ENUM_GROUP_ITEM
{
	char Name[MAX_USERNAME_LEN + 1];				// User name
	wchar_t Realname[MAX_SIZE];						// Real name
	wchar_t Note[MAX_SIZE];							// Note
	UINT NumUsers;									// Number of users
	bool DenyAccess;								// Access denied
};

// Group enumeration
struct RPC_ENUM_GROUP
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumGroup;									// Number of groups
	RPC_ENUM_GROUP_ITEM *Groups;					// Group
};

// Deleting a user or group
struct RPC_DELETE_USER
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	char Name[MAX_USERNAME_LEN + 1];				// User or group name
};

// Enumeration items of session
struct RPC_ENUM_SESSION_ITEM
{
	char Name[MAX_SESSION_NAME_LEN + 1];			// Session name
	bool RemoteSession;								// Remote session
	char RemoteHostname[MAX_HOST_NAME_LEN + 1];		// Remote server name
	char Username[MAX_USERNAME_LEN + 1];			// User name
	UINT Ip;										// IP address (IPv4)
	char Hostname[MAX_HOST_NAME_LEN + 1];			// Host name
	UINT MaxNumTcp;									// Maximum number of TCP connections
	UINT CurrentNumTcp;								// Number of currentl TCP connections
	UINT64 PacketSize;								// Packet size
	UINT64 PacketNum;								// Number of packets
	bool LinkMode;									// Link mode
	bool SecureNATMode;								// SecureNAT mode
	bool BridgeMode;								// Bridge mode
	bool Layer3Mode;								// Layer 3 mode
	bool Client_BridgeMode;							// Client is bridge mode
	bool Client_MonitorMode;						// Client is monitoring mode
	UINT VLanId;									// VLAN ID
	UCHAR UniqueId[16];								// Unique ID
	bool IsDormantEnabled;							// Is the dormant state enabled
	bool IsDormant;									// Is in the dormant state
	UINT64 LastCommDormant;							// Last comm interval in the dormant state
};

// Disconnect the session
struct RPC_DELETE_SESSION
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	char Name[MAX_SESSION_NAME_LEN + 1];			// Session name
};

// Enumeration items of the MAC table
struct RPC_ENUM_MAC_TABLE_ITEM
{
	UINT Key;										// Key
	char SessionName[MAX_SESSION_NAME_LEN + 1];		// Session name
	UCHAR MacAddress[6];							// MAC address
	UCHAR Padding[2];
	UINT64 CreatedTime;								// Creation date and time
	UINT64 UpdatedTime;								// Updating date
	bool RemoteItem;								// Remote items
	char RemoteHostname[MAX_HOST_NAME_LEN + 1];		// Remote host name
	UINT VlanId;									// VLAN ID
};

// Enumeration of the MAC table
struct RPC_ENUM_MAC_TABLE
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumMacTable;								// Number of tables
	RPC_ENUM_MAC_TABLE_ITEM *MacTables;				// MAC table
};

// Enumeration items of IP table
struct RPC_ENUM_IP_TABLE_ITEM
{
	UINT Key;										// Key
	char SessionName[MAX_SESSION_NAME_LEN + 1];		// Session name
	UINT Ip;										// IP address
	IP IpV6;										// IPv6 address
	bool DhcpAllocated;								// Assigned by the DHCP
	UINT64 CreatedTime;								// Creation date and time
	UINT64 UpdatedTime;								// Updating date
	bool RemoteItem;								// Remote items
	char RemoteHostname[MAX_HOST_NAME_LEN + 1];		// Remote host name
};

// Enumeration of IP table
struct RPC_ENUM_IP_TABLE
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumIpTable;								// Number of tables
	RPC_ENUM_IP_TABLE_ITEM *IpTables;				// MAC table
};

// Delete the table
struct RPC_DELETE_TABLE
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT Key;										// Key
};

// KEEP setting
struct RPC_KEEP
{
	bool UseKeepConnect;					// Keep connected to the Internet
	char KeepConnectHost[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT KeepConnectPort;					// Port number
	UINT KeepConnectProtocol;				// Protocol
	UINT KeepConnectInterval;				// Interval
};

// Ethernet enumeration item
struct RPC_ENUM_ETH_ITEM
{
	char DeviceName[MAX_SIZE];				// Device name
	wchar_t NetworkConnectionName[MAX_SIZE];// Network connection name
};

// Ethernet enumeration
struct RPC_ENUM_ETH
{
	UINT NumItem;							// Number of items
	RPC_ENUM_ETH_ITEM *Items;				// Item
};

// Bridge item
struct RPC_LOCALBRIDGE
{
	char DeviceName[MAX_SIZE];				// Device name
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB Name
	bool Online;							// Online flag
	bool Active;							// Running flag
	bool TapMode;							// Tap mode
};

// Bridge enumeration
struct RPC_ENUM_LOCALBRIDGE
{
	UINT NumItem;							// Number of items
	RPC_LOCALBRIDGE *Items;					// Item
};

// Bridge support information
struct RPC_BRIDGE_SUPPORT
{
	bool IsBridgeSupportedOs;				// Whether the OS supports the bridge
	bool IsWinPcapNeeded;					// Whether WinPcap is necessary
};

// Config operation
struct RPC_CONFIG
{
	char FileName[MAX_PATH];				// File name
	char *FileData;							// File data
};

// Administration options list
struct RPC_ADMIN_OPTION
{
	char HubName[MAX_HUBNAME_LEN + 1];		// Virtual HUB name
	UINT NumItem;							// Count
	ADMIN_OPTION *Items;					// Data
};

// Layer-3 switch
struct RPC_L3SW
{
	char Name[MAX_HUBNAME_LEN + 1];			// L3 switch name
};

// Layer-3 switch enumeration
struct RPC_ENUM_L3SW_ITEM
{
	char Name[MAX_HUBNAME_LEN + 1];			// Name
	UINT NumInterfaces;						// Number of interfaces
	UINT NumTables;							// Routing table number
	bool Active;							// In operation
	bool Online;							// Online
};
struct RPC_ENUM_L3SW
{
	UINT NumItem;
	RPC_ENUM_L3SW_ITEM *Items;
};

// Layer-3 interface
struct RPC_L3IF
{
	char Name[MAX_HUBNAME_LEN + 1];			// L3 switch name
	char HubName[MAX_HUBNAME_LEN + 1];		// Virtual HUB name
	UINT IpAddress;							// IP address
	UINT SubnetMask;						// Subnet mask
};

// Layer-3 interface enumeration
struct RPC_ENUM_L3IF
{
	char Name[MAX_HUBNAME_LEN + 1];			// L3 switch name
	UINT NumItem;
	RPC_L3IF *Items;
};

// Routing table
struct RPC_L3TABLE
{
	char Name[MAX_HUBNAME_LEN + 1];			// L3 switch name
	UINT NetworkAddress;					// Network address
	UINT SubnetMask;						// Subnet mask
	UINT GatewayAddress;					// Gateway address
	UINT Metric;							// Metric
};

// Routing table enumeration
struct RPC_ENUM_L3TABLE
{
	char Name[MAX_HUBNAME_LEN + 1];			// L3 switch name
	UINT NumItem;
	RPC_L3TABLE *Items;
};

// CRL entry
struct RPC_CRL
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB Name
	UINT Key;								// Key
	CRL *Crl;								// CRL body
};

// CRL enumeration
struct RPC_ENUM_CRL_ITEM
{
	UINT Key;								// Key
	wchar_t CrlInfo[MAX_SIZE];				// Information
};
struct RPC_ENUM_CRL
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB Name
	UINT NumItem;							// Number of items
	RPC_ENUM_CRL_ITEM *Items;				// List
};

// AC list
struct RPC_AC_LIST
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB Name
	LIST *o;								// List body
	bool InternalFlag1;
};

// Log file enumeration
struct RPC_ENUM_LOG_FILE_ITEM
{
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	char FilePath[MAX_PATH];				// File Path
	UINT FileSize;							// File size
	UINT64 UpdatedTime;						// Updating date
};
struct RPC_ENUM_LOG_FILE
{
	UINT NumItem;							// Number of items
	RPC_ENUM_LOG_FILE_ITEM *Items;			// List
};

// Read a Log file
struct RPC_READ_LOG_FILE
{
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	char FilePath[MAX_PATH];				// File Path
	UINT Offset;							// Offset
	BUF *Buffer;							// Buffer
};

// Download information
struct DOWNLOAD_PROGRESS
{
	void *Param;							// User define data
	UINT TotalSize;							// The total file size
	UINT CurrentSize;						// Size which has loaded
	UINT ProgressPercent;					// Percent Complete
};

// Enumerate the license keys
struct RPC_ENUM_LICENSE_KEY_ITEM
{
	UINT Id;								// ID
	char LicenseKey[LICENSE_KEYSTR_LEN + 1];	// License key
	char LicenseId[LICENSE_LICENSEID_STR_LEN + 1];	// License ID
	char LicenseName[LICENSE_MAX_PRODUCT_NAME_LEN + 1];	// License name
	UINT64 Expires;							// Expiration date
	UINT Status;							// Situation
	UINT ProductId;							// Product ID
	UINT64 SystemId;						// System ID
	UINT SerialId;							// Serial ID
};
struct RPC_ENUM_LICENSE_KEY
{
	UINT NumItem;							// Number of items
	RPC_ENUM_LICENSE_KEY_ITEM *Items;		// List
};

// License status of the server
struct RPC_LICENSE_STATUS
{
	UINT EditionId;							// Edition ID
	char EditionStr[LICENSE_MAX_PRODUCT_NAME_LEN + 1];	// Edition name
	UINT64 SystemId;						// System ID
	UINT64 SystemExpires;					// System expiration date
	UINT NumClientConnectLicense;			// Maximum number of concurrent client connections
	UINT NumBridgeConnectLicense;			// Available number of concurrent bridge connections

											// v3.0
	bool NeedSubscription;					// Subscription system is enabled
	UINT64 SubscriptionExpires;				// Subscription expiration date
	bool IsSubscriptionExpired;				// Whether the subscription is expired
	UINT NumUserCreationLicense;			// Maximum number of users
	bool AllowEnterpriseFunction;			// Operation of the enterprise function
	UINT64 ReleaseDate;						// Release date
};

// Enumeration of VLAN support status of physical LAN card
struct RPC_ENUM_ETH_VLAN_ITEM
{
	char DeviceName[MAX_SIZE];				// Device name
	char Guid[MAX_SIZE];					// GUID
	char DeviceInstanceId[MAX_SIZE];		// Device Instance ID
	char DriverName[MAX_SIZE];				// Driver file name
	char DriverType[MAX_SIZE];				// Type of driver
	bool Support;							// Check whether it is supported
	bool Enabled;							// Whether it is enabled
};
struct RPC_ENUM_ETH_VLAN
{
	UINT NumItem;							// Number of items
	RPC_ENUM_ETH_VLAN_ITEM *Items;			// List
};

// Message
struct RPC_MSG
{
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB Name
	wchar_t *Msg;							// Message
};

// EtherIP setting list
struct RPC_ENUM_ETHERIP_ID
{
	UINT NumItem;
	ETHERIP_ID *IdList;
};

// Set the special listener
struct RPC_SPECIAL_LISTENER
{
	bool VpnOverIcmpListener;				// VPN over ICMP
	bool VpnOverDnsListener;				// VPN over DNS
};

// Get / Set the Azure state
struct RPC_AZURE_STATUS
{
	bool IsEnabled;							// Whether enabled
	bool IsConnected;						// Whether it's connected
};


// Function prototype
UINT AdminAccept(CONNECTION *c, PACK *p);
void HashAdminPassword(void *hash, char *password);
SESSION *AdminConnectMain(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd, bool *empty_password);
RPC *AdminConnect(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err);
RPC *AdminConnectEx(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name);
RPC *AdminConnectEx2(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd);
void AdminDisconnect(RPC *rpc);
UINT AdminReconnect(RPC *rpc);
UINT AdminCheckPassword(CEDAR *c, void *random, void *secure_password, char *hubname, bool accept_empty_password, bool *is_password_empty);
PACK *AdminDispatch(RPC *rpc, char *name, PACK *p);
PACK *AdminCall(RPC *rpc, char *function_name, PACK *p);
void SiEnumLocalSession(SERVER *s, char *hubname, RPC_ENUM_SESSION *t);
void CopyOsInfo(OS_INFO *dst, OS_INFO *info);
CAPSLIST *ScGetCapsEx(RPC *rpc);
UINT SiEnumMacTable(SERVER *s, char *hubname, RPC_ENUM_MAC_TABLE *t);
UINT SiEnumIpTable(SERVER *s, char *hubname, RPC_ENUM_IP_TABLE *t);
void SiEnumLocalLogFileList(SERVER *s, char *hubname, RPC_ENUM_LOG_FILE *t);
void SiReadLocalLogFile(SERVER *s, char *filepath, UINT offset, RPC_READ_LOG_FILE *t);
typedef bool (DOWNLOAD_PROC)(DOWNLOAD_PROGRESS *progress);
BUF *DownloadFileFromServer(RPC *r, char *server_name, char *filepath, UINT total_size, DOWNLOAD_PROC *proc, void *param);
bool CheckAdminSourceAddress(SOCK *sock, char *hubname);
void SiEnumSessionMain(SERVER *s, RPC_ENUM_SESSION *t);
bool SiIsEmptyPassword(void *hash_password);

UINT StTest(ADMIN *a, RPC_TEST *t);
UINT StGetServerInfo(ADMIN *a, RPC_SERVER_INFO *t);
UINT StGetServerStatus(ADMIN *a, RPC_SERVER_STATUS *t);
UINT StCreateListener(ADMIN *a, RPC_LISTENER *t);
UINT StEnumListener(ADMIN *a, RPC_LISTENER_LIST *t);
UINT StDeleteListener(ADMIN *a, RPC_LISTENER *t);
UINT StEnableListener(ADMIN *a, RPC_LISTENER *t);
UINT StSetServerPassword(ADMIN *a, RPC_SET_PASSWORD *t);
UINT StSetFarmSetting(ADMIN *a, RPC_FARM *t);
UINT StGetFarmSetting(ADMIN *a, RPC_FARM *t);
UINT StGetFarmInfo(ADMIN *a, RPC_FARM_INFO *t);
UINT StEnumFarmMember(ADMIN *a, RPC_ENUM_FARM *t);
UINT StGetFarmConnectionStatus(ADMIN *a, RPC_FARM_CONNECTION_STATUS *t);
UINT StSetServerCert(ADMIN *a, RPC_KEY_PAIR *t);
UINT StGetServerCert(ADMIN *a, RPC_KEY_PAIR *t);
UINT StGetServerCipher(ADMIN *a, RPC_STR *t);
UINT StSetServerCipher(ADMIN *a, RPC_STR *t);
UINT StCreateHub(ADMIN *a, RPC_CREATE_HUB *t);
UINT StSetHub(ADMIN *a, RPC_CREATE_HUB *t);
UINT StGetHub(ADMIN *a, RPC_CREATE_HUB *t);
UINT StEnumHub(ADMIN *a, RPC_ENUM_HUB *t);
UINT StDeleteHub(ADMIN *a, RPC_DELETE_HUB *t);
UINT StGetHubRadius(ADMIN *a, RPC_RADIUS *t);
UINT StSetHubRadius(ADMIN *a, RPC_RADIUS *t);
UINT StEnumConnection(ADMIN *a, RPC_ENUM_CONNECTION *t);
UINT StDisconnectConnection(ADMIN *a, RPC_DISCONNECT_CONNECTION *t);
UINT StGetConnectionInfo(ADMIN *a, RPC_CONNECTION_INFO *t);
UINT StSetHubOnline(ADMIN *a, RPC_SET_HUB_ONLINE *t);
UINT StGetHubStatus(ADMIN *a, RPC_HUB_STATUS *t);
UINT StSetHubLog(ADMIN *a, RPC_HUB_LOG *t);
UINT StGetHubLog(ADMIN *a, RPC_HUB_LOG *t);
UINT StAddCa(ADMIN *a, RPC_HUB_ADD_CA *t);
UINT StEnumCa(ADMIN *a, RPC_HUB_ENUM_CA *t);
UINT StGetCa(ADMIN *a, RPC_HUB_GET_CA *t);
UINT StDeleteCa(ADMIN *a, RPC_HUB_DELETE_CA *t);
UINT StCreateLink(ADMIN *a, RPC_CREATE_LINK *t);
UINT StEnumLink(ADMIN *a, RPC_ENUM_LINK *t);
UINT StGetLinkStatus(ADMIN *a, RPC_LINK_STATUS *t);
UINT StSetLinkOnline(ADMIN *a, RPC_LINK *t);
UINT StSetLinkOffline(ADMIN *a, RPC_LINK *t);
UINT StDeleteLink(ADMIN *a, RPC_LINK *t);
UINT StRenameLink(ADMIN *a, RPC_RENAME_LINK *t);
UINT StAddAccess(ADMIN *a, RPC_ADD_ACCESS *t);
UINT StDeleteAccess(ADMIN *a, RPC_DELETE_ACCESS *t);
UINT StEnumAccess(ADMIN *a, RPC_ENUM_ACCESS_LIST *t);
UINT StCreateUser(ADMIN *a, RPC_SET_USER *t);
UINT StSetUser(ADMIN *a, RPC_SET_USER *t);
UINT StGetUser(ADMIN *a, RPC_SET_USER *t);
UINT StDeleteUser(ADMIN *a, RPC_DELETE_USER *t);
UINT StEnumUser(ADMIN *a, RPC_ENUM_USER *t);
UINT StCreateGroup(ADMIN *a, RPC_SET_GROUP *t);
UINT StSetGroup(ADMIN *a, RPC_SET_GROUP *t);
UINT StGetGroup(ADMIN *a, RPC_SET_GROUP *t);
UINT StDeleteGroup(ADMIN *a, RPC_DELETE_USER *t);
UINT StEnumGroup(ADMIN *a, RPC_ENUM_GROUP *t);
UINT StEnumSession(ADMIN *a, RPC_ENUM_SESSION *t);
UINT StGetSessionStatus(ADMIN *a, RPC_SESSION_STATUS *t);
UINT StDeleteSession(ADMIN *a, RPC_DELETE_SESSION *t);
UINT StEnumMacTable(ADMIN *a, RPC_ENUM_MAC_TABLE *t);
UINT StDeleteMacTable(ADMIN *a, RPC_DELETE_TABLE *t);
UINT StEnumIpTable(ADMIN *a, RPC_ENUM_IP_TABLE *t);
UINT StDeleteIpTable(ADMIN *a, RPC_DELETE_TABLE *t);
UINT StGetLink(ADMIN *a, RPC_CREATE_LINK *t);
UINT StSetLink(ADMIN *a, RPC_CREATE_LINK *t);
UINT StSetAccessList(ADMIN *a, RPC_ENUM_ACCESS_LIST *t);
UINT StSetKeep(ADMIN *a, RPC_KEEP *t);
UINT StGetKeep(ADMIN *a, RPC_KEEP *t);
UINT StEnableSecureNAT(ADMIN *a, RPC_HUB *t);
UINT StDisableSecureNAT(ADMIN *a, RPC_HUB *t);
UINT StSetSecureNATOption(ADMIN *a, VH_OPTION *t);
UINT StGetSecureNATOption(ADMIN *a, VH_OPTION *t);
UINT StEnumNAT(ADMIN *a, RPC_ENUM_NAT *t);
UINT StEnumDHCP(ADMIN *a, RPC_ENUM_DHCP *t);
UINT StGetSecureNATStatus(ADMIN *a, RPC_NAT_STATUS *t);
UINT StEnumEthernet(ADMIN *a, RPC_ENUM_ETH *t);
UINT StAddLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t);
UINT StDeleteLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t);
UINT StEnumLocalBridge(ADMIN *a, RPC_ENUM_LOCALBRIDGE *t);
UINT StGetBridgeSupport(ADMIN *a, RPC_BRIDGE_SUPPORT *t);
UINT StRebootServer(ADMIN *a, RPC_TEST *t);
UINT StGetCaps(ADMIN *a, CAPSLIST *t);
UINT StGetConfig(ADMIN *a, RPC_CONFIG *t);
UINT StSetConfig(ADMIN *a, RPC_CONFIG *t);
UINT StGetDefaultHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StGetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StSetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StGetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StSetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StAddL3Switch(ADMIN *a, RPC_L3SW *t);
UINT StDelL3Switch(ADMIN *a, RPC_L3SW *t);
UINT StEnumL3Switch(ADMIN *a, RPC_ENUM_L3SW *t);
UINT StStartL3Switch(ADMIN *a, RPC_L3SW *t);
UINT StStopL3Switch(ADMIN *a, RPC_L3SW *t);
UINT StAddL3If(ADMIN *a, RPC_L3IF *t);
UINT StDelL3If(ADMIN *a, RPC_L3IF *t);
UINT StEnumL3If(ADMIN *a, RPC_ENUM_L3IF *t);
UINT StAddL3Table(ADMIN *a, RPC_L3TABLE *t);
UINT StDelL3Table(ADMIN *a, RPC_L3TABLE *t);
UINT StEnumL3Table(ADMIN *a, RPC_ENUM_L3TABLE *t);
UINT StEnumCrl(ADMIN *a, RPC_ENUM_CRL *t);
UINT StAddCrl(ADMIN *a, RPC_CRL *t);
UINT StDelCrl(ADMIN *a, RPC_CRL *t);
UINT StGetCrl(ADMIN *a, RPC_CRL *t);
UINT StSetCrl(ADMIN *a, RPC_CRL *t);
UINT StSetAcList(ADMIN *a, RPC_AC_LIST *t);
UINT StGetAcList(ADMIN *a, RPC_AC_LIST *t);
UINT StEnumLogFile(ADMIN *a, RPC_ENUM_LOG_FILE *t);
UINT StReadLogFile(ADMIN *a, RPC_READ_LOG_FILE *t);
UINT StAddLicenseKey(ADMIN *a, RPC_TEST *t);
UINT StDelLicenseKey(ADMIN *a, RPC_TEST *t);
UINT StEnumLicenseKey(ADMIN *a, RPC_ENUM_LICENSE_KEY *t);
UINT StGetLicenseStatus(ADMIN *a, RPC_LICENSE_STATUS *t);
UINT StSetSysLog(ADMIN *a, SYSLOG_SETTING *t);
UINT StGetSysLog(ADMIN *a, SYSLOG_SETTING *t);
UINT StEnumEthVLan(ADMIN *a, RPC_ENUM_ETH_VLAN *t);
UINT StSetEnableEthVLan(ADMIN *a, RPC_TEST *t);
UINT StSetHubMsg(ADMIN *a, RPC_MSG *t);
UINT StGetHubMsg(ADMIN *a, RPC_MSG *t);
UINT StCrash(ADMIN *a, RPC_TEST *t);
UINT StGetAdminMsg(ADMIN *a, RPC_MSG *t);
UINT StFlush(ADMIN *a, RPC_TEST *t);
UINT StDebug(ADMIN *a, RPC_TEST *t);
UINT StSetIPsecServices(ADMIN *a, IPSEC_SERVICES *t);
UINT StGetIPsecServices(ADMIN *a, IPSEC_SERVICES *t);
UINT StAddEtherIpId(ADMIN *a, ETHERIP_ID *t);
UINT StGetEtherIpId(ADMIN *a, ETHERIP_ID *t);
UINT StDeleteEtherIpId(ADMIN *a, ETHERIP_ID *t);
UINT StEnumEtherIpId(ADMIN *a, RPC_ENUM_ETHERIP_ID *t);
UINT StSetOpenVpnSstpConfig(ADMIN *a, OPENVPN_SSTP_CONFIG *t);
UINT StGetOpenVpnSstpConfig(ADMIN *a, OPENVPN_SSTP_CONFIG *t);
UINT StGetDDnsClientStatus(ADMIN *a, DDNS_CLIENT_STATUS *t);
UINT StChangeDDnsClientHostname(ADMIN *a, RPC_TEST *t);
UINT StRegenerateServerCert(ADMIN *a, RPC_TEST *t);
UINT StMakeOpenVpnConfigFile(ADMIN *a, RPC_READ_LOG_FILE *t);
UINT StSetSpecialListener(ADMIN *a, RPC_SPECIAL_LISTENER *t);
UINT StGetSpecialListener(ADMIN *a, RPC_SPECIAL_LISTENER *t);
UINT StGetAzureStatus(ADMIN *a, RPC_AZURE_STATUS *t);
UINT StSetAzureStatus(ADMIN *a, RPC_AZURE_STATUS *t);
UINT StGetDDnsInternetSetting(ADMIN *a, INTERNET_SETTING *t);
UINT StSetDDnsInternetSetting(ADMIN *a, INTERNET_SETTING *t);
UINT StSetVgsConfig(ADMIN *a, VGS_CONFIG *t);
UINT StGetVgsConfig(ADMIN *a, VGS_CONFIG *t);

UINT ScTest(RPC *r, RPC_TEST *t);
UINT ScGetServerInfo(RPC *r, RPC_SERVER_INFO *t);
UINT ScGetServerStatus(RPC *r, RPC_SERVER_STATUS *t);
UINT ScCreateListener(RPC *r, RPC_LISTENER *t);
UINT ScEnumListener(RPC *r, RPC_LISTENER_LIST *t);
UINT ScDeleteListener(RPC *r, RPC_LISTENER *t);
UINT ScEnableListener(RPC *r, RPC_LISTENER *t);
UINT ScSetServerPassword(RPC *r, RPC_SET_PASSWORD *t);
UINT ScSetFarmSetting(RPC *r, RPC_FARM *t);
UINT ScGetFarmSetting(RPC *r, RPC_FARM *t);
UINT ScGetFarmInfo(RPC *r, RPC_FARM_INFO *t);
UINT ScEnumFarmMember(RPC *r, RPC_ENUM_FARM *t);
UINT ScGetFarmConnectionStatus(RPC *r, RPC_FARM_CONNECTION_STATUS *t);
UINT ScSetServerCert(RPC *r, RPC_KEY_PAIR *t);
UINT ScGetServerCert(RPC *r, RPC_KEY_PAIR *t);
UINT ScGetServerCipher(RPC *r, RPC_STR *t);
UINT ScSetServerCipher(RPC *r, RPC_STR *t);
UINT ScCreateHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScSetHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScGetHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScEnumHub(RPC *r, RPC_ENUM_HUB *t);
UINT ScDeleteHub(RPC *r, RPC_DELETE_HUB *t);
UINT ScGetHubRadius(RPC *r, RPC_RADIUS *t);
UINT ScSetHubRadius(RPC *r, RPC_RADIUS *t);
UINT ScEnumConnection(RPC *r, RPC_ENUM_CONNECTION *t);
UINT ScDisconnectConnection(RPC *r, RPC_DISCONNECT_CONNECTION *t);
UINT ScGetConnectionInfo(RPC *r, RPC_CONNECTION_INFO *t);
UINT ScSetHubOnline(RPC *r, RPC_SET_HUB_ONLINE *t);
UINT ScGetHubStatus(RPC *r, RPC_HUB_STATUS *t);
UINT ScSetHubLog(RPC *r, RPC_HUB_LOG *t);
UINT ScGetHubLog(RPC *r, RPC_HUB_LOG *t);
UINT ScAddCa(RPC *r, RPC_HUB_ADD_CA *t);
UINT ScEnumCa(RPC *r, RPC_HUB_ENUM_CA *t);
UINT ScGetCa(RPC *r, RPC_HUB_GET_CA *t);
UINT ScDeleteCa(RPC *r, RPC_HUB_DELETE_CA *t);
UINT ScCreateLink(RPC *r, RPC_CREATE_LINK *t);
UINT ScEnumLink(RPC *r, RPC_ENUM_LINK *t);
UINT ScGetLinkStatus(RPC *r, RPC_LINK_STATUS *t);
UINT ScSetLinkOnline(RPC *r, RPC_LINK *t);
UINT ScSetLinkOffline(RPC *r, RPC_LINK *t);
UINT ScDeleteLink(RPC *r, RPC_LINK *t);
UINT ScRenameLink(RPC *r, RPC_RENAME_LINK *t);
UINT ScAddAccess(RPC *r, RPC_ADD_ACCESS *t);
UINT ScDeleteAccess(RPC *r, RPC_DELETE_ACCESS *t);
UINT ScEnumAccess(RPC *r, RPC_ENUM_ACCESS_LIST *t);
UINT ScCreateUser(RPC *r, RPC_SET_USER *t);
UINT ScSetUser(RPC *r, RPC_SET_USER *t);
UINT ScGetUser(RPC *r, RPC_SET_USER *t);
UINT ScDeleteUser(RPC *r, RPC_DELETE_USER *t);
UINT ScEnumUser(RPC *r, RPC_ENUM_USER *t);
UINT ScCreateGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScSetGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScGetGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScDeleteGroup(RPC *r, RPC_DELETE_USER *t);
UINT ScEnumGroup(RPC *r, RPC_ENUM_GROUP *t);
UINT ScEnumSession(RPC *r, RPC_ENUM_SESSION *t);
UINT ScGetSessionStatus(RPC *r, RPC_SESSION_STATUS *t);
UINT ScDeleteSession(RPC *r, RPC_DELETE_SESSION *t);
UINT ScEnumMacTable(RPC *r, RPC_ENUM_MAC_TABLE *t);
UINT ScDeleteMacTable(RPC *r, RPC_DELETE_TABLE *t);
UINT ScEnumIpTable(RPC *r, RPC_ENUM_IP_TABLE *t);
UINT ScDeleteIpTable(RPC *r, RPC_DELETE_TABLE *t);
UINT ScGetLink(RPC *a, RPC_CREATE_LINK *t);
UINT ScSetLink(RPC *a, RPC_CREATE_LINK *t);
UINT ScSetAccessList(RPC *r, RPC_ENUM_ACCESS_LIST *t);
UINT ScSetKeep(RPC *r, RPC_KEEP *t);
UINT ScGetKeep(RPC *r, RPC_KEEP *t);
UINT ScEnableSecureNAT(RPC *r, RPC_HUB *t);
UINT ScDisableSecureNAT(RPC *r, RPC_HUB *t);
UINT ScSetSecureNATOption(RPC *r, VH_OPTION *t);
UINT ScGetSecureNATOption(RPC *r, VH_OPTION *t);
UINT ScEnumNAT(RPC *r, RPC_ENUM_NAT *t);
UINT ScEnumDHCP(RPC *r, RPC_ENUM_DHCP *t);
UINT ScGetSecureNATStatus(RPC *r, RPC_NAT_STATUS *t);
UINT ScEnumEthernet(RPC *r, RPC_ENUM_ETH *t);
UINT ScAddLocalBridge(RPC *r, RPC_LOCALBRIDGE *t);
UINT ScDeleteLocalBridge(RPC *r, RPC_LOCALBRIDGE *t);
UINT ScEnumLocalBridge(RPC *r, RPC_ENUM_LOCALBRIDGE *t);
UINT ScGetBridgeSupport(RPC *r, RPC_BRIDGE_SUPPORT *t);
UINT ScRebootServer(RPC *r, RPC_TEST *t);
UINT ScGetCaps(RPC *r, CAPSLIST *t);
UINT ScGetConfig(RPC *r, RPC_CONFIG *t);
UINT ScSetConfig(RPC *r, RPC_CONFIG *t);
UINT ScGetDefaultHubAdminOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScGetHubAdminOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScSetHubAdminOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScGetHubExtOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScSetHubExtOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScAddL3Switch(RPC *r, RPC_L3SW *t);
UINT ScDelL3Switch(RPC *r, RPC_L3SW *t);
UINT ScEnumL3Switch(RPC *r, RPC_ENUM_L3SW *t);
UINT ScStartL3Switch(RPC *r, RPC_L3SW *t);
UINT ScStopL3Switch(RPC *r, RPC_L3SW *t);
UINT ScAddL3If(RPC *r, RPC_L3IF *t);
UINT ScDelL3If(RPC *r, RPC_L3IF *t);
UINT ScEnumL3If(RPC *r, RPC_ENUM_L3IF *t);
UINT ScAddL3Table(RPC *r, RPC_L3TABLE *t);
UINT ScDelL3Table(RPC *r, RPC_L3TABLE *t);
UINT ScEnumL3Table(RPC *r, RPC_ENUM_L3TABLE *t);
UINT ScEnumCrl(RPC *r, RPC_ENUM_CRL *t);
UINT ScAddCrl(RPC *r, RPC_CRL *t);
UINT ScDelCrl(RPC *r, RPC_CRL *t);
UINT ScGetCrl(RPC *r, RPC_CRL *t);
UINT ScSetCrl(RPC *r, RPC_CRL *t);
UINT ScSetAcList(RPC *r, RPC_AC_LIST *t);
UINT ScGetAcList(RPC *r, RPC_AC_LIST *t);
UINT ScEnumLogFile(RPC *r, RPC_ENUM_LOG_FILE *t);
UINT ScReadLogFile(RPC *r, RPC_READ_LOG_FILE *t);
UINT ScAddLicenseKey(RPC *r, RPC_TEST *t);
UINT ScDelLicenseKey(RPC *r, RPC_TEST *t);
UINT ScEnumLicenseKey(RPC *r, RPC_ENUM_LICENSE_KEY *t);
UINT ScGetLicenseStatus(RPC *r, RPC_LICENSE_STATUS *t);
UINT ScSetSysLog(RPC *r, SYSLOG_SETTING *t);
UINT ScGetSysLog(RPC *r, SYSLOG_SETTING *t);
UINT ScEnumEthVLan(RPC *r, RPC_ENUM_ETH_VLAN *t);
UINT ScSetEnableEthVLan(RPC *r, RPC_TEST *t);
UINT ScSetHubMsg(RPC *r, RPC_MSG *t);
UINT ScGetHubMsg(RPC *r, RPC_MSG *t);
UINT ScCrash(RPC *r, RPC_TEST *t);
UINT ScGetAdminMsg(RPC *r, RPC_MSG *t);
UINT ScFlush(RPC *r, RPC_TEST *t);
UINT ScDebug(RPC *r, RPC_TEST *t);
UINT ScSetIPsecServices(RPC *r, IPSEC_SERVICES *t);
UINT ScGetIPsecServices(RPC *r, IPSEC_SERVICES *t);
UINT ScAddEtherIpId(RPC *r, ETHERIP_ID *t);
UINT ScGetEtherIpId(RPC *r, ETHERIP_ID *t);
UINT ScDeleteEtherIpId(RPC *r, ETHERIP_ID *t);
UINT ScEnumEtherIpId(RPC *r, RPC_ENUM_ETHERIP_ID *t);
UINT ScSetOpenVpnSstpConfig(RPC *r, OPENVPN_SSTP_CONFIG *t);
UINT ScGetOpenVpnSstpConfig(RPC *r, OPENVPN_SSTP_CONFIG *t);
UINT ScGetDDnsClientStatus(RPC *r, DDNS_CLIENT_STATUS *t);
UINT ScChangeDDnsClientHostname(RPC *r, RPC_TEST *t);
UINT ScRegenerateServerCert(RPC *r, RPC_TEST *t);
UINT ScMakeOpenVpnConfigFile(RPC *r, RPC_READ_LOG_FILE *t);
UINT ScSetSpecialListener(RPC *r, RPC_SPECIAL_LISTENER *t);
UINT ScGetSpecialListener(RPC *r, RPC_SPECIAL_LISTENER *t);
UINT ScGetAzureStatus(RPC *r, RPC_AZURE_STATUS *t);
UINT ScSetAzureStatus(RPC *r, RPC_AZURE_STATUS *t);
UINT ScGetDDnsInternetSetting(RPC *r, INTERNET_SETTING *t);
UINT ScSetDDnsInternetSetting(RPC *r, INTERNET_SETTING *t);
UINT ScSetVgsConfig(RPC *r, VGS_CONFIG *t);
UINT ScGetVgsConfig(RPC *r, VGS_CONFIG *t);

void InRpcTest(RPC_TEST *t, PACK *p);
void OutRpcTest(PACK *p, RPC_TEST *t);
void FreeRpcTest(RPC_TEST *t);
void InRpcServerInfo(RPC_SERVER_INFO *t, PACK *p);
void OutRpcServerInfo(PACK *p, RPC_SERVER_INFO *t);
void FreeRpcServerInfo(RPC_SERVER_INFO *t);
void InRpcServerStatus(RPC_SERVER_STATUS *t, PACK *p);
void OutRpcServerStatus(PACK *p, RPC_SERVER_STATUS *t);
void InRpcListener(RPC_LISTENER *t, PACK *p);
void OutRpcListener(PACK *p, RPC_LISTENER *t);
void InRpcListenerList(RPC_LISTENER_LIST *t, PACK *p);
void OutRpcListenerList(PACK *p, RPC_LISTENER_LIST *t);
void FreeRpcListenerList(RPC_LISTENER_LIST *t);
void InRpcStr(RPC_STR *t, PACK *p);
void OutRpcStr(PACK *p, RPC_STR *t);
void FreeRpcStr(RPC_STR *t);
void InRpcSetPassword(RPC_SET_PASSWORD *t, PACK *p);
void OutRpcSetPassword(PACK *p, RPC_SET_PASSWORD *t);
void InRpcFarm(RPC_FARM *t, PACK *p);
void OutRpcFarm(PACK *p, RPC_FARM *t);
void FreeRpcFarm(RPC_FARM *t);
void InRpcFarmHub(RPC_FARM_HUB *t, PACK *p);
void OutRpcFarmHub(PACK *p, RPC_FARM_HUB *t);
void InRpcFarmInfo(RPC_FARM_INFO *t, PACK *p);
void OutRpcFarmInfo(PACK *p, RPC_FARM_INFO *t);
void FreeRpcFarmInfo(RPC_FARM_INFO *t);
void InRpcEnumFarm(RPC_ENUM_FARM *t, PACK *p);
void OutRpcEnumFarm(PACK *p, RPC_ENUM_FARM *t);
void FreeRpcEnumFarm(RPC_ENUM_FARM *t);
void InRpcFarmConnectionStatus(RPC_FARM_CONNECTION_STATUS *t, PACK *p);
void OutRpcFarmConnectionStatus(PACK *p, RPC_FARM_CONNECTION_STATUS *t);
void InRpcHubOption(RPC_HUB_OPTION *t, PACK *p);
void OutRpcHubOption(PACK *p, RPC_HUB_OPTION *t);
void InRpcRadius(RPC_RADIUS *t, PACK *p);
void OutRpcRadius(PACK *p, RPC_RADIUS *t);
void InRpcHub(RPC_HUB *t, PACK *p);
void OutRpcHub(PACK *p, RPC_HUB *t);
void InRpcCreateHub(RPC_CREATE_HUB *t, PACK *p);
void OutRpcCreateHub(PACK *p, RPC_CREATE_HUB *t);
void InRpcEnumHub(RPC_ENUM_HUB *t, PACK *p);
void OutRpcEnumHub(PACK *p, RPC_ENUM_HUB *t);
void FreeRpcEnumHub(RPC_ENUM_HUB *t);
void InRpcDeleteHub(RPC_DELETE_HUB *t, PACK *p);
void OutRpcDeleteHub(PACK *p, RPC_DELETE_HUB *t);
void InRpcEnumConnection(RPC_ENUM_CONNECTION *t, PACK *p);
void OutRpcEnumConnection(PACK *p, RPC_ENUM_CONNECTION *t);
void FreeRpcEnumConnetion(RPC_ENUM_CONNECTION *t);
void InRpcDisconnectConnection(RPC_DISCONNECT_CONNECTION *t, PACK *p);
void OutRpcDisconnectConnection(PACK *p, RPC_DISCONNECT_CONNECTION *t);
void InRpcConnectionInfo(RPC_CONNECTION_INFO *t, PACK *p);
void OutRpcConnectionInfo(PACK *p, RPC_CONNECTION_INFO *t);
void InRpcSetHubOnline(RPC_SET_HUB_ONLINE *t, PACK *p);
void OutRpcSetHubOnline(PACK *p, RPC_SET_HUB_ONLINE *t);
void InRpcHubStatus(RPC_HUB_STATUS *t, PACK *p);
void OutRpcHubStatus(PACK *p, RPC_HUB_STATUS *t);
void InRpcHubLog(RPC_HUB_LOG *t, PACK *p);
void OutRpcHubLog(PACK *p, RPC_HUB_LOG *t);
void InRpcHubAddCa(RPC_HUB_ADD_CA *t, PACK *p);
void OutRpcHubAddCa(PACK *p, RPC_HUB_ADD_CA *t);
void FreeRpcHubAddCa(RPC_HUB_ADD_CA *t);
void InRpcHubEnumCa(RPC_HUB_ENUM_CA *t, PACK *p);
void OutRpcHubEnumCa(PACK *p, RPC_HUB_ENUM_CA *t);
void FreeRpcHubEnumCa(RPC_HUB_ENUM_CA *t);
void InRpcHubGetCa(RPC_HUB_GET_CA *t, PACK *p);
void OutRpcHubGetCa(PACK *p, RPC_HUB_GET_CA *t);
void FreeRpcHubGetCa(RPC_HUB_GET_CA *t);
void InRpcHubDeleteCa(RPC_HUB_DELETE_CA *t, PACK *p);
void OutRpcHubDeleteCa(PACK *p, RPC_HUB_DELETE_CA *t);
void InRpcCreateLink(RPC_CREATE_LINK *t, PACK *p);
void OutRpcCreateLink(PACK *p, RPC_CREATE_LINK *t);
void FreeRpcCreateLink(RPC_CREATE_LINK *t);
void InRpcEnumLink(RPC_ENUM_LINK *t, PACK *p);
void OutRpcEnumLink(PACK *p, RPC_ENUM_LINK *t);
void FreeRpcEnumLink(RPC_ENUM_LINK *t);
void InRpcLinkStatus(RPC_LINK_STATUS *t, PACK *p);
void OutRpcLinkStatus(PACK *p, RPC_LINK_STATUS *t);
void FreeRpcLinkStatus(RPC_LINK_STATUS *t);
void InRpcLink(RPC_LINK *t, PACK *p);
void OutRpcLink(PACK *p, RPC_LINK *t);
void InRpcAccessEx(ACCESS *a, PACK *p, UINT index);
void InRpcAccess(ACCESS *a, PACK *p);
void OutRpcAccessEx(PACK *p, ACCESS *a, UINT index, UINT total);
void OutRpcAccess(PACK *p, ACCESS *a);
void InRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a, PACK *p);
void OutRpcEnumAccessList(PACK *p, RPC_ENUM_ACCESS_LIST *a);
void FreeRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a);
void *InRpcAuthData(PACK *p, UINT *authtype);
void OutRpcAuthData(PACK *p, void *authdata, UINT authtype);
void FreeRpcAuthData(void *authdata, UINT authtype);
void InRpcSetUser(RPC_SET_USER *t, PACK *p);
void OutRpcSetUser(PACK *p, RPC_SET_USER *t);
void FreeRpcSetUser(RPC_SET_USER *t);
void InRpcEnumUser(RPC_ENUM_USER *t, PACK *p);
void OutRpcEnumUser(PACK *p, RPC_ENUM_USER *t);
void FreeRpcEnumUser(RPC_ENUM_USER *t);
void InRpcSetGroup(RPC_SET_GROUP *t, PACK *p);
void OutRpcSetGroup(PACK *p, RPC_SET_GROUP *t);
void InRpcEnumGroup(RPC_ENUM_GROUP *t, PACK *p);
void OutRpcEnumGroup(PACK *p, RPC_ENUM_GROUP *t);
void FreeRpcEnumGroup(RPC_ENUM_GROUP *t);
void InRpcDeleteUser(RPC_DELETE_USER *t, PACK *p);
void OutRpcDeleteUser(PACK *p, RPC_DELETE_USER *t);
void InRpcEnumSession(RPC_ENUM_SESSION *t, PACK *p);
void OutRpcEnumSession(PACK *p, RPC_ENUM_SESSION *t);
void FreeRpcEnumSession(RPC_ENUM_SESSION *t);
void InRpcNodeInfo(NODE_INFO *t, PACK *p);
void OutRpcNodeInfo(PACK *p, NODE_INFO *t);
void InRpcSessionStatus(RPC_SESSION_STATUS *t, PACK *p);
void OutRpcSessionStatus(PACK *p, RPC_SESSION_STATUS *t);
void FreeRpcSessionStatus(RPC_SESSION_STATUS *t);
void InRpcDeleteSession(RPC_DELETE_SESSION *t, PACK *p);
void OutRpcDeleteSession(PACK *p, RPC_DELETE_SESSION *t);
void InRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t, PACK *p);
void OutRpcEnumMacTable(PACK *p, RPC_ENUM_MAC_TABLE *t);
void FreeRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t);
void InRpcEnumIpTable(RPC_ENUM_IP_TABLE *t, PACK *p);
void OutRpcEnumIpTable(PACK *p, RPC_ENUM_IP_TABLE *t);
void FreeRpcEnumIpTable(RPC_ENUM_IP_TABLE *t);
void InRpcDeleteTable(RPC_DELETE_TABLE *t, PACK *p);
void OutRpcDeleteTable(PACK *p, RPC_DELETE_TABLE *t);
void InRpcMemInfo(MEMINFO *t, PACK *p);
void OutRpcMemInfo(PACK *p, MEMINFO *t);
void InRpcKeyPair(RPC_KEY_PAIR *t, PACK *p);
void OutRpcKeyPair(PACK *p, RPC_KEY_PAIR *t);
void FreeRpcKeyPair(RPC_KEY_PAIR *t);
void InRpcAddAccess(RPC_ADD_ACCESS *t, PACK *p);
void OutRpcAddAccess(PACK *p, RPC_ADD_ACCESS *t);
void InRpcDeleteAccess(RPC_DELETE_ACCESS *t, PACK *p);
void OutRpcDeleteAccess(PACK *p, RPC_DELETE_ACCESS *t);
void FreeRpcSetGroup(RPC_SET_GROUP *t);
void AdjoinRpcEnumSession(RPC_ENUM_SESSION *dest, RPC_ENUM_SESSION *src);
void AdjoinRpcEnumMacTable(RPC_ENUM_MAC_TABLE *dest, RPC_ENUM_MAC_TABLE *src);
void AdjoinRpcEnumIpTable(RPC_ENUM_IP_TABLE *dest, RPC_ENUM_IP_TABLE *src);
void InRpcKeep(RPC_KEEP *t, PACK *p);
void OutRpcKeep(PACK *p, RPC_KEEP *t);
void InRpcOsInfo(OS_INFO *t, PACK *p);
void OutRpcOsInfo(PACK *p, OS_INFO *t);
void FreeRpcOsInfo(OS_INFO *t);
void InRpcEnumEth(RPC_ENUM_ETH *t, PACK *p);
void OutRpcEnumEth(PACK *p, RPC_ENUM_ETH *t);
void FreeRpcEnumEth(RPC_ENUM_ETH *t);
void InRpcLocalBridge(RPC_LOCALBRIDGE *t, PACK *p);
void OutRpcLocalBridge(PACK *p, RPC_LOCALBRIDGE *t);
void InRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t, PACK *p);
void OutRpcEnumLocalBridge(PACK *p, RPC_ENUM_LOCALBRIDGE *t);
void FreeRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t);
void InRpcBridgeSupport(RPC_BRIDGE_SUPPORT *t, PACK *p);
void OutRpcBridgeSupport(PACK *p, RPC_BRIDGE_SUPPORT *t);
void InRpcConfig(RPC_CONFIG *t, PACK *p);
void OutRpcConfig(PACK *p, RPC_CONFIG *t);
void FreeRpcConfig(RPC_CONFIG *t);
void InRpcAdminOption(RPC_ADMIN_OPTION *t, PACK *p);
void OutRpcAdminOption(PACK *p, RPC_ADMIN_OPTION *t);
void FreeRpcAdminOption(RPC_ADMIN_OPTION *t);
void InRpcEnumL3Table(RPC_ENUM_L3TABLE *t, PACK *p);
void OutRpcEnumL3Table(PACK *p, RPC_ENUM_L3TABLE *t);
void FreeRpcEnumL3Table(RPC_ENUM_L3TABLE *t);
void InRpcL3Table(RPC_L3TABLE *t, PACK *p);
void OutRpcL3Table(PACK *p, RPC_L3TABLE *t);
void InRpcEnumL3If(RPC_ENUM_L3IF *t, PACK *p);
void OutRpcEnumL3If(PACK *p, RPC_ENUM_L3IF *t);
void FreeRpcEnumL3If(RPC_ENUM_L3IF *t);
void InRpcL3If(RPC_L3IF *t, PACK *p);
void OutRpcL3If(PACK *p, RPC_L3IF *t);
void InRpcL3Sw(RPC_L3SW *t, PACK *p);
void OutRpcL3Sw(PACK *p, RPC_L3SW *t);
void InRpcEnumL3Sw(RPC_ENUM_L3SW *t, PACK *p);
void OutRpcEnumL3Sw(PACK *p, RPC_ENUM_L3SW *t);
void FreeRpcEnumL3Sw(RPC_ENUM_L3SW *t);
void InRpcCrl(RPC_CRL *t, PACK *p);
void OutRpcCrl(PACK *p, RPC_CRL *t);
void FreeRpcCrl(RPC_CRL *t);
void InRpcEnumCrl(RPC_ENUM_CRL *t, PACK *p);
void OutRpcEnumCrl(PACK *p, RPC_ENUM_CRL *t);
void FreeRpcEnumCrl(RPC_ENUM_CRL *t);
void InRpcInt(RPC_INT *t, PACK *p);
void OutRpcInt(PACK *p, RPC_INT *t);
void InRpcAcList(RPC_AC_LIST *t, PACK *p);
void OutRpcAcList(PACK *p, RPC_AC_LIST *t);
void FreeRpcAcList(RPC_AC_LIST *t);
void InRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, PACK *p);
void OutRpcEnumLogFile(PACK *p, RPC_ENUM_LOG_FILE *t);
void FreeRpcEnumLogFile(RPC_ENUM_LOG_FILE *t);
void AdjoinRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, RPC_ENUM_LOG_FILE *src);
void InRpcReadLogFile(RPC_READ_LOG_FILE *t, PACK *p);
void OutRpcReadLogFile(PACK *p, RPC_READ_LOG_FILE *t);
void FreeRpcReadLogFile(RPC_READ_LOG_FILE *t);
void InRpcRenameLink(RPC_RENAME_LINK *t, PACK *p);
void OutRpcRenameLink(PACK *p, RPC_RENAME_LINK *t);
void InRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t, PACK *p);
void OutRpcEnumLicenseKey(PACK *p, RPC_ENUM_LICENSE_KEY *t);
void FreeRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t);
void InRpcLicenseStatus(RPC_LICENSE_STATUS *t, PACK *p);
void OutRpcLicenseStatus(PACK *p, RPC_LICENSE_STATUS *t);
void InRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t, PACK *p);
void OutRpcEnumEthVLan(PACK *p, RPC_ENUM_ETH_VLAN *t);
void FreeRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t);
void InRpcMsg(RPC_MSG *t, PACK *p);
void OutRpcMsg(PACK *p, RPC_MSG *t);
void FreeRpcMsg(RPC_MSG *t);
void InRpcWinVer(RPC_WINVER *t, PACK *p);
void OutRpcWinVer(PACK *p, RPC_WINVER *t);
void InIPsecServices(IPSEC_SERVICES *t, PACK *p);
void OutIPsecServices(PACK *p, IPSEC_SERVICES *t);
void InRpcEnumEtherIpId(RPC_ENUM_ETHERIP_ID *t, PACK *p);
void OutRpcEnumEtherIpId(PACK *p, RPC_ENUM_ETHERIP_ID *t);
void FreeRpcEnumEtherIpId(RPC_ENUM_ETHERIP_ID *t);
void InEtherIpId(ETHERIP_ID *t, PACK *p);
void OutEtherIpId(PACK *p, ETHERIP_ID *t);
void InOpenVpnSstpConfig(OPENVPN_SSTP_CONFIG *t, PACK *p);
void OutOpenVpnSstpConfig(PACK *p, OPENVPN_SSTP_CONFIG *t);
void InDDnsClientStatus(DDNS_CLIENT_STATUS *t, PACK *p);
void OutDDnsClientStatus(PACK *p, DDNS_CLIENT_STATUS *t);
void InRpcSpecialListener(RPC_SPECIAL_LISTENER *t, PACK *p);
void OutRpcSpecialListener(PACK *p, RPC_SPECIAL_LISTENER *t);
void InRpcAzureStatus(RPC_AZURE_STATUS *t, PACK *p);
void OutRpcAzureStatus(PACK *p, RPC_AZURE_STATUS *t);
void InRpcInternetSetting(INTERNET_SETTING *t, PACK *p);
void OutRpcInternetSetting(PACK *p, INTERNET_SETTING *t);

//////////////////////////////////////////////////////////////////////////
// Nat.h



// Constants
#define	NAT_CONFIG_FILE_NAME			"@vpn_router.config"	// NAT configuration file
#define	DEFAULT_NAT_ADMIN_PORT			2828		// Default port number for management
#define	NAT_ADMIN_PORT_LISTEN_INTERVAL	1000		// Interval for trying to open a port for management
#define	NAT_FILE_SAVE_INTERVAL			(30 * 1000)	// Interval to save


// NAT object
struct NAT
{
	LOCK *lock;							// Lock
	UCHAR HashedPassword[SHA1_SIZE];	// Administrative password
	VH_OPTION Option;					// Option
	CEDAR *Cedar;						// Cedar
	UINT AdminPort;						// Management port number
	bool Online;						// Online flag
	VH *Virtual;						// Virtual host object
	CLIENT_OPTION *ClientOption;		// Client Option
	CLIENT_AUTH *ClientAuth;			// Client authentication data
	CFG_RW *CfgRw;						// Config file R/W
	THREAD *AdminAcceptThread;			// Management connection reception thread
	SOCK *AdminListenSock;				// Management port socket
	EVENT *HaltEvent;					// Halting event
	volatile bool Halt;					// Halting flag
	LIST *AdminList;					// Management thread list
	X *AdminX;							// Server certificate for management
	K *AdminK;							// Server private key for management
	SNAT *SecureNAT;					// SecureNAT object
};

// NAT management connection
struct NAT_ADMIN
{
	NAT *Nat;							// NAT
	SOCK *Sock;							// Socket
	THREAD *Thread;						// Thread
};

// RPC_DUMMY
struct RPC_DUMMY
{
	UINT DummyValue;
};

// RPC_NAT_STATUS
struct RPC_NAT_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];			// HUB name
	UINT NumTcpSessions;						// Number of TCP sessions
	UINT NumUdpSessions;						// Ntmber of UDP sessions
	UINT NumIcmpSessions;						// Nymber of ICMP sessions
	UINT NumDnsSessions;						// Number of DNS sessions
	UINT NumDhcpClients;						// Number of DHCP clients
	bool IsKernelMode;							// Whether kernel mode
	bool IsRawIpMode;							// Whether raw IP mode
};

// RPC_NAT_INFO *
struct RPC_NAT_INFO
{
	char NatProductName[128];					// Server product name
	char NatVersionString[128];					// Server version string
	char NatBuildInfoString[128];				// Server build information string
	UINT NatVerInt;								// Server version integer value
	UINT NatBuildInt;							// Server build number integer value
	char NatHostName[MAX_HOST_NAME_LEN + 1];	// Server host name
	OS_INFO OsInfo;								// OS information
	MEMINFO MemInfo;							// Memory information
};

// RPC_ENUM_NAT_ITEM
struct RPC_ENUM_NAT_ITEM
{
	UINT Id;									// ID
	UINT Protocol;								// Protocol
	UINT SrcIp;									// Source IP address
	char SrcHost[MAX_HOST_NAME_LEN + 1];		// Source host name
	UINT SrcPort;								// Source port number
	UINT DestIp;								// Destination IP address
	char DestHost[MAX_HOST_NAME_LEN + 1];		// Destination host name
	UINT DestPort;								// Destination port number
	UINT64 CreatedTime;							// Connection time
	UINT64 LastCommTime;						// Last communication time
	UINT64 SendSize;							// Transmission size
	UINT64 RecvSize;							// Receive size
	UINT TcpStatus;								// TCP state
};

// RPC_ENUM_NAT *
struct RPC_ENUM_NAT
{
	char HubName[MAX_HUBNAME_LEN + 1];			// HUB name
	UINT NumItem;								// Number of items
	RPC_ENUM_NAT_ITEM *Items;					// Item
};

// RPC_ENUM_DHCP_ITEM
struct RPC_ENUM_DHCP_ITEM
{
	UINT Id;									// ID
	UINT64 LeasedTime;							// Lease time
	UINT64 ExpireTime;							// Expiration date
	UCHAR MacAddress[6];						// MAC address
	UCHAR Padding[2];							// Padding
	UINT IpAddress;								// IP address
	UINT Mask;									// Subnet mask
	char Hostname[MAX_HOST_NAME_LEN + 1];		// Host name
};

// RPC_ENUM_DHCP *
struct RPC_ENUM_DHCP
{
	char HubName[MAX_HUBNAME_LEN + 1];			// HUB name
	UINT NumItem;								// Number of items
	RPC_ENUM_DHCP_ITEM *Items;					// Item
};


// Function prototype
NAT *NiNewNat();
NAT *NiNewNatEx(SNAT *snat, VH_OPTION *o);
void NiFreeNat(NAT *n);
void NiInitConfig(NAT *n);
void NiFreeConfig(NAT *n);
void NiInitDefaultConfig(NAT *n);
void NiSetDefaultVhOption(NAT *n, VH_OPTION *o);
void NiClearUnsupportedVhOptionForDynamicHub(VH_OPTION *o, bool initial);
void NiWriteConfig(NAT *n);
void NiWriteVhOption(NAT *n, FOLDER *root);
void NiWriteVhOptionEx(VH_OPTION *o, FOLDER *root);
void NiWriteClientData(NAT *n, FOLDER *root);
void NiLoadVhOption(NAT *n, FOLDER *root);
void NiLoadVhOptionEx(VH_OPTION *o, FOLDER *root);
bool NiLoadConfig(NAT *n, FOLDER *root);
void NiLoadClientData(NAT *n, FOLDER *root);
void NiInitAdminAccept(NAT *n);
void NiFreeAdminAccept(NAT *n);
void NiListenThread(THREAD *thread, void *param);
void NiAdminThread(THREAD *thread, void *param);
void NiAdminMain(NAT *n, SOCK *s);
PACK *NiRpcServer(RPC *r, char *name, PACK *p);

RPC *NatAdminConnect(CEDAR *cedar, char *hostname, UINT port, void *hashed_password, UINT *err);
void NatAdminDisconnect(RPC *r);

void NtStartNat();
void NtStopNat();
void NtInit();
void NtFree();


UINT NtOnline(NAT *n, RPC_DUMMY *t);
UINT NtOffline(NAT *n, RPC_DUMMY *t);
UINT NtSetHostOption(NAT *n, VH_OPTION *t);
UINT NtGetHostOption(NAT *n, VH_OPTION *t);
UINT NtSetClientConfig(NAT *n, RPC_CREATE_LINK *t);
UINT NtGetClientConfig(NAT *n, RPC_CREATE_LINK *t);
UINT NtGetStatus(NAT *n, RPC_NAT_STATUS *t);
UINT NtGetInfo(NAT *n, RPC_NAT_INFO *t);
UINT NtEnumNatList(NAT *n, RPC_ENUM_NAT *t);
UINT NtEnumDhcpList(NAT *n, RPC_ENUM_DHCP *t);
UINT NtSetPassword(NAT *n, RPC_SET_PASSWORD *t);


UINT NcOnline(RPC *r, RPC_DUMMY *t);
UINT NcOffline(RPC *r, RPC_DUMMY *t);
UINT NcSetHostOption(RPC *r, VH_OPTION *t);
UINT NcGetHostOption(RPC *r, VH_OPTION *t);
UINT NcSetClientConfig(RPC *r, RPC_CREATE_LINK *t);
UINT NcGetClientConfig(RPC *r, RPC_CREATE_LINK *t);
UINT NcGetStatus(RPC *r, RPC_NAT_STATUS *t);
UINT NcGetInfo(RPC *r, RPC_NAT_INFO *t);
UINT NcEnumNatList(RPC *r, RPC_ENUM_NAT *t);
UINT NcEnumDhcpList(RPC *r, RPC_ENUM_DHCP *t);
UINT NcSetPassword(RPC *r, RPC_SET_PASSWORD *t);




void InRpcEnumDhcp(RPC_ENUM_DHCP *t, PACK *p);
void OutRpcEnumDhcp(PACK *p, RPC_ENUM_DHCP *t);
void FreeRpcEnumDhcp(RPC_ENUM_DHCP *t);
void InRpcEnumNat(RPC_ENUM_NAT *t, PACK *p);
void OutRpcEnumNat(PACK *p, RPC_ENUM_NAT *t);
void FreeRpcEnumNat(RPC_ENUM_NAT *t);
void InRpcNatInfo(RPC_NAT_INFO *t, PACK *p);
void OutRpcNatInfo(PACK *p, RPC_NAT_INFO *t);
void FreeRpcNatInfo(RPC_NAT_INFO *t);
void InRpcNatStatus(RPC_NAT_STATUS *t, PACK *p);
void OutRpcNatStatus(PACK *p, RPC_NAT_STATUS *t);
void FreeRpcNatStatus(RPC_NAT_STATUS *t);
void InVhOption(VH_OPTION *t, PACK *p);
void OutVhOption(PACK *p, VH_OPTION *t);
void InRpcDummy(RPC_DUMMY *t, PACK *p);
void OutRpcDummy(PACK *p, RPC_DUMMY *t);


//////////////////////////////////////////////////////////////////////////
// WebUI.h



#define WU_PASSWORD_NOCHANGE	"********"
#define WU_CONTEXT_EXPIRE 600000

// Prototype declaration

typedef struct WEBUI
{
	CEDAR *Cedar;
	LIST *PageList;
	LIST *Contexts;
} WEBUI;

// WebUI context
typedef struct WU_CONTEXT
{
	ADMIN *Admin;
	UINT64 ExpireDate;
} WU_CONTEXT;

typedef struct WU_WEBPAGE
{
	char *data;
	UINT size;
	HTTP_HEADER *header;
} WU_WEBPAGE;

// Prototype declaration
bool WuFreeWebUI(WEBUI *wu);
WEBUI *WuNewWebUI(CEDAR *cedar);
WU_WEBPAGE *WuGetPage(char *target, WEBUI *wu);
void WuFreeWebPage(WU_WEBPAGE *page);





//////////////////////////////////////////////////////////////////////////
// VG.h


#define	VG_HUBNAME			"VPNGATE"


bool InitVg();
void FreeVg();
void VgUseStaticLink();


#ifdef	OS_WIN32
//////////////////////////////////////////////////////////////////////////
// WinUi.h



#define	WINUI_DEBUG_TEXT							"@winui_debug.txt"

#define	LV_INSERT_RESET_ALL_ITEM_MIN				500

#define WINUI_PASSWORD_NULL_USERNAME				"NULL"

#define WINUI_DEFAULT_DIALOG_UNIT_X					7
#define WINUI_DEFAULT_DIALOG_UNIT_Y					14

// Make available the types for Windows even if windows.h is not included
#ifndef	_WINDEF_

typedef void *HWND;
typedef void *HFONT;
typedef void *HICON;
typedef void *HMENU;
typedef UINT_PTR WPARAM;
typedef LONG_PTR LPARAM;
typedef void *HINSTANCE;

#endif	// _WINDEF_


// Constants
#define	FREE_REGKEY				"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN Client\\Free Edition Info"
#define ONCE_MSG_REGKEY			"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Common"
#define ONCE_MSG_REGVALUE		"HideMessage_%u"

#define	NICINFO_AUTOCLOSE_TIME_1	(20 * 1000)
#define	NICINFO_AUTOCLOSE_TIME_2	1800

extern bool UseAlpha;
extern UINT AlphaValue;


// Minimum font size
#define	WINUI_MIN_FONTSIZE			5


// Macro
#define	DIALOG			DIALOGEX(false)
#define	DIALOG_WHITE	DIALOGEX(true)
#define	DIALOGEX(white)								\
	void *param = GetParam(hWnd);					\
	{												\
		UINT ret;									\
		ret = DlgProc(hWnd, msg, wParam, lParam, white);	\
		if (ret != 0) return ret;					\
	}

typedef UINT(__stdcall DIALOG_PROC)(HWND, UINT, WPARAM, LPARAM);

typedef UINT(WINUI_DIALOG_PROC)(HWND, UINT, WPARAM, LPARAM, void *);

typedef UINT(WINUI_WIZARD_PROC)(HWND, UINT, WPARAM, LPARAM, WIZARD *, WIZARD_PAGE *, void *);


// Special message to be used for this wizard
#define	WM_WIZ_BASE						(WM_APP + 201)
#define	WM_WIZ_NEXT						(WM_WIZ_BASE + 0)
#define	WM_WIZ_BACK						(WM_WIZ_BASE + 1)
#define	WM_WIZ_CLOSE					(WM_WIZ_BASE + 2)
#define	WM_WIZ_SHOW						(WM_WIZ_BASE + 3)
#define	WM_WIZ_HIDE						(WM_WIZ_BASE + 4)


// Secure operation contents
#define	WINUI_SECURE_ENUM_OBJECTS		1			// Enumerate objects
#define	WINUI_SECURE_WRITE_DATA			2			// Write the data
#define	WINUI_SECURE_READ_DATA			3			// Read the data
#define	WINUI_SECURE_WRITE_CERT			4			// Write the certificate
#define	WINUI_SECURE_READ_CERT			5			// Read the certificate
#define	WINUI_SECURE_WRITE_KEY			6			// Write the secret key
#define	WINUI_SECURE_SIGN_WITH_KEY		7			// Signature by the private key
#define	WINUI_SECURE_DELETE_OBJECT		8			// Delete the object
#define	WINUI_SECURE_DELETE_CERT		9			// Delete the certificate
#define	WINUI_SECURE_DELETE_KEY			10			// Delete the private key
#define	WINUI_SECURE_DELETE_DATA		11			// Delete the Data

// Secure operation structure
typedef struct WINUI_SECURE_BATCH
{
	UINT Type;										// Type of operation
	char *Name;										// Name
	bool Private;									// Private mode
	BUF *InputData;									// Input data
	BUF *OutputData;								// Output data
	X *InputX;										// Input certificate
	X *OutputX;										// Output certificate
	K *InputK;										// Input secret key
	LIST *EnumList;									// Enumerated list
	UCHAR OutputSign[4096 / 8];						// Output signature
	bool Succeed;									// Success flag
} WINUI_SECURE_BATCH;

// Status window
typedef struct STATUS_WINDOW
{
	HWND hWnd;
	THREAD *Thread;
} STATUS_WINDOW;

// Batch processing items
typedef struct LVB_ITEM
{
	UINT NumStrings;				// The number of strings
	wchar_t **Strings;				// String buffer
	UINT Image;						// Image number
	void *Param;					// Parameters
} LVB_ITEM;

// LV insertion batch process
typedef struct LVB
{
	LIST *ItemList;					// Item list
} LVB;


#ifdef	CreateWindow

// Internal code

// Font
typedef struct FONT
{
	UINT Size;						// Size
	bool Bold;						// Bold type
	bool Italic;					// Italic type
	bool UnderLine;					// Underline
	bool StrikeOut;					// Strike through
	char *Name;						// Font name
	HFONT hFont;					// Font
	UINT x, y;						// Font size
} FONT;

// Font cache list
static LIST *font_list = NULL;

// Dialog related
typedef struct DIALOG_PARAM
{
	bool white;
	void *param;
	WINUI_DIALOG_PROC *proc;
	bool meiryo;
	LIST *BitmapList;

	WIZARD *wizard;
	WIZARD_PAGE *wizard_page;
	WINUI_WIZARD_PROC *wizard_proc;
} DIALOG_PARAM;

// Secure device window related
typedef struct SECURE_DEVICE_WINDOW
{
	WINUI_SECURE_BATCH *batch;
	UINT num_batch;
	UINT device_id;
	struct SECURE_DEVICE_THREAD *p;
	char *default_pin;
	UINT BitmapId;
} SECURE_DEVICE_WINDOW;

// Thread
typedef struct SECURE_DEVICE_THREAD
{
	SECURE_DEVICE_WINDOW *w;
	HWND hWnd;
	bool Succeed;
	wchar_t *ErrorMessage;
	char *pin;
} SECURE_DEVICE_THREAD;

void StartSecureDevice(HWND hWnd, SECURE_DEVICE_WINDOW *w);

// Passphrase
typedef struct PASSPHRASE_DLG
{
	char pass[MAX_SIZE];
	BUF *buf;
	bool p12;
} PASSPHRASE_DLG;

void PassphraseDlgProcCommand(HWND hWnd, PASSPHRASE_DLG *p);

// Status window
typedef struct STATUS_WINDOW_PARAM
{
	HWND hWnd;
	SOCK *Sock;
	THREAD *Thread;
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];
} STATUS_WINDOW_PARAM;

// Certificate display dialog
typedef struct CERT_DLG
{
	X *x, *issuer_x;
	bool ManagerMode;
} CERT_DLG;


typedef struct IMAGELIST_ICON
{
	UINT id;
	HICON hSmallImage;
	HICON hLargeImage;
	UINT Index;
} IMAGELIST_ICON;

typedef struct SEARCH_WINDOW_PARAM
{
	wchar_t *caption;
	HWND hWndFound;
} SEARCH_WINDOW_PARAM;

// Remote connection screen setting
typedef struct WINUI_REMOTE
{
	bool flag1;
	char *RegKeyName;					// Registry key name
	UINT Icon;							// Icon
	wchar_t *Caption;					// Caption
	wchar_t *Title;						// Title
	char *Hostname;						// Host name
	char *DefaultHostname;				// Default host name
	LIST *CandidateList;				// Candidate list
} WINUI_REMOTE;

void InitImageList();
void FreeImageList();
IMAGELIST_ICON *LoadIconForImageList(UINT id);
int CompareImageListIcon(void *p1, void *p2);
BOOL CALLBACK EnumResNameProc(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR lParam);
void PrintCertInfo(HWND hWnd, CERT_DLG *p);
void CertDlgUpdate(HWND hWnd, CERT_DLG *p);
bool CALLBACK SearchWindowEnumProc(HWND hWnd, LPARAM lParam);
UINT RemoteDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void RemoteDlgInit(HWND hWnd, WINUI_REMOTE *r);
void RemoteDlgRefresh(HWND hWnd, WINUI_REMOTE *r);
void RemoteDlgOnOk(HWND hWnd, WINUI_REMOTE *r);
int CALLBACK LvSortProc(LPARAM param1, LPARAM param2, LPARAM sort_param);

// Icon cache
typedef struct ICON_CACHE
{
	UINT id;
	bool small_icon;
	HICON hIcon;
} ICON_CACHE;

static LIST *icon_cache_list = NULL;

// Sort related
typedef struct WINUI_LV_SORT
{
	HWND hWnd;
	UINT id;
	UINT subitem;
	bool desc;
	bool numeric;
} WINUI_LV_SORT;

// Version information
typedef struct WINUI_ABOUT
{
	CEDAR *Cedar;
	wchar_t *ProductName;
	UINT Bitmap;
	WINUI_UPDATE *Update;
} WINUI_ABOUT;

UINT AboutDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void AboutDlgInit(HWND hWnd, WINUI_ABOUT *a);

typedef struct WIN9X_REBOOT_DLG
{
	UINT64 StartTime;
	UINT TotalTime;
} WIN9X_REBOOT_DLG;

#define	LED_WIDTH	96
#define	LED_HEIGHT	16
#define	LED_FORCE_UPDATE	60000

// LED
struct LED
{
	HDC hDC;
	HBITMAP hBM;
	void *Buf;
	UCHAR px[LED_WIDTH][LED_HEIGHT];
	bool Updated;
	UINT64 LastUpdated;
};

void LedDrawString(LED *d, char *str, HFONT f);
void LedDrawRect(LED *d);
void LedMainDraw(LED *d, HANDLE h);
void LedSpecial(LED *d, HANDLE h, UINT n);


// STRING
typedef struct STRING_DLG
{
	wchar_t String[MAX_SIZE];
	wchar_t *Title;
	wchar_t *Info;
	UINT Icon;
	bool AllowEmpty;
	bool AllowUnsafe;
} STRING_DLG;

void StringDlgInit(HWND hWnd, STRING_DLG *s);
void StringDlgUpdate(HWND hWnd, STRING_DLG *s);

// PIN code is cached for five minutes
#define	WINUI_SECUREDEVICE_PIN_CACHE_TIME		(5 * 60 * 1000)
extern char cached_pin_code[MAX_SIZE];
extern UINT64 cached_pin_code_expires;

// TCP connection dialog related
typedef struct WINCONNECT_DLG_DATA
{
	wchar_t *caption;
	wchar_t *info;
	UINT icon_id;
	UINT timeout;
	char *hostname;
	UINT port;
	bool cancel;
	SOCK *ret_sock;
	THREAD *thread;
	HWND hWnd;
	char nat_t_svc_name[MAX_SIZE];
	UINT nat_t_error_code;
	bool try_start_ssl;
	bool ssl_no_tls;
} WINCONNECT_DLG_DATA;

HBITMAP ResizeBitmap(HBITMAP hSrc, UINT src_x, UINT src_y, UINT dst_x, UINT dst_y);

#endif	// WINUI_C

// Kakushi
typedef struct KAKUSHI
{
	HWND hWnd;
	THREAD *Thread;
	volatile bool Halt;
	UINT64 StartTick, Span;
} KAKUSHI;

// The information screen about the free version
typedef struct FREEINFO
{
	char ServerName[MAX_SERVER_STR_LEN + 1];
	HWND hWnd;
	THREAD *Thread;
	EVENT *Event;
} FREEINFO;

// Message
typedef struct ONCEMSG_DLG
{
	UINT Icon;
	wchar_t *Title;
	wchar_t *Message;
	bool ShowCheckbox;
	bool Checked;
	UINT MessageHash;
	bool *halt;
} ONCEMSG_DLG;

// Definition of bad process
typedef struct BAD_PROCESS
{
	char *ExeName;
	char *Title;
} BAD_PROCESS;

#ifdef	SECLIB_INTERNAL
#ifdef	SECLIB_C
// Process name list of incompatible anti-virus software
static BAD_PROCESS bad_processes[] =
{
	{ "nod32krn.exe", "NOD32 Antivirus", },
{ "avp.exe", "Kaspersky", },
};

static UINT num_bad_processes = sizeof(bad_processes) / sizeof(bad_processes[0]);

#endif	// SECLIB_C
#endif	// SECLIB_INTERNAL

// Page in the wizard
struct WIZARD_PAGE
{
	UINT Id;
	UINT Index;
	WINUI_WIZARD_PROC *Proc;
	wchar_t *Title;
	WIZARD *Wizard;

	struct DIALOG_PARAM *DialogParam;
	HWND hWndPage;
	bool EnableNext;
	bool EnableBack;
	bool EnableClose;
	bool IsFinish;
};

// Wizard
struct WIZARD
{
	UINT Icon;
	HWND hWndParent;
	LIST *Pages;
	void *Param;
	UINT Bitmap;
	wchar_t *Caption;
	wchar_t *CloseConfirmMsg;
	bool IsAreoStyle;

	HWND hWndWizard;
	bool SetCenterFlag;
	bool ReplaceWindowProcFlag;
	void *OriginalWindowProc;
};

// Update notification
struct WINUI_UPDATE
{
	wchar_t SoftwareTitle[MAX_SIZE];
	char SoftwareName[MAX_SIZE];
	UINT64 CurrentDate;
	UINT CurrentBuild;
	UINT CurrentVer;
	char ClientId[128];
	char RegKey[MAX_PATH];
	UPDATE_CLIENT *UpdateClient;
	bool UseSuppressFlag;
	bool CurrentlyDisabled;
};

// Update notification parameters
struct WINUI_UPDATE_DLG_PARAM
{
	WINUI_UPDATE *Update;
	UINT LatestBuild;
	UINT64 LatestDate;
	char *LatestVer;
	char *Url;
	volatile bool *halt_flag;
	bool IsInConfigDialog;
};

// Registry key to save the update notification settings
#define WINUI_UPDATE_REGKEY			"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Check Update\\%s"


// Function prototype
void InitWinUi(wchar_t *software_name, char *font, UINT fontsize);
void SetWinUiTitle(wchar_t *title);
void FreeWinUi();

WINUI_UPDATE *InitUpdateUi(wchar_t *title, char *name, char *family_name, UINT64 current_date, UINT current_build, UINT current_ver, char *client_id, bool use_suppress_flag);
void FreeUpdateUi(WINUI_UPDATE *u);
void DisableUpdateUi(WINUI_UPDATE *u);
void LoadUpdateUiSetting(WINUI_UPDATE *u, UPDATE_CLIENT_SETTING *s);
void SaveUpdateUiSetting(WINUI_UPDATE *u, UPDATE_CLIENT_SETTING *s);
void UpdateNotifyProcUi(UPDATE_CLIENT *c, UINT latest_build, UINT64 latest_date, char *latest_ver, char *url, volatile bool *halt_flag, void *param);
UINT UpdateNoticeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool ConfigUpdateUi(WINUI_UPDATE *u, HWND hWnd);
UINT UpdateConfigDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);

bool IsThisProcessForeground();
HWND DlgItem(HWND hWnd, UINT id);
void SetText(HWND hWnd, UINT id, wchar_t *str);
void SetTextInner(HWND hWnd, UINT id, wchar_t *str);
void SetTextA(HWND hWnd, UINT id, char *str);
wchar_t *GetText(HWND hWnd, UINT id);
char *GetTextA(HWND hWnd, UINT id);
bool GetTxt(HWND hWnd, UINT id, wchar_t *str, UINT size);
bool GetTxtA(HWND hWnd, UINT id, char *str, UINT size);
bool IsEnable(HWND hWnd, UINT id);
bool IsDisable(HWND hWnd, UINT id);
void Enable(HWND hWnd, UINT id);
void Disable(HWND hWnd, UINT id);
void SetEnable(HWND hWnd, UINT id, bool b);
void Close(HWND hWnd);
void DoEvents(HWND hWnd);
void Refresh(HWND hWnd);
UINT GetInt(HWND hWnd, UINT id);
void SetInt(HWND hWnd, UINT id, UINT value);
void SetIntEx(HWND hWnd, UINT id, UINT value);
void Focus(HWND hWnd, UINT id);
void FocusEx(HWND hWnd, UINT id);
bool IsFocus(HWND hWnd, UINT id);
wchar_t *GetClass(HWND hWnd, UINT id);
char *GetClassA(HWND hWnd, UINT id);
void SelectEdit(HWND hWnd, UINT id);
void SetCursorOnRight(HWND hWnd, UINT id);
void UnselectEdit(HWND hWnd, UINT id);
UINT SendMsg(HWND hWnd, UINT id, UINT msg, WPARAM wParam, LPARAM lParam);
bool IsEmpty(HWND hWnd, UINT id);
UINT GetTextLen(HWND hWnd, UINT id, bool unicode);
UINT GetTextSize(HWND hWnd, UINT id, bool unicode);
UINT GetStyle(HWND hWnd, UINT id);
void SetStyle(HWND hWnd, UINT id, UINT style);
void RemoveStyle(HWND hWnd, UINT id, UINT style);
UINT GetExStyle(HWND hWnd, UINT id);
void SetExStyle(HWND hWnd, UINT id, UINT style);
void RemoveExStyle(HWND hWnd, UINT id, UINT style);
void Hide(HWND hWnd, UINT id);
void Show(HWND hWnd, UINT id);
void SetShow(HWND hWnd, UINT id, bool b);
bool IsHide(HWND hWnd, UINT id);
bool IsShow(HWND hWnd, UINT id);
void Top(HWND hWnd);
void NoTop(HWND hWnd);
void *GetParam(HWND hWnd);
void SetParam(HWND hWnd, void *param);
UINT DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, bool white_color);
void NoticeSettingChange();
void UiTest();
UINT DialogInternal(HWND hWnd, UINT id, DIALOG_PROC *proc, void *param);
UINT MsgBox(HWND hWnd, UINT flag, wchar_t *msg);
UINT MsgBoxEx(HWND hWnd, UINT flag, wchar_t *msg, ...);
void SetTextEx(HWND hWnd, UINT id, wchar_t *str, ...);
void SetTextExA(HWND hWnd, UINT id, char *str, ...);
void FormatText(HWND hWnd, UINT id, ...);
void FormatTextA(HWND hWnd, UINT id, ...);
void Center(HWND hWnd);
void Center2(HWND hWnd);
void GetWindowClientRect(HWND hWnd, struct tagRECT *rect);
void CenterParent(HWND hWnd);
void GetMonitorSize(UINT *width, UINT *height);
void DisableClose(HWND hWnd);
void EnableClose(HWND hWnd);
void InitFont();
void FreeFont();
int CompareFont(void *p1, void *p2);
HFONT GetFont(char *name, UINT size, bool bold, bool italic, bool underline, bool strikeout);
double GetTextScalingFactor();
bool CalcFontSize(HFONT hFont, UINT *x, UINT *y);
bool GetFontSize(HFONT hFont, UINT *x, UINT *y);
void SetFont(HWND hWnd, UINT id, HFONT hFont);
void SetFontEx(HWND hWnd, UINT id, HFONT hFont, bool no_adjust_font_size);
void LimitText(HWND hWnd, UINT id, UINT count);
bool CheckTextLen(HWND hWnd, UINT id, UINT len, bool unicode);
bool CheckTextSize(HWND hWnd, UINT id, UINT size, bool unicode);
void Check(HWND hWnd, UINT id, bool b);
bool IsChecked(HWND hWnd, UINT id);
void SetIcon(HWND hWnd, UINT id, UINT icon_id);
void SetBitmap(HWND hWnd, UINT id, UINT bmp_id);
bool SecureDeviceWindow(HWND hWnd, WINUI_SECURE_BATCH *batch, UINT num_batch, UINT device_id, UINT bitmap_id);
UINT Dialog(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param);
UINT DialogEx(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white);
UINT DialogEx2(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white, bool meiryo);
HWND DialogCreateEx(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white);
UINT __stdcall InternalDialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
UINT SecureDeviceWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
HFONT Font(UINT size, UINT bold);
void DlgFont(HWND hWnd, UINT id, UINT size, UINT bold);
void OpenAvi(HWND hWnd, UINT id, UINT avi_id);
void CloseAvi(HWND hWnd, UINT id);
void PlayAvi(HWND hWnd, UINT id, bool repeat);
void StopAvi(HWND hWnd, UINT id);
void EnableSecureDeviceWindowControls(HWND hWnd, bool enable);
void SecureDeviceThread(THREAD *t, void *param);
void Command(HWND hWnd, UINT id);
wchar_t *OpenDlg(HWND hWnd, wchar_t *filter, wchar_t *title);
char *OpenDlgA(HWND hWnd, char *filter, char *title);
wchar_t *SaveDlg(HWND hWnd, wchar_t *filter, wchar_t *title, wchar_t *default_name, wchar_t *default_ext);
char *SaveDlgA(HWND hWnd, char *filter, char *title, char *default_name, char *default_ext);
wchar_t *MakeFilter(wchar_t *str);
char *MakeFilterA(char *str);
void PkcsUtil();
UINT PkcsUtilProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void PkcsUtilWrite(HWND hWnd);
void PkcsUtilErase(HWND hWnd);
bool PassphraseDlg(HWND hWnd, char *pass, UINT pass_size, BUF *buf, bool p12);
UINT PassphraseDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool PasswordDlg(HWND hWnd, UI_PASSWORD_DLG *p);
void PasswordDlgOnOk(HWND hWnd, UI_PASSWORD_DLG *p);
UINT PasswordDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void PasswordDlgProcChange(HWND hWnd, UI_PASSWORD_DLG *p);
UINT CbAddStr(HWND hWnd, UINT id, wchar_t *str, UINT data);
UINT CbAddStrA(HWND hWnd, UINT id, char *str, UINT data);
UINT CbAddStr9xA(HWND hWnd, UINT id, char *str, UINT data);
UINT CbInsertStr(HWND hWnd, UINT id, UINT index, wchar_t *str, UINT data);
UINT CbInsertStrA(HWND hWnd, UINT id, UINT index, char *str, UINT data);
UINT CbInsertStr9xA(HWND hWnd, UINT id, UINT index, char *str, UINT data);
void CbSelectIndex(HWND hWnd, UINT id, UINT index);
UINT CbNum(HWND hWnd, UINT id);
UINT CbFindStr(HWND hWnd, UINT id, wchar_t *str);
UINT CbFindStr9xA(HWND hWnd, UINT id, char *str);
wchar_t *CbGetStr(HWND hWnd, UINT id);
UINT CbFindData(HWND hWnd, UINT id, UINT data);
UINT CbGetData(HWND hWnd, UINT id, UINT index);
void CbSelect(HWND hWnd, UINT id, int data);
void CbReset(HWND hWnd, UINT id);
void CbSetHeight(HWND hWnd, UINT id, UINT value);
UINT CbGetSelectIndex(HWND hWnd, UINT id);
UINT CbGetSelect(HWND hWnd, UINT id);
void SetRange(HWND hWnd, UINT id, UINT start, UINT end);
void SetPos(HWND hWnd, UINT id, UINT pos);
UINT LbAddStr(HWND hWnd, UINT id, wchar_t *str, UINT data);
UINT LbAddStrA(HWND hWnd, UINT id, char *str, UINT data);
UINT LbInsertStr(HWND hWnd, UINT id, UINT index, wchar_t *str, UINT data);
UINT LbInsertStrA(HWND hWnd, UINT id, UINT index, char *str, UINT data);
void LbSelectIndex(HWND hWnd, UINT id, UINT index);
UINT LbNum(HWND hWnd, UINT id);
UINT LbFindStr(HWND hWnd, UINT id, wchar_t *str);
wchar_t *LbGetStr(HWND hWnd, UINT id);
UINT LbFindData(HWND hWnd, UINT id, UINT data);
UINT LbGetData(HWND hWnd, UINT id, UINT index);
void LbSelect(HWND hWnd, UINT id, int data);
void LbReset(HWND hWnd, UINT id);
void LbSetHeight(HWND hWnd, UINT id, UINT value);
UINT LbGetSelectIndex(HWND hWnd, UINT id);
UINT LbGetSelect(HWND hWnd, UINT id);
STATUS_WINDOW *StatusPrinterWindowStart(SOCK *s, wchar_t *account_name);
void StatusPrinterWindowStop(STATUS_WINDOW *sw);
void StatusPrinterWindowPrint(STATUS_WINDOW *sw, wchar_t *str);
void StatusPrinterWindowThread(THREAD *thread, void *param);
UINT StatusPrinterWindowDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CertDlg(HWND hWnd, X *x, X *issuer_x, bool manager);
UINT CertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void LvInit(HWND hWnd, UINT id);
void LvInitEx(HWND hWnd, UINT id, bool no_image);
void LvInitEx2(HWND hWnd, UINT id, bool no_image, bool large_icon);
void LvReset(HWND hWnd, UINT id);
void LvInsertColumn(HWND hWnd, UINT id, UINT index, wchar_t *str, UINT width);
UINT GetIcon(UINT icon_id);
void LvInsert(HWND hWnd, UINT id, UINT icon, void *param, UINT num_str, ...);
UINT LvInsertItem(HWND hWnd, UINT id, UINT icon, void *param, wchar_t *str);
UINT LvInsertItemByImageListId(HWND hWnd, UINT id, UINT image, void *param, wchar_t *str);
UINT LvInsertItemByImageListIdA(HWND hWnd, UINT id, UINT image, void *param, char *str);
void LvSetItem(HWND hWnd, UINT id, UINT index, UINT pos, wchar_t *str);
void LvSetItemA(HWND hWnd, UINT id, UINT index, UINT pos, char *str);
void LvSetItemParam(HWND hWnd, UINT id, UINT index, void *param);
void LvSetItemImage(HWND hWnd, UINT id, UINT index, UINT icon);
void LvSetItemImageByImageListId(HWND hWnd, UINT id, UINT index, UINT image);
void LvDeleteItem(HWND hWnd, UINT id, UINT index);
UINT LvNum(HWND hWnd, UINT id);
void *LvGetParam(HWND hWnd, UINT id, UINT index);
wchar_t *LvGetStr(HWND hWnd, UINT id, UINT index, UINT pos);
char *LvGetStrA(HWND hWnd, UINT id, UINT index, UINT pos);
void LvShow(HWND hWnd, UINT id, UINT index);
UINT LvSearchParam(HWND hWnd, UINT id, void *param);
UINT LvSearchStr(HWND hWnd, UINT id, UINT pos, wchar_t *str);
UINT LvSearchStrA(HWND hWnd, UINT id, UINT pos, char *str);
UINT LvGetSelected(HWND hWnd, UINT id);
void *LvGetSelectedParam(HWND hWnd, UINT id);
UINT LvGetFocused(HWND hWnd, UINT id);
wchar_t *LvGetFocusedStr(HWND hWnd, UINT id, UINT pos);
wchar_t *LvGetSelectedStr(HWND hWnd, UINT id, UINT pos);
char *LvGetSelectedStrA(HWND hWnd, UINT id, UINT pos);
bool LvIsSelected(HWND hWnd, UINT id);
UINT LvGetNextMasked(HWND hWnd, UINT id, UINT start);
bool LvIsMasked(HWND hWnd, UINT id);
bool LvIsSingleSelected(HWND hWnd, UINT id);
bool LvIsMultiMasked(HWND hWnd, UINT id);
UINT LvGetMaskedNum(HWND hWnd, UINT id);
void LvAutoSize(HWND hWnd, UINT id);
void LvSelect(HWND hWnd, UINT id, UINT index);
void LvSelectByParam(HWND hWnd, UINT id, void *param);
void LvSelectAll(HWND hWnd, UINT id);
void LvSwitchSelect(HWND hWnd, UINT id);
void LvSetView(HWND hWnd, UINT id, bool details);
UINT LvGetColumnWidth(HWND hWnd, UINT id, UINT index);
void CheckCertDlg(UI_CHECKCERT *p);
UINT CheckCertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void PrintCheckCertInfo(HWND hWnd, UI_CHECKCERT *p);
void ShowDlgDiffWarning(HWND hWnd, UI_CHECKCERT *p);
void CheckCertDialogOnOk(HWND hWnd, UI_CHECKCERT *p);
bool ConnectErrorDlg(UI_CONNECTERROR_DLG *p);
UINT ConnectErrorDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
HINSTANCE GetUiDll();
HICON LoadLargeIconInner(UINT id);
HICON LoadSmallIconInner(UINT id);
HICON LoadLargeIcon(UINT id);
HICON LoadSmallIcon(UINT id);
HICON LoadIconEx(UINT id, bool small_icon);
void InitIconCache();
void FreeIconCache();
LVB *LvInsertStart();
void LvInsertAdd(LVB *b, UINT icon, void *param, UINT num_str, ...);
void LvInsertEnd(LVB *b, HWND hWnd, UINT id);
void LvInsertEndEx(LVB *b, HWND hWnd, UINT id, bool force_reset);
void LvSetStyle(HWND hWnd, UINT id, UINT style);
void LvRemoveStyle(HWND hWnd, UINT id, UINT style);
HMENU LoadSubMenu(UINT menu_id, UINT pos, HMENU *parent_menu);
UINT GetMenuItemPos(HMENU hMenu, UINT id);
void DeleteMenuItem(HMENU hMenu, UINT pos);
void SetMenuItemEnable(HMENU hMenu, UINT pos, bool enable);
void SetMenuItemBold(HMENU hMenu, UINT pos, bool bold);
wchar_t *GetMenuStr(HMENU hMenu, UINT pos);
char *GetMenuStrA(HMENU hMenu, UINT pos);
void SetMenuStr(HMENU hMenu, UINT pos, wchar_t *str);
void SetMenuStrA(HMENU hMenu, UINT pos, char *str);
void RemoveShortcutKeyStrFromMenu(HMENU hMenu);
UINT GetMenuNum(HMENU hMenu);
void PrintMenu(HWND hWnd, HMENU hMenu);
void LvRename(HWND hWnd, UINT id, UINT pos);
void AllowFGWindow(UINT process_id);
HWND SearchWindow(wchar_t *caption);
char *RemoteDlg(HWND hWnd, char *regkey, UINT icon, wchar_t *caption, wchar_t *title, char *default_host);
LIST *ReadCandidateFromReg(UINT root, char *key, char *name);
void WriteCandidateToReg(UINT root, char *key, LIST *o, char *name);
UINT LvGetColumnNum(HWND hWnd, UINT id);
void LvSetItemParamEx(HWND hWnd, UINT id, UINT index, UINT subitem, void *param);
void LvSortEx(HWND hWnd, UINT id, UINT subitem, bool desc, bool numeric);
void LvSort(HWND hWnd, UINT id, UINT subitem, bool desc);
void *LvGetParamEx(HWND hWnd, UINT id, UINT index, UINT subitem);
void LvSortHander(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT id);
void LvStandardHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT id);
void IpSet(HWND hWnd, UINT id, UINT ip);
UINT IpGet(HWND hWnd, UINT id);
void IpClear(HWND hWnd, UINT id);
bool IpIsFilled(HWND hWnd, UINT id);
UINT IpGetFilledNum(HWND hWnd, UINT id);
void About(HWND hWnd, CEDAR *cedar, wchar_t *product_name);
void AboutEx(HWND hWnd, CEDAR *cedar, wchar_t *product_name, WINUI_UPDATE *u);
void Win9xReboot(HWND hWnd);
void Win9xRebootThread(THREAD *t, void *p);
UINT Win9xRebootDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
wchar_t *StringDlg(HWND hWnd, wchar_t *title, wchar_t *info, wchar_t *def, UINT icon, bool allow_empty, bool allow_unsafe);
char *StringDlgA(HWND hWnd, wchar_t *title, wchar_t *info, char *def, UINT icon, bool allow_empty, bool allow_unsafe);
UINT StringDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void InitDialogInternational(HWND hWnd, void *pparam);
void AdjustWindowAndControlSize(HWND hWnd, bool *need_resize, double *factor_x, double *factor_y);
void GetWindowAndControlSizeResizeScale(HWND hWnd, bool *need_resize, double *factor_x, double *factor_y);
void AdjustDialogXY(UINT *x, UINT *y, UINT dlgfont_x, UINT dlgfont_y);
HFONT GetDialogDefaultFont();
HFONT GetDialogDefaultFontEx(bool meiryo);
void InitMenuInternational(HMENU hMenu, char *prefix);
void InitMenuInternationalUni(HMENU hMenu, char *prefix);
void ShowTcpIpConfigUtil(HWND hWnd, bool util_mode);
void ShowCpu64Warning();
UINT Cpu64DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT TcpIpDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void TcpIpDlgInit(HWND hWnd);
void TcpIpDlgUpdate(HWND hWnd);
UINT TcpMsgDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT KakushiDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void KakushiThread(THREAD *thread, void *param);
KAKUSHI *InitKakushi();
void FreeKakushi(KAKUSHI *k);
void ShowEasterEgg(HWND hWnd);
bool ExecuteHamcoreExe(char *name);
bool IsRegistedToDontShowFreeEditionDialog(char *server_name);
void RegistToDontShowFreeEditionDialog(char *server_name);
void ShowFreeInfoDialog(HWND hWnd, FREEINFO *info);
UINT FreeInfoDialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
FREEINFO *StartFreeInfoDlg(char *server_name);
void FreeInfoThread(THREAD *thread, void *param);
void EndFreeInfoDlg(FREEINFO *info);
bool Win32CnCheckAlreadyExists(bool lock);
void RegistWindowsFirewallAll();
void RegistWindowsFirewallAllEx(char *dir);
void InitVistaWindowTheme(HWND hWnd);
void WinUiDebug(wchar_t *str);
void WinUiDebugInit();
void WinUiDebugFree();
void OnceMsg(HWND hWnd, wchar_t *title, wchar_t *message, bool show_checkbox, UINT icon);
void OnceMsgEx(HWND hWnd, wchar_t *title, wchar_t *message, bool show_checkbox, UINT icon, bool *halt);
UINT GetOnceMsgHash(wchar_t *title, wchar_t *message);
UINT OnceMsgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool CheckBadProcesses(HWND hWnd);
BAD_PROCESS *IsBadProcess(char *exe);
void ShowBadProcessWarning(HWND hWnd, BAD_PROCESS *bad);
void SetFontMeiryo(HWND hWnd, UINT id, UINT font_size);
char *GetMeiryoFontName();
void SetFontDefault(HWND hWnd, UINT id);
HFONT GetMeiryoFont();
HFONT GetMeiryoFontEx(UINT font_size);
HFONT GetMeiryoFontEx2(UINT font_size, bool bold);
bool ShowWindowsNetworkConnectionDialog();
SOCK *WinConnectEx2(HWND hWnd, char *server, UINT port, UINT timeout, UINT icon_id, wchar_t *caption, wchar_t *info, bool try_start_ssl, bool ssl_no_tls);
SOCK *WinConnectEx3(HWND hWnd, char *server, UINT port, UINT timeout, UINT icon_id, wchar_t *caption, wchar_t *info, UINT *nat_t_error_code, char *nat_t_svc_name, bool try_start_ssl, bool ssl_no_tls);
UINT WinConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void WinConnectDlgThread(THREAD *thread, void *param);
void NicInfo(UI_NICINFO *info);
UINT NicInfoProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NicInfoInit(HWND hWnd, UI_NICINFO *info);
void NicInfoOnTimer(HWND hWnd, UI_NICINFO *info);
void NicInfoRefresh(HWND hWnd, UI_NICINFO *info);
void NicInfoShowStatus(HWND hWnd, UI_NICINFO *info, wchar_t *msg1, wchar_t *msg2, UINT icon, bool animate);
void NicInfoCloseAfterTime(HWND hWnd, UI_NICINFO *info, UINT tick);

WIZARD *NewWizard(UINT icon, UINT bitmap, wchar_t *caption, void *param);
void FreeWizard(WIZARD *w);
WIZARD_PAGE *NewWizardPage(UINT id, WINUI_WIZARD_PROC *proc, wchar_t *title);
void FreeWizardPage(WIZARD_PAGE *p);
void AddWizardPage(WIZARD *w, WIZARD_PAGE *p);
WIZARD_PAGE *GetWizardPage(WIZARD *w, UINT id);
UINT GetWizardPageIndex(WIZARD *w, UINT id);
void *CreateWizardPageInstance(WIZARD *w, WIZARD_PAGE *p);
void ShowWizard(HWND hWndParent, WIZARD *w, UINT start_id);
void SetWizardButton(WIZARD_PAGE *p, bool enable_next, bool enable_back, bool enable_close, bool is_finish);
void SetWizardButtonEx(WIZARD_PAGE *p, bool enable_next, bool enable_back, bool enable_close, bool is_finish, bool shield_icon);
void JumpWizard(WIZARD_PAGE *p, UINT next_id);
void CloseWizard(WIZARD_PAGE *p);
void SetUacIcon(HWND hWnd, UINT id);

LIST *NewBitmapList();
void FreeBitmapList(LIST *o);

bool GetBitmapSize(void *bmp, UINT *x, UINT *y);

bool GetFontParam(HFONT hFont, struct FONT *f);
void AdjustFontSize(HWND hWnd, UINT id);
bool IsFontFitInRect(struct FONT *f, UINT width, UINT height, wchar_t *text, UINT format, bool *aborted);

void ShowTextFile(HWND hWnd, char *filename, wchar_t *caption, UINT icon);


//////////////////////////////////////////////////////////////////////////
// CM.h



// Constants
#define	CM_REG_KEY			"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Client Manager"
#define	SECURE_MANAGER_KEY	"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\SmartCard Manager"
#define	CM_TRAFFIC_REG_KEY	"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Traffic Test Tool"
#define	CM_VGC_REG_KEY		"Software\\University of Tsukuba\\VPN Gate Client Plugin"


#define	CM_TRY_EXEC_UI_HELPER_INTERVAL		5000

#define	CM_DEFAULT_WIDTH	800
#define	CM_DEFAULT_HEIGHT	600

#define	WM_CM_NOTIFY		(WM_APP + 999)

#define	CM_IMPORT_FILENAME_MSG	1267
#define	CM_IMPORT_FILENAME_MSG_OVERWRITE	1268

#define	CM_NUM_RECENT		8

#define	PUBLIC_SERVER_HTML	"http://www.softether.com/jp/special/se2hub.aspx"
#define PUBLIC_SERVER_HTML_EN "http://www.softether.com/jp/special/se2hub_en.aspx"
#define	PUBLIC_SERVER_TAG	L"help:no; status:no; DialogWidth:600px; dialogHeight=700px"
#define	PUBLIC_SERVER_NAME	"public.softether.com"

#define	VOICE_SSK			0	// ssk
#define	VOICE_AHO			1	// aho

// The code for external export

// Structure

// Function prototype
void CMExec();
void CmTraffic(HWND hWnd);
void *CmStartUacHelper();
void CmStopUacHelper(void *p);
void *CmExecUiHelperMain();
UINT CmGetSecureBitmapId(char *dest_hostname);


//////////////////////////////////////////////////////////////////////////
// SM.h

void SMExec();

//////////////////////////////////////////////////////////////////////////
// NM.h

// External function
void NMExec();

//////////////////////////////////////////////////////////////////////////
// EM.h

// Public function
void EMExec();

//////////////////////////////////////////////////////////////////////////
// UT.h


// Function prototype
void UtSpeedMeter();
void UtSpeedMeterEx(void *hWnd);

//////////////////////////////////////////////////////////////////////////
// SW.h


#define	SW_REG_KEY					"Software\\" GC_REG_COMPANY_NAME "\\Setup Wizard Settings"


UINT SWExec();
UINT SWExecMain();
LIST *SwNewSfxFileList();
void SwFreeSfxFileList(LIST *o);
bool SwAddBasicFilesToList(LIST *o, char *component_name);
bool SwCompileSfx(LIST *o, wchar_t *dst_filename);
bool SwGenSfxModeMain(char *mode, wchar_t *dst);
bool SwWaitForVpnClientPortReady(UINT timeout);



//////////////////////////////////////////////////////////////////////////
// Win32Com.h


// For external function

#pragma comment(lib,"htmlhelp.lib")
#pragma comment(lib,"Urlmon.lib")

#if	defined(__cplusplus)
extern "C"
{
#endif

	void ShowHtml(HWND hWnd, char *url, wchar_t *option);
	bool CreateLink(wchar_t *filename, wchar_t *target, wchar_t *workdir, wchar_t *args,
		wchar_t *comment, wchar_t *icon, UINT icon_index);
	wchar_t *FolderDlgW(HWND hWnd, wchar_t *title, wchar_t *default_dir);
	char *FolderDlgA(HWND hWnd, wchar_t *title, char *default_dir);

	bool InstallNdisProtocolDriver(wchar_t *inf_path, wchar_t *id, UINT lock_timeout);
	bool UninstallNdisProtocolDriver(wchar_t *id, UINT lock_timeout);

	bool Win32UPnPAddPort(UINT outside_port, UINT inside_port, bool udp, char *local_ip, wchar_t *description, bool remove_before_add);

	//////////////////////////////////////////////////////////////////////////
	//JumpList

	//Application ID for VPN Client Manager
#define APPID_CM GC_UI_APPID_CM


	//////////////////////////////////////////////////////////////////////////
	//DrawImage
	// 

#if	defined(__cplusplus)

	typedef UCHAR ct_uchar;
	typedef char ct_char;

#define ct_max(a,b) (((a) > (b)) ? (a): (b))
#define ct_min(a,b) (((a) < (b)) ? (a): (b))
#define ct_clamp(n,mi,ma) (ct_max(ct_min((n),(ma)),(mi)))
#define ct_clamp01(n) ct_clamp(n,0,1)

	/**
	* Union representing 32-bit color with alpha channel.
	* CT_Color32, CT_AHSV32, CT_AYCbCr32 are also the same.
	*
	*/
	typedef union CT_ARGB32
	{
	public:

		/** 32-bit integer intensity */
		UINT ARGB;

		/** RGB Color System */
		struct
		{
			ct_uchar B;
			ct_uchar G;
			ct_uchar R;
			ct_uchar A;
		};

		/** HSV Color System */
		struct HSVA
		{
			ct_uchar V;
			ct_uchar S;
			ct_uchar H;
			ct_uchar A;
		}HSVA;

		/** YCbCr Color System */
		struct  YCbCrA
		{
			ct_uchar Y;
			ct_char Cb;
			ct_char Cr;
			ct_uchar A;
		}YCbCrA;


		/** Default constructor */
		CT_ARGB32() {}

		/** Constructor to initialize by specified color.
		* @param a Alpha channel
		* @param r Red, Hue, Cr
		* @param g Green, Saturation, Cb
		* @param b Blue, Value, Y
		*/
		CT_ARGB32(ct_uchar a, ct_uchar r, ct_uchar g, ct_uchar b)
		{
			A = a;
			R = r;
			G = g;
			B = b;
		}



	}CT_ARGB32;


	class CT_Size
	{
	public:
		int Width;
		int Height;

		CT_Size(int w, int h)
		{
			Width = w;
			Height = h;
		}
	};

	class CT_Rect
	{
	public:
		int X;
		int Y;
		int Width;
		int Height;

		CT_Rect()
		{
			X = 0;
			Y = 0;
			Width = 0;
			Height = 0;
		}

		CT_Rect(int x, int y, int w, int h)
		{
			X = x;
			Y = y;
			Width = w;
			Height = h;
		}

		int Right() { return X + Width; }
		int Bottom() { return Y + Height; }

		void Right(int r) { Width = r - X; }
		void Bottom(int b) { Height = b - Y; }

	};



#endif //__cplusplus

	typedef struct CT_RectF_c
	{
		float X;
		float Y;
		float Width;
		float Height;
	} CT_RectF_c;

	void CT_DrawImage(UCHAR* dest, CT_RectF_c destRect, int destWidth, int destHeight,
		UCHAR* src, CT_RectF_c srcRect, int srcWidth, int srcHeight);



#if	defined(__cplusplus)
}
#endif


//EXTERN_C const IID IID_IObjectCollection;
//EXTERN_C const IID IID_ICustomDestinationList;

#if defined(__cplusplus)


#ifndef	__IObjectArray_INTERFACE_DEFINED__
#define	__IObjectArray_INTERFACE_DEFINED__

MIDL_INTERFACE("92CA9DCD-5622-4bba-A805-5E9F541BD8C9")
IObjectArray : public IUnknown
{
public:
	virtual HRESULT STDMETHODCALLTYPE GetCount(
		/* [out] */ __RPC__out UINT *pcObjects) = 0;

	virtual HRESULT STDMETHODCALLTYPE GetAt(
		/* [in] */ UINT uiIndex,
		/* [in] */ __RPC__in REFIID riid,
		/* [iid_is][out] */ __RPC__deref_out_opt void **ppv) = 0;

};

MIDL_INTERFACE("5632b1a4-e38a-400a-928a-d4cd63230295")
IObjectCollection : public IObjectArray
{
public:
	virtual HRESULT STDMETHODCALLTYPE AddObject(
		/* [in] */ __RPC__in_opt IUnknown *punk) = 0;

	virtual HRESULT STDMETHODCALLTYPE AddFromArray(
		/* [in] */ __RPC__in_opt IObjectArray *poaSource) = 0;

	virtual HRESULT STDMETHODCALLTYPE RemoveObjectAt(
		/* [in] */ UINT uiIndex) = 0;

	virtual HRESULT STDMETHODCALLTYPE Clear(void) = 0;

};

#endif	// __IObjectArray_INTERFACE_DEFINED__

#ifndef	__ICustomDestinationList_INTERFACE_DEFINED__
#define	__ICustomDestinationList_INTERFACE_DEFINED__

typedef /* [v1_enum] */
enum KNOWNDESTCATEGORY
{
	KDC_FREQUENT = 1,
	KDC_RECENT = (KDC_FREQUENT + 1)
} 	KNOWNDESTCATEGORY;

MIDL_INTERFACE("6332debf-87b5-4670-90c0-5e57b408a49e")
ICustomDestinationList : public IUnknown
{
public:
	virtual HRESULT STDMETHODCALLTYPE SetAppID(
		/* [string][in] */ __RPC__in_string LPCWSTR pszAppID) = 0;

	virtual HRESULT STDMETHODCALLTYPE BeginList(
		/* [out] */ __RPC__out UINT *pcMinSlots,
		/* [in] */ __RPC__in REFIID riid,
		/* [iid_is][out] */ __RPC__deref_out_opt void **ppv) = 0;

	virtual HRESULT STDMETHODCALLTYPE AppendCategory(
		/* [string][in] */ __RPC__in_string LPCWSTR pszCategory,
		/* [in] */ __RPC__in_opt IObjectArray *poa) = 0;

	virtual HRESULT STDMETHODCALLTYPE AppendKnownCategory(
		/* [in] */ KNOWNDESTCATEGORY category) = 0;

	virtual HRESULT STDMETHODCALLTYPE AddUserTasks(
		/* [in] */ __RPC__in_opt IObjectArray *poa) = 0;

	virtual HRESULT STDMETHODCALLTYPE CommitList(void) = 0;

	virtual HRESULT STDMETHODCALLTYPE GetRemovedDestinations(
		/* [in] */ __RPC__in REFIID riid,
		/* [iid_is][out] */ __RPC__deref_out_opt void **ppv) = 0;

	virtual HRESULT STDMETHODCALLTYPE DeleteList(
		/* [string][unique][in] */ __RPC__in_opt_string LPCWSTR pszAppID) = 0;

	virtual HRESULT STDMETHODCALLTYPE AbortList(void) = 0;

};


#endif	// __ICustomDestinationList_INTERFACE_DEFINED__


#endif //defined(__cplusplus)



#endif	// OS_WIN32


//////////////////////////////////////////////////////////////////////////
// Cedar.h

TRAFFIC *NewTraffic();
void FreeTraffic(TRAFFIC *t);
CEDAR *NewCedar(X *server_x, K *server_k);
void CedarForceLink();
void SetCedarVpnBridge(CEDAR *c);
void SetCedarCert(CEDAR *c, X *server_x, K *server_k);
void ReleaseCedar(CEDAR *c);
void CleanupCedar(CEDAR *c);
void StopCedar(CEDAR *c);
void AddListener(CEDAR *c, LISTENER *r);
void StopAllListener(CEDAR *c);
void AddTraffic(TRAFFIC *dst, TRAFFIC *diff);
void AddHub(CEDAR *c, HUB *h);
void DelHub(CEDAR *c, HUB *h);
void DelHubEx(CEDAR *c, HUB *h, bool no_lock);
void StopAllHub(CEDAR *c);
void StopAllConnection(CEDAR *c);
void AddConnection(CEDAR *cedar, CONNECTION *c);
UINT GetUnestablishedConnections(CEDAR *cedar);
void DelConnection(CEDAR *cedar, CONNECTION *c);
void SetCedarCipherList(CEDAR *cedar, char *name);
void InitCedar();
void FreeCedar();
void AddCa(CEDAR *cedar, X *x);
bool DeleteCa(CEDAR *cedar, UINT ptr);
bool CheckSignatureByCa(CEDAR *cedar, X *x);
bool CheckSignatureByCaLinkMode(SESSION *s, X *x);
X *FindCaSignedX(LIST *o, X *x);
void InitNetSvcList(CEDAR *cedar);
void FreeNetSvcList(CEDAR *cedar);
int CompareNetSvc(void *p1, void *p2);
char *GetSvcName(CEDAR *cedar, bool udp, UINT port);
void InitHiddenPassword(char *str, UINT size);
bool IsHiddenPasswordChanged(char *str);
UINT64 GetTrafficPacketSize(TRAFFIC *t);
UINT64 GetTrafficPacketNum(TRAFFIC *t);
void EnableDebugLog(CEDAR *c);
void StartCedarLog();
void StopCedarLog();
void CedarLog(char *str);
int CompareNoSslList(void *p1, void *p2);
void InitNoSslList(CEDAR *c);
void FreeNoSslList(CEDAR *c);
bool AddNoSsl(CEDAR *c, IP *ip);
void DecrementNoSsl(CEDAR *c, IP *ip, UINT num_dec);
void DeleteOldNoSsl(CEDAR *c);
NON_SSL *SearchNoSslList(CEDAR *c, IP *ip);
bool IsInNoSsl(CEDAR *c, IP *ip);
void FreeTinyLog(TINY_LOG *t);
void WriteTinyLog(TINY_LOG *t, char *str);
TINY_LOG *NewTinyLog();
void GetWinVer(RPC_WINVER *v);
bool IsSupportedWinVer(RPC_WINVER *v);
bool IsLaterBuild(CEDAR *c, UINT64 t);
SOCK *GetInProcListeningSock(CEDAR *c);
SOCK *GetReverseListeningSock(CEDAR *c);
void GetCedarVersion(char *tmp, UINT size);
UINT64 GetCurrentBuildDate();
void CedarAddCurrentTcpQueueSize(CEDAR *c, int diff);
UINT CedarGetCurrentTcpQueueSize(CEDAR *c);
void CedarAddQueueBudget(CEDAR *c, int diff);
void CedarAddFifoBudget(CEDAR *c, int diff);
UINT CedarGetQueueBudgetConsuming(CEDAR *c);
UINT CedarGetFifoBudgetConsuming(CEDAR *c);
UINT CedarGetQueueBudgetBalance(CEDAR *c);
UINT CedarGetFifoBudgetBalance(CEDAR *c);
bool CedarIsThereAnyEapEnabledRadiusConfig(CEDAR *c);



#ifdef	OS_WIN32
#ifdef	SECLIB_C

//////////////////////////////////////////////////////////////////////////
// CMInner.h



#define STARTUP_MUTEX_NAME	GC_SW_SOFTETHER_PREFIX "vpncmgr_startup_mutex"

#define	NAME_OF_VPN_CLIENT_MANAGER	"vpncmgr"

void CmVoice(char *name);

typedef struct CM_UAC_HELPER
{
	THREAD *Thread;
	volatile bool Halt;
	EVENT *HaltEvent;
} CM_UAC_HELPER;

typedef struct CM_VOICE
{
	UINT voice_id;
	char *perfix;
} CM_VOICE;

static CM_VOICE cm_voice[] =
{
	{VOICE_SSK,		"ssk"		},
	{VOICE_AHO,		"aho"		},
};

typedef struct CM_ENUM_HUB
{
	HWND hWnd;
	THREAD *Thread;
	SESSION *Session;
	CLIENT_OPTION *ClientOption;
	TOKEN_LIST *Hub;
} CM_ENUM_HUB;

#define CM_SETTING_INIT_NONE		0
#define CM_SETTING_INIT_EASY		1	// Transition to the simple mode
#define CM_SETTING_INIT_NORMAL		2	// Transition to the normal mode
#define CM_SETTING_INIT_SELECT		3	// Show a selection screen
#define	CM_SETTING_INIT_CONNECT		4	// Import process by the simple installer

typedef struct CM
{
	HWND hMainWnd;
	HWND hStatusBar;
	REMOTE_CLIENT *Client;
	char *server_name;
	char *password;
	wchar_t *import_file_name;
	bool HideStatusBar;
	bool HideTrayIcon;
	bool ShowGrid;
	bool VistaStyle;
	bool ShowPort;
	wchar_t StatudBar1[MAX_SIZE];
	wchar_t StatudBar2[MAX_SIZE];
	wchar_t StatudBar3[MAX_SIZE];
	HICON Icon2, Icon3;
	bool IconView;
	THREAD *NotifyClientThread;
	NOTIFY_CLIENT *NotifyClient;
	volatile bool Halt;
	bool OnCloseDispatched;
	LIST *StatusWindowList;
	CEDAR *Cedar;
	LIST *EnumHubList;
	UINT WindowCount;
	bool DisableVoice;
	UINT VoiceId;
	UINT OldConnectedNum;
	bool UpdateConnectedNumFlag;
	UCHAR ShortcutKey[SHA1_SIZE];
	bool TrayInited;
	bool TraySucceed;
	bool TrayAnimation;
	bool TraySpeedAnimation;
	UINT TrayAnimationCounter;
	bool StartupMode;
	THREAD *TryExecUiHelperThread;
	volatile bool TryExecUiHelperHalt;
	HANDLE TryExecUiHelperProcessHandle;
	EVENT *TryExecUiHelperHaltEvent;
	bool WindowsShutdowning;
	bool CmSettingSupported;
	bool CmEasyModeSupported;
	bool CmSettingInitialFlag;
	CM_SETTING CmSetting;
	HWND hEasyWnd;
	bool StartupFinished;
	bool ConnectStartedFlag;
	bool PositiveDisconnectFlag;
	wchar_t EasyLastSelectedAccountName[MAX_ACCOUNT_NAME_LEN + 1];
	WINDOWPLACEMENT FakeWindowPlacement;
	bool CheckedAndShowedAdminPackMessage;
	INSTANCE *StartupMutex;
	bool BadProcessChecked;
	bool MenuPopuping;
	WINUI_UPDATE *Update;
} CM;

typedef struct CM_STATUS
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];		// Account name
	HWND hWndPolicy;					// Policy dialog
} CM_STATUS;

typedef struct CM_POLICY
{
	HWND hWnd;
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];		// Account name
	POLICY *Policy;						// Policy dialog
	CM_STATUS *CmStatus;				// CM_STATUS
	bool Extension;						// Extension
} CM_POLICY;

typedef struct CM_ACCOUNT
{
	bool EditMode;						// Edit mode (false: New mode)
	bool LinkMode;						// Link mode
	bool NatMode;						// NAT mode
	CLIENT_OPTION *ClientOption;		// Client option
	CLIENT_AUTH *ClientAuth;			// Authentication data
	bool Startup;						// Startup account
	bool CheckServerCert;				// Check the server certificate
	X *ServerCert;						// Server certificate
	char old_server_name[MAX_HOST_NAME_LEN + 1];	// Old server name
	bool Inited;						// Initialization flag
	POLICY Policy;						// Policy (only link mode)
	struct SM_HUB *Hub;					// HUB
	RPC *Rpc;							// RPC
	bool OnlineFlag;					// Online flag
	bool Flag1;							// Flag 1
	bool HideClientCertAuth;			// Hide the client authentication
	bool HideSecureAuth;				// Hide the smart card authentication
	bool HideTrustCert;					// Hide the trusted certificate authority button
	UCHAR ShortcutKey[SHA1_SIZE];		// Shortcut key
	bool LockMode;						// Setting lock mode
	bool Link_ConnectNow;				// Start the connection immediately
	UINT PolicyVer;						// Policy version
} CM_ACCOUNT;

typedef struct CM_CHANGE_PASSWORD
{
	CLIENT_OPTION *ClientOption;		// Client Option
	char Username[MAX_USERNAME_LEN + 1];	// User name
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB name
} CM_CHANGE_PASSWORD;

typedef struct CM_TRAFFIC
{
	bool ServerMode;		// Server mode
	bool Double;			// 2x mode
	bool Raw;				// Raw data mode
	UINT Port;				// Port number
	char Host[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT NumTcp;			// Number of TCP connections
	UINT Type;				// Type
	UINT Span;				// Period
} CM_TRAFFIC;

typedef struct CM_TRAFFIC_DLG
{
	HWND hWnd;				// Window handle
	CM_TRAFFIC *Setting;	// Setting
	TTS *Tts;				// Measurement server
	TTC *Ttc;				// Measurement client
	THREAD *HaltThread;		// Thread for stopping
	THREAD *ClientEndWaitThread;	// Thread to wait for the client to finish
	bool Started;			// Started flag
	bool Stopping;			// Stopping
	UINT RetCode;			// Return value
	TT_RESULT Result;		// Result
	EVENT *ResultShowEvent;	// Display result event
	bool CloseDialogAfter;	// Flag of whether or not to close the dialog
} CM_TRAFFIC_DLG;

// Internet connection settings
typedef struct CM_INTERNET_SETTING
{
	UINT ProxyType;								// Type of proxy server
	char ProxyHostName[MAX_HOST_NAME_LEN + 1];	// Proxy server host name
	UINT ProxyPort;								// Proxy server port number
	char ProxyUsername[MAX_USERNAME_LEN + 1];	// Proxy server user name
	char ProxyPassword[MAX_USERNAME_LEN + 1];	// Proxy server password
} CM_INTERNET_SETTING;

static CM *cm = NULL;

void CmFreeTrayExternal(void *hWnd);

// Normal RPC call macro
__forceinline static bool CALL(HWND hWnd, UINT code)
{
	UINT ret = code;
	if (ret != ERR_NO_ERROR)
	{
		if (ret == ERR_DISCONNECTED)
		{
			if (cm != NULL)
			{
				Close(cm->hMainWnd);
			}
			else
			{
				MsgBox(hWnd, MB_ICONSTOP, _UU("SM_DISCONNECTED"));
			}

			if (cm != NULL)
			{
				CmFreeTrayExternal((void *)cm->hMainWnd);
			}
			exit(0);
		}
		else
		{
			UINT flag = MB_ICONEXCLAMATION;
			if (ret == ERR_VLAN_IS_USED)
			{
				CmVoice("using_vlan");
			}
			if (hWnd != NULL && cm != NULL && cm->hEasyWnd != NULL)
			{
				hWnd = cm->hEasyWnd;
			}
			if (hWnd != NULL && cm != NULL && hWnd == cm->hEasyWnd)
			{
				flag |= MB_SETFOREGROUND | MB_TOPMOST;
			}
			MsgBox(hWnd, flag, _E(ret));
		}
	}

	if (ret == ERR_NO_ERROR)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Extended RPC call macro (get an error value)
__forceinline static UINT CALLEX(HWND hWnd, UINT code)
{
	UINT ret = code;
	if (ret != ERR_NO_ERROR)
	{
		if (ret == ERR_DISCONNECTED)
		{
			if (cm != NULL)
			{
				Close(cm->hMainWnd);
			}
			else
			{
				MsgBox(hWnd, MB_ICONSTOP, _UU("SM_DISCONNECTED"));
			}
			if (cm != NULL)
			{
				CmFreeTrayExternal((void *)cm->hMainWnd);
			}
			exit(0);
		}
	}

	return ret;
}

typedef struct CM_LOADX
{
	X *x;
} CM_LOADX;

typedef struct CM_SETTING_DLG
{
	bool CheckPassword;
	UCHAR HashedPassword[SHA1_SIZE];
} CM_SETTING_DLG;

typedef struct CM_EASY_DLG
{
	bool EndDialogCalled;
} CM_EASY_DLG;



// Task tray related
#define	WM_CM_TRAY_MESSAGE			(WM_APP + 44)
#define WM_CM_SETTING_CHANGED_MESSAGE	(WM_APP + 45)
#define WM_CM_EASY_REFRESH			(WM_APP + 46)
#define WM_CM_SHOW					(WM_APP + 47)
#define	CMD_EASY_DBLCLICK			40697
#define	CMD_VGC_CONNECT				40698
#define	CM_TRAY_ANIMATION_INTERVAL	3000
#define	CM_TRAY_MAX_ITEMS			4096
#define	CM_TRAY_MENU_ID_START		12000
#define	CM_TRAY_MENU_CONNECT_ID_START	(CM_TRAY_MENU_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_MENU_STATUS_ID_START	(CM_TRAY_MENU_CONNECT_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_MENU_DISCONNECT_ID_START	(CM_TRAY_MENU_STATUS_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_MENU_RECENT_ID_START	(CM_TRAY_MENU_DISCONNECT_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_IS_CONNECT_ID(id)	(((id) >= CM_TRAY_MENU_CONNECT_ID_START) && (id) < CM_TRAY_MENU_STATUS_ID_START)
#define	CM_TRAY_IS_STATUS_ID(id)	(((id) >= CM_TRAY_MENU_STATUS_ID_START) && (id) < CM_TRAY_MENU_DISCONNECT_ID_START)
#define	CM_TRAY_IS_DISCONNECT_ID(id)	(((id) >= CM_TRAY_MENU_DISCONNECT_ID_START) && (id) < (CM_TRAY_MENU_DISCONNECT_ID_START + CM_TRAY_MAX_ITEMS))
#define	CM_TRAY_IS_RECENT_ID(id)	(((id) >= CM_TRAY_MENU_RECENT_ID_START) && (id) < (CM_TRAY_MENU_RECENT_ID_START + CM_TRAY_MAX_ITEMS))


// Function prototype
void InitCM(bool set_app_id);
void FreeCM();
void MainCM();
bool LoginCM();
void LogoutCM();
UINT CmLoginDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void MainCMWindow();
void CmSendImportMessage(HWND hWnd, wchar_t *filename, UINT msg);
UINT CmMainWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmMainWindowOnSize(HWND hWnd);
void CmMainWindowOnInit(HWND hWnd);
void CmMainWindowOnQuit(HWND hWnd);
void CmSaveMainWindowPos(HWND hWnd);
void CmMainWindowOnCommand(HWND hWnd, WPARAM wParam, LPARAM lParam);
void CmMainWindowOnCommandEx(HWND hWnd, WPARAM wParam, LPARAM lParam, bool easy);
bool CmIsEnabled(HWND hWnd, UINT id);
bool CmIsChecked(UINT id);
bool CmIsBold(UINT id);
void CmMainWindowOnPopupMenu(HWND hWnd, HMENU hMenu, UINT pos);
void CmSaveMainWindowPos(HWND hWnd);
void CmRedrawStatusBar(HWND hWnd);
void CmRefresh(HWND hWnd);
void CmRefreshEx(HWND hWnd, bool style_changed);
void CmSetForegroundProcessToCnService();
void CmInitAccountList(HWND hWnd);
void CmInitAccountListEx(HWND hWnd, bool easy);
void CmInitVLanList(HWND hWnd);
void CmRefreshAccountList(HWND hWnd);
void CmRefreshAccountListEx(HWND hWnd, bool easy);
void CmRefreshAccountListEx2(HWND hWnd, bool easy, bool style_changed);
void CmRefreshVLanList(HWND hWnd);
void CmRefreshVLanListEx(HWND hWnd, bool style_changed);
void CmSaveAccountListPos(HWND hWnd);
void CmSaveVLanListPos(HWND hWnd);
wchar_t *CmGetProtocolName(UINT n);
void CmVLanNameToPrintName(char *str, UINT size, char *name);
bool CmPrintNameToVLanName(char *name, UINT size, char *str);
void CmMainWindowOnNotify(HWND hWnd, NMHDR *n);
void CmOnKey(HWND hWnd, bool ctrl, bool alt, UINT key);
void CmAccountListRightClick(HWND hWnd);
void CmVLanListRightClick(HWND hWnd);
void CmConnect(HWND hWnd, wchar_t *account_name);
void CmDisconnect(HWND hWnd, wchar_t *account_name);
void CmInitNotifyClientThread();
void CmFreeNotifyClientThread();
void CmNotifyClientThread(THREAD *thread, void *param);
void CmDeleteAccount(HWND hWnd, wchar_t *account_name);
void CmStatus(HWND hWnd, wchar_t *account_name);
void CmStatusDlg(HWND hWnd, wchar_t *account_name);
UINT CmStatusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmStatusDlgPrint(HWND hWnd, CM_STATUS *cmst);
void CmPrintStatusToListView(LVB *b, RPC_CLIENT_GET_CONNECTION_STATUS *s);
void CmPrintStatusToListViewEx(LVB *b, RPC_CLIENT_GET_CONNECTION_STATUS *s, bool server_mode);
void CmStatusDlgPrintCert(HWND hWnd, CM_STATUS *st, bool server);
void CmPolicyDlg(HWND hWnd, CM_STATUS *st);
UINT CmPolicyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmPolicyDlgPrint(HWND hWnd, CM_POLICY *p);
void CmPolicyDlgPrintEx(HWND hWnd, CM_POLICY *p, bool cascade_mode);
void CmPolicyDlgPrintEx2(HWND hWnd, CM_POLICY *p, bool cascade_mode, bool ver);
void CmNewAccount(HWND hWnd);
void CmEditAccount(HWND hWnd, wchar_t *account_name);
void CmGenerateNewAccountName(HWND hWnd, wchar_t *name, UINT size);
void CmGenerateCopyName(HWND hWnd, wchar_t *name, UINT size, wchar_t *old_name);
void CmGenerateImportName(HWND hWnd, wchar_t *name, UINT size, wchar_t *old_name);
CM_ACCOUNT *CmCreateNewAccountObject(HWND hWnd);
CM_ACCOUNT *CmGetExistAccountObject(HWND hWnd, wchar_t *account_name);
void CmEnumHubStart(HWND hWnd, CLIENT_OPTION *o);
void CmInitEnumHub();
void CmFreeEnumHub();
void CmFreeAccountObject(HWND hWnd, CM_ACCOUNT *a);
bool CmEditAccountDlg(HWND hWnd, CM_ACCOUNT *a);
UINT CmEditAccountDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmEditAccountDlgUpdate(HWND hWnd, CM_ACCOUNT *a);
void CmEditAccountDlgInit(HWND hWnd, CM_ACCOUNT *a);
void CmEditAccountDlgOnOk(HWND hWnd, CM_ACCOUNT *a);
void CmEditAccountDlgStartEnumHub(HWND hWnd, CM_ACCOUNT *a);
bool CmLoadXAndK(HWND hWnd, X **x, K **k);
bool CmLoadK(HWND hWnd, K **k);
bool CmLoadKEx(HWND hWnd, K **k, char *filename, UINT size);
bool CmLoadKExW(HWND hWnd, K **k, wchar_t *filename, UINT size);
bool CmLoadXFromFileOrSecureCard(HWND hWnd, X **x);
void CmLoadXFromFileOrSecureCardDlgInit(HWND hWnd, CM_LOADX *p);
void CmLoadXFromFileOrSecureCardDlgUpdate(HWND hWnd, CM_LOADX *p);
UINT CmLoadXFromFileOrSecureCardDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool CmLoadX(HWND hWnd, X **x);
bool CmLoadXEx(HWND hWnd, X **x, char *filename, UINT size);
bool CmLoadXExW(HWND hWnd, X **x, wchar_t *filename, UINT size);
X *CmGetIssuer(X *x);
bool CmProxyDlg(HWND hWnd, CLIENT_OPTION *a);
void CmProxyDlgUpdate(HWND hWnd, CLIENT_OPTION *a);
UINT CmProxyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool CmDetailDlg(HWND hWnd, CM_ACCOUNT *a);
UINT CmDetailDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
char *CmNewVLanDlg(HWND hWnd);
UINT CmNewVLanDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmCopyAccount(HWND hWnd, wchar_t *account_name);
void CmExportAccount(HWND hWnd, wchar_t *account_name);
void CmSortcut(HWND hWnd, wchar_t *account_name);
void CmImportAccount(HWND hWnd);
void CmImportAccountMain(HWND hWnd, wchar_t *filename);
void CmImportAccountMainEx(HWND hWnd, wchar_t *filename, bool overwrite);
void CmTrustDlg(HWND hWnd);
UINT CmTrustDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrustDlgUpdate(HWND hWnd);
void CmTrustDlgRefresh(HWND hWnd);
void CmTrustImport(HWND hWnd);
void CmTrustExport(HWND hWnd);
void CmTrustView(HWND hWnd);
void CmPassword(HWND hWnd);
UINT CmPasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmPasswordRefresh(HWND hWnd);
void CmRefreshStatusBar(HWND hWnd);
UINT CmGetNumConnected(HWND hWnd);
void CmDisconnectAll(HWND hWnd);
wchar_t *CmGenerateMainWindowTitle();
void CmConfigDlg(HWND hWnd);
UINT CmConfigDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmConfigDlgInit(HWND hWnd);
void CmConfigDlgRefresh(HWND hWnd);
void CmConfigDlgOnOk(HWND hWnd);
bool CmWarningDesktop(HWND hWnd, wchar_t *account_name);
UINT CmDesktopDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmDesktopDlgInit(HWND hWnd, wchar_t *account_name);
bool CmStopInstallVLan(HWND hWnd);
void CmChangePassword(HWND hWnd, CLIENT_OPTION *o, char *hubname, char *username);
UINT CmChangePasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmChangePasswordUpdate(HWND hWnd, CM_CHANGE_PASSWORD *p);
void SmShowPublicVpnServerHtml(HWND hWnd);
void CmConnectShortcut(UCHAR *key);
UINT CmSelectSecure(HWND hWnd, UINT current_id);
void CmClientSecureManager(HWND hWnd);
UINT CmClientSelectSecure(HWND hWnd);
UINT CmSelectSecureDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSelectSecureDlgInit(HWND hWnd, UINT default_id);
void CmSelectSecureDlgUpdate(HWND hWnd);
void CmSecureManager(HWND hWnd, UINT id);
void CmSecureManagerEx(HWND hWnd, UINT id, bool no_new_cert);
UINT CmSecureManagerDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSecureManagerDlgInit(HWND hWnd, UINT id);
void CmSecureManagerDlgUpdate(HWND hWnd, UINT id);
void CmSecureManagerDlgRefresh(HWND hWnd, UINT id);
void CmSecureManagerDlgPrintList(HWND hWnd, LIST *o);
void CmSecureManagerDlgPrintListEx(HWND hWnd, UINT id, LIST *o, UINT type);
wchar_t *CmSecureObjTypeToStr(UINT type);
UINT CmSecureType(HWND hWnd);
UINT CmSecureTypeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSecureManagerDlgImport(HWND hWnd, UINT id);
void CmSecureManagerDlgDelete(HWND hWnd, UINT id);
void CmSecureManagerDlgExport(HWND hWnd, UINT id);
void CmSecureManagerDlgNewCert(HWND hWnd, UINT id);
void CmSecurePin(HWND hWnd, UINT id);
UINT CmSecurePinDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSecurePinDlgUpdate(HWND hWnd);
void CmInitTray(HWND hWnd);
void CmPollingTray(HWND hWnd);
void CmFreeTray(HWND hWnd);
void CmChangeTrayString(HWND hWnd, wchar_t *str);
UINT CmGetTrayIconId(bool animation, UINT animation_counter);
void CmShowOrHideWindow(HWND hWnd);
void CmShowTrayMenu(HWND hWnd);
HMENU CmCreateTraySubMenu(HWND hWnd, bool flag, UINT start_id);
HMENU CmCreateRecentSubMenu(HWND hWnd, UINT start_id);
bool CmCheckPkcsEula(HWND hWnd, UINT id);
UINT CmPkcsEulaDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmDeleteOldStartupTrayFile();
UINT CmTrafficDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrafficDlgInit(HWND hWnd);
bool CmTrafficDlgUpdate(HWND hWnd);
void CmTrafficDlgOnOk(HWND hWnd);
bool CmTrafficLoadFromReg(CM_TRAFFIC *t);
void CmTrafficGetDefaultSetting(CM_TRAFFIC *t);
void CmTrafficSaveToReg(CM_TRAFFIC *t);
void CmTrafficDlgToStruct(HWND hWnd, CM_TRAFFIC *t);
void CmExecTraffic(HWND hWnd, CM_TRAFFIC *t);
UINT CmTrafficRunDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrafficRunDlgInit(HWND hWnd, CM_TRAFFIC_DLG *d);
void CmTrafficRunDlgStart(HWND hWnd, CM_TRAFFIC_DLG *d);
void CmTrafficRunDlgPrintProc(void *param, wchar_t *str);
void CmTrafficRunDlgAddStr(HWND hWnd, wchar_t *str);
void CmTrafficRunDlgHalt(HWND hWnd, CM_TRAFFIC_DLG *d);
void CmTrafficRunDlgHaltThread(THREAD *t, void *param);
void CmTrafficRunDlgClientWaitThread(THREAD *t, void *param);
void CmTrafficResult(HWND hWnd, TT_RESULT *r);
UINT CmTrafficResultDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrafficResultDlgInit(HWND hWnd, TT_RESULT *res);
void CmTryToExecUiHelper();
void CmInitTryToExecUiHelper();
void CmFreeTryToExecUiHelper();
void CmTryToExecUiHelperThread(THREAD *thread, void *param);
bool CmSetting(HWND hWnd);
UINT CmSettingDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSettingDlgInit(HWND hWnd, CM_SETTING_DLG *d);
void CmSettingDlgUpdate(HWND hWnd, CM_SETTING_DLG *d);
void CmSettingDlgOnOk(HWND hWnd, CM_SETTING_DLG *d);
void CmApplyCmSetting();
void CmMainWindowOnTrayClicked(HWND hWnd, WPARAM wParam, LPARAM lParam);
void CmShowEasy();
void CmCloseEasy();
void CmMainWindowOnShowEasy(HWND hWnd);
UINT CmEasyDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmEasyDlgInit(HWND hWnd, CM_EASY_DLG *d);
void CmEasyDlgUpdate(HWND hWnd, CM_EASY_DLG *d);
void CmEasyDlgRefresh(HWND hWnd, CM_EASY_DLG *d);
void CmRefreshEasy();
void CmEasyDlgOnNotify(HWND hWnd, CM_EASY_DLG *d, NMHDR *n);
void CmEasyDlgOnKey(HWND hWnd, CM_EASY_DLG *d, bool ctrl, bool alt, UINT key);
void CmEasyDlgOnCommand(HWND hWnd, CM_EASY_DLG *d, WPARAM wParam, LPARAM lParam);

bool CmStartStartupMutex();
void CmEndStartupMutex();
void CmSetUacWindowActive();
void CmUacHelperThread(THREAD *thread, void *param);
void CmProxyDlgUseForIE(HWND hWnd, CLIENT_OPTION *o);
void CmGetSystemInternetSetting(CM_INTERNET_SETTING *setting);
void CmProxyDlgSet(HWND hWnd, CLIENT_OPTION *o, CM_INTERNET_SETTING *setting);
bool CmGetProxyServerNameAndPortFromIeProxyRegStr(char *name, UINT name_size, UINT *port, char *str, char *server_type);
void *CmUpdateJumpList(UINT start_id);


//////////////////////////////////////////////////////////////////////////
// SMInner.h


// Constants
#define	SM_REG_KEY			"Software\\SoftEther Corporation\\PacketiX VPN\\Server Manager"
#define	SM_CERT_REG_KEY		"Software\\SoftEther Corporation\\PacketiX VPN\\Server Manager\\Cert Tool"
#define	SM_SETTING_REG_KEY	"Software\\SoftEther Corporation\\PacketiX VPN\\Server Manager\\Settings"
#define	SM_LASTHUB_REG_KEY	"Software\\SoftEther Corporation\\PacketiX VPN\\Server Manager\\Last HUB Name"
#define	SM_HIDE_CERT_UPDATE_MSG_KEY	"Software\\SoftEther Corporation\\PacketiX VPN\\Server Manager\\Hide Cert Update Msg"

#define	NAME_OF_VPN_SERVER_MANAGER	"vpnsmgr"
#define	NAME_OF_VPN_SERVER_TARGET	"vpnserver@%s"
#define	NAME_OF_VPN_BRIDGE_TARGET	"vpnbridge@%s"

// Constants (Old value)
#define	SM_SETTING_REG_KEY_OLD	"Software\\SoftEther Corporation\\SoftEther VPN 2.0\\Server Manager\\Settings"

// Connection setting
typedef struct SETTING
{
	wchar_t Title[MAX_SIZE];	// Setting Name
	bool ServerAdminMode;		// Server management mode
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB name
	UCHAR HashedPassword[SHA1_SIZE];	// Password
	CLIENT_OPTION ClientOption;	// Client Option
	UCHAR Reserved[10240 - sizeof(bool) * 8 - SHA1_SIZE];	// Reserved area
} SETTING;

// Structure declaration
typedef struct SM
{
	CEDAR *Cedar;				// Cedar
	LIST *SettingList;			// Setting List
	SETTING *TempSetting;		// Temporaly setting
	HWND hParentWnd;			// Parent window handle
	WINUI_UPDATE *Update;		// Updater
} SM;

// Edit connection settings
typedef struct SM_EDIT_SETTING
{
	bool EditMode;				// Edit mode
	SETTING *OldSetting;		// Pointer to the previous settings
	SETTING *Setting;			// Pointer to the configuration
	bool Inited;				// Initialized flag
} SM_EDIT_SETTING;

// Server management dialog
typedef struct SM_SERVER
{
	RPC *Rpc;					// RPC
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	wchar_t Title[MAX_SIZE];	// Title
	bool ServerAdminMode;		// Server management mode
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB name
	UINT ServerType;			// Type of server
	bool Bridge;				// VPN Bridge product
	UINT PolicyVer;				// Policy version
	RPC_SERVER_STATUS ServerStatus;	// Server status
	RPC_SERVER_INFO ServerInfo;		// Server Information
	CAPSLIST *CapsList;			// Caps list
	SETTING *CurrentSetting;	// The current connection settings
	wchar_t *AdminMsg;			// Message for Administrators
	bool IPsecMessageDisplayed;	// Whether to have already displayed a message about IPsec
	bool VgsMessageDisplayed;	// Whether to have already displayed a message about VGS
	WINUI_UPDATE *Update;		// Update notification
	bool IsInClient;			// Within VPN Client mode
} SM_SERVER;

typedef void (SM_STATUS_INIT_PROC)(HWND hWnd, SM_SERVER *p, void *param);
typedef bool (SM_STATUS_REFRESH_PROC)(HWND hWnd, SM_SERVER *p, void *param);

// Information display dialog
typedef struct SM_STATUS
{
	SM_SERVER *p;				// Pointer to the P
	void *Param;				// Parameter
	UINT Icon;					// Icon
	wchar_t *Caption;			// Title
	bool show_refresh_button;	// Show Updates button
	bool NoImage;				// No image
	SM_STATUS_INIT_PROC *InitProc;
	SM_STATUS_REFRESH_PROC *RefreshProc;
} SM_STATUS;

// Virtual HUB edit dialog
typedef struct SM_EDIT_HUB
{
	SM_SERVER *p;				// P
	bool EditMode;				// Edit mode
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB name
} SM_EDIT_HUB;

// SSL related
typedef struct SM_SSL
{
	SM_SERVER *p;				// P
	X *Cert;					// Certificate
	K *Key;						// Secret key
	bool SetCertAndKey;			// Set the key
} SM_SSL;

// Save the certificate
typedef struct SM_SAVE_KEY_PAIR
{
	X *Cert;					// Certificate
	K *Key;						// Secret key
	char *Pass;					// Passphrase
} SM_SAVE_KEY_PAIR;

// Connection information
typedef struct SM_CONNECTION_INFO
{
	SM_SERVER *p;				// P
	char *ConnectionName;		// Connection name
} SM_CONNECTION_INFO;

// Management of HUB
typedef struct SM_HUB
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	char *HubName;				// HUB name
	char CurrentPushRouteStr[MAX_DHCP_CLASSLESS_ROUTE_TABLE_STR_SIZE];	// Current editing push routing table string
} SM_HUB;

// Show the User list
typedef struct SM_USER
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	char *GroupName;			// Filter by group name
	bool SelectMode;			// Selection mode
	char *SelectedName;			// User name of the selected
	bool AllowGroup;			// Allow selection of group
	bool CreateNow;				// Create a user immediately
} SM_USER;

// Edit the User
typedef struct SM_EDIT_USER
{
	bool Inited;				// Initialized flag
	bool EditMode;				// Edit mode
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	RPC_SET_USER SetUser;		// Configure the User
} SM_EDIT_USER;

// User information
typedef struct SM_USER_INFO
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	char *Username;				// Username
} SM_USER_INFO;

// Policy
typedef struct SM_POLICY
{
	bool Inited;				// Initialize
	POLICY *Policy;				// Policy
	wchar_t *Caption;			// Title
	bool CascadeMode;			// Cascade mode
	UINT Ver;					// Version
} SM_POLICY;

// Show the Group list
typedef struct SM_GROUP
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	bool SelectMode;			// Selection mode
	char *SelectedGroupName;	// Group name of the selected
} SM_GROUP;

// Edit the Group
typedef struct SM_EDIT_GROUP
{
	bool Inited;				// Initialization flag
	bool EditMode;				// Edit mode
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	RPC_SET_GROUP SetGroup;		// Group Settings
} SM_EDIT_GROUP;

// Access list
typedef struct SM_ACCESS_LIST
{
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	LIST *AccessList;			// Access list
} SM_ACCESS_LIST;

// Edit the access list
typedef struct SM_EDIT_ACCESS
{
	SM_HUB *Hub;				// HUB
	bool Inited;				// Initialization flag
	bool EditMode;				// Edit mode
	SM_ACCESS_LIST *AccessList;	// Access list
	ACCESS *Access;				// Access list item
} SM_EDIT_ACCESS;

// Display status of the access list
typedef struct SM_LINK
{
	SM_HUB *Hub;				// HUB
	wchar_t *AccountName;		// Account name
} SM_LINK;

// Session status
typedef struct SM_SESSION_STATUS
{
	SM_HUB *Hub;				// HUB
	char *SessionName;			// Session name
} SM_SESSION_STATUS;

// Address table
typedef struct SM_TABLE
{
	SM_HUB *Hub;				// HUB
	RPC *Rpc;					// RPC
	char *SessionName;			// Session name
} SM_TABLE;

// Certificate tool
typedef struct SM_CERT
{
	X *x;						// Generated certificate
	K *k;						// Generated secret key
	X *root_x;					// Root certificate
	K *root_k;					// Private key of the root certificate
	bool do_not_save;			// Do not save to the file
	char *default_cn;			// Default CN
	bool root_only;				// Only the root certificate
} SM_CERT;

// Config edit
typedef struct SM_CONFIG
{
	SM_SERVER *s;				// SM_SERVER
	RPC_CONFIG Config;			// Config body
} SM_CONFIG;

// Hub_admin_option edit
typedef struct SM_EDIT_AO
{
	SM_EDIT_HUB *e;
	bool CanChange;
	RPC_ADMIN_OPTION CurrentOptions;
	RPC_ADMIN_OPTION DefaultOptions;
	bool NewMode;
	char Name[MAX_ADMIN_OPTION_NAME_LEN + 1];
	UINT Value;
	bool ExtOption;
} SM_EDIT_AO;

// Editing the switch
typedef struct SM_L3SW
{
	SM_SERVER *s;
	char *SwitchName;
	bool Enable;
} SM_L3SW;

// Specify the certificate and private key in the smart card
typedef struct SM_SECURE_KEYPAIR
{
	UINT Id;
	bool UseCert;
	bool UseKey;
	char CertName[MAX_SIZE];
	char KeyName[MAX_SIZE];
	bool Flag;
	UINT BitmapId;
} SM_SECURE_KEYPAIR;

// CRL edit
typedef struct SM_EDIT_CRL
{
	SM_HUB *s;
	bool NewCrl;
	UINT Key;
} SM_EDIT_CRL;

// AC list edit
typedef struct SM_EDIT_AC_LIST
{
	SM_EDIT_HUB *s;
	LIST *AcList;
} SM_EDIT_AC_LIST;

// AC edit
typedef struct SM_EDIT_AC
{
	SM_EDIT_AC_LIST *e;
	UINT id;
} SM_EDIT_AC;

// Download the log File
typedef struct SM_READ_LOG_FILE
{
	HWND hWnd;
	SM_SERVER *s;
	char *server_name;
	char *filepath;
	UINT totalsize;
	bool cancel_flag;
	BUF *Buffer;
} SM_READ_LOG_FILE;

// Setup dialog
typedef struct SM_SETUP
{
	SM_SERVER *s;
	RPC *Rpc;
	bool IsBridge;
	bool UseRemote;			// Remote Access VPN
	bool UseSite;			// LAN-to-LAN VPN
	bool UseSiteEdge;		// VPN Server / Bridge to be installed in each site
	char HubName[MAX_HUBNAME_LEN + 1];	// Virtual HUB name
	bool Flag1;
	bool Flag2;
} SM_SETUP;

// EtherIP ID edit dialog
typedef struct SM_ETHERIP_ID
{
	SM_SERVER *s;
	bool EditMode;
	char EditId[MAX_SIZE];
	bool InitCompleted;
	ETHERIP_ID Data;
} SM_ETHERIP_ID;

// DDNS dialog
typedef struct SM_DDNS
{
	SM_SERVER *s;
	DDNS_CLIENT_STATUS Status;
	bool Flag;
	bool HostnameSetFlag;
	bool Changed;
	bool Silent;
	bool NoChangeCert;
	bool DoNotPoll;
} SM_DDNS;

// VPN Azure dialog
typedef struct SM_AZURE
{
	SM_SERVER *s;
	bool OnSetup;
} SM_AZURE;



// Function prototype
void InitSM();
void InitSMEx(bool from_cm);
void SmParseCommandLine();
void MainSM();
void FreeSM();
void FreeSMEx(bool from_cm);
void SmMainDlg();
UINT SmMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmMainDlgInit(HWND hWnd);
void SmMainDlgUpdate(HWND hWnd);
void SmInitSettingList();
void SmFreeSettingList();
void SmWriteSettingList();
void SmLoadSettingList();
void SmInitDefaultSettingList();
int SmCompareSetting(void *p1, void *p2);
SETTING *SmGetSetting(wchar_t *title);
bool SmAddSetting(SETTING *s);
void SmDeleteSetting(wchar_t *title);
bool SmCheckNewName(SETTING *s, wchar_t *new_title);
void SmRefreshSetting(HWND hWnd);
void SmRefreshSettingEx(HWND hWnd, wchar_t *select_name);
bool SmAddSettingDlg(HWND hWnd, wchar_t *new_name, UINT new_name_size);
bool SmEditSettingDlg(HWND hWnd);
UINT SmEditSettingDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditSettingDlgInit(HWND hWnd, SM_EDIT_SETTING *p);
void SmEditSettingDlgUpdate(HWND hWnd, SM_EDIT_SETTING *p);
void SmEditSettingDlgOnOk(HWND hWnd, SM_EDIT_SETTING *p);
void SmConnect(HWND hWnd, SETTING *s);
void SmConnectEx(HWND hWnd, SETTING *s, bool is_in_client);
char *SmPassword(HWND hWnd, char *server_name);
UINT SmServerDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmServerDlgInit(HWND hWnd, SM_SERVER *p);
void SmServerDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmServerDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmStatusDlg(HWND hWnd, SM_SERVER *p, void *param, bool no_image, bool show_refresh_button, wchar_t *caption, UINT icon,
				 SM_STATUS_INIT_PROC *init, SM_STATUS_REFRESH_PROC *refresh);
UINT SmStatusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool SmRefreshHubStatus(HWND hWnd, SM_SERVER *p, void *param);
void SmInsertTrafficInfo(LVB *b, TRAFFIC *t);
bool SmCreateHubDlg(HWND hWnd, SM_SERVER *p);
bool SmEditHubDlg(HWND hWnd, SM_SERVER *p, char *hubname);
UINT SmEditHubProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditHubInit(HWND hWnd, SM_EDIT_HUB *s);
void SmEditHubUpdate(HWND hWnd, SM_EDIT_HUB *s);
void SmEditHubOnOk(HWND hWnd, SM_EDIT_HUB *s);
bool SmCreateListenerDlg(HWND hWnd, SM_SERVER *p);
UINT SmCreateListenerDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSslDlg(HWND hWnd, SM_SERVER *p);
UINT SmSslDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSslDlgInit(HWND hWnd, SM_SSL *s);
void SmSslDlgOnOk(HWND hWnd, SM_SSL *s);
void SmSslDlgUpdate(HWND hWnd, SM_SSL *s);
void SmGetCertInfoStr(wchar_t *str, UINT size, X *x);
bool SmRegenerateServerCert(HWND hWnd, SM_SERVER *server, char *default_cn, X **x, K **k, bool root_only);
bool SmSaveKeyPairDlg(HWND hWnd, X *x, K *k);
UINT SmSaveKeyPairDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSaveKeyPairDlgInit(HWND hWnd, SM_SAVE_KEY_PAIR *s);
void SmSaveKeyPairDlgUpdate(HWND hWnd, SM_SAVE_KEY_PAIR *s);
void SmSaveKeyPairDlgOnOk(HWND hWnd, SM_SAVE_KEY_PAIR *s);
bool SmRefreshServerStatus(HWND hWnd, SM_SERVER *p, void *param);
bool SmRefreshServerInfo(HWND hWnd, SM_SERVER *p, void *param);
void SmPrintNodeInfo(LVB *b, NODE_INFO *info);
wchar_t *SmGetConnectionTypeStr(UINT type);
void SmConnectionDlg(HWND hWnd, SM_SERVER *p);
UINT SmConnectionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmConnectionDlgInit(HWND hWnd, SM_SERVER *p);
void SmConnectionDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmConnectionDlgUpdate(HWND hWnd, SM_SERVER *p);
bool SmRefreshConnectionStatus(HWND hWnd, SM_SERVER *p, void *param);
bool SmFarmDlg(HWND hWnd, SM_SERVER *p);
UINT SmFarmDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmFarmDlgInit(HWND hWnd, SM_SERVER *p);
void SmFarmDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmFarmDlgOnOk(HWND hWnd, SM_SERVER *p);
LIST *SmStrToPortList(char *str);
UINT SmFarmMemberDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmFarmMemberDlgInit(HWND hWnd, SM_SERVER *p);
void SmFarmMemberDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmFarmMemberDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmFarmMemberDlgOnOk(HWND hWnd, SM_SERVER *p);
void SmFarmMemberCert(HWND hWnd, SM_SERVER *p, UINT id);
bool SmRefreshFarmMemberInfo(HWND hWnd, SM_SERVER *p, void *param);
bool SmRefreshFarmConnectionInfo(HWND hWnd, SM_SERVER *p, void *param);
UINT SmChangeServerPasswordDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubDlg(HWND hWnd, SM_HUB *s);
UINT SmHubDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubDlgInit(HWND hWnd, SM_HUB *s);
void SmHubDlgUpdate(HWND hWnd, SM_HUB *s);
void SmHubDlgRefresh(HWND hWnd, SM_HUB *s);
void SmUserListDlg(HWND hWnd, SM_HUB *s);
UINT SmUserListProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmUserListInit(HWND hWnd, SM_USER *s);
void SmUserListRefresh(HWND hWnd, SM_USER *s);
void SmUserListUpdate(HWND hWnd, SM_USER *s);
wchar_t *SmGetAuthTypeStr(UINT id);
bool SmCreateUserDlg(HWND hWnd, SM_HUB *s);
UINT SmEditUserDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditUserDlgInit(HWND hWnd, SM_EDIT_USER *s);
void SmEditUserDlgUpdate(HWND hWnd, SM_EDIT_USER *s);
void SmEditUserDlgOk(HWND hWnd, SM_EDIT_USER *s);
bool SmPolicyDlg(HWND hWnd, POLICY *p, wchar_t *caption);
bool SmPolicyDlgEx(HWND hWnd, POLICY *p, wchar_t *caption, bool cascade_mode);
bool SmPolicyDlgEx2(HWND hWnd, POLICY *p, wchar_t *caption, bool cascade_mode, UINT ver);
UINT SmPolicyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmPolicyDlgInit(HWND hWnd, SM_POLICY *s);
void SmPolicyDlgUpdate(HWND hWnd, SM_POLICY *s);
void SmPolicyDlgOk(HWND hWnd, SM_POLICY *s);
bool SmEditUserDlg(HWND hWnd, SM_HUB *s, char *username);
bool SmRefreshUserInfo(HWND hWnd, SM_SERVER *s, void *param);
void SmGroupListDlg(HWND hWnd, SM_HUB *s);
char *SmSelectGroupDlg(HWND hWnd, SM_HUB *s, char *default_name);
UINT SmGroupListDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmGroupListDlgInit(HWND hWnd, SM_GROUP *s);
void SmGroupListDlgUpdate(HWND hWnd, SM_GROUP *s);
void SmGroupListDlgRefresh(HWND hWnd, SM_GROUP *s);
bool SmCreateGroupDlg(HWND hWnd, SM_GROUP *s);
bool SmEditGroupDlg(HWND hWnd, SM_GROUP *s, char *name);
UINT SmEditGroupDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditGroupDlgInit(HWND hWnd, SM_EDIT_GROUP *g);
void SmEditGroupDlgUpdate(HWND hWnd, SM_EDIT_GROUP *g);
void SmEditGroupDlgOnOk(HWND hWnd, SM_EDIT_GROUP *g);
void SmUserListDlgEx(HWND hWnd, SM_HUB *s, char *groupname, bool create);
void SmAccessListDlg(HWND hWnd, SM_HUB *s);
UINT SmAccessListProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmAccessListInit(HWND hWnd, SM_ACCESS_LIST *s);
void SmAccessListUpdate(HWND hWnd, SM_ACCESS_LIST *s);
void SmAccessListRefresh(HWND hWnd, SM_ACCESS_LIST *s);
bool SmAddAccess(HWND hWnd, SM_ACCESS_LIST *s, bool ipv6);
bool SmCloneAccess(HWND hWnd, SM_ACCESS_LIST *s, ACCESS *t);
bool SmEditAccess(HWND hWnd, SM_ACCESS_LIST *s, ACCESS *a);
UINT SmEditAccessDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditAccessInit(HWND hWnd, SM_EDIT_ACCESS *s);
void SmEditAccessUpdate(HWND hWnd, SM_EDIT_ACCESS *s);
void SmEditAccessOnOk(HWND hWnd, SM_EDIT_ACCESS *s);
void SmRedirect(HWND hWnd, SM_EDIT_ACCESS *s);
UINT SmRedirectDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmRedirectDlgInit(HWND hWnd, SM_EDIT_ACCESS *s);
void SmRedirectDlgUpdate(HWND hWnd, SM_EDIT_ACCESS *s);
UINT SmSimulationDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSimulationUpdate(HWND hWnd, SM_EDIT_ACCESS *s);
void SmSimulationInit(HWND hWnd, SM_EDIT_ACCESS *s);
void SmSimulationOnOk(HWND hWnd, SM_EDIT_ACCESS *s);
char *SmSelectUserDlg(HWND hWnd, SM_HUB *s, char *default_name);
char *SmSelectUserDlgEx(HWND hWnd, SM_HUB *s, char *default_name, bool allow_group);
void SmRadiusDlg(HWND hWnd, SM_HUB *s);
UINT SmRadiusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmRadiusDlgInit(HWND hWnd, SM_HUB *s);
void SmRadiusDlgUpdate(HWND hWnd, SM_HUB *s);
void SmRadiusDlgOnOk(HWND hWnd, SM_HUB *s);
void SmLinkDlg(HWND hWnd, SM_HUB *s);
void SmLinkDlgEx(HWND hWnd, SM_HUB *s, bool createNow);
UINT SmLinkDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLinkDlgInit(HWND hWnd, SM_HUB *s);
void SmLinkDlgUpdate(HWND hWnd, SM_HUB *s);
void SmLinkDlgRefresh(HWND hWnd, SM_HUB *s);
bool SmLinkCreate(HWND hWnd, SM_HUB *s);
bool SmLinkCreateEx(HWND hWnd, SM_HUB *s, bool connectNow);
bool SmLinkEdit(HWND hWnd, SM_HUB *s, wchar_t *name);
bool SmRefreshLinkStatus(HWND hWnd, SM_SERVER *s, void *param);
UINT SmLogDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLogDlgInit(HWND hWnd, SM_HUB *s);
void SmLogDlgUpdate(HWND hWnd, SM_HUB *s);
void SmLogDlgOnOk(HWND hWnd, SM_HUB *s);
void SmCaDlg(HWND hWnd, SM_HUB *s);
UINT SmCaDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmCaDlgInit(HWND hWnd, SM_HUB *s);
void SmCaDlgRefresh(HWND hWnd, SM_HUB *s);
void SmCaDlgUpdate(HWND hWnd, SM_HUB *s);
void SmCaDlgOnOk(HWND hWnd, SM_HUB *s);
bool SmCaDlgAdd(HWND hWnd, SM_HUB *s);
void SmSessionDlg(HWND hWnd, SM_HUB *s);
UINT SmSessionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSessionDlgInit(HWND hWnd, SM_HUB *s);
void SmSessionDlgUpdate(HWND hWnd, SM_HUB *s);
void SmSessionDlgRefresh(HWND hWnd, SM_HUB *s);
bool SmRefreshSessionStatus(HWND hWnd, SM_SERVER *s, void *param);
void SmMacTableDlg(HWND hWnd, SM_HUB *s, char *session_name);
UINT SmMacTableDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmMacTableDlgInit(HWND hWnd, SM_TABLE *s);
void SmMacTableDlgUpdate(HWND hWnd, SM_TABLE *s);
void SmMacTableDlgRefresh(HWND hWnd, SM_TABLE *s);
void SmIpTableDlg(HWND hWnd, SM_HUB *s, char *session_name);
UINT SmIpTableDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmIpTableDlgInit(HWND hWnd, SM_TABLE *s);
void SmIpTableDlgUpdate(HWND hWnd, SM_TABLE *s);
void SmIpTableDlgRefresh(HWND hWnd, SM_TABLE *s);
bool SmCreateCert(HWND hWnd, X **x, K **k, bool do_not_save, char *default_cn, bool root_only);
UINT SmCreateCertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmCreateCertDlgInit(HWND hWnd, SM_CERT *s);
void SmCreateCertDlgUpdate(HWND hWnd, SM_CERT *s);
void SmCreateCertDlgOnOk(HWND hWnd, SM_CERT *s);
UINT SmSNATDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSNATDlgUpdate(HWND hWnd, SM_HUB *s);
void SmBridgeDlg(HWND hWnd, SM_SERVER *s);
void SmInstallWinPcap(HWND hWnd, SM_SERVER *s);
UINT SmBridgeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT SmBridgeDlgInit(HWND hWnd, SM_SERVER *s);
void SmBridgeDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmBridgeDlgRefresh(HWND hWnd, SM_SERVER *s);
void SmBridgeDlgOnOk(HWND hWnd, SM_SERVER *s);
void SmAddServerCaps(LVB *b, CAPSLIST *t);
void SmConfig(HWND hWnd, SM_SERVER *s);
UINT SmConfigDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmConfigDlgInit(HWND hWnd, SM_CONFIG *c);
void SmHubAdminOption(HWND hWnd, SM_EDIT_HUB *e);
void SmHubExtOption(HWND hWnd, SM_EDIT_HUB *e);
UINT SmHubAdminOptionDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubAdminOptionDlgUpdate(HWND hWnd, SM_EDIT_AO *a);
void SmHubAdminOptionDlgInit(HWND hWnd, SM_EDIT_AO *a);
void SmHubAdminOptionDlgOk(HWND hWnd, SM_EDIT_AO *a);
UINT SmHubAdminOptionValueDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubAdminOptionValueDlgUpdate(HWND hWnd, SM_EDIT_AO *a);
void SmL3(HWND hWnd, SM_SERVER *s);
UINT SmL3Dlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3DlgInit(HWND hWnd, SM_SERVER *s);
void SmL3DlgUpdate(HWND hWnd, SM_SERVER *s);
void SmL3DlgRefresh(HWND hWnd, SM_SERVER *s);
UINT SmL3AddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3AddDlgUpdate(HWND hWnd, SM_SERVER *s);
UINT SmL3SwDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3SwDlgInit(HWND hWnd, SM_L3SW *w);
void SmL3SwDlgUpdate(HWND hWnd, SM_L3SW *w);
void SmL3SwDlgRefresh(HWND hWnd, SM_L3SW *w);
UINT SmL3SwIfDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3SwIfDlgInit(HWND hWnd, SM_L3SW *w);
void SmL3SwIfDlgUpdate(HWND hWnd, SM_L3SW *w);
UINT SmL3SwTableDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3SwTableDlgInit(HWND hWnd, SM_L3SW *w);
void SmL3SwTableDlgUpdate(HWND hWnd, SM_L3SW *w);
bool SmL3IsSwActive(SM_SERVER *s, char *name);
UINT SmGetCurrentSecureId(HWND hWnd);
UINT SmGetCurrentSecureIdFromReg();
UINT SmSelectSecureId(HWND hWnd);
void SmWriteSelectSecureIdReg(UINT id);
bool SmSelectKeyPair(HWND hWnd, char *cert_name, UINT cert_name_size, char *key_name, UINT key_name_size);
bool SmSelectKeyPairEx(HWND hWnd, char *cert_name, UINT cert_name_size, char *key_name, UINT key_name_size, UINT bitmap_id);
UINT SmSelectKeyPairDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSelectKeyPairDlgInit(HWND hWnd, SM_SECURE_KEYPAIR *k);
void SmSelectKeyPairDlgUpdate(HWND hWnd, SM_SECURE_KEYPAIR *k);
void SmSelectKeyPairDlgRefresh(HWND hWnd, SM_SECURE_KEYPAIR *k);
void SmSecureManager(HWND hWnd);
UINT SmCrlDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmCrlDlgInit(HWND hWnd, SM_HUB *s);
void SmCrlDlgUpdate(HWND hWnd, SM_HUB *s);
void SmCrlDlgRefresh(HWND hWnd, SM_HUB *s);
UINT SmEditCrlDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditCrlDlgInit(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgUpdate(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgOnOk(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgOnLoad(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgSetName(HWND hWnd, NAME *name);
void SmEditCrlDlgSetSerial(HWND hWnd, X_SERIAL *serial);
void SmEditCrlDlgSetHash(HWND hWnd, UCHAR *hash_md5, UCHAR *hash_sha1);
void SmHubAc(HWND hWnd, SM_EDIT_HUB *s);
UINT SmHubAcDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubAcDlgInit(HWND hWnd, SM_EDIT_AC_LIST *p);
void SmHubAcDlgUpdate(HWND hWnd, SM_EDIT_AC_LIST *p);
void SmHubAcDlgRefresh(HWND hWnd, SM_EDIT_AC_LIST *p);
UINT SmHubEditAcDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubEditAcDlgInit(HWND hWnd, SM_EDIT_AC *p);
void SmHubEditAcDlgUpdate(HWND hWnd, SM_EDIT_AC *p);
void SmHubEditAcDlgOnOk(HWND hWnd, SM_EDIT_AC *p);
UINT SmLogFileDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLogFileDlgInit(HWND hWnd, SM_SERVER *p);
void SmLogFileDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmLogFileDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmLogFileStartDownload(HWND hWnd, SM_SERVER *s, char *server_name, char *filepath, UINT totalsize);
UINT SmReadLogFile(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool SmReadLogFileProc(DOWNLOAD_PROGRESS *g);
UINT SmSaveLogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLicense(HWND hWnd, SM_SERVER *s);
UINT SmLicenseDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLicenseDlgInit(HWND hWnd, SM_SERVER *s);
void SmLicenseDlgRefresh(HWND hWnd, SM_SERVER *s);
void SmLicenseDlgUpdate(HWND hWnd, SM_SERVER *s);
bool SmLicenseAdd(HWND hWnd, SM_SERVER *s);
UINT SmLicenseAddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLicenseAddDlgInit(HWND hWnd, SM_SERVER *s);
void SmLicenseAddDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmLicenseAddDlgShiftTextItem(HWND hWnd, UINT id1, UINT id2, UINT *next_focus);
void SmLicenseAddDlgGetText(HWND hWnd, char *str, UINT size);
void SmLicenseAddDlgOnOk(HWND hWnd, SM_SERVER *s);
bool SmSetup(HWND hWnd, SM_SERVER *s);
UINT SmSetupDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSetupDlgInit(HWND hWnd, SM_SETUP *s);
void SmSetupDlgUpdate(HWND hWnd, SM_SETUP *s);
void SmSetupDlgOnOk(HWND hWnd, SM_SETUP *s);
UINT SmSetupHubDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSetupHubDlgUpdate(HWND hWnd, SM_SETUP *s);
bool SmSetupInit(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllHub(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllLocalBridge(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllLayer3(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllObjectInBridgeHub(HWND hWnd, SM_SETUP *s);
void SmSetupStep(HWND hWnd, SM_SETUP *s);
UINT SmSetupStepDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSetupStepDlgInit(HWND hWnd, SM_SETUP *s);
void SmSetupOnClose(HWND hWnd, SM_SETUP *s);
bool SmSetupIsNew(SM_SERVER *s);
void SmVLan(HWND hWnd, SM_SERVER *s);
UINT SmVLanDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmVLanDlgInit(HWND hWnd, SM_SERVER *s);
void SmVLanDlgRefresh(HWND hWnd, SM_SERVER *s);
void SmVLanDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmHubMsg(HWND hWnd, SM_EDIT_HUB *s);
UINT SmHubMsgDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubMsgDlgInit(HWND hWnd, SM_EDIT_HUB *s);
void SmHubMsgDlgUpdate(HWND hWnd, SM_EDIT_HUB *s);
void SmHubMsgDlgOnOk(HWND hWnd, SM_EDIT_HUB *s);
void SmIPsec(HWND hWnd, SM_SERVER *s);
UINT SmIPsecDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmIPsecDlgInit(HWND hWnd, SM_SERVER *s);
void SmIPsecDlgOnOk(HWND hWnd, SM_SERVER *s);
void SmIPsecDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmIPsecDlgGetSetting(HWND hWnd, IPSEC_SERVICES *sl);
void SmEtherIp(HWND hWnd, SM_SERVER *s);
UINT SmEtherIpDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEtherIpDlgInit(HWND hWnd, SM_SERVER *s);
void SmEtherIpDlgRefresh(HWND hWnd, SM_SERVER *s);
void SmEtherIpDlgUpdate(HWND hWnd, SM_SERVER *s);
bool SmEtherIpId(HWND hWnd, SM_ETHERIP_ID *t);
UINT SmEtherIpIdDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEtherIpIdDlgInit(HWND hWnd, SM_ETHERIP_ID *t);
void SmEtherIpIdDlgOnOk(HWND hWnd, SM_ETHERIP_ID *t);
void SmEtherIpIdDlgUpdate(HWND hWnd, SM_ETHERIP_ID *t);
void SmEtherIpIdDlgGetSetting(HWND hWnd, SM_ETHERIP_ID *t);
bool SmDDns(HWND hWnd, SM_SERVER *s, bool silent, bool no_change_cert);
UINT SmDDnsDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmDDnsDlgInit(HWND hWnd, SM_DDNS *d);
void SmDDnsRefresh(HWND hWnd, SM_DDNS *d);
void SmDDnsDlgOnOk(HWND hWnd, SM_DDNS *d);
void SmDDnsDlgUpdate(HWND hWnd, SM_DDNS *d);
void SmOpenVpn(HWND hWnd, SM_SERVER *s);
UINT SmOpenVpnDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmOpenVpnDlgInit(HWND hWnd, SM_SERVER *s);
void SmOpenVpnDlgOnOk(HWND hWnd, SM_SERVER *s, bool no_close);
void SmOpenVpnDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmOpenVpn(HWND hWnd, SM_SERVER *s);
void SmSpecialListener(HWND hWnd, SM_SERVER *s);
UINT SmSpecialListenerDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSpecialListenerDlgInit(HWND hWnd, SM_SERVER *s);
void SmSpecialListenerDlgOnOk(HWND hWnd, SM_SERVER *s);
void SmShowIPSecMessageIfNecessary(HWND hWnd, SM_SERVER *p);
void SmShowCertRegenerateMessageIfNecessary(HWND hWnd, SM_SERVER *p);
UINT SmVmBridgeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmAzure(HWND hWnd, SM_SERVER *s, bool on_setup);
UINT SmAzureDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmAzureDlgOnInit(HWND hWnd, SM_AZURE *a);
void SmAzureDlgRefresh(HWND hWnd, SM_AZURE *a);
void SmAzureSetStatus(HWND hWnd, SM_AZURE *a);
bool SmProxy(HWND hWnd, INTERNET_SETTING *t);
UINT SmProxyDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmProxyDlgInit(HWND hWnd, INTERNET_SETTING *t);
void SmProxyDlgUpdate(HWND hWnd, INTERNET_SETTING *t);



//////////////////////////////////////////////////////////////////////////
// NMInner.h



// Constants
#define	NM_REG_KEY			"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\User-mode Router Manager"
#define	NM_SETTING_REG_KEY	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\User-mode Router Manager\\Settings"

#define	NM_REFRESH_TIME			1000
#define	NM_NAT_REFRESH_TIME		1000
#define	NM_DHCP_REFRESH_TIME	1000

// Nat Admin structure
typedef struct NM
{
	CEDAR *Cedar;				// Cedar
} NM;

// Connection structure
typedef struct NM_CONNECT
{
	RPC *Rpc;					// RPC
	char *Hostname;
	UINT Port;
} NM_CONNECT;

// Login
typedef struct NM_LOGIN
{
	char *Hostname;
	UINT Port;
	UCHAR hashed_password[SHA1_SIZE];
} NM_LOGIN;

// Internal function
void InitNM();
void FreeNM();
void MainNM();
RPC *NmConnect(char *hostname, UINT port);
UINT NmConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT NmLogin(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmMainDlg(RPC *r);
UINT NmMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmMainDlgInit(HWND hWnd, RPC *r);
void NmMainDlgRefresh(HWND hWnd, RPC *r);
void NmEditClientConfig(HWND hWnd, RPC *r);
void NmEditVhOption(HWND hWnd, SM_HUB *r);
UINT NmEditVhOptionProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmEditVhOptionInit(HWND hWnd, SM_HUB *r);
void NmEditVhOptionUpdate(HWND hWnd, SM_HUB *r);
void NmEditVhOptionOnOk(HWND hWnd, SM_HUB *r);
void NmEditVhOptionFormToVH(HWND hWnd, VH_OPTION *t);
bool NmStatus(HWND hWnd, SM_SERVER *s, void *param);
bool NmInfo(HWND hWnd, SM_SERVER *s, void *param);
void NmNat(HWND hWnd, SM_HUB *r);
UINT NmNatProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmNatInit(HWND hWnd, SM_HUB *r);
void NmNatRefresh(HWND hWnd, SM_HUB *r);
void NmDhcp(HWND hWnd, SM_HUB *r);
UINT NmDhcpProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmDhcpRefresh(HWND hWnd, SM_HUB *r);
void NmDhcpInit(HWND hWnd, SM_HUB *r);
void NmChangePassword(HWND hWnd, RPC *r);
UINT NmChangePasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool NmEditPushRoute(HWND hWnd, SM_HUB *r);
UINT NmEditPushRouteProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);



//////////////////////////////////////////////////////////////////////////
// EMInner.h


// Constants
#define	EM_REG_KEY			"Software\\" GC_REG_COMPANY_NAME "\\EtherLogger\\Manager"

// Innner structure
typedef struct EM_ADD
{
	RPC *Rpc;
	bool NewMode;
	char DeviceName[MAX_SIZE];
} EM_ADD;

// Inner functions
void EMMain(RPC *r);
UINT EmMainDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void EmMainInit(HWND hWnd, RPC *r);
void EmMainUpdate(HWND hWnd, RPC *r);
void EmMainRefresh(HWND hWnd, RPC *r);
void EmAdd(HWND hWnd, RPC *r, char *device_name);
UINT EmAddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void EmAddInit(HWND hWnd, EM_ADD *p);
void EmDlgToHubLog(HWND hWnd, HUB_LOG *g);
void EmHubLogToDlg(HWND hWnd, HUB_LOG *g);
void EmAddOk(HWND hWnd, EM_ADD *p);
void EmAddUpdate(HWND hWnd, EM_ADD *p);
UINT EmPasswordDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT EmLicenseDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void EmLicenseDlgInit(HWND hWnd, RPC *s);
void EmLicenseDlgRefresh(HWND hWnd, RPC *s);
void EmLicenseDlgUpdate(HWND hWnd, RPC *s);
bool EmLicenseAdd(HWND hWnd, RPC *s);
UINT EmLicenseAddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void EmLicenseAddDlgInit(HWND hWnd, RPC *s);
void EmLicenseAddDlgUpdate(HWND hWnd, RPC *s);
void EmLicenseAddDlgShiftTextItem(HWND hWnd, UINT id1, UINT id2, UINT *next_focus);
void EmLicenseAddDlgGetText(HWND hWnd, char *str, UINT size);
void EmLicenseAddDlgOnOk(HWND hWnd, RPC *s);

//////////////////////////////////////////////////////////////////////////
// UT.h


// Function prototype
UINT UtSpeedMeterDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void UtSpeedMeterDlgInit(HWND hWnd);
void UtSpeedMeterDlgRefreshList(HWND hWnd);
void UtSpeedMeterDlgRefreshStatus(HWND hWnd);
void UtSpeedMeterDlgUpdate(HWND hWnd);
void UtSpeedMeterDlgRefreshStatus(HWND hWnd);


//////////////////////////////////////////////////////////////////////////
// SWInner.h


// Component string
#define	SW_NAME_VPNSERVER			"vpnserver"
#define	SW_LONG_VPNSERVER			_UU("SW_LONG_VPNSERVER")

#define	SW_NAME_VPNCLIENT			"vpnclient"
#define	SW_LONG_VPNCLIENT			_UU("SW_LONG_VPNCLIENT")

#define	SW_NAME_VPNBRIDGE			"vpnbridge"
#define	SW_LONG_VPNBRIDGE			_UU("SW_LONG_VPNBRIDGE")

#define	SW_NAME_VPNSMGR				"vpnsmgr"
#define	SW_LONG_VPNSMGR				_UU("SW_LONG_VPNSMGR")

#define	SW_NAME_VPNCMGR				"vpncmgr"
#define	SW_LONG_VPNCMGR				_UU("SW_LONG_VPNCMGR")

#define	SW_VPN_CLIENT_UIHELPER_REGVALUE	GC_SW_UIHELPER_REGVALUE

#define	SW_VPN_CLIENT_EXT_REGKEY	"SOFTWARE\\Classes\\.vpn"
#define	SW_VPN_CLIENT_EXT_REGVALUE	"vpnfile"
#define	SW_VPN_CLIENT_EXT_REGKEY_SUB1	"SOFTWARE\\Classes\\.vpn\\vpnfile"
#define	SW_VPN_CLIENT_EXT_REGKEY_SUB2	"SOFTWARE\\Classes\\.vpn\\vpnfile\\ShellNew"

#define	SW_VPN_CLIENT_VPNFILE_REGKEY	"SOFTWARE\\Classes\\vpnfile"
#define	SW_VPN_CLIENT_VPNFILE_REGVALUE	"VPN Client Connection Setting File"
#define	SW_VPN_CLIENT_VPNFILE_ICON_REGKEY	"SOFTWARE\\Classes\\vpnfile\\DefaultIcon"
#define	SW_VPN_CLIENT_VPNFILE_SHELLOPEN_CMD_REGKEY	"SOFTWARE\\Classes\\vpnfile\\shell\\open\\command"
#define	SW_VPN_CLIENT_VPNFILE_SHELLOPEN_CMD_REGKEY_SUB1	"SOFTWARE\\Classes\\vpnfile\\shell\\open"
#define	SW_VPN_CLIENT_VPNFILE_SHELLOPEN_CMD_REGKEY_SUB2	"SOFTWARE\\Classes\\vpnfile\\shell"

#define	SW_REG_KEY_EULA					"Software\\" GC_REG_COMPANY_NAME "\\Setup Wizard Settings\\Eula"


// Component ID
#define	SW_CMP_VPN_SERVER			1	// VPN Server
#define	SW_CMP_VPN_CLIENT			2	// VPN Client
#define	SW_CMP_VPN_BRIDGE			3	// VPN Bridge
#define	SW_CMP_VPN_SMGR				4	// VPN Server Manager (Tools Only)
#define	SW_CMP_VPN_CMGR				5	// VPN Client Manager (Tools Only)

// Exit code
#define	SW_EXIT_CODE_USER_CANCEL			1000000001		// Cancel by the user
#define	SW_EXIT_CODE_INTERNAL_ERROR			1000000002		// Internal error

// Special messages to be used in the setup wizard
#define	WM_SW_BASE						(WM_APP + 251)
#define	WM_SW_INTERACT_UI				(WM_SW_BASE + 0)	// UI processing
#define	WM_SW_EXIT						(WM_SW_BASE + 1)	// Close

// Automatic connection setting file
#define	SW_AUTO_CONNECT_ACCOUNT_FILE_NAME	"auto_connect.vpn"
#define	SW_AUTO_CONNECT_ACCOUNT_FILE_NAME_W	L"auto_connect.vpn"

// Installer cache file to be stored in the VPN Client installation folder
#define	SW_SFX_CACHE_FILENAME				L"installer.cache"

// Flag file
#define	SW_FLAG_EASY_MODE					"easy_mode.flag"
#define	SW_FLAG_EASY_MODE_2					"@easy_mode.flag"

// Multiple-starts prevention name
#define	SW_SINGLE_INSTANCE_NAME				"SoftEther_VPN_Setup_Wizard"

// Time to wait for the VPN Client service startup
#define	SW_VPNCLIENT_SERVICE_WAIT_READY_TIMEOUT		(30 * 1000)

// UI interaction
typedef struct SW_UI
{
	UINT Type;							// Type
	wchar_t *Message;					// Message string
	UINT Param;							// Parameters
	UINT RetCode;						// Return value
} SW_UI;

// Type of UI interaction
#define	SW_UI_TYPE_PRINT				0	// Display the message
#define	SW_UI_TYPE_MSGBOX				1	// Show a message box
#define	SW_UI_TYPE_FINISH				2	// Completion
#define	SW_UI_TYPE_ERROR				3	// Error

// Resource type of the file stored in the setup.exe
#define	SW_SFX_RESOURCE_TYPE			"DATAFILE"

// Code of old MSI
typedef struct SW_OLD_MSI
{
	char *ProductCode;						// Product code
	char *ComponentCode;					// Component code
} SW_OLD_MSI;

// Component
typedef struct SW_COMPONENT
{
	UINT Id;							// ID
	bool Detected;						// Whether it has been detected as an installation source
	LIST *NeedFiles;					// Necessary files
	char *Name;							// Internal name
	char *SvcName;						// Service name
	wchar_t *Title;						// Display name
	wchar_t *Description;				// Detail
	wchar_t *DefaultDirName;			// Installation directory name of the default
	wchar_t *LongName;					// Long name
	UINT Icon;							// Icon
	UINT IconExeIndex;					// The index number of the icon within the Setup.exe
	bool SystemModeOnly;				// Only system mode
	bool InstallService;				// Installation of service
	wchar_t *SvcFileName;				// Service file name
	wchar_t *StartExeName;				// Start EXE file name
	wchar_t *StartDescription;			// Description of the running software
	SW_OLD_MSI *OldMsiList;				// Old MSI Product List
	UINT NumOldMsi;						// The number of old MSI Product List
	bool CopyVGDat;						// Copy of the VPN Gate DAT file
} SW_COMPONENT;

// File copy task
typedef struct SW_TASK_COPY
{
	wchar_t SrcFileName[MAX_SIZE];		// Original file name
	wchar_t DstFileName[MAX_SIZE];		// Destination file name
	wchar_t SrcDir[MAX_SIZE];			// Source directory
	wchar_t DstDir[MAX_SIZE];			// Destination directory
	bool Overwrite;						// Override flag
	bool SetupFile;						// Setup file flag
} SW_TASK_COPY;

// Link creation task
typedef struct SW_TASK_LINK
{
	wchar_t TargetDir[MAX_SIZE];		// Target directory
	wchar_t TargetExe[MAX_SIZE];		// Target EXE file name
	wchar_t TargetArg[MAX_SIZE];		// Arguments to pass to the target
	wchar_t IconExe[MAX_SIZE];			// Icon EXE file name
	UINT IconIndex;						// Icon Index number
	wchar_t DestDir[MAX_SIZE];			// Directory name to be created
	wchar_t DestName[MAX_SIZE];			// File name to be created
	wchar_t DestDescription[MAX_SIZE];	// Description string
	bool NoDeleteDir;					// Do not delete the directory on uninstall
} SW_TASK_LINK;

// Setup Tasks
typedef struct SW_TASK
{
	LIST *CopyTasks;					// File copy task
	LIST *SetSecurityPaths;				// List of paths to set the security
	LIST *LinkTasks;					// Link creation task
} SW_TASK;

// Setup log
typedef struct SW_LOG
{
	UINT Type;							// Type of log
	wchar_t Path[MAX_PATH];				// Path
} SW_LOG;

// Type of setup log
#define	SW_LOG_TYPE_FILE				1	// File
#define	SW_LOG_TYPE_DIR					2	// Directory
#define	SW_LOG_TYPE_REGISTRY			3	// Registry
#define	SW_LOG_TYPE_LNK					4	// Shortcut file
#define	SW_LOG_TYPE_LNK_DIR				5	// Shortcut directory
#define	SW_LOG_TYPE_SVC					6	// Service

// Setup log files
typedef struct SW_LOGFILE
{
	LIST *LogList;							// List of log
	bool IsSystemMode;						// Whether the system mode
	UINT Build;								// Build Number
	SW_COMPONENT *Component;				// Component
} SW_LOGFILE;

// SFX file
typedef struct SW_SFX_FILE
{
	char InnerFileName[MAX_PATH];				// Internal file name
	wchar_t DiskFileName[MAX_PATH];				// File name of the disk
} SW_SFX_FILE;

// SW instance
typedef struct SW
{
	LIST *ComponentList;				// List of components
	wchar_t InstallSrc[MAX_SIZE];		// Source directory
	bool IsSystemMode;					// Whether the system mode
	bool UninstallMode;					// Uninstall mode
	UINT ExitCode;						// Exit code
	void *ReExecProcessHandle;			// Child process handle of a result of the re-run itself
	bool IsReExecForUac;				// Whether the process was re-run for UAC handling
	SW_COMPONENT *CurrentComponent;		// Component that is currently selected
	bool EulaAgreed;					// Whether the user accepted the license agreement
	bool DoubleClickBlocker;			// Double-click blocker
	bool LanguageMode;					// Language setting mode
	UINT LangId;						// Language ID in the language setting mode
	bool SetLangAndReboot;				// Prompt to restart after making the language setting
	bool LangNow;						// Start the language setting process right now
	bool EasyMode;						// Simple installer creation mode
	bool WebMode;						// Web installer creation mode
	bool OnlyAutoSettingMode;			// Apply only mode of connection settings of VPN Client

	INSTANCE *Single;					// Multiple-starts check
	wchar_t DefaultInstallDir_System[MAX_PATH];		// Default system installation directory
	wchar_t DefaultInstallDir_User[MAX_PATH];		// Default user installation directory
	bool IsAvailableSystemMode;			// Whether the system mode is selectable
	bool IsAvailableUserMode;			// Whether the user mode is selectable
	bool ShowWarningForUserMode;		// Whether to display a warning for the user-mode
	wchar_t InstallDir[MAX_PATH];		// Destination directory
	THREAD *PerformThread;				// Set up processing thread
	bool Run;							// Whether to start the tool after Setup finishes
	SW_LOGFILE *LogFile;				// Log file
	bool MsiRebootRequired;				// Need to be re-started as a result of MSI
	bool LangNotChanged;				// Language has not changed
	wchar_t FinishMsg[MAX_SIZE * 2];	// Completion message
	wchar_t Easy_SettingFile[MAX_PATH];	// Connection settings file name of the Simple installer creation kit:
	wchar_t Easy_OutFile[MAX_PATH];		// Destination file name of the simple installer creation kit
	bool Easy_EraseSensitive;			// Simple installer creation kit: Delete the confidential information
	bool Easy_EasyMode;					// Simple installer creation kit: simple mode
	wchar_t Web_SettingFile[MAX_PATH];	// Connection setting file name for the Web installer creation Kit
	wchar_t Web_OutFile[MAX_PATH];		// Destination file name of the Web installer creation Kit
	bool Web_EraseSensitive;			// Web installer creation Kit: removing confidential information
	bool Web_EasyMode;					// Web installer creation kit: simple mode
	wchar_t vpncmgr_path[MAX_PATH];		// Path of vpncmgr.exe
	wchar_t auto_setting_path[MAX_PATH];	// Path of automatic connection setting
	bool HideStartCommand;				// Not to show the option to start the program on installation complete screen
	char SfxMode[MAX_SIZE];				// SFX generation mode
	wchar_t SfxOut[MAX_PATH];			// SFX destination
	wchar_t CallerSfxPath[MAX_PATH];	// Calling SFX path
	bool IsEasyInstaller;				// Whether the calling SFX was built by the simple installer creation kit
	bool IsWebInstaller;				// Whether Web installer
	bool DisableAutoImport;				// Not to use the automatic import process
	bool SuInstMode;					// SuInst mode
	UINT CurrentEulaHash;				// Hash of the license agreement
} SW;


// Function prototype
SW *NewSw();
UINT FreeSw(SW *sw);

void SwDefineComponents(SW *sw);
SW_COMPONENT *SwNewComponent(char *name, char *svc_name, UINT id, UINT icon, UINT icon_index, wchar_t *svc_filename,
							 wchar_t *long_name, bool system_mode_only, UINT num_files, char *files[],
							 wchar_t *start_exe_name, wchar_t *start_description,
							 SW_OLD_MSI *old_msis, UINT num_old_msis);
void SwFreeComponent(SW_COMPONENT *c);
void SwDetectComponents(SW *sw);
bool SwIsComponentDetected(SW *sw, SW_COMPONENT *c);
void SwParseCommandLine(SW *sw);
SW_COMPONENT *SwFindComponent(SW *sw, char *name);

void SwInitDefaultInstallDir(SW *sw);
void SwUiMain(SW *sw);
bool SwCheckNewDirName(wchar_t *name);
wchar_t *SwGetOldMsiInstalledDir(SW_COMPONENT *c);
bool SwUninstallOldMsiInstalled(HWND hWnd, WIZARD_PAGE *wp, SW_COMPONENT *c, bool *reboot_required);

bool SwReExecMyself(SW *sw, wchar_t *additional_params, bool as_admin);

SW_TASK *SwNewTask();
void SwFreeTask(SW_TASK *t);
SW_TASK_COPY *SwNewCopyTask(wchar_t *srcfilename, wchar_t *dstfilename, wchar_t *srcdir, wchar_t *dstdir, bool overwrite, bool setup_file);
void SwFreeCopyTask(SW_TASK_COPY *ct);
void SwDefineTasks(SW *sw, SW_TASK *t, SW_COMPONENT *c);
SW_TASK_LINK *SwNewLinkTask(wchar_t *target_dir, wchar_t *target_exe, wchar_t *target_arg,
							wchar_t *icon_exe, UINT icon_index,
							wchar_t *dest_dir, wchar_t *dest_name, wchar_t *dest_desc,
							bool no_delete_dir);
void SwFreeLinkTask(SW_TASK_LINK *lt);

void SwAddLog(SW *sw, SW_LOGFILE *logfile, UINT type, wchar_t *path);
void SwAddLogA(SW *sw, SW_LOGFILE *logfile, UINT type, char *path);
bool SwSaveLogFile(SW *sw, wchar_t *dst_name, SW_LOGFILE *logfile);
SW_LOGFILE *SwLoadLogFile(SW *sw, wchar_t *filename);
SW_LOGFILE *SwNewLogFile();
void SwFreeLogFile(SW_LOGFILE *logfile);

void SwInstallShortcuts(SW *sw, WIZARD_PAGE *wp, SW_COMPONENT *c, SW_TASK *t);
void SwDeleteShortcuts(SW_LOGFILE *logfile);

bool SwCheckOs(SW *sw, SW_COMPONENT *c);

bool SwEnterSingle(SW *sw);
void SwLeaveSingle(SW *sw);

UINT SwWelcomeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwModeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwNotAdminDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwComponents(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwComponentsInit(HWND hWnd, SW *sw);
void SwComponentsUpdate(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page);
UINT SwEula(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwEulaUpdate(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page);
UINT SwDir(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwDirUpdate(HWND hWnd, SW *sw, WIZARD_PAGE *wizard_page);
UINT SwReady(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwPerform(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwPerformInit(HWND hWnd, SW *sw, WIZARD_PAGE *wp);
void SwPerformThread(THREAD *thread, void *param);
void SwPerformPrint(WIZARD_PAGE *wp, wchar_t *str);
UINT SwPerformMsgBox(WIZARD_PAGE *wp, UINT flags, wchar_t *msg);
UINT SwInteractUi(WIZARD_PAGE *wp, SW_UI *ui);
void SwInteractUiCalled(HWND hWnd, SW *sw, WIZARD_PAGE *wp, SW_UI *ui);
bool SwInstallMain(SW *sw, WIZARD_PAGE *wp, SW_COMPONENT *c);
UINT SwError(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwFinish(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwUninst1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
bool SwUninstallMain(SW *sw, WIZARD_PAGE *wp, SW_COMPONENT *c);
UINT SwLang1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwLang1Init(HWND hWnd, SW *sw);
UINT SwGetLangIcon(char *name);
void SwLang1Update(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page);
UINT SwEasy1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwEasy2(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwEasy2Update(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page);
bool SwEasyMain(SW *sw, WIZARD_PAGE *wp);
UINT SwWeb1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwWeb2(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwWeb2Update(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page);
bool SwWebMain(SW *sw, WIZARD_PAGE *wp);


void SwGenerateDefaultSfxFileName(wchar_t *name, UINT size);
void SwGenerateDefaultZipFileName(wchar_t *name, UINT size);

bool CALLBACK SwEnumResourceNamesProc(HMODULE hModule, const char *type, char *name, LONG_PTR lParam);

UINT SwSfxModeMain();
bool CALLBACK SfxModeMainDialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
bool SwSfxExtractProcess(HWND hWnd, bool *hide_error_msg);
bool SwSfxExtractFile(HWND hWnd, void *data, UINT size, wchar_t *dst, bool compressed);
SW_SFX_FILE *SwNewSfxFile(char *inner_file_name, wchar_t *disk_file_name);
bool SwSfxCopyVgFiles(HWND hWnd, wchar_t *src, wchar_t *dst);


//////////////////////////////////////////////////////////////////////////
// resource.h

#define IDOK3                           2
#define B_POLICY                        3
#define B_SAVE                          3
#define B_ABOUT                         3
#define B_OFFLINE                       3
#define IDOK2                           3
#define IDCANCEL3                       3
#define B_WEB                           3
#define B_SIMULATION                    3
#define B_RESTORE                       3
#define B_MESSAGE                       3
#define B_PUSH                          3
#define B_HUB_STATUS                    4
#define IDCANCEL2                       4
#define B_SECURE_MANAGER                4
#define B_REDIRECT                      4
#define B_EULA                          4
#define DLG_SECURE                      5
#define D_SECURE                        5
#define B_CLIENT_CERT                   5
#define B_CREATE                        5
#define B_SELECT_SECURE                 5
#define B_IMPORTANT                     5
#define B_CREATE_LISTENER               6
#define B_CERT_TOOL                     6
#define B_LEGAL                         6
#define B_DELETE_LISTENER               7
#define B_LEGAL2                        7
#define B_UPDATE_CONFIG                 7
#define B_START                         8
#define B_LEGAL3                        8
#define B_LANGUAGE                      8
#define B_STOP                          9
#define B_AUTHORS                       9
#define B_EDIT                          10
#define S_STATUSBAR                     101
#define ICO_TEST                        103
#define BMP_TEST                        104
#define ICO_KEY                         105
#define BMP_SECURE                      106
#define BMP_SECURE2                     107
#define AVI_PROGRESS                    108
#define ICO_CERT                        109
#define D_PKCSUTIL                      110
#define D_PASSPHRASE                    111
#define D_DEFAULT                       112
#define D_SPEEDMETER                    112
#define D_PASSWORD                      113
#define ICO_SERVER_ONLINE               113
#define D_STATUS                        114
#define D_CERT                          115
#define D_CHECKCERT                     116
#define ICO_WARNING                     117
#define D_CONNECTERROR                  117
#define ICO_NULL                        118
#define D_CM_LOGIN                      118
#define D_CM_MAIN                       119
#define ICO_TOWER                       119
#define ICO_VPN                         120
#define D_CONNECTION_STATUS             120
#define ICO_VPNSERVER                   121
#define D_CM_POLICY                     121
#define D_CM_ACCOUNT                    122
#define ICO_NIC_ONLINE                  123
#define D_CM_PROXY                      123
#define ICO_SETUP                       124
#define D_CM_DETAIL                     124
#define ICO_MACHINE                     125
#define D_CM_NEW_VLAN                   125
#define D_CM_TRUST                      126
#define D_CM_PASSWORD                   127
#define ICO_HUB                         128
#define D_CM_CONFIG                     128
#define ICO_VLAN                        129
#define D_ABOUT                         129
#define ICO_SERVER_OFFLINE              130
#define M_MAIN                          130
#define D_REMOTE                        130
#define ICO_NIC_OFFLINE                 131
#define D_CM_DESKTOP                    131
#define D_CM_CHANGE_PASSWORD            132
#define ICO_INFORMATION                 133
#define D_SM_MAIN                       133
#define ICO_STOP                        134
#define D_SM_EDIT_SETTING               134
#define ICO_SERVER_DELETE               135
#define D_SM_SERVER                     135
#define ICO_SERVER_ONLINE_EX            136
#define D_SM_STATUS                     136
#define ICO_SERVER_OFFLINE_EX           137
#define D_SM_EDIT_HUB                   137
#define ICO_INTERNET                    138
#define D_SM_CREATE_LISTENER            138
#define ICO_DISPLAY                     139
#define D_SM_SSL                        139
#define D_SM_SAVE_KEY_PAIR              140
#define BMP_MANAGER_LOGO                141
#define D_SM_CONNECTION                 141
#define D_SM_FARM                       142
#define ICO_GROUP                       143
#define D_SM_FARM_MEMBER                143
#define ICO_USER                        144
#define D_SM_CHANGE_PASSWORD            144
#define ICO_USER_ADMIN                  145
#define D_SM_HUB                        145
#define ICO_HUB_OFFLINE                 146
#define D_SM_USER                       146
#define ICO_FARM                        147
#define D_SM_EDIT_USER                  147
#define D_SM_POLICY                     148
#define D_SM_GROUP                      149
#define ICO_X                           150
#define D_SM_EDIT_GROUP                 150
#define ICO_PROTOCOL                    151
#define D_SM_ACCESS_LIST                151
#define ICO_PROTOCOL_X                  152
#define D_SM_EDIT_ACCESS                152
#define ICO_DISCARD                     153
#define D_SM_RADIUS                     153
#define ICO_PASS                        154
#define D_SM_LINK                       154
#define ICO_PROTOCOL_OFFLINE            155
#define D_SM_LOG                        155
#define ICO_MEMORY                      156
#define D_SM_CA                         156
#define ICO_PKCS12                      157
#define D_SM_SESSION                    157
#define ICO_SERVER_CERT                 158
#define D_SM_MAC                        158
#define D_SM_IP                         159
#define ICO_LINK                        160
#define D_SM_CREATE_CERT                160
#define ICO_PENGUIN                     161
#define D_NM_LOGIN                      161
#define ICO_LINK2                       162
#define ICO_CASCADE                     163
#define ICO_USER1                       164
#define ICO_USER_DENY                   164
#define ICO_GROUP_DENY                  165
#define ICO_LOG                         166
#define ICO_LOG2                        167
#define ICO_DATETIME                    168
#define ICO_NEW                         169
#define ICO_PASS_DISABLE                170
#define ICO_DISCARD_DISABLE             171
#define ICO_CASCADE_ERROR               172
#define ICO_CASCADE_OFFLINE             173
#define ICO_PROTOCOL_DHCP               174
#define ICO_ROUTER                      175
#define BMP_ROUTER_BANNER               176
#define BMP_ROUTER_LOGO                 178
#define BMP_COINS                       179
#define ICO_BRIDGE                      180
#define BIN_WINPCAP                     181
#define ICO_SWITCH                      182
#define ICO_SWITCH_OFFLINE              183
#define ICO_SECURE                      184
#define ICO_CERT_X                      185
#define ICO_INTERNET_X                  186
#define ICO_LICENSE                     187
#define ICO_SESSION_BRIDGE              188
#define BMP_SECURE3                     188
#define ICO_VPN1                        189
#define ICO_SESSION_MONITOR             189
#define ICO_TRAY1                       190
#define BMP_CLIENT_BANNER               190
#define ICO_TRAY2                       191
#define BMP_SETUP_2                     191
#define ICO_TRAY3                       192
#define BMP_SETUP_1                     192
#define ICO_TRAY4                       193
#define BMP_TSUKUBA                     193
#define ICO_VPN2                        194
#define ICO_TRAY0                       194
#define IDR_MENU1                       194
#define M_VOICE_BACKUP                  194
#define BMP_ETHERIP                     195
#define BMP_L2TP                        197
#define ICO_IPSEC                       201
#define BMP_IX2015                      202
#define ICO_DDNS                        203
#define ICO_OPENVPN                     204
#define BMP_OPENVPN                     205
#define BMP_SSTP                        206
#define ICO_SPECIALLISTENER             207
#define BMP_SPECIALLISTENER             208
#define ICO_INSTALLER                   209
#define BMP_SELOGO49x49                 211
#define ICO_LANGUAGE                    215
#define BMP_SW_LANG_1                   216
#define BMP_SW_LANG_2                   217
#define BMP_SW_LANG_3                   218
#define ICO_LANG_CHINESE                219
#define ICO_LANG_ENGLISH                220
#define ICO_LANG_JAPANESE               221
#define ICO_EASYINSTALLER               222
#define BMP_VPNSERVER_FIGURE            223
#define BMP_ABOUTBOX                    224
#define BMP_UPDATE                      225
#define BMP_IBARAKI                     226
#define IDB_BITMAP1                     227
#define BMP_WINPC                       227
#define BMP_VMBRIDGE                    228
#define BMP_AZURE                       229
#define BMP_AZURE_JA                    230
#define ICO_AZURE                       231
#define IDB_BITMAP2                     232
#define BMP_AZURE_CN                    232
#define ICO_ZURUHAM                     233
#define IDI_ICON2                       234
#define ICO_ZURUKKO                     234
#define BMP_VPNGATEBANNER               235
#define BMP_ZURUKKO                     236
#define BMP_VPNGATEEN                   237
#define BMP_VPNGATEJA                   238
#define ICO_RESEARCH                    239
#define BMP_UNIVTSUKUBA                 240
#define ICO_POLICE                      241
#define S_TITLE                         1007
#define S_INSERT_SECURE                 1008
#define S_TITLE2                        1008
#define S_STATIC                        1008
#define S_RESEARCH                      1008
#define S_DEVICE_INFO                   1009
#define E_PIN                           1010
#define IDS_STATIC1                     1012
#define S_WARNING                       1013
#define A_PROGRESS                      1014
#define S_MSG_1                         1014
#define S_WARNING2                      1014
#define S_STATUS                        1015
#define S_MSG_2                         1015
#define S_PIN_CODE                      1016
#define S_MSG_3                         1016
#define S_STATUS3                       1016
#define S_SOFTWARE_TITLE                1017
#define S_STATUS4                       1017
#define B_WRITE                         1018
#define S_STATUS6                       1018
#define B_ERASE                         1019
#define S_STATUS5                       1019
#define S_COPYRIGHT                     1020
#define S_SUFFIX                        1020
#define E_PASSPHRASE                    1021
#define S_STATUS7                       1021
#define S_STATUS8                       1022
#define E_USERNAME                      1023
#define C_TYPE                          1024
#define E_HUBNAME                       1024
#define E_REALNAME                      1024
#define P_PROGRESS                      1025
#define E_NOTE                          1025
#define E_NICNAME                       1025
#define E_GROUP                         1026
#define E_PRIORITY                      1026
#define E_PASSWORD                      1027
#define E_CN                            1027
#define E_SRC_IP_V6                     1027
#define S_COUNTDOWN                     1028
#define E_PASSWORD2                     1028
#define E_SRC_PORT_1                    1028
#define E_O                             1028
#define S_RETRYINFO                     1029
#define E_RADIUS_USERNAME               1029
#define E_SRC_PORT_2                    1029
#define E_OU                            1029
#define E_SUBJECT                       1030
#define E_DST_PORT_1                    1030
#define E_C                             1030
#define E_ISSUER                        1031
#define E_DST_PORT_2                    1031
#define E_ST                            1031
#define E_EXPIRES                       1032
#define E_L                             1032
#define E_SRC_PORT_3                    1032
#define E_IP_PROTO                      1032
#define L_CERTINFO                      1033
#define E_MD5                           1033
#define E_EXPIRES_TIME                  1033
#define E_EXPIRE                        1033
#define E_SERI                          1033
#define E_DST_MAC                       1033
#define S_PARENT                        1034
#define E_DOMAIN                        1034
#define E_MD5_HASH                      1034
#define E_SRC_MAC                       1034
#define B_PARENT                        1035
#define E_SHA1                          1035
#define E_SHA1_HASH                     1035
#define E_SRC_MAC_MASK                  1035
#define E_DST_MAC_MASK                  1036
#define S_WARNING_ICON                  1037
#define E_SRC_MASK_V6                   1037
#define S_CERT_ICON                     1038
#define E_DST_IP_V6                     1038
#define S_PARENT_BUTTON_STR             1039
#define E_DST_MASK_V6                   1039
#define E_DETAIL                        1040
#define B_SHOW                          1041
#define S_MSG1                          1043
#define E_ERROR                         1044
#define L_ACCOUNT                       1047
#define L_VLAN                          1048
#define L_STATUS                        1048
#define S_DESCRIPTION                   1051
#define L_POLICY                        1052
#define E_ACCOUNT_NAME                  1053
#define E_HOSTNAME                      1054
#define E_RETRY_NUM                     1055
#define E_SECRET1                       1055
#define E_SECRET2                       1056
#define R_DIRECT_TCP                    1057
#define R_HTTPS                         1059
#define R_SOCKS                         1060
#define S_USERNAME                      1062
#define E_RETRY_SPAN                    1065
#define C_HUBNAME                       1066
#define S_PASSWORD                      1067
#define S_CERT                          1068
#define S_CONTROLLER_PORT               1068
#define B_REGIST_CLIENT_CERT            1069
#define S_CERT_INFO                     1070
#define R_RETRY                         1071
#define R_INFINITE                      1072
#define R_USE_ENCRYPT                   1072
#define B_DETAIL                        1073
#define R_USE_COMPRESS                  1073
#define R_CHECK_CERT                    1074
#define R_USE_COMPRESS2                 1074
#define R_DISABLE_UDP                   1074
#define B_CONFIG_L2                     1074
#define B_VIEW_CLIENT_CERT              1075
#define C_NUM_TCP                       1075
#define B_TRUST                         1076
#define E_INTERVAL                      1076
#define B_PROXY_CONFIG                  1077
#define B_SERVER_CERT                   1078
#define B_VIEW_SERVER_CERT              1079
#define R_USE_HALF_CONNECTION           1080
#define C_PORT                          1080
#define S_STATIC13                      1080
#define R_USE_DISCONNECT                1081
#define S_RETRY_NUM_1                   1081
#define S_RETRY_NUM_2                   1082
#define S_RETRY_SPAN_1                  1083
#define E_DISCONNECT_SPAN               1083
#define S_RETRY_SPAN_2                  1084
#define R_NO_ROUTING                    1084
#define E_NAME                          1085
#define B_CHANGE_PASSWORD               1085
#define L_CERT                          1086
#define S_CHANGE_PASSWORD               1086
#define B_IMPORT                        1087
#define B_PROXY_CONFIG2                 1087
#define B_IE                            1087
#define B_EXPORT                        1088
#define IDC_STATIC1                     1088
#define R_R_NOTLS1                      1088
#define R_NOTLS1                        1088
#define R_USE_PASSWORD                  1089
#define IDC_STATIC3                     1089
#define B_IMPORT2                       1089
#define B_REGENERATE                    1089
#define B_FACTORY                       1089
#define R_RETRY2                        1089
#define R_REMOTE_ONLY                   1090
#define IDC_STATIC4                     1090
#define B_DELETE                        1091
#define IDC_STATIC2                     1091
#define R_ALLOW_REMOTE_CONFIG           1092
#define B_REFRESH                       1092
#define IDC_STATIC5                     1092
#define B_DELETE2                       1092
#define B_ETH_VLAN                      1092
#define B_VLAN                          1092
#define R_USE_KEEP_CONNECT              1093
#define B_CERT                          1093
#define IDC_STATIC6                     1093
#define B_SESSION_IP_TABLE              1093
#define B_NEW_CERT                      1093
#define B_RENAME                        1093
#define S_HOSTNAME                      1094
#define B_REFRESH2                      1094
#define B_BRIDGE                        1094
#define B_PIN                           1094
#define R_ALPHA                         1095
#define B_SESSION_MAC_TABLE             1095
#define B_PASSWORD2                     1095
#define B_L3                            1095
#define R_TCP                           1096
#define B_MAC_TABLE                     1096
#define B_IPSEC                         1096
#define S_INFO                          1097
#define B_OPENVPN                       1097
#define B_DEFAULT                       1097
#define S_PORT                          1098
#define B_BRIDGE2                       1098
#define B_DDNS                          1098
#define S_INFO7                         1098
#define E_PORT                          1099
#define B_AZURE                         1099
#define S_INFO8                         1099
#define S_INTERVAL                      1100
#define E_CONTROLLER                    1100
#define B_IP_TABLE                      1100
#define E_PORT2                         1100
#define E_RADIUS_RETRY_INTERVAL         1100
#define S_INFO6                         1100
#define B_VPNGATE                       1100
#define S_INFO2                         1101
#define S_INTERVAL2                     1102
#define R_LOCAL                         1102
#define S_PROTOCOL                      1103
#define C_HOSTNAME                      1103
#define R_UDP                           1104
#define S_ICON                          1104
#define E_ALPHA_VALUE                   1105
#define S_INFO4                         1105
#define S_ICON2                         1105
#define S_INFO3                         1106
#define E_OLD_PASSWORD                  1106
#define E_NEW_PASSWORD1                 1107
#define S_INFO5                         1107
#define E_NEW_PASSWORD2                 1108
#define L_SETTING                       1109
#define B_NEW_SETTING                   1110
#define B_EDIT_SETTING                  1111
#define R_SERVER_ADMIN                  1111
#define B_DELETE_SETTING                1112
#define R_NO_SAVE                       1112
#define B_MODE                          1112
#define R_HUB_ADMIN                     1113
#define B_MODE2                         1113
#define B_VGC                           1113
#define S_HUBNAME                       1114
#define E_MAX_SESSION                   1115
#define R_LOCALHOST                     1116
#define L_HUB                           1118
#define L_LISTENER                      1120
#define B_SSL                           1121
#define B_STATUS                        1123
#define E_PASSWORD1                     1123
#define B_INFO                          1124
#define R_LIMIT_MAX_SESSION             1124
#define B_FARM                          1125
#define S_MAX_SESSION_1                 1125
#define B_INFO2                         1125
#define S_MAX_SESSION_2                 1126
#define B_CONNECTION                    1126
#define R_ONLINE                        1127
#define B_FARM_STATUS                   1127
#define R_OFFLINE                       1128
#define S_BOLD                          1129
#define S_FARM_INFO                     1130
#define S_BOLD2                         1130
#define R_STATIC                        1131
#define R_DYNAMIC                       1132
#define C_CIPHER                        1132
#define S_AO_3                          1133
#define S_ACL                           1134
#define B_VIEW                          1136
#define R_PKCS12                        1136
#define R_USE_PASS                      1137
#define E_PASS1                         1138
#define E_PASS2                         1139
#define R_X509_AND_KEY                  1140
#define S_PASS1                         1141
#define S_PASS2                         1142
#define B_DISCONNECT                    1143
#define R_SECURE                        1143
#define L_LIST                          1144
#define S_CURRENT                       1145
#define L_KEY                           1145
#define R_STANDALONE                    1146
#define R_CONTROLLER                    1147
#define R_MEMBER                        1148
#define S_PORT_2                        1151
#define S_PORT_1                        1152
#define S_IP_1                          1153
#define E_IP                            1154
#define S_SRC_MAC_ALL                   1154
#define S_CHECK_SRC_MAC                 1154
#define S_IP_2                          1155
#define E_SRC_MASK                      1155
#define E_MASK                          1155
#define S_CONTROLLER                    1156
#define E_DST_IP                        1156
#define E_DHCP_START                    1156
#define E_CONTROLLER_PORT               1157
#define E_DST_MASK                      1157
#define E_DHCP_END                      1157
#define S_PORT_3                        1158
#define E_DHCP_MASK                     1158
#define L_FARM_MEMBER                   1159
#define E_GATEWAY                       1159
#define B_USER                          1160
#define E_DNS                           1160
#define B_GROUP                         1161
#define B_CASCADE                       1161
#define E_DNS2                          1161
#define S_USER                          1162
#define B_USER2                         1162
#define S_GROUP                         1163
#define B_SECURENAT                     1163
#define B_ACCESS                        1164
#define S_LINK                          1165
#define S_RADIUS                        1166
#define L_USER                          1167
#define S_RADIUS2                       1167
#define S_CA                            1167
#define B_PROPERTY                      1168
#define B_RADIUS                        1169
#define B_LINK                          1170
#define S_PASSWORD_2                    1170
#define B_SESSION                       1171
#define S_PASSWORD_3                    1171
#define B_LOG                           1172
#define B_LOAD_CERT                     1172
#define B_RADIUS2                       1173
#define B_VIEW_CERT                     1173
#define B_CA                            1173
#define R_CN                            1174
#define B_SNAT                          1174
#define R_SERIAL                        1175
#define S_SNAT                          1175
#define R_O                             1175
#define R_SET_RADIUS_USERNAME           1176
#define B_CRL                           1176
#define R_OU                            1176
#define S_RADIUS_2                      1177
#define R_C                             1177
#define B_LOG_FILE                      1177
#define R_POLICY                        1178
#define S_RADIUS_4                      1178
#define R_ST                            1178
#define S_RADIUS_5                      1179
#define R_L                             1179
#define R_EXPIRES                       1180
#define R_SERI                          1180
#define S_RADIUS_7                      1180
#define R_MD5_HASH                      1181
#define S_RADIUS_9                      1181
#define R_SHA1_HASH                     1182
#define L_AUTH                          1183
#define S_RADIUS_8                      1183
#define S_RADIUS_1                      1184
#define S_RADIUS_3                      1185
#define S_POLICY_1                      1186
#define S_PASSWORD_1                    1187
#define S_POLICY_2                      1187
#define S_ROOT_CERT_1                   1188
#define S_ROOT_CERT_2                   1189
#define S_ROOT_CERT_3                   1190
#define S_USER_CERT_1                   1191
#define S_RADIUS_10                     1192
#define S_HINT                          1192
#define E_EXPIRES_DATE                  1193
#define S_POLICY_TITLE                  1194
#define E_POLICY_DESCRIPTION            1195
#define R_ENABLE                        1196
#define R_DISABLE                       1197
#define R_DEFINE                        1198
#define E_VALUE                         1199
#define S_TANI                          1200
#define S_LIMIT                         1201
#define L_GROUP                         1202
#define E_GROUPNAME                     1203
#define B_ADD                           1205
#define L_ACCESS_LIST                   1206
#define B_DEL_IF                        1206
#define B_ADD_TABLE                     1207
#define B_ADD_V6                        1207
#define R_PASS                          1208
#define B_DEL_TABLE                     1208
#define B_DEL                           1208
#define R_DISCARD                       1209
#define R_DENY                          1209
#define R_SRC_ALL                       1210
#define B_OBTAIN                        1210
#define R_IPV4                          1210
#define R_DST_ALL                       1211
#define R_IPV6                          1211
#define C_PROTOCOL                      1212
#define E_USERNAME1                     1213
#define E_USERNAME2                     1214
#define S_SRC_IP_1                      1215
#define S_SRC_IP_2                      1216
#define S_SRC_IP_3                      1217
#define E_SRC_IP                        1218
#define S_SRC_IP_4                      1218
#define S_IP_DST_1                      1219
#define S_IP_DST_2                      1220
#define S_IP_DST_3                      1221
#define S_TCP_1                         1222
#define S_TCP_2                         1223
#define S_TCP_3                         1224
#define S_TCP_4                         1225
#define S_TCP_5                         1226
#define S_TCP_6                         1227
#define S_TCP_7                         1228
#define B_USER1                         1229
#define S_SRC_MAC                       1230
#define R_USE_RADIUS                    1231
#define R_SRC_MAC_ALL                   1231
#define R_CHECK_SRC_MAC                 1231
#define S_DST_MAC                       1232
#define S_RADIUS3                       1233
#define R_DST_MAC_ALL                   1233
#define R_CHECK_DST_MAC                 1233
#define S_RADIUS_6                      1234
#define S_SRC_MAC_MASK                  1234
#define S_LOG                           1235
#define S_DST_MAC_MASK                  1235
#define S_MAC_NOTE                      1236
#define L_LINK                          1237
#define E_SERIAL                        1238
#define S_VLAN_GROUP                    1238
#define B_SEC                           1240
#define S_SEC                           1241
#define C_SEC_SWITCH                    1242
#define B_PACKET                        1243
#define S_PACKET                        1244
#define C_PACKET_SWITCH                 1245
#define S_PACKET_0                      1246
#define S_PACKET_1                      1247
#define B_PACKET_0_0                    1248
#define B_PACKET_1_0                    1249
#define S_FARM_INFO_1                   1249
#define B_PACKET_0_1                    1250
#define S_FARM_INFO_2                   1250
#define B_PACKET_1_1                    1251
#define L_TABLE                         1251
#define B_PACKET_0_2                    1252
#define R_ROOT_CERT                     1252
#define B_PACKET_1_2                    1253
#define R_SIGNED_CERT                   1253
#define S_PACKET_2                      1254
#define B_LOAD                          1254
#define B_PACKET_2_0                    1255
#define S_LOAD_1                        1255
#define B_PACKET_2_1                    1256
#define S_LOAD_2                        1256
#define B_PACKET_2_2                    1257
#define S_LOAD_3                        1257
#define S_LOAD_4                        1258
#define S_LOAD_5                        1259
#define S_STATIC_S                      1259
#define S_ACCESS                        1259
#define S_LOAD_6                        1260
#define S_VERSION                       1260
#define S_LOAD_7                        1261
#define S_LOGO                          1261
#define S_PACKET_3                      1262
#define S_LOAD_8                        1262
#define S_VERSION2                      1262
#define B_PACKET_3_0                    1263
#define S_LOAD_9                        1263
#define S_BUILD                         1263
#define B_PACKET_3_1                    1264
#define S_LOAD_10                       1264
#define B_PACKET_3_2                    1265
#define S_LOAD_11                       1265
#define B_SETTING                       1265
#define S_PACKET_4                      1266
#define B_CONNECT                       1266
#define S_ACCOUNT_NAME                  1266
#define S_LOAD_12                       1266
#define B_PACKET_4_0                    1267
#define S_ROUTER_LOGO                   1267
#define S_LOAD_13                       1267
#define B_PACKET_4_1                    1268
#define B_OPTION                        1268
#define E_MAC                           1268
#define B_PACKET_4_2                    1269
#define B_NAT                           1269
#define R_USE_NAT                       1269
#define S_PACKET_5                      1270
#define E_MTU                           1270
#define B_PACKET_5_0                    1271
#define B_DHCP                          1271
#define E_TCP                           1271
#define B_PACKET_5_1                    1272
#define E_UDP                           1272
#define B_PACKET_5_2                    1273
#define R_USE_DHCP                      1273
#define S_PACKET_6                      1274
#define R_SAVE_LOG                      1274
#define B_PACKET_6_0                    1275
#define R_HIDE                          1275
#define B_PACKET_6_1                    1276
#define S_PROPERTY                      1276
#define R_HIDE2                         1276
#define B_PACKET_6_2                    1277
#define B_ENABLE                        1277
#define S_PACKET_7                      1278
#define B_DISABLE                       1278
#define B_PACKET_7_0                    1279
#define B_CONFIG                        1279
#define B_CLONE                         1279
#define B_DISABLE2                      1279
#define B_PROXY                         1279
#define B_PACKET_7_1                    1280
#define S_TSUKUBA1                      1280
#define B_LICENSE                       1280
#define B_PACKET_7_2                    1281
#define S_TSUKUBA2                      1281
#define IDC_CHECK1                      1285
#define R_NO_SAVE_PASSWORD              1285
#define R_PROMISCUS                     1285
#define R_NO_ENUM                       1285
#define R_ETHERNET                      1285
#define R_CONTROLLER_ONLY               1285
#define B_HIDE                          1285
#define R_DISABLE_QOS                   1285
#define R_LOCK                          1285
#define C_REMOTE                        1285
#define C_DONTSHOWAGAIN                 1285
#define R_CHECK_TCP_STATE               1285
#define C_DELAY                         1285
#define C_USEMSG                        1285
#define R_L2TP_OVER_IPSEC               1285
#define B_AGREE                         1285
#define R_SHOWCUSTOM                    1285
#define B_RUN                           1285
#define B_DELETE_SENSITIVE              1285
#define R_LOG                           1285
#define R_DOUBLE                        1286
#define C_SITE                          1286
#define C_JITTER                        1286
#define R_REDIRECT                      1286
#define R_L2TP                          1286
#define E_LIST                          1287
#define C_OTHER                         1287
#define C_LOSS                          1287
#define R_L2TP_RAW                      1287
#define B_EASYMODE                      1287
#define R_ETHERIP                       1288
#define R_BRIDGE                        1289
#define R_TAP                           1290
#define R_MONITOR                       1290
#define E_TAPNAME                       1291
#define S_ETH_1                         1292
#define S_TAP_1                         1293
#define S_TAP_2                         1294
#define S_VHUB_BRIDGE                   1295
#define C_DEVICE                        1296
#define IDC_INFO                        1297
#define E_CONFIG                        1298
#define B_ADMINOPTION                   1300
#define S_AO_1                          1301
#define S_AO_2                          1302
#define S_ACL_3                         1303
#define S_ACL_2                         1304
#define B_ACL                           1305
#define B_ACL2                          1306
#define B_EXTOPTION                     1306
#define S_AO_4                          1307
#define B_MSG                           1308
#define C_NAME                          1309
#define S_ACL_5                         1310
#define L_IF                            1311
#define S_BOLD1                         1313
#define B_ADD_IF                        1314
#define E_NETWORK                       1315
#define E_METRIC                        1316
#define B_BOLD                          1317
#define R_CERT                          1319
#define R_KEY                           1320
#define E_STRING                        1320
#define R_DATA                          1321
#define B_BOLD1                         1321
#define B_BOLD2                         1322
#define R_FROM_FILE                     1322
#define R_FROM_SECURE                   1323
#define B_SELECT                        1324
#define S_FILE                          1325
#define S_PASS3                         1326
#define S_PASS4                         1327
#define E_PIN1                          1328
#define E_PIN2                          1329
#define E_PIN3                          1330
#define R_SINGLE                        1331
#define R_MASKED                        1332
#define S_MASK                          1333
#define S_MODE                          1336
#define B_PASSWORD                      1339
#define R_RECV_DISABLE                  1340
#define B_PASSWORD3                     1340
#define B_SPECIALLISTENER               1340
#define R_RECV_ENABLE                   1341
#define E_RECV                          1342
#define S_RECV                          1343
#define B_RECV                          1344
#define R_SEND_DISABLE                  1345
#define R_SEND_ENABLE                   1346
#define E_SEND                          1347
#define R_OPTIMIZE                      1347
#define S_SEND                          1348
#define R_MANUAL                        1348
#define B_SEND                          1349
#define R_NO                            1349
#define S_IMAGE                         1351
#define S_IMAGE2                        1352
#define S_INFO_1                        1352
#define S_INFO_2                        1353
#define S_IMAGE3                        1353
#define S_IMAGE_TSUKUBA                 1353
#define S_INFO_3                        1354
#define S_INFO_4                        1355
#define S_PROTOID                       1356
#define S_1                             1359
#define S_18                            1360
#define S_3                             1361
#define R_SERVER                        1362
#define S_19                            1362
#define R_CLIENT                        1363
#define S_20                            1363
#define S_4                             1364
#define S_21                            1364
#define S_5                             1365
#define S_23                            1365
#define C_HOST                          1366
#define S_22                            1366
#define S_6                             1367
#define S_25                            1367
#define S_8                             1368
#define S_9                             1369
#define S_7                             1370
#define R_DOWNLOAD                      1371
#define R_UPLOAD                        1372
#define R_FULL                          1373
#define S_10                            1374
#define S_11                            1375
#define C_NUM                           1376
#define S_12                            1377
#define E_SPAN                          1378
#define S_13                            1379
#define E_EDIT                          1379
#define S_14                            1380
#define IDC_EDIT1                       1380
#define E_WEIGHT                        1380
#define B_KEY1                          1380
#define E_SYSLOG_HOSTNAME               1380
#define E_TEXT                          1380
#define E_DELAY                         1380
#define E_IPV6                          1380
#define E_SECRET                        1380
#define E_ID                            1380
#define E_DDNS_HOST                     1380
#define E_SAMPLE1                       1380
#define E_CURRENT                       1380
#define E_OWNER                         1380
#define S_15                            1381
#define S_2                             1381
#define E_SYSLOG_PORT                   1381
#define E_JITTER                        1381
#define E_IPV7                          1381
#define E_MASKV6                        1381
#define E_SAMPLE2                       1381
#define E_DDNS_HOST2                    1381
#define E_AZURE_HOST                    1381
#define E_LOSS                          1382
#define S_16                            1382
#define E_URL                           1382
#define E_ABUSE                         1382
#define S_17                            1383
#define E_MSG                           1383
#define S_24                            1384
#define ABOUT                           1387
#define C_SYSLOG                        1388
#define B_KEY2                          1389
#define S_01                            1389
#define B_KEY3                          1390
#define S_02                            1390
#define B_KEY4                          1391
#define R_EASY                          1391
#define B_KEY5                          1392
#define R_NORMAL                        1392
#define B_KEY6                          1393
#define S_PASSWORD1                     1393
#define S_PASSWORD2                     1394
#define S_PASSWORD3                     1395
#define S_STATIC3                       1397
#define S_STATIC4                       1398
#define S_STATIC5                       1399
#define S_STATIC7                       1400
#define S_STATIC66                      1401
#define S_STATIC2                       1402
#define S_STATIC11                      1403
#define S_STATIC1                       1404
#define S_STATIC6                       1405
#define S_STATIC8                       1406
#define S_STATIC9                       1407
#define S_STATIC10                      1408
#define S_STATIC12                      1409
#define S_STATIC19                      1410
#define S_STATIC133                     1411
#define S_REMOTE_1                      1413
#define S_SITE_1                        1414
#define S_SITE_2                        1415
#define C_CENTER                        1416
#define C_EDGE                          1417
#define S_OTHER                         1418
#define S_1_1                           1421
#define S_1_2                           1422
#define S_2_1                           1423
#define S_2_2                           1424
#define S_3_1                           1425
#define S_3_2                           1426
#define IDC_COMBO1                      1427
#define C_BITS                          1427
#define R_NEVER                         1427
#define IDC_BUTTON1                     1428
#define BMP_UT                          1428
#define S_LICENSE                       1429
#define IDC_BUTTON2                     1429
#define S_BETA                          1430
#define IDC_BUTTON3                     1430
#define S_DST_MAC_ALL                   1431
#define S_CHECK_DST_MAC                 1431
#define IDC_BUTTON4                     1431
#define S_ACCESS_DST_ALL                1432
#define S_ACCESS_SRC_ALL                1433
#define IDC_RADIO1                      1434
#define R_ESTABLISHED                   1434
#define R_SYSTEM                        1434
#define R_DEFAULT                       1434
#define S_ENABLE                        1434
#define R_2WEEKS                        1434
#define IDC_RADIO2                      1435
#define R_UNESTABLISHED                 1435
#define R_USER                          1435
#define R_CUSTOM                        1435
#define S_DISBLE                        1435
#define R_PERMANENT                     1435
#define R_FOR_SYSTEM                    1436
#define IDC_NETADDRESS1                 1437
#define R_FOR_USER                      1437
#define IDC_PROGRESS1                   1438
#define E_HELP                          1440
#define S_DELAY                         1441
#define S_DELAY2                        1442
#define S_JITTER                        1443
#define S_JITTER2                       1444
#define S_LOSS                          1445
#define S_LOSS2                         1446
#define S_STATIC14                      1448
#define S_STATIC15                      1449
#define S_MSG_4                         1450
#define S_STATUS1                       1451
#define S_STATUS2                       1452
#define P_BAR                           1453
#define L_HUBNAME                       1454
#define S_PSK                           1455
#define S_PSK2                          1456
#define S_WIN8                          1457
#define R_OPENVPN                       1458
#define S_UDP                           1459
#define S_UDP2                          1460
#define S_TOOL                          1461
#define S_TOOL2                         1462
#define R_SSTP                          1463
#define B_CONFIG_L3                     1464
#define S_SSTP                          1465
#define E_HOST                          1466
#define E_IPV4                          1467
#define E_NEWHOST                       1468
#define B_NSLOOKUP                      1469
#define E_KEY                           1469
#define B_HINT                          1470
#define S_DDNS                          1470
#define R_OVER_ICMP                     1471
#define S_AZURE                         1471
#define B_HINT2                         1471
#define R_OVER_ICMP2                    1472
#define R_OVER_DNS                      1472
#define B_WIZ_NEXT                      1472
#define B_WIZ_NEXT2                     1473
#define B_WIZ_PREV                      1473
#define S_ACK                           1473
#define S_WELCOME                       1474
#define S_ACK2                          1475
#define S_WELCOME2                      1475
#define S_WELCOME3                      1476
#define E_DIR                           1479
#define B_BROWSE                        1480
#define S_DEST                          1481
#define B_BROWSE_OUT                    1481
#define S_UAC                           1482
#define E_SETTING                       1483
#define E_OUT                           1484
#define B_BROWSE_SETTING                1485
#define S_INFO1                         1486
#define S_PRODUCT                       1487
#define S_INFO9                         1487
#define S_PRODUCT_STR                   1488
#define S_CURRENT_STR                   1490
#define S_LATEST                        1491
#define S_LATEST_STR                    1492
#define S_BMP_EN                        1494
#define S_BMP_JA                        1495
#define B_CHANGE                        1496
#define S_HOSTNAME_BORDER               1497
#define S_HOSTNAME_INFO                 1498
#define S_BMP_CN                        1499
#define S_REFRESH                       1499
#define S_VLAN                          1500
#define C_VLAN                          1502
#define S_VPNGATEJA                     1504
#define S_ICO_VPNGATE                   1505
#define S_VPNGATEJA2                    1505
#define S_VPNGATEEN                     1505
#define S1                              1506
#define S2                              1507
#define S3                              1508
#define S4                              1509
#define S5                              1510
#define S_VGS1                          1511
#define S_VGS2                          1512
#define B_VGS                           1513
#define S_VGS3                          1514
#define S_TSUKUBA                       1515
#define R_DISABLE_NATT                  1516
#define S_SMARTCARD_ICON                1517
#define B_ONLINE                        1655
#define D_NM_CONNECT                    1998
#define D_NM_MAIN                       1999
#define D_NM_OPTION                     2000
#define D_NM_NAT                        2001
#define D_NM_DHCP                       2002
#define D_NM_CHANGE_PASSWORD            2003
#define D_SM_SNAT                       2004
#define D_SM_BRIDGE                     2005
#define D_WIN9X_REBOOT                  2006
#define D_DEFAULT1                      2007
#define D_EM_MAIN                       2008
#define D_EM_ADD                        2009
#define D_EM_PASSWORD                   2010
#define D_SM_CONFIG                     2011
#define D_SM_ADMIN_OPTION               2012
#define D_SM_AO_VALUE                   2013
#define D_SM_L3                         2014
#define D_SM_L3_ADD                     2015
#define D_SM_L3_SW                      2016
#define D_SM_L3_SW_IF                   2017
#define D_SM_L3_SW_TABLE                2018
#define D_CM_SELECT_SECURE              2019
#define D_CM_SECURE_MANAGER             2020
#define D_CM_SECURE_TYPE                2021
#define D_STRING                        2022
#define D_SM_SELECT_KEYPAIR             2023
#define D_CM_LOAD_X                     2024
#define D_CM_SECURE_PIN                 2025
#define D_SM_CRL                        2026
#define D_SM_EDIT_CRL                   2027
#define D_SM_AC_LIST                    2028
#define D_SM_AC                         2029
#define D_SM_LOG_FILE                   2030
#define D_SM_READ_LOG_FILE              2031
#define D_SM_SAVE_LOG                   2032
#define D_TCP                           2033
#define D_TCP_MSG                       2034
#define D_CM_PKCSEULA                   2035
#define D_CM_KAKUSHI                    2036
#define D_CM_TRAFFIC                    2037
#define D_CM_TRAFFIC_RUN                2038
#define D_CM_TRAFFIC_RESULT             2039
#define D_SM_LICENSE                    2040
#define D_SM_LICENSE_ADD                2041
#define D_FREEEDITION                   2042
#define D_FREEINFO                      2042
#define D_EM_LICENSE_ADD                2043
#define D_EM_LICENSE                    2044
#define D_EM_REMOTE                     2045
#define D_CM_SETTING                    2046
#define D_CM_EASY                       2047
#define D_SM_SETUP                      2048
#define D_SM_SETUP_HUB                  2049
#define D_SM_SETUP_STEP                 2050
#define D_DEFAULT2                      2051
#define D_CPU64_WARNING                 2051
#define D_ONCEMSG                       2052
#define D_CONNECT                       2053
#define D_SM_SIMULATION                 2054
#define D_SM_EDIT_ACCESS1               2055
#define D_SM_EDIT_ACCESS_V6             2055
#define D_SM_VLAN                       2056
#define D_SM_MSG                        2057
#define D_NICSTATUS                     2058
#define D_NICINFO                       2058
#define D_SM_IPSEC                      2059
#define D_SM_ETHERIP                    2060
#define D_SM_ETHERIP_ID                 2061
#define D_SM_OPENVPN                    2062
#define D_DDNS                          2063
#define D_SM_DDNS                       2063
#define D_SM_SPECIALLISTENER            2064
#define D_SM_REDIRECT                   2065
#define D_SW_TEST1                      2066
#define D_DUMMY                         2067
#define D_SW_TEST2                      2068
#define D_SW_DEFAULT                    2069
#define D_SW_WELCOME                    2070
#define D_SW_MODE                       2071
#define D_SW_NOT_ADMIN                  2072
#define D_SW_COMPONENTS                 2073
#define D_SW_EULA                       2074
#define D_SW_WARNING                    2075
#define D_SW_DIR                        2076
#define D_SW_READY                      2077
#define D_SW_PERFORM                    2078
#define D_SW_ERROR                      2079
#define D_SW_ERROR1                     2080
#define D_SW_FINISH                     2080
#define D_SW_WELCOME1                   2081
#define D_SW_UNINST1                    2081
#define D_SW_LANG1                      2082
#define D_SW_EASY1                      2083
#define D_SW_EASY2                      2084
#define D_SW_WEB1                       2085
#define D_SW_EASY4                      2086
#define D_SW_WEB2                       2086
#define D_UPDATE_NOTICE                 2087
#define D_UPDATE_CONFIG                 2088
#define D_SM_VMBRIDGE                   2089
#define D_SM_AZURE                      2090
#define D_SM_PROXY                      2091
#define D_VGC_LIST                      2092
#define D_VGC_PROTOCOL                  2093
#define D_VGS_CONFIG                    2094
#define D_VGS_OPTION                    2095
#define D_VGS_WARNING                   2096
#define D_DEFAULT3                      2097
#define D_NM_PUSH                       2097
#define ID_Menu40011                    40011
#define CMD_CONNECT                     40020
#define CMD_STATUS                      40021
#define CMD_DISCONNECT                  40022
#define CMD_NEW                         40023
#define CMD_CLONE                       40024
#define CMD_STARTUP                     40025
#define CMD_NOSTARTUP                   40026
#define CMD_PROPERTY                    40028
#define CMD_EXIT                        40029
#define CMD_SWITCH_SELECT               40031
#define CMD_SELECT_ALL                  40032
#define CMD_TOOLBAR                     40033
#define CMD_STATUSBAR                   40034
#define CMD_ICON                        40035
#define CMD_DETAIL                      40036
#define CMD_REFRESH                     40037
#define CMD_PASSWORD                    40038
#define CMD_ABOUT                       40040
#define CMD_DELETE_VLAN                 40045
#define CMD_NEW_VLAN                    40046
#define CMD_REINSTALL                   40050
#define CMD_PROPERTY_VLAN               40052
#define CMD_DISABLE_VLAN                40054
#define CMD_ENABLE_VLAN                 40056
#define CMD_RENAME                      40059
#define CMD_DELETE                      40061
#define CMD_GRID                        40062
#define CMD_                            40063
#define CMD_TRUST                       40065
#define CMD_DISCONNECT_ALL              40067
#define CMD_VOICE_NORMAL                40072
#define CMD_VOIDE_NONE                  40073
#define CMD_VOICE_ODD                   40074
#define CMD_EXPORT_ACCOUNT              40075
#define CMD_IMPORT_ACCOUNT              40078
#define CMD_SHORTCUT                    40079
#define ID_40080                        40080
#define ID_40082                        40082
#define CMD_SECURE_MANAGER              40083
#define CMD_SECURE_SELECT               40084
#define CMD_QUIT                        40086
#define CMD_NETIF                       40088
#define CMD_TCPIP                       40089
#define CMD_TRAFFIC                     40090
#define CMD_OPTION                      40092
#define ID__40093                       40093
#define CMD_CM_SETTING                  40094
#define CMD_MMCSS                       40095
#define CMD_TRAYICON                    40096
#define ID__                            40097
#define CMD_WINNET                      40098
#define ID__40099                       40099
#define CMD_VISTASTYLE                  40100
#define ID__40101                       40101
#define CMD_SHOWPORT                    40102
#define ID__40103                       40103
#define CMD_RECENT                      40104
#define ID__40105                       40105
#define ID__40106                       40106
#define CMD_LANGUAGE                    40107
#define ID_VPNGATE40108                 40108
#define ID__40109                       40109
#define CMD_VGS                         40110





#endif	// SECLIB_C
#endif	// OS_WIN32





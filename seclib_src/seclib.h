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
#ifdef	MICROSOFT_C

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
#pragma warning( disable : 4099 )
#endif	// OS_WIN32



// Switches
#if	defined(OS_UNIX) || (_MSC_VER >= 1900)
#define SECLIB_SW_USE_NEW_WCSTOK
#endif


#endif // SECLIB_H




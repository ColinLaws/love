

#ifdef _WIN32


// For rand_s() in stdlib.h
#define _CRT_RAND_S


#include <Winsock2.h>
#include <pcap.h>


#endif	// _WIN32


#include <iostream>
#include <vector>
#include <sstream>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#if defined(__sgi) || defined(__GNUC__)


#include <pthread.h>
#include <strings.h>
#include <unistd.h>
#include <sys/dir.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>


#endif	// __sgi || __GNUC__


// NOTE: Redefine missing types


typedef unsigned int iaddr_t;


#define IP_V4_ADDR_LEN 4
#define LS_ERROR_LEN 56


/////////////////////////////////////////////////
// NOTE: SGI IRIX
/////////////////////////////////////////////////


#ifdef __sgi


#include <bstring.h>
#include <net/raw.h>
#include <protocols/bootp.h>


#define ETHERHDRPAD RAW_HDRPAD(sizeof(struct ether_header))


// NOTE: Ethernet packet
//
//  Every packet returned by the snoop interface (see class SNOOPI)
//  uses the following data structure to store data.
//
//  The etherpacket struct is used on all supported OSs, but its
//  definition is OS-specific.


struct etherpacket
{
	struct snoopheader  snoop;
	char   pad[ETHERHDRPAD];
	struct ether_header ether;
	char   data[ETHERMTU];
};


#endif	// __sgi


/////////////////////////////////////////////////
// NOTE: GNU/Linux
/////////////////////////////////////////////////


#ifdef __GNUC__


#include <cstring>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <ifaddrs.h>



#define ETHER_TYPE 0x0800
#define ARG_MAX    131072


// NOTE: Ethernet packet
//
//  Every packet returned by the snoop interface (see class SNOOPI)
//  uses the following data structure to store data.
//
//  The etherpacket struct is used on all supported OSs, but its
//  definition is OS-specific.


struct etherpacket
{
	struct ether_header ether;
	char   data[ETHERMTU];
};


// NOTE: Bootp protocol header
//
//  SGI IRIX's protocols/bootp.h header is reproduced
//  here partially to consolidate interfaces and ease porting.


struct vend {
	u_char  v_magic[4];     // magic number
	u_int   v_flags;        // flags/opcodes, etc.
	u_char  v_unused[56];   // currently unused
};


struct bootp {
	u_char  bp_op;          // packet opcode type
#define BOOTREQUEST     1
#define BOOTREPLY       2
	u_char  bp_htype;       // hardware addr type
	u_char  bp_hlen;        // hardware addr length 
	u_char  bp_hops;        // gateway hops 
	u_int   bp_xid;         // transaction ID 
	u_short bp_secs;        // seconds since boot began 
	u_short bp_unused;
	iaddr_t bp_ciaddr;      // client IP address 
	iaddr_t bp_yiaddr;      // 'your' IP address 
	iaddr_t bp_siaddr;      // server IP address 
	iaddr_t bp_giaddr;      // gateway IP address 
	u_char  bp_chaddr[16];  // client hardware address 
	u_char  bp_sname[64];   // server host name 
	u_char  bp_file[128];   // boot file name 
	union {
		u_char  vend_unused[64];
		struct  vend    sgi_vadmin;
	} rfc1048;
#define bp_vend         rfc1048.vend_unused             // rfc951 field
#define vd_magic        rfc1048.sgi_vadmin.v_magic      // magic #
#define vd_flags        rfc1048.sgi_vadmin.v_flags      // opcodes
#define vd_clntname     rfc1048.sgi_vadmin.v_unused     // client name
} __attribute__((__packed__));


// UDP port numbers, server and client.
#define IPPORT_BOOTPS           67
#define IPPORT_BOOTPC           68


#define VM_STANFORD     "STAN"          // v_magic for Stanford
#define VM_SGI          0xc01a3309      // v_magic for Silicon Graphics Inc.
#define VM_AUTOREG      0xc01a330a      // v_magic for Silicon Graphics Inc.

// v_flags values
#define VF_PCBOOT       1       // IBM PC or Mac wants environment info
#define VF_HELP         2       // Help is requested
#define VF_GET_IPADDR   3       // Request for client IP address
#define VF_RET_IPADDR   4       // Response for client IP address
#define VF_NEW_IPADDR   5       // Response for client IP address


#endif	// __GNUC__


/////////////////////////////////////////////////
// NOTE: MS Windows
/////////////////////////////////////////////////


#ifdef _WIN32


#include <stdlib.h>
#include <windows.h>
#include <process.h>
#include <synchapi.h>
#include <IO.h>


#define ETHERMTU	1500
#define ETH_ALEN	6
#define ETHER_TYPE	0x0800
#define MAXPATHLEN	260
#define IFNAMSIZ	1024


#define u_char UCHAR
#define u_int UINT
#define u_short USHORT


typedef signed int ssize_t;


// NOTE: Ethernet packet
//
//  Every packet returned by the snoop interface (see class SNOOPI)
//  uses the following data structure to store data.
//
//  The etherpacket struct is used on all supported OSs, but its
//  definition is OS-specific.


#pragma pack(1)
struct ether_header
{
	uint8_t  ether_dhost[ETH_ALEN];       // Destination eth addr
	uint8_t  ether_shost[ETH_ALEN];       // Source ether addr
	uint16_t ether_type;                  // Packet type ID field
};


#pragma pack(1)
struct etherpacket
{
	struct ether_header ether;
	char   data[ETHERMTU];
};


// NOTE: IP protocol header


#pragma pack(1)
struct iphdr
{
	unsigned char vers_ihl;
	unsigned char tos;
	unsigned short total_length;
	unsigned short id;
	unsigned short frag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned int source_address;
	unsigned int dest_address;
};


// NOTE: UDP protocol header


#pragma pack(1)
struct udphdr
{
	uint16_t uh_sport;
	uint16_t uh_dport;
	uint16_t uh_ulen;
	uint16_t uh_sum;
};


// NOTE: Bootp protocol header
//
//  SGI IRIX's protocols/bootp.h header is reproduced
//  here partially to consolidate interfaces and ease porting.


#pragma pack(1)
struct vend {
	u_char  v_magic[4];     // magic number
	u_int   v_flags;        // flags/opcodes, etc.
	u_char  v_unused[56];   // currently unused
};


#pragma pack(1)
struct bootp {
	u_char  bp_op;          // packet opcode type
#define BOOTREQUEST     1
#define BOOTREPLY       2
	u_char  bp_htype;       // hardware addr type
	u_char  bp_hlen;        // hardware addr length 
	u_char  bp_hops;        // gateway hops 
	u_int   bp_xid;         // transaction ID 
	u_short bp_secs;        // seconds since boot began 
	u_short bp_unused;
	iaddr_t bp_ciaddr;      // client IP address 
	iaddr_t bp_yiaddr;      // 'your' IP address 
	iaddr_t bp_siaddr;      // server IP address 
	iaddr_t bp_giaddr;      // gateway IP address 
	u_char  bp_chaddr[16];  // client hardware address 
	u_char  bp_sname[64];   // server host name 
	u_char  bp_file[128];   // boot file name 
	union {
		u_char  vend_unused[64];
		struct  vend    sgi_vadmin;
	} rfc1048;
#define bp_vend         rfc1048.vend_unused             // rfc951 field
#define vd_magic        rfc1048.sgi_vadmin.v_magic      // magic #
#define vd_flags        rfc1048.sgi_vadmin.v_flags      // opcodes
#define vd_clntname     rfc1048.sgi_vadmin.v_unused     // client name
};


// UDP port numbers, server and client.
#define IPPORT_BOOTPS           67
#define IPPORT_BOOTPC           68


#define VM_STANFORD     "STAN"          // v_magic for Stanford
#define VM_SGI          0xc01a3309      // v_magic for Silicon Graphics Inc.
#define VM_AUTOREG      0xc01a330a      // v_magic for Silicon Graphics Inc.

// v_flags values
#define VF_PCBOOT       1       // IBM PC or Mac wants environment info
#define VF_HELP         2       // Help is requested
#define VF_GET_IPADDR   3       // Request for client IP address
#define VF_RET_IPADDR   4       // Response for client IP address
#define VF_NEW_IPADDR   5       // Response for client IP address


#endif	// _WIN32


#define IPPORT_TFTPD 69
#define IPPORT_RSHD 514
#define INPORT_ANY 0
#define MAX_LABEL_LENGTH 64
#define MAX_TFTP_PATH_LENGTH 128
#define TFTPD_TIDS_MAX 65536
#define LOG_MAX_SIZE 8192


// NOTE: TFTP definitions


#define TFTP_MAX_PACKET_SIZE 516


#define TFTP_OPCODE_READ	0x01
#define TFTP_OPCODE_WRITE	0x02
#define TFTP_OPCODE_DATA	0x03
#define TFTP_OPCODE_ACK		0x04
#define TFTP_OPCODE_ERROR	0x05


// NOTE: Class definitions


#ifdef ECHO
#define ECHO_BAK ECHO
#undef ECHO
#endif


class REGULAR_FILE
{
public:

	static bool exists(std::string&);
};


class PATH
{
private:

	int type;
	int os_type;
	int local_os_type;
	std::string path;
	std::string original_path;
	std::vector<std::string> components;


	// Constructor helper
	int construct(const std::string&);


	// Split string by delimiter
	int split(const std::string&,
		char,
		std::vector<std::string>&);


	// Join into string using delimiter
	int join(char,
		std::string&);


	// Check for drive designator
	bool is_drive_designator(char,
		char);


	// Set local OS type
	void set_local_os_type();


	// Get path for UNIX
	int get_unix(std::string&);


	// Reset internal state
	void reset();

public:

	class type
	{
	public:

		static const unsigned int NONE_PATH;
		static const unsigned int ABSOLUTE_PATH;
		static const unsigned int DRIVE_ABSOLUTE_PATH;
		static const unsigned int UNC_PATH;
	};


	class os_type
	{
	public:

		static const unsigned int NONE_OS;
		static const unsigned int UNIX_OS;
		static const unsigned int WIN32_OS;
	};


	// Default constructor
	PATH();


	// Direct constructor with string
	PATH(const std::string&);


	// Direct constructor with character array
	PATH(const char*);


	// Set new path with string
	int set(const std::string&);


	// Set new path with string
	int set(const char*);


	// Add component from string
	int add_component(const std::string&);


	// Add component from character array
	int add_component(const char*);


	// Add components from string
	int add_components(const std::string&,
		unsigned int);


	// Add components from character array
	int add_components(const char*,
		unsigned int);


	// Get path for local host
	int get_local(std::string&);


	// Get path for IRIX
	int get_irix(std::string&);


	// Get path for LINUX
	int get_linux(std::string&);


	// Get path for WIN32
	int get_win32(std::string&);


	// Check for empty pathname
	bool empty();


	// Check for ".." special component
	bool contains_dotdot();


	// Print path and components
	void print_path();
};


const unsigned int PATH::type::NONE_PATH = 0;
const unsigned int PATH::type::ABSOLUTE_PATH = 1;
const unsigned int PATH::type::DRIVE_ABSOLUTE_PATH = 2;
const unsigned int PATH::type::UNC_PATH = 3;


const unsigned int PATH::os_type::NONE_OS = 0;
const unsigned int PATH::os_type::UNIX_OS = 1;
const unsigned int PATH::os_type::WIN32_OS = 2;


bool PATH::is_drive_designator(char first_char,		// - IN: First character (A, B, C, ...)
	char second_char)	// - IN: Second character (:)
{
	// Check for drive letter
	if (((first_char < 'a') || (first_char > 'z')) &&
		((first_char < 'A') || (first_char > 'Z')))
	{
		return false;	// ERROR: No drive letter
	}


	// Check for colon
	if (second_char != ':')
	{
		return false;	// ERROR: No colon
	}


	return true;	// SUCCESS
}


int PATH::split(const std::string& string,			// - IN: Command string
	char delimiter,					// - IN: Word delimiter
	std::vector<std::string>& words)		// - OUT: Command words
{
	bool last_word;
	std::size_t pos;
	std::size_t space_pos_0;
	std::size_t space_pos_1;
	std::size_t word_length;


	// IN: Check for empty string
	if (string.length() == 0)
	{
		return 0;       // ERROR: Empty string
	}


	// IN: Check for word delimiter
	if (delimiter == '\0')
	{
		return -1;      // ERROR: No word delimiter
	}


	// Find first space character
	pos = 0;
	space_pos_1 = string.find_first_of(delimiter, pos);


	// Check for space character
	if (space_pos_1 == std::string::npos)
	{
		// NOTE: Single word


		// Get single word
		words.push_back(string);
	}
	else
	{
		// NOTE: Multiple words


		// Split string
		last_word = false;
		space_pos_0 = 0;
		while (true)
		{
			// Get word
			word_length = space_pos_1 - space_pos_0;
			words.push_back(string.substr(space_pos_0, word_length));


			// Check for last word
			if (last_word == true)
			{
				break;
			}


			// Update lower position
			space_pos_0 = space_pos_1 + 1;


			// Get position of next space character
			space_pos_1 = string.find_first_of(delimiter, space_pos_0);


			// Check for space character
			if (space_pos_1 == std::string::npos)
			{
				// NOTE: No more space characters


				// Check for trailing word
				if (space_pos_0 < string.length())
				{
					// Set end position to string length
					space_pos_1 = string.length();


					// Set flag for trailing word
					last_word = true;
				}
				else
				{
					// NOTE: No more words in command string


					break;
				}
			}
		}
	}


	return 1;       // SUCCESS
}


int PATH::join(char delimiter,		// - IN: Delimiter to join words with
	std::string& string)	// - OUT: Joined string
{
	std::vector<std::string>::iterator it;


	// IN: Check for delimiter
	if (delimiter == '\0')
	{
		return 0;	// ERROR: No delimiter
	}


	// Clear string
	string.clear();


	// Check for single component
	if (this->components.size() == 1)
	{
		string = this->components[0] + delimiter;
	}
	else
	{
		// Traverse components
		for (it = this->components.begin();
			it < this->components.end();
			it++)
		{
			// Check for first component
			if (it == this->components.begin())
			{
				// Just add component to string
				string += *it;


				continue;
			}


			// Add prefixed component
			string += delimiter + *it;
		}
	}


	return 1;	// SUCCESS
}


int PATH::construct(const std::string& path)	// - IN: Path
{
	char first_char;
	char second_char;


	// Check for empty path
	if (path.empty() == true)
	{
		return 0;	// ERROR: Empty path
	}


	// NOTE: Paths
	//
	//  On different OSs, different path syntaxes are used. This class supports
	//  IRIX, LINUX and WIN32 platforms:
	//
	//   IRIX/LINUX:
	//
	//    /component_0/.../component_N
	//
	//   WIN32:
	//
	//    With drive designator: C:\...\component_N
	//    Absolute path: \...\component_N
	//    UNC: \\server\...\component_N
	//
	//    In any case, a path under WIN32 is always at most 260 characters in
	//    length.
	//
	//  The PATH class can only be initialized with absolute pathnames on all
	//  supported platforms.


	// Get first character
	first_char = path[0];


	// Check for IRIX/LINUX path
	if (first_char == '/')
	{
		// NOTE: IRIX/LINUX path


		// Split components at '/'
		if (this->split(path,
			'/',
			this->components) < 1)
		{
			// NOTE: Split error


			this->components.clear();


			return -1;	// ERROR: Split error
		}


		// Set type
		this->type = PATH::type::ABSOLUTE_PATH;


		// Set OS type
		this->os_type = PATH::os_type::UNIX_OS;


		// Set original path
		this->original_path = path;


		// NOTE: Split and join
		//
		//  The original path string is first split, and then joined
		//  back again. The purpose of this is to have a consistent view
		//  of the path string for adding components later on.


		// Join components with '/'
		if (this->join('/',
			this->path) < 1)
		{
			// NOTE: Join error


			// Reset internal state
			this->type = PATH::type::NONE_PATH;
			this->os_type = PATH::os_type::NONE_OS;
			this->original_path.clear();
			this->path.clear();
			this->components.clear();


			return -2;	// ERROR: Join error
		}
	}
	else
	{
		// NOTE: Not IRIX/LINUX path


		// Check for trivial case
		if (path.length() == 1)
		{
			// NOTE: Must be '\'


			// Check for '\'
			if (first_char != '\\')
			{
				// NOTE: Not '\'


				return -3;	// ERROR: Single character path is not '\'
			}


			// Set type
			this->type = PATH::type::ABSOLUTE_PATH;


			// Set OS type
			this->os_type = PATH::os_type::WIN32_OS;


			// Set original path
			this->original_path = path;
		}
		else
		{
			// HINT: path.length() > 1


			// Get second character
			second_char = path[1];


			// Check for path type
			if (this->is_drive_designator(first_char,
				second_char) == true)
			{
				// NOTE: Drive absolute path
				//
				//  Absolute pathname with drive designator.


				// Set type
				this->type = PATH::type::DRIVE_ABSOLUTE_PATH;


				// Set OS type
				this->os_type = PATH::os_type::WIN32_OS;


				// Set original path
				this->original_path = path;
			}
			else if ((first_char == '\\') &&
				(second_char == '\\'))
			{
				// NOTE: UNC


				// Set type
				this->type = PATH::type::UNC_PATH;


				// Set OS type
				this->os_type = PATH::os_type::WIN32_OS;


				// Set original path
				this->original_path = path;
			}
			else if (first_char == '\\')
			{
				// NOTE: Absolute path
				//
				//  Absolute pathname relative to current drive.


				// Set type
				this->type = PATH::type::ABSOLUTE_PATH;


				// Set OS type
				this->os_type = PATH::os_type::WIN32_OS;


				// Set original path
				this->original_path = path;
			}
			else
			{
				// NOTE: Unrecognized path


				return -4;	// ERROR: Unrecognized path
			}
		}


		// Split components at '\'
		if (this->split(path,
			'\\',
			this->components) < 1)
		{
			// NOTE: Split error


			// Reset internal state
			this->type = PATH::type::NONE_PATH;
			this->os_type = PATH::os_type::NONE_OS;
			this->original_path.clear();
			this->path.clear();
			this->components.clear();


			return -5;	// ERROR: Split error
		}


		// NOTE: Split and join
		//
		//  The original path string is first split, and then joined
		//  back again. The purpose of this is to have a consistent view
		//  of the path string for adding components later on.


		// Join components with '\'
		if (this->join('\\',
			this->path) < 1)
		{
			// NOTE: Join error


			// Reset internal state
			this->type = PATH::type::NONE_PATH;
			this->os_type = PATH::os_type::NONE_OS;
			this->original_path.clear();
			this->path.clear();
			this->components.clear();


			return -6;	// ERROR: Join error
		}
	}


	return 1;	// SUCCESS
}


void PATH::reset()
{
	this->type = PATH::type::NONE_PATH;
	this->os_type = PATH::os_type::NONE_OS;
	this->local_os_type = PATH::os_type::NONE_OS;
	this->original_path = "";
	this->path = "";
	this->components.clear();
}


int PATH::set(const std::string& path)
{
	// Reset object
	this->reset();


	// Set local OS type
	this->set_local_os_type();


	// Construct object
	if (this->construct(path) < 1)
	{
		return 0;	// ERROR: Couldn't construct object
	}


	return 1;	// SUCCESS
}


int PATH::set(const char* path)
{
	// Reset object
	this->reset();


	// Set local OS type
	this->set_local_os_type();


	// Construct object
	if (this->construct(std::string(path)) < 1)
	{
		return 0;	// ERROR: Couldn't construct object
	}


	return 1;	// SUCCESS
}


void PATH::set_local_os_type()
{


#if defined(__sgi) || defined(__GNUC__)


	// Set local OS type
	this->local_os_type = PATH::os_type::UNIX_OS;


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Set local OS type
	this->local_os_type = PATH::os_type::WIN32_OS;


#endif	// _WIN32


}


PATH::PATH() : type(PATH::type::NONE_PATH),
os_type(PATH::os_type::NONE_OS),
local_os_type(PATH::os_type::NONE_OS),
original_path(""),
path(""),
components()
{
	// Set local OS type
	this->set_local_os_type();
}


PATH::PATH(const std::string& path) : type(PATH::type::NONE_PATH),
os_type(PATH::os_type::NONE_OS),
local_os_type(PATH::os_type::NONE_OS),
original_path(""),
path(""),
components()
{
	// Set local OS type
	this->set_local_os_type();


	// Construct object
	this->construct(path);
}


PATH::PATH(const char* path) : type(PATH::type::NONE_PATH),
os_type(PATH::os_type::NONE_OS),
local_os_type(PATH::os_type::NONE_OS),
original_path(""),
path(""),
components()
{
	// Set local OS type
	this->set_local_os_type();


	// Construct object
	this->construct(std::string(path));
}


// Add component from string
int PATH::add_component(const std::string& component)	// - IN: Component to add
{
	// Check for empty new component
	if (component.empty() == true)
	{
		return 0;	// ERROR: Empty new component
	}


	// Check for empty current components
	if (this->components.empty() == true)
	{
		return -1;	// ERROR: Empty current components
	}


	// Add component
	this->components.push_back(component);


	// NOTE: Update path


	// Check for OS type
	if (this->os_type == PATH::os_type::UNIX_OS)
	{
		// NOTE: UNIX path


		// Check for single root component
		if (this->path.compare("/") == 0)
		{
			// NOTE: /component


			this->path += component;
		}
		else
		{
			// NOTE: /component_0[/...]/component


			this->path += '/' + component;
		}
	}
	else if (this->os_type == PATH::os_type::WIN32_OS)
	{
		// NOTE: WIN32 path


		// Check for path type
		if (this->type == PATH::type::ABSOLUTE_PATH)
		{
			// NOTE: Absolute path
			//
			//  Absolute path without drive designator:
			//
			//   \component_0\...\component_N


			// Check for single root component
			if (this->path.compare("\\") == 0)
			{
				// NOTE: \component


				this->path += component;
			}
			else
			{
				// NOTE: \component_0[\...]\component


				this->path += '\\' + component;
			}
		}
		else if (this->type == PATH::type::DRIVE_ABSOLUTE_PATH)
		{
			// NOTE: Drive absolute path
			//
			//  Absolute path with drive designator:
			//
			//   C:\component_0\...\component_N


			// Check for single root component
			if (this->path.length() == 3)
			{
				if (this->path[2] == '\\')
				{
					// NOTE: C:\component


					this->path += component;
				}
				else
				{
					// NOTE: Invalid single root component


					return -2;	// ERROR: Invalid single root component
				}
			}
			else
			{
				// NOTE: C:\component_0[\...]\component


				this->path += '\\' + component;
			}
		}
		else if (this->type == PATH::type::UNC_PATH)
		{
			// NOTE: UNC path
			//
			//  Universal naming convention path.
			//
			//   \\server\share\component_0\...\component_N


			this->path += '\\' + component;
		}
		else
		{
			return -3;	// ERROR: Invalid path type
		}
	}
	else
	{
		return -4;	// ERROR: Invalid OS type
	}


	return 1;	// SUCCESS
}


// Add component from character array
int PATH::add_component(const char* component)	// - IN: Component to add
{
	// IN: Check for component
	if (component == NULL)
	{
		return 0;	// ERROR: No component
	}


	// Check for empty component
	if (component[0] == '\0')
	{
		return -1;	// ERROR: Empty component
	}


	// Add component
	if (this->add_component(std::string(component)) < 1)
	{
		return -2;	// ERROR: Couldn't add component
	}


	return 1;	// SUCCESS
}


int PATH::add_components(const std::string& components,	// - IN: Path components to add
	unsigned int os_type)		// - IN: OS type of path components
{
	std::vector<std::string>::iterator it;
	std::vector<std::string> new_components;


	// IN: Check for empty path components
	if (components.empty() == true)
	{
		return 0;	// ERROR: Empty path components
	}


	// Check path OS type
	if (os_type == PATH::os_type::UNIX_OS)
	{
		// NOTE: IRIX/LINUX path


		// Check for absolute pathname
		if (components[0] == '/')
		{
			// NOTE: Absolute pathname
			//
			//  Only relative pathname is allowed.


			return -1;	// ERROR: Absolute pathname
		}


		// Split components at '/' (slash)
		if (this->split(components,
			'/',
			new_components) < 1)
		{
			// NOTE: Split error


			return -2;	// ERROR: Split error
		}
	}
	else if (os_type == PATH::os_type::WIN32_OS)
	{
		// NOTE: WIN32 path


		// Check for absolute pathname
		if (components[0] == '\\')
		{
			// NOTE: Absolute pathname
			//
			//  Only relative pathname is allowed.


			return -3;	// ERROR: Absolute pathname
		}


		// Split components at '\\' (backslash)
		if (this->split(components,
			'\\',
			new_components) < 1)
		{
			// NOTE: Split error


			return -4;	// ERROR: Split error
		}
	}
	else
	{
		return -5;	// ERROR: Path OS type not allowed
	}


	// Traverse new components
	for (it = new_components.begin();
		it < new_components.end();
		it++)
	{
		// Add new component
		if (this->add_component(*it) < 1)
		{
			return -6;	// ERROR: Couldn't add new component
		}
	}


	return 1;	// SUCCESS
}


int PATH::add_components(const char* components,	// - IN: Path components to add
	unsigned int os_type)		// - IN: OS type of path components
{
	// IN: Check for components
	if (components == NULL)
	{
		return 0;	// ERROR: No components
	}


	// Check for empty components
	if (components[0] == '\0')
	{
		return -1;	// ERROR: Empty components
	}


	// Add components
	if (this->add_components(std::string(components),
		os_type) < 1)
	{
		return -2;	// ERROR: Couldn't add component
	}


	return 1;	// SUCCESS
}


int PATH::get_local(std::string& path)
{
#if defined(__sgi)


	return this->get_irix(path);


#endif


#if defined(__GNUC__)


	return this->get_linux(path);


#endif


#ifdef _WIN32


	return this->get_win32(path);


#endif	// _WIN32
}


int PATH::get_unix(std::string& path)
{
	// Check path OS type
	if (this->os_type == PATH::os_type::UNIX_OS)
	{
		// NOTE: IRIX/LINUX


		// Copy path
		path.clear();
		path = this->path;
	}
	else if (this->os_type == PATH::os_type::WIN32_OS)
	{
		// NOTE: WIN32


		// Join components with '/'
		path.clear();
		if (this->join('/',
			path) < 1)
		{
			// NOTE: Join error


			return 0;	// ERROR: Join error
		}


		// Check for path type
		if (this->type == PATH::type::DRIVE_ABSOLUTE_PATH)
		{
			// Prepend '/'
			path = '/' + path;


			// Delete ':' after drive letter
			path.erase(path.begin() + 2);


			// Check for trailing '/'
			std::size_t last_index = path.length() - 1;
			if (path.at(last_index) == '/')
			{
				// Delete trailing '/'
				path.erase(path.end() - 1);
			}
		}
		else if (this->type == PATH::type::UNC_PATH)
		{
			// Delete first '/'
			path.erase(path.begin());
		}
		else if (this->type == PATH::type::ABSOLUTE_PATH)
		{
		}
		else
		{
			// Reset path
			path.clear();


			return -1;	// ERROR: Unknown path type
		}
	}
	else
	{
		return -2;	// ERROR: Unknown path OS type
	}


	return 1;	// SUCCESS
}


int PATH::get_irix(std::string& path)
{
	return this->get_unix(path);
}


int PATH::get_linux(std::string& path)
{
	return this->get_unix(path);
}


int PATH::get_win32(std::string& path)
{
	// Check path OS type
	if (this->os_type == PATH::os_type::WIN32_OS)
	{
		// NOTE: WIN32


		// Copy path
		path.clear();
		path = this->path;
	}
	else if (this->os_type == PATH::os_type::UNIX_OS)
	{
		// NOTE: IRIX/LINUX


		// Join components with '\\'
		path.clear();
		if (this->join('\\',
			path) < 1)
		{
			// NOTE: Join error


			return 0;	// ERROR: Join error
		}
	}
	else
	{
		return -1;	// ERROR: Unknown path OS type
	}


	return 1;	// SUCCESS
}


bool PATH::empty()
{
	// Check for empty path
	if (this->path.empty() == true)
	{
		return true;
	}


	return false;
}


bool PATH::contains_dotdot()
{
	bool dotdot_found;
	std::vector<std::string>::iterator it;


	// Traverse components
	dotdot_found = false;
	for (it = this->components.begin();
		it < this->components.end();
		it++)
	{
		// Check for ".." component
		if ((*it).compare("..") == 0)
		{
			dotdot_found = true;


			break;
		}
	}


	// Check for found ".." component
	if (dotdot_found != true)
	{
		return false;	// SUCCESS: Couldn't find ".."
	}


	return true;	// SUCCESS
}


void PATH::print_path()
{
	std::vector<std::string>::iterator it;


	std::cout << "[PATH::print_path] ORIGINALPATH: " << this->original_path << "\n";
	std::cout << "[PATH::print_path] PATH: " << this->path << "\n";
	std::cout << "[PATH::print_path] TYPE: " << this->type << "\n";


	// Traverse components
	for (it = this->components.begin();
		it < this->components.end();
		it++)
	{
		std::cout << "[PATH::print_path] COMPONENT: " << *it << "\n";
	}
}


struct tftp
{
	unsigned short opcode;
	unsigned short server_tid;
	unsigned short client_tid;


	struct
	{
		std::string filename;
		char mode_string[8 + 1];
		unsigned int mode;
	} rw;


	struct
	{
		char block[512];
		unsigned short block_number;
		unsigned short size;
	} data;


	struct
	{
		unsigned short block_number;
	} ack;


	struct
	{
		char error_msg[128 + 1];
		unsigned short error_code;
	} error;
};


struct rsh
{
	std::string name;
	unsigned int type;
	unsigned int subtype;


	struct
	{
		PATH if_filename;
		std::string echo;
		bool has_fgrep;
		unsigned int iseek;
	} dd;


	struct
	{
		bool has_L;
		bool has_a;
		PATH target;
		std::string echo;
		std::string req_path;
	} ls;


	struct
	{
		std::string text;
		std::string echo;
	} echo;


	struct
	{
		std::string echo;
		std::string suffix;
	} trap;
};


class LABEL_FILE
{
public:

	struct LINE
	{
	private:

		// Raw line
		std::string string;

	public:

		// Constant definitions
		static const unsigned int NONE;
		static const unsigned int FQLN;
		static const unsigned int PATH;
		static const unsigned int ALIASES;
		static const unsigned int SIZE;


		// Constant label type definitions
		static const unsigned int TYPE_NONE;
		static const unsigned int TYPE_INSTALLATION;
		static const unsigned int TYPE_STANDALONE;
		static const unsigned int TYPE_SIZE;


		// Default constructor
		LINE()
		{
			this->index = 0;
			this->type = 0;
		}


		// Fully qualified label name
		std::string fqln;


		// Pathname
		std::string path;


		// Aliases string
		std::string aliases_string;


		// Aliases strings
		std::vector<std::string> aliases;


		// Line index
		unsigned int index;


		// Label type
		unsigned int type;


		// Check for valid character
		static bool char_is_valid(char,
			unsigned int);


		// Check for blank character
		static bool char_is_blank(char);


		// Clear raw line
		void clear();


		// Clear all internal state
		void clear_all();


		// Return C character array from raw line
		const char* c_str();


		// Check for substring in raw line
		bool contains(const std::string&);


		// Get iterator for raw line
		std::string::iterator begin();


		// Get end iterator for raw line
		std::string::iterator end();


		// Add character to raw line
		LABEL_FILE::LINE& operator +=(char);
	};


	// Get prefixed label from RSHD client request
	static int get_label_prefix(std::string&,
		std::string&,
		std::string&);


	// Get directory from stat modes
	static bool is_directory(unsigned short);


	// Lookup label in label file
	int lookup_label(std::string&,
		bool,
		std::string&,
		std::string&,
		unsigned int&);


	// Read line from label file
	int read_line(int,
		LABEL_FILE::LINE*);


	// Parse label file
	int parse_file(const std::string&,
		bool,
		std::vector<LABEL_FILE::LINE*>&);
};


class BOOTPD
{
public:

	int get_request(struct etherpacket*,
		struct bootp*,
		struct in_addr*,
		std::string&,
		std::string&);


	int send_reply(struct bootp*,
		std::string&,
		bool);
};


class Socket
{
private:

	int sock;
	int sock_errno;
	unsigned int sock_type;


	std::string bind_address;
	unsigned short bind_port;


	std::string connect_address;
	unsigned short connect_port;


	unsigned int listen_backlog;


	std::string accept_address;
	unsigned short accept_port;
	struct sockaddr_in accept_sockaddr_in;


	// Reset internal state
	void reset_state();


	// Internal socket bind
	int bind_socket(std::string&,
		unsigned short);


	// Internal socket connect
	int connect_socket(std::string&,
		unsigned short);

public:

	// CLASS: Socket types


	class type
	{
	private:

		unsigned int sock_type;

	public:

		static unsigned int SOCK_UNKNOWN;
		static unsigned int SOCK_TCP;
		static unsigned int SOCK_UDP;


		// Converting constructor for unsigned int
		type(unsigned int);


		bool operator==(unsigned int);


		bool operator!=(unsigned int);
	};


	// CLASS: Socket address


	class address
	{
	private:

		unsigned int bytes;
		std::string ip_address;

	public:

		// Default constructor for Socket data members
		address();


		// Copy constructor
		address(Socket::address&);


		// Converting constructor for unsigned int
		address(unsigned int);


		// Converting constructor for string
		address(std::string);


		// Direct constructor for address pair
		address(unsigned int,
			std::string);


		// Get socket address as byte sequence
		unsigned int get_bytes();


		// Get socket address as string
		std::string get_string();


		// Copy assignment
		address& operator=(const address&);
	};


	// NOTE: Public static member functions


	// Convert socket bytes address to ASCII address
	static int convert_bytes_to_ascii(unsigned int,
		std::string&);


	// Convert socket ASCII address to bytes address
	static int convert_ascii_to_bytes(std::string&,
		unsigned int&);


	// NOTE: Public data members


	// Socket source address
	Socket::address src;


	// Socket destination address
	Socket::address dst;


	// NOTE: Public member functions


	// Constructor with one argument
	Socket(Socket::type);


	// Default constructor without arguments
	Socket();


	// Default destructor without arguments
	~Socket();


	// Bind socket to local address (as bytes) and port pair
	int bind(unsigned int,
		unsigned short);


	// Bind socket to local address (as string) and port pair
	int bind(std::string,
		unsigned short);


	// Connect socket to remote address (as bytes) and port pair
	int connect(unsigned int,
		unsigned short);


	// Connect socket to remote address (as string) and port pair
	int connect(std::string,
		unsigned short);


	// Listen for incoming connections
	int listen(unsigned int);


	// Accept connection through socket
	int accept(Socket&);


	// Shutdown socket
	int shutdown(unsigned int);


	// Open new underlying system socket
	int open();


	// Open new underlying system socket with explicit socket type
	int open(Socket::type);


	// Close socket
	int close();


	// Get socket option
	int getsockopt(int,
		int,
		void*,
		socklen_t*);


	// Set socket option
	int setsockopt(int,
		int,
		const void*,
		socklen_t);


	// Set linger time out socket option
	int set_linger(unsigned short);


	// Set blocking mode socket option
	int set_blocking(bool);


	// Set reuse address socket option
	int set_reuseaddr(bool);


	// Get last socket errno
	int get_errno();


	// Get internal socket descriptor
	int get_fd();


	// Get socket type
	unsigned int get_type();


	// Get bind address
	std::string get_bind_address();


	// Get bind port
	unsigned short get_bind_port();


	// Get connect address
	std::string get_connect_address();


	// Get connect port
	unsigned short get_connect_port();


	// Get listen backlog
	unsigned int get_listen_backlog();


	// Get accept address
	std::string get_accept_address();


	// Get accept port
	unsigned short get_accept_port();


private:

	void init(Socket::type);

};


class Thread
{
private:


#if defined(__sgi) || defined(__GNUC__)


	pthread_t thread_id;


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	HANDLE thread_id;


#endif	// _WIN32


public:


	// Create thread
	int create_thread(void* function,
		void* function_arg);
};


class Mutex
{
private:


	bool was_created;


#if defined(__sgi) || defined(__GNUC__)


	pthread_mutex_t mutex;


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	HANDLE mutex;


#endif	// _WIN32


public:


	// Constructor
	Mutex();


	// Destructor
	~Mutex();


	// Create mutex
	int create_mutex();


	// Destroy mutex
	int destroy_mutex();


	// Lock mutex
	int lock_mutex();


	// Unlock mutex
	int unlock_mutex();
};


int Thread::create_thread(void* function,	// - IN: Start function to execute in new thread
	void* function_arg)	// - IN: Argument to start function
{
	// IN: Check for start function
	if (function == NULL)
	{
		return 0;	// ERROR: No start function
	}


#if defined(__sgi) || defined(__GNUC__)


	// Create thread
	if (pthread_create(&this->thread_id,
		NULL,
		(void* (*)(void*)) function,
		function_arg) != 0)
	{
		// NOTE: Thread creation error


		return -1;	// ERROR: Couldn't create thread
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Create thread
	this->thread_id = (HANDLE)_beginthread((void (*)(void*)) function,
		0,
		function_arg);
	if ((signed long)this->thread_id == -1L)
	{
		// NOTE: Thread creation error


		return -1;	// ERROR: Couldn't create thread
	}


#endif	// _WIN32


	return 1;	// SUCCESS
}


Mutex::Mutex()
{
	// Initialize was created flag
	this->was_created = false;


#if defined(__sgi) || defined(__GNUC__)


	bzero((void*)&mutex,
		sizeof(pthread_mutex_t));


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	this->mutex = NULL;


#endif	// _WIN32
}


Mutex::~Mutex()
{
	// Check for created mutex
	if (this->was_created == true)
	{
		// NOTE: Mutex was created


		// Destroy mutex
		this->destroy_mutex();
	}
}


int Mutex::create_mutex()
{
#if defined(__sgi) || defined(__GNUC__)


	// Create mutex
	if (pthread_mutex_init(&this->mutex,
		NULL) != 0)
	{
		return 0;	// ERROR: Couldn't create mutex
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Create mutex
	this->mutex = CreateMutex(NULL,
		FALSE,
		NULL);
	if (this->mutex == NULL)
	{
		return 0;	// ERROR: Couldn't create mutex
	}


#endif	// _WIN32


	// Set was created flag
	this->was_created = true;


	return 1;	// SUCCESS
}


int Mutex::destroy_mutex()
{
#if defined(__sgi) || defined(__GNUC__)


	// Destroy mutex
	if (pthread_mutex_destroy(&this->mutex) != 0)
	{
		return 0;	// ERROR: Couldn't destroy mutex
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Destroy mutex
	if (CloseHandle(this->mutex) == 0)
	{
		return 0;	// ERROR: Couldn't destroy mutex
	}


#endif	// _WIN32


	// Reset was created flag
	this->was_created = false;


	return 1;	// SUCCESS
}


int Mutex::lock_mutex()
{
#if defined(__sgi) || defined(__GNUC__)


	// Lock mutex
	if (pthread_mutex_lock(&this->mutex) != 0)
	{
		return 0;	// ERROR: Couldn't lock mutex
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Lock mutex
	if (WaitForSingleObject(this->mutex,
		INFINITE) != WAIT_OBJECT_0)
	{
		return 0;	// ERROR: Couldn't lock mutex
	}


#endif	// _WIN32


	return 1;	// SUCCESS
}


int Mutex::unlock_mutex()
{
#if defined(__sgi) || defined(__GNUC__)


	// Unlock mutex
	if (pthread_mutex_unlock(&this->mutex) != 0)
	{
		return 0;	// ERROR: Couldn't unlock mutex
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Unlock mutex
	if (ReleaseMutex(this->mutex) == 0)
	{
		return 0;	// ERROR: Couldn't unlock mutex
	}


#endif	// _WIN32


	return 1;	// SUCCESS
}


struct thread_args_s
{
	int stderr_sock;
	void* object;
	struct sockaddr_in client_sockaddr_in;
	struct tftp packet;
	Thread* thread_id;
	Socket* server_sock;
	Socket* client_sock;
};


class RSHD
{
private:

	Thread thread_id;
	bool daemon_started;

public:

	class COMMAND
	{
	public:

		static const unsigned int NONE;
		static const unsigned int DD;
		static const unsigned int LS;
		static const unsigned int LS_DOT;
		static const unsigned int ECHO;
		static const unsigned int FLUSH;
		static const unsigned int TRAP;


		// Implementation of UNIX's dd command
		static int dd(Socket&,
			Socket&,
			struct rsh&,
			std::string&,
			unsigned int*,
			unsigned int*);


		// Implementation of UNIX's ls command
		static int ls(Socket&,
			struct rsh*,
			std::string&);


		static int get_mode(struct stat*,
			bool,
			std::string&);


		static int get_mtime(struct stat*,
			std::string&);


		static int add_sorted(char*,
			std::vector<std::string>&);
	};


	// Convert positive decimal number from ASCII to unsigned integer
	static int convert_to_uint(std::string&,
		unsigned int*);


	// Process echo filename suffix
	static void process_status_suffix(std::string&,
		std::string*);


#ifdef _WIN32


	// Get win32 inode
	static int get_win32_inode(std::string&,
		unsigned long long&);


#endif	// _WIN32


	// Default constructor
	RSHD();


	// Start RSHD server
	int start();


	// Check for started RSHD daemon
	bool started();


	// Set RSHD daemon to started
	void set_started();


	// Start new RSHD client session
	int start_session(Socket&,
		Socket&);


	// Parse RSH client command
	int parse(std::string&,
		std::string&,
		struct rsh*);


	// Split string by character
	int split(std::string&,
		char,
		std::vector<std::string>&);


	// RSHD mainloop
	void* loop(void*);


	// Read input from RSH client
	int read_input(Socket&,
		unsigned int,
		char,
		std::string&);
};


class TFTP_FILE : public REGULAR_FILE
{
private:

	int file_desc;
	char prev_char;
	std::string filename;
	unsigned int mode;
	unsigned int block_number;

public:

	// Constructor with filename
	TFTP_FILE(std::string&,
		unsigned int);


	// Checks if the file exists
	bool exists(void);


	// Open file
	int open(void);


	// Reads one block from the file
	int read_block(char*,
		unsigned short*);


	// Close file
	int close(void);


	// Destructor
	~TFTP_FILE();
};


class TFTPD
{
private:

	Thread thread_id;
	Mutex tid_mutex;
	bool seq_tid;
	bool daemon_started;
	unsigned long seed_num;
	unsigned short last_tid;
	std::vector<unsigned short> tids;


	void generate_seq_tid(unsigned short,
		unsigned short&);

	void insert_ordered(unsigned short,
		bool);

public:

	// Default constructor
	TFTPD();


	// Initialize TFTPD
	int init();


	// Deinitialize TFTPD
	int deinit();


	// Start TFTPD daemon
	int start();


	// Check for started TFTPD daemon
	bool started();


	// Set TFTPD daemon to started
	void set_started();


	// Start new TFTPD client session
	int start_session(Socket&,
		struct sockaddr_in,
		std::string,
		unsigned int);


	// Daemon main loop
	void* loop(void*);


	// Read TFTP packet
	int read_packet(Socket&,
		struct sockaddr_in*,
		unsigned int,
		struct tftp*);


	// Write TFTP packet
	int write_packet(Socket&,
		struct sockaddr_in*,
		struct tftp*);


	// Generate TID
	int generate_tid(unsigned short&);


	// Remove TID
	int remove_tid(unsigned short&);
};


class SNOOPI
{
private:

#if defined(__sgi) || defined(__GNUC__)


	int raw_sock;


#endif


#ifdef _WIN32


	pcap_t* dev_handle;


#endif	// _WIN32

public:

	// Initialize SNOOPI
	int init();


	// Deinitialize SNOOPI
	int deinit();


	// Start snooping
	int start(char*);


	// Stop snooping
	int stop();


#if defined(__sgi) || defined(__GNUC__)


	// Get raw socket descriptor
	int get_fd();


#endif	// __sgi || __GNUC__


	// Read ethernet packet
	int read_ethernet_packet(struct etherpacket*,
		size_t);
};


class NetIF
{
public:

	// Check that address corresponds to a local network interface
	int check_addr(SNOOPI,
		iaddr_t,
		char*);
};


class Tracelog
{
private:

	int fd;

public:

	// Open tracelog
	int open(const std::string&);


	// Write to tracelog
	int write(const std::string&);


	// Close tracelog
	int close();
};


// NOTE: Static member definitions


const unsigned int LABEL_FILE::LINE::NONE = 0;
const unsigned int LABEL_FILE::LINE::FQLN = 1;
const unsigned int LABEL_FILE::LINE::PATH = 2;
const unsigned int LABEL_FILE::LINE::ALIASES = 3;
const unsigned int LABEL_FILE::LINE::SIZE = 4;


const unsigned int LABEL_FILE::LINE::TYPE_NONE = 0;
const unsigned int LABEL_FILE::LINE::TYPE_INSTALLATION = 1;
const unsigned int LABEL_FILE::LINE::TYPE_STANDALONE = 2;
const unsigned int LABEL_FILE::LINE::TYPE_SIZE = 3;


const unsigned int RSHD::COMMAND::NONE = 0;
const unsigned int RSHD::COMMAND::DD = 1;
const unsigned int RSHD::COMMAND::LS = 2;
const unsigned int RSHD::COMMAND::LS_DOT = 3;
const unsigned int RSHD::COMMAND::ECHO = 4;
const unsigned int RSHD::COMMAND::FLUSH = 5;
const unsigned int RSHD::COMMAND::TRAP = 6;


unsigned int Socket::type::SOCK_UNKNOWN = 0;
unsigned int Socket::type::SOCK_TCP = 1;
unsigned int Socket::type::SOCK_UDP = 2;


// NOTE: Global variables


iaddr_t local_hostaddr;
const unsigned int loop_forever = 1;
Mutex printf_mutex;
char log_string[LOG_MAX_SIZE];
std::string labels_path;
LABEL_FILE labels;
SNOOPI snoopi;
NetIF nif;
BOOTPD bootpd;
TFTPD tftpd;
RSHD rshd;
Tracelog trace_log;


// Argument switch variables
bool args_debug = false;
bool args_trace = false;
std::string args_trace_path;


// NOTE: Free function declarations


int sync_printf(const char*,
	...);
int sync_dprintf(const char*,
	...);
int sync_print_format(const char*,
	va_list);
int love_gethostbyname(const char*,
	iaddr_t*,
	int*);
void love_sleep(unsigned int);
int love_open(const char*,
	int,
	int);
int love_read(int const,
	void* const,
	unsigned int const);
int love_write(int,
	const void*,
	unsigned int);
int love_close(int);
int love_snprintf(char*,
	unsigned long,
	const char*,
	...);
long love_lseek(int,
	long,
	int);
bool LoadNpcapDlls();
void* RSHD_loop(void*);
void* TFTPD_loop(void*);


#ifdef _WIN32


void bzero(void*,
	unsigned int);
void bcopy(void*,
	void*,
	unsigned int);


#endif	// _WIN32


// NOTE: Member function definitions


bool LABEL_FILE::LINE::char_is_valid(char line_char,            // - IN: Line character to validate
	unsigned int field_type)   // - IN: Field type
{
	// IN: Check for valid field type
	if ((field_type == LABEL_FILE::LINE::NONE) ||
		(field_type > LABEL_FILE::LINE::SIZE))
	{
		return false;   // ERROR: Invalid field type
	}


	// Switch out by field type
	switch (field_type)
	{
	case LABEL_FILE::LINE::FQLN:

		// NOTE: FQLN


		// Check for alphanumeric characters and dot
		if ((('0' <= line_char) && (line_char <= '9')) ||
			(('A' <= line_char) && (line_char <= 'Z')) ||
			(('a' <= line_char) && (line_char <= 'z')) ||
			(line_char == '.'))
		{
			// NOTE: Pass
		}
		else
		{
			// NOTE: Invalid FQLN character


			return false;   // ERROR: Invalid FQLN character
		}


		break;

	case LABEL_FILE::LINE::PATH:

		// NOTE: Not implemented
		//
		//  Possible errors in the pathnames are caught when opening the
		//  corresponding resource.


		break;

	case LABEL_FILE::LINE::ALIASES:

		// NOTE: ALIASES


		// Check for alphanumeric characters, dot and blanks
		if ((('0' <= line_char) && (line_char <= '9')) ||
			(('A' <= line_char) && (line_char <= 'Z')) ||
			(('a' <= line_char) && (line_char <= 'z')) ||
			(line_char == ' ') ||
			(line_char == '\t') ||
			(line_char == '.'))
		{
			// NOTE: Pass
		}
		else
		{
			// NOTE: Invalid ALIASES character


			return false;   // ERROR: Invalid ALIASES character
		}


		break;

	default:

		// NOTE: Never reached


		break;
	}


	return true;    // SUCCESS
}


bool LABEL_FILE::LINE::char_is_blank(char line_char)    // - IN: Line character to validate
{
	// Check for blank character
	if ((line_char == ' ') ||
		(line_char == '\t'))
	{
		// NOTE: Pass
	}
	else
	{
		// NOTE: Not a blank character


		return false;   // ERROR: Not a blank character
	}


	return true;    // SUCCESS
}


void LABEL_FILE::LINE::clear()
{
	this->string.clear();
}


void LABEL_FILE::LINE::clear_all()
{
	// Clear raw string
	this->string.clear();


	// Fully qualified label name
	this->fqln.clear();


	// Pathname
	this->path.clear();


	// Aliases string
	this->aliases_string.clear();


	// Aliases strings
	aliases.clear();


	// Line index
	this->index = 0;


	// Label type
	this->type = 0;
}


const char* LABEL_FILE::LINE::c_str()
{
	return this->string.c_str();
}


bool LABEL_FILE::LINE::contains(const std::string& fixed_string)	// - IN: Fixed string to search for
{
	// Check for empty fixed string
	if (fixed_string.length() > 0)
	{
		// NOTE: Non-empty fixed string


		// Check for the fixed string
		if (this->string.find(fixed_string) == std::string::npos)
		{
			return 0;	// ERROR: Fixed string not found
		}
	}


	return 1;	// SUCCESS: Fixed string found
}


std::string::iterator LABEL_FILE::LINE::begin()
{
	return this->string.begin();
}


std::string::iterator LABEL_FILE::LINE::end()
{
	return this->string.end();
}


LABEL_FILE::LINE& LABEL_FILE::LINE::operator +=(char line_char) // - IN: Line character
{
	this->string += line_char;


	return *this;
}


bool LABEL_FILE::is_directory(unsigned short mode)
{
#if defined(__sgi) || defined(__GNUC__)


	if (S_ISDIR(mode))
	{
		return true;
	}


	return false;


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	if ((mode & _S_IFDIR) == _S_IFDIR)
	{
		return true;
	}


	return false;


#endif	// _WIN32
}


int LABEL_FILE::get_label_prefix(std::string& prefixed_path,	// - IN/OUT: Path prefixed with a label
	std::string& label,		// - OUT: Prefixed label
	std::string& path)		// - OUT: Path
{
	unsigned int path_index;
	std::string::iterator it;
	LABEL_FILE::LINE line;


	// IN: Check for empty prefixed path
	if (prefixed_path.empty() == true)
	{
		return 0;	// ERROR: Empty prefixed path
	}


	// Traverse prefixed path
	label.clear();
	path_index = 0;
	for (it = prefixed_path.begin();
		it < prefixed_path.end();
		it++)
	{
		// Check for valid label character
		if (LABEL_FILE::LINE::char_is_valid(*it,
			LABEL_FILE::LINE::FQLN) == true)
		{
			// OUT: Add character to label
			label += *it;
		}
		else
		{
			// NOTE: Break
			//
			//  Break on first invalid character.


			break;
		}


		// Increment path index
		path_index++;
	}


	// Check for empty label
	if (label.empty() == true)
	{
		return -2;	// ERROR: Empty label
	}


	// Get path
	path = prefixed_path.substr(path_index);


	return 1;	// SUCCESS
}


int LABEL_FILE::lookup_label(std::string& label,	// - IN: Label to lookup
	bool typeless,		// - IN: Set typeless lookup
	std::string& label_path,	// - IN: Path corresponding to label file
	std::string& path,		// - OUT: Path corresponding to label
	unsigned int& type)	// - OUT: Label type
{
	bool label_found;
	bool wants_lines;
	unsigned int label_type;
	unsigned int label_length;
	std::string* fqln_0;
	std::size_t sa_index;
	std::vector<std::string>* aliases;
	std::vector<std::string>::iterator it_aliases;
	std::vector<LABEL_FILE::LINE*> lines;
	std::vector<LABEL_FILE::LINE*>::iterator it;


	// IN: Check for empty label
	if (label.length() == 0)
	{
		return 0;	// ERROR: Empty label
	}


	// IN: Check for empty label file path
	if (label_path.length() == 0)
	{
		return -1;	// ERROR: Empty label file path
	}


	// DEBUG
	sync_dprintf("[LABEL_FILE::lookup_label] START: label \"%s\" typeless = %s\n",
		label.c_str(),
		typeless == true ? "YES" : "NO");


	// NOTE: Initialization


	path.clear();


	// Check for typeless lookup
	if (typeless != true)
	{
		// NOTE: Type based lookup


		// Check for label type
		label_length = label.length();
		if (label_length >= 3)
		{
			// Check for INSTALLATION suffix
			sa_index = label_length - 3;
			if (label.substr(sa_index).compare("/sa") == 0)
			{
				// NOTE: INSTALLATION type


				label_type = LABEL_FILE::LINE::TYPE_INSTALLATION;


				// Get label
				label = label.substr(0, sa_index);
			}
			else
			{
				// NOTE: STANDALONE type


				label_type = LABEL_FILE::LINE::TYPE_STANDALONE;
			}
		}
		else
		{
			// NOTE: STANDALONE type


			label_type = LABEL_FILE::LINE::TYPE_STANDALONE;
		}
	}


	// DEBUG
	sync_dprintf("[LABEL_FILE::lookup_label] LABELS: Parse \"%s\"\n",
		label_path.c_str());


	// Parse label file
	wants_lines = true;
	this->parse_file(label_path,
		wants_lines,
		lines);


	// DEBUG
	sync_dprintf("[LABEL_FILE::lookup_label] LABELS: Traverse %u lines\n",
		lines.size());


	// Traverse fqln labels
	label_found = false;
	for (it = lines.begin();
		it < lines.end();
		it++)
	{
		// NOTE: Label type
		//
		//  Only labels (FQLNs and aliases) of the same
		//  label type are considered for the lookup.


		// Check for typeless lookup
		if (typeless == true)
		{
			// NOTE: Typeless label lookup
			//
			//  Pass through.
		}
		else
		{
			// NOTE: Type bound label lookup


			// Check for same label type
			if (label_type != (*it)->type)
			{
				// NOTE: Skip different label types


				continue;
			}
		}


		// Get fqln
		fqln_0 = &(*it)->fqln;


		// Compare labels for equality
		if (label.compare(*fqln_0) == 0)
		{
			// NOTE: Found label


			// DEBUG
			sync_dprintf("[LABEL_FILE::lookup_label] FOUND: \"%s\"\n",
				fqln_0->c_str());


			// Set found label flag
			label_found = true;


			// Check for typeless label lookup
			if (typeless == true)
			{
				// NOTE: Label type
				//
				//  For typeless label lookup, the found label specifies the label type.
				//
				//  The label type is needed for postprocessing. See below for details.


				// Set found label type
				label_type = (*it)->type;
			}


			// Copy path
			path = (*it)->path;


			// DEBUG
			sync_dprintf("[LABEL_FILE::lookup_label] PATH: \"%s\"\n",
				path.c_str());


			break;
		}


		// Get aliases vector
		aliases = &(*it)->aliases;


		// Traverse aliases vector
		for (it_aliases = aliases->begin();
			it_aliases < aliases->end();
			it_aliases++)
		{
			// DEBUG
			sync_dprintf("[LABEL_FILE::lookup_label] INFO: label \"%s\" alias \"%s\"\n",
				label.c_str(),
				it_aliases->c_str());


			// DEBUG
			sync_dprintf("[LABEL_FILE::lookup_label] INFO: label \"%s\" (l=%u,c=%u) alias \"%s\" (l=%u,c=%u)\n",
				label.c_str(),
				label.length(),
				label.capacity(),
				it_aliases->c_str(),
				it_aliases->length(),
				it_aliases->capacity());


			// Compare labels for equality
			if (label.compare(*it_aliases) == 0)
			{
				// NOTE: Found equal labels


				sync_printf("[LABEL_FILE::lookup_label] FOUND: \"%s\"\n",
					it_aliases->c_str());


				// Set found label flag
				label_found = true;


				// Check for typeless label lookup
				if (typeless == true)
				{
					// NOTE: Label type
					//
					//  For typeless label lookup, the found label specifies the label type.
					//
					//  The label type is needed for postprocessing. See below for details.


					// Set found label type
					label_type = (*it)->type;
				}


				// Copy path
				path = (*it)->path;


				sync_printf("[LABEL_FILE::lookup_label] PATH: \"%s\"\n",
					path.c_str());


				break;
			}
		}


		// Check for found alias label
		if (label_found == true)
		{
			break;
		}
	}


	// Check for found label
	if (label_found != true)
	{
		sync_printf("[LABEL_FILE::lookup_label] NOTFOUND: Label \"%s\" not found\n",
			label.c_str());


		return -2;	// ERROR: Couldn't find label
	}


	// Check for type bound label lookup
	if (typeless != true)
	{
		// NOTE: INSTALLATION path
		//
		//  The installation paths given in the labels file, point to
		//  the IRIX installation /dist subdirectory of an IRIX distribution
		//  tree.
		//
		//  When an INSTALLATION path is requested, "/sa" must be appended to
		//  that path for the client to get the sa miniroot filesystem file
		//  needed to boot an miniroot installation.


		// Check for INSTALLATION type
		if (label_type == LABEL_FILE::LINE::TYPE_INSTALLATION)
		{
			// Append "/sa" to IRIX distribution path
			path += "/sa";
		}
	}


	// OUT: Set label type
	type = label_type;


	// DEBUG
	sync_dprintf("[LABEL_FILE::lookup_label] STOP: Path \"%s\"\n",
		path.c_str());


	return 1;	// SUCCESS
}


int LABEL_FILE::parse_file(const std::string& file_path,                // - IN: Label file path
	bool wants_lines,                            // - IN: Flag to indicate wether lines should be returned
	std::vector<LABEL_FILE::LINE*>& lines)      // - OUT: Vector of line objects
{
	int ret;
	int file;
	bool is_eof;
	bool skip_line;
	bool path_has_spaces;
	bool path_is_finished;
	unsigned int num_alloc;
	unsigned int field_type;
	unsigned int char_index;
	unsigned int line_index;
	struct stat path_stat;
	std::string alias;
	std::string* aliases_string;
	std::string::iterator it_line;
	std::string::iterator it_alias;
	std::vector<LABEL_FILE::LINE*>::iterator it;
	LABEL_FILE::LINE line;
	LABEL_FILE::LINE* line_new;


	// IN: Check for empty label file path
	if (file_path.length() == 0)
	{
		return 0;       // ERROR: Empty label file path
	}


	// NOTE: Initialization


	ret = 0;
	file = -1;
	is_eof = false;
	skip_line = false;
	path_has_spaces = false;
	path_is_finished = false;
	num_alloc = 0;
	field_type = 0;
	char_index = 0;
	line_index = 0;
	bzero((void*)&path_stat,
		sizeof(struct stat));
	alias.clear();
	aliases_string = NULL;
	line.clear();
	line_new = NULL;


	// Open label file
	file = ::love_open(file_path.c_str(),
		O_RDONLY,
		0);
	if (file == -1)
	{
		return -1;      // ERROR: Couldn't open label file
	}


	// DEBUG
	sync_dprintf("[LABEL_FILE::parse_file] FILE_DESC:START: file = %i\n",
		file);


	// Traverse lines
	num_alloc = 0;
	line_index = 0;
	while (loop_forever)
	{
		// NOTE: Line endings
		//
		//  Both UNIX and Windows line endings are supported.


		// Read line
		line.clear_all();
		ret = this->read_line(file, &line);
		if (ret < 1)
		{
			if (::love_close(file) == -1)
			{
				// DEBUG
				sync_dprintf("[LABEL_FILE::parse_file] WARNING: Couldn't close label file\n");
			}


			return -2;      // ERROR: Couldn't read line
		}


		// Check for EOF
		is_eof = false;
		if (ret == 2)
		{
			// NOTE: EOF
			//
			//  EOF reached for label file.
			//
			//  Process last input (not terminated with newline) and exit.


			is_eof = true;
		}


		// NOTE: Fields
		//
		//  A line can be of two types:
		//
		//   1. Comment
		//
		//    A comment line begins with a # (pound) and extends to the end of the line.
		//
		//   2. Label
		//
		//    A label must have at least two fields separated by tabs or white spaces, with
		//    an optional third field for aliases. The field of aliases is a sequence of
		//    zero or more labels separated by one or more tabs or white spaces.


		// Set line index
		line.index = line_index;


		// Traverse line
		char_index = 0;
		skip_line = false;
		it_line = line.begin();
		while (loop_forever)
		{
			// Check for empty line
			if (char_index == 0)
			{
				if (line.begin() == line.end())
				{
					// NOTE: Empty line


					skip_line = true;


					break;
				}
			}


			// Check for line end
			if (it_line >= line.end())
			{
				// NOTE: End of line


				// Check for ALIASES field type
				if (field_type >= LABEL_FILE::LINE::PATH)
				{
					// Check for finished PATH field
					if ((path_has_spaces == true) &&
						(path_is_finished != true))
					{
						// NOTE: Unfinished PATH field


						sync_printf("[LABEL_FILE::parse_file] SKIPPED: Unfinished PATH field \"%s\"\n",
							line.c_str());


						skip_line = true;
					}
				}


				break;
			}


			// Check character
			switch (*it_line)
			{
			case '#':

				// NOTE: #


				// Check for beginning of line
				if (char_index == 0)
				{
					// NOTE: Comment line


					skip_line = true;
				}


				// Check for skipped line
				if (skip_line == true)
				{
					break;
				}


				// NOTE: Pass through

			default:

				// NOTE: Process character


				// Check for first character
				if (char_index == 0)
				{
					// NOTE: First character


					// Check for valid character
					if (LABEL_FILE::LINE::char_is_valid(*it_line,
						LABEL_FILE::LINE::FQLN) == true)
					{
						// NOTE: Start FQLN


						line.fqln += *it_line;


						// Set field type to FQLN
						field_type = LABEL_FILE::LINE::FQLN;
					}
					else
					{
						// NOTE: Invalid first character


						skip_line = true;


						sync_printf("[LABEL_FILE::parse_file] SKIP: Invalid first character \"%s\"\n",
							line.c_str());
					}
				}
				else
				{
					// NOTE: Subsequent character


					// Check for field type
					if (field_type == LABEL_FILE::LINE::FQLN)
					{
						// Check for valid character
						if (LABEL_FILE::LINE::char_is_valid(*it_line,
							field_type) == true)
						{
							// NOTE: FQLN


							line.fqln += *it_line;
						}
						else if (LABEL_FILE::LINE::char_is_blank(*it_line) == true)
						{
							// NOTE: Blank character
							//
							//  A blank character is defined as one of tab or
							//  white space.
							//
							//  Blank characters are ignored.


							// Traverse blank characters
							it_line++;
							while (it_line < line.end())
							{
								// Check for blank character
								if (LABEL_FILE::LINE::char_is_blank(*it_line) != true)
								{
									// Check for valid character
									if (*it_line == '"')
									{
										// NOTE: Start PATH with spaces
										//
										//  First character is ", so the PATH field
										//  contains spaces.


										path_has_spaces = true;
									}
									else
									{
										// NOTE: Start PATH without spaces
										//
										//  Since first PATH field character is
										//  not ", the PATH contains no spaces.


										path_has_spaces = false;


										line.path += *it_line;
									}


									// Set field type to PATH
									field_type = LABEL_FILE::LINE::PATH;


									path_is_finished = false;


									break;
								}


								// Increment line iterator
								it_line++;


								// Increment character index
								char_index++;
							}


							// Check for PATH field
							if (field_type != LABEL_FILE::LINE::PATH)
							{
								// NOTE: No PATH field


								skip_line = true;


								sync_printf("[LABEL_FILE::parse_file] SKIP: No PATH field \"%s\"\n",
									line.c_str());
							}
						}
						else
						{
							// NOTE: Invalid character


							skip_line = true;


							sync_printf("[LABEL_FILE::parse_file] SKIP: Invalid character \"%s\"\n",
								line.c_str());
						}
					}
					else if (field_type == LABEL_FILE::LINE::PATH)
					{
						// Check for spaces in PATH field
						if (path_has_spaces == true)
						{
							// NOTE: PATH field has spaces


							// Check for finished PATH field
							if (path_is_finished == true)
							{
								// NOTE: PATH field is finished


								// Check for blank characters
								if (LABEL_FILE::LINE::char_is_blank(*it_line) == true)
								{
									// NOTE: Blank character
									//
									//  A blank character is defined as one of tab or
									//  white space.
									//
									//  Blank characters are ignored.


									// Traverse blank characters
									it_line++;
									while (it_line < line.end())
									{
										// Check for blank character
										if (LABEL_FILE::LINE::char_is_blank(*it_line) != true)
										{
											// Check for valid character
											if (LABEL_FILE::LINE::char_is_valid(*it_line,
												LABEL_FILE::LINE::ALIASES) == true)
											{
												// NOTE: Start ALIASES


												line.aliases_string += *it_line;


												// Set field type to ALIASES
												field_type = LABEL_FILE::LINE::ALIASES;
											}
											else
											{
												// NOTE: Invalid character


												skip_line = true;


												sync_printf("[LABEL_FILE::parse_file] SKIP: Invalid character \"%s\"\n",
													line.c_str());
											}


											break;
										}


										// Increment line iterator
										it_line++;


										// Increment character index
										char_index++;
									}
								}
								else
								{
									// NOTE: Invalid character


									skip_line = true;


									sync_printf("[LABEL_FILE::parse_file] SKIP: Invalid character \"%s\"\n",
										line.c_str());
								}
							}
							else if (path_is_finished != true)
							{
								if (*it_line != '"')
								{
									// NOTE: PATH


									line.path += *it_line;
								}
								else if (*it_line == '"')
								{
									// NOTE: PATH field finished


									path_is_finished = true;
								}
								else
								{
									// NOTE: Never reached
								}
							}
						}
						else
						{
							// NOTE: PATH field has no spaces


							// Check for valid character
							if (LABEL_FILE::LINE::char_is_blank(*it_line) != true)
							{
								// NOTE: PATH


								line.path += *it_line;
							}
							else
							{
								// NOTE: Blank character
								//
								//  A blank character is defined as one of tab or
								//  white space.
								//
								//  Blank characters are ignored.


								// Traverse blank characters
								it_line++;
								while (it_line < line.end())
								{
									// Check for blank character
									if (LABEL_FILE::LINE::char_is_blank(*it_line) != true)
									{
										// Check for valid character
										if (LABEL_FILE::LINE::char_is_valid(*it_line,
											LABEL_FILE::LINE::ALIASES) == true)
										{
											// NOTE: Start ALIASES


											line.aliases_string += *it_line;


											// Set field type to ALIASES
											field_type = LABEL_FILE::LINE::ALIASES;
										}
										else
										{
											// NOTE: Invalid character


											skip_line = true;


											sync_printf("[LABEL_FILE::parse_file] SKIP: Invalid character \"%s\"\n",
												line.c_str());
										}


										break;
									}


									// Increment line iterator
									it_line++;


									// Increment character index
									char_index++;
								}
							}
						}
					}
					else if (field_type == LABEL_FILE::LINE::ALIASES)
					{
						// Check for valid character
						if (LABEL_FILE::LINE::char_is_valid(*it_line,
							field_type) == true)
						{
							// NOTE: ALIASES


							line.aliases_string += *it_line;
						}
						else
						{
							// NOTE: Invalid character


							skip_line = true;


							sync_printf("[LABEL_FILE::parse_file] SKIP: Invalid character \"%s\"\n",
								line.c_str());
						}
					}
				}


				break;
			}


			// Check for skipped line
			if (skip_line == true)
			{
				// NOTE: Skip line


				break;
			}


			// Increment line iterator
			it_line++;


			// Increment character index
			char_index++;
		}


		// Check for skipped line
		if (skip_line != true)
		{
			// NOTE: Parsed line
			//
			//  A line has been successfully parsed. The last step consists
			//  of checking if the path or file exists.
			//
			//  This will also set the type of line: INSTALLATION for
			//  installation directory paths, or STANDALONE for standalone
			//  execution file paths.


			// Check for existence
			if (stat(line.path.c_str(),
				&path_stat) == 0)
			{
				// NOTE: Path exists
				//
				//  If path is a symbolic link to a file, the link target is
				//  stat()'ed, not the link file itself.


				// Check for path type
				if (this->is_directory(path_stat.st_mode) == true)
				{
					// NOTE: INSTALLATION type of line


					line.type = LABEL_FILE::LINE::TYPE_INSTALLATION;
				}
				else
				{
					// NOTE: STANDALONE type of line
					//
					//  In this case, no check is performed to allow
					//  the user to source the file from devices,
					//  sockets or FIFO's too.


					line.type = LABEL_FILE::LINE::TYPE_STANDALONE;
				}


				// DEBUG: Output everything
				sync_printf("[LABEL_FILE::parse_file] LINE: \"%s\"\n",
					line.c_str());
				sync_printf("[LABEL_FILE::parse_file] LINE.FQLN: \"%s\"\n",
					line.fqln.c_str());
				sync_printf("[LABEL_FILE::parse_file] LINE.PATH: \"%s\"\n",
					line.path.c_str());
				sync_printf("[LABEL_FILE::parse_file] LINE.ALIASES: \"%s\"\n",
					line.aliases_string.c_str());


				// Check for wanted lines
				if (wants_lines == true)
				{
					// Allocate new line
					line_new = new LABEL_FILE::LINE();
					if (line_new == NULL)
					{
						if (::love_close(file) == -1)
						{
							sync_printf("[LABEL_FILE::parse_file] WARNING: Couldn't close label file\n");
						}


						return -3;      // ERROR: Couldn't allocate new line
					}


					// Increment stats
					num_alloc++;


					// Copy line
					*line_new = line;


					// Add line to lines vector
					lines.push_back(line_new);
				}
			}
			else
			{
				// NOTE: Path doesn't exist


				sync_printf("[LABEL_FILE::parse_file] SKIP: Path doesn't exist \"%s\"\n",
					line.c_str());
			}
		}


		// Increment line index
		line_index++;


		// Check for EOF
		if (is_eof == true)
		{
			break;
		}
	}


	// NOTE: ALIASES field
	//
	//  After the first parsing phase, the aliases, if any,
	//  are stored in a single string.
	//
	//  This string is parsed next and results in the aliases
	//  being stored as single strings in a vector of each
	//  line object.


	// Traverse aliases strings
	for (it = lines.begin();
		it < lines.end();
		it++)
	{
		// Check for aliases string
		if ((*it)->aliases_string.length() > 0)
		{
			// NOTE: Aliases found
			//
			//  Aliases strings are already validated characterwise
			//  from the first parsing phase. See main loop above.
			//
			//  Furthermore, the aliases string is guaranteed to start
			//  with a non-blank character.


			// Traverse aliases string
			alias.clear();
			aliases_string = &(*it)->aliases_string;
			for (it_alias = aliases_string->begin();
				it_alias < aliases_string->end();
				it_alias++)
			{
				// Check for blank character
				if (LABEL_FILE::LINE::char_is_blank(*it_alias) == true)
				{
					// NOTE: Blank character


					// Check for alias temporary string
					if (alias.length() > 0)
					{
						// Add alias temporary string to line aliases
						(*it)->aliases.push_back(std::string(alias));


						// Clear alias temporary string
						alias.clear();
					}
				}
				else
				{
					// Add character to alias temporary string
					alias += *it_alias;
				}
			}


			// Check for alias temporary string
			if (alias.length() > 0)
			{
				// Add alias temporary string to line aliases
				(*it)->aliases.push_back(std::string(alias));


				// Clear alias temporary string
				alias.clear();
			}
		}
	}


	// Close labels file
	if (::love_close(file) == -1)
	{
		sync_printf("[LABEL_FILE::parse_file] WARNING: Couldn't close label file\n");
	}


	// DEBUG
	sync_dprintf("[LABEL_FILE::parse_file] INFO: num_alloc = %u lines.size() = %i\n",
		num_alloc,
		lines.size());


	return 1;       // SUCCESS
}


int LABEL_FILE::read_line(int file_desc,                // - IN: File descriptor
	LABEL_FILE::LINE* line)       // - OUT: Line output string
{
	long ret;
	char line_char;


	// IN: Check for valid file descriptor
	if (file_desc < 0)
	{
		return 0;       // ERROR: Invalid file descriptor
	}


	// OUT: Check for line
	if (line == NULL)
	{
		return -1;      // ERROR: No line
	}


	// Traverse character stream
	while (loop_forever)
	{
		// Read character
		ret = ::love_read(file_desc,
			(void*)&line_char,
			1);
		if (ret == 0)
		{
			// NOTE: EOF


			return 2;       // SUCCESS: EOF
		}
		else if (ret == 1)
		{
			// NOTE: Line character


			// Check for newline
			if (line_char == '\n')
			{
				break;
			}


			// Add character to line
			*line += line_char;
		}
		else
		{
			// NOTE: Read error


			return -1;      // ERROR: Read error
		}
	}


	return 1;       // SUCCESS
}


int BOOTPD::get_request(struct etherpacket* ep,	// - IN: Ethernet packet
	struct bootp* request,	// - OUT: BOOTP request
	struct in_addr* ip_src,	// - OUT: Source IP address in NBO
	std::string& label,	// - OUT: Label from prefixed path
	std::string& path)	// - OUT: Path from prefixed path
{
	char* file;
	unsigned int file_index;
	unsigned int prefixed_index;
	struct bootp* bootp_header;
	struct udphdr* udp_header;


#if defined(__sgi)


	struct ip* ip_header;


#elif defined(__GNUC__) || defined(_WIN32)


	struct iphdr* ip_header;


#endif	// __sgi


	std::string prefixed_path;


	// IN: Check for ethernet packet
	if (ep == NULL)
	{
		return 0;	// ERROR: No ethernet packet
	}


	// OUT: Check for BOOTP request
	if (request == NULL)
	{
		return -1;	// ERROR: No BOOTP request
	}


	// OUT: Check for source IP address
	if (ip_src == NULL)
	{
		return -2;	// ERROR: No source IP address
	}


	// NOTE: Initialization


	label.clear();
	path.clear();
	prefixed_path.clear();


#ifdef __sgi


	// Get UDP datagram
	ip_header = (struct ip*)ep->data;
	udp_header = (struct udphdr*)((unsigned long)ip_header + sizeof(struct ip));


#elif defined(__GNUC__) || defined(_WIN32)


	// Get UDP datagram
	ip_header = (struct iphdr*)((unsigned long)ep + sizeof(struct ether_header));
	udp_header = (struct udphdr*)((unsigned long)ip_header + sizeof(struct iphdr));


#endif	// __sgi


	// Check for BOOTP datagram
	if ((ntohs(udp_header->uh_dport) != IPPORT_BOOTPS) ||
		(ntohs(udp_header->uh_sport) != IPPORT_BOOTPC))
	{
		return -3;	// ERROR: Not BOOTP datagram
	}


	// Get BOOTP header
	bootp_header = (struct bootp*)((unsigned long)udp_header + sizeof(struct udphdr));


	// Check for label
	file = (char*)bootp_header->bp_file;
	if (file[0] == '\0')
	{
		// NOTE: No label


		return -4;	// ERROR: No label
	}


	// Get prefixed path
	prefixed_index = 0;
	for (file_index = 0;
		file_index < 64;
		file_index++)
	{
		// Check for NULL byte
		if (file[file_index] == '\0')
		{
			break;
		}


		// OUT: Copy prefixed path character
		prefixed_path += file[file_index];


		// Increment prefixed path index
		prefixed_index++;
	}


	// DEBUG
	sync_dprintf("[BOOTPD::get_bootp_request] PREFIXED_PATH: \"%s\"\n",
		prefixed_path.c_str());


	// Get label without path components
	if (LABEL_FILE::get_label_prefix(prefixed_path,
		label,
		path) < 1)
	{
		// NOTE: No prefixed path
		//
		//  All SGI client requests must begin with the string "love". If not,
		//  this request is not for love or is otherwise garbled.
		//
		//  Love is genuine and unique. There is only one love that governs us all.


		// DEBUG
		sync_dprintf("[BOOTPD::get_bootp_request] ERROR: No prefixed path\"%s\"\n",
			prefixed_path.c_str());


		return -5;	// ERROR: No prefixed path
	}


	sync_printf("[BOOTPD::get_bootp_request] PATH: \"%s\"\n",
		prefixed_path.c_str());
	sync_printf("[BOOTPD::get_bootp_request] LABEL: \"%s\"\n",
		label.c_str());
	sync_printf("[BOOTPD::get_bootp_request] PATH: \"%s\"\n",
		path.c_str());


	// Copy BOOTP header
	bcopy((void*)bootp_header,
		(void*)request,
		sizeof(struct bootp));


#ifdef __sgi


	// OUT: Copy client IP address
	* ip_src = ip_header->ip_src;


#elif defined(__GNUC__)


	// OUT: Copy client IP address
	ip_src->s_addr = ip_header->saddr;


#endif	// __sgi


	// DEBUG
	sync_dprintf("[BOOTPD::get_bootp_label] STOP: label = \"%s\"\n",
		label.c_str());


	return 1;	// SUCCESS
}


void print_bootp_packet(struct bootp* packet)
{
	char* byte_pointer;
	unsigned int byte_index;


	/*

	struct bootp {
		u_char  bp_op;          // packet opcode type //
#define BOOTREQUEST     1
#define BOOTREPLY       2
		u_char  bp_htype;       // hardware addr type //
		u_char  bp_hlen;        // hardware addr length //
		u_char  bp_hops;        // gateway hops //
		u_int   bp_xid;         // transaction ID //
		u_short bp_secs;        // seconds since boot began //
		u_short bp_unused;
		iaddr_t bp_ciaddr;      // client IP address //
		iaddr_t bp_yiaddr;      // 'your' IP address //
		iaddr_t bp_siaddr;      // server IP address //
		iaddr_t bp_giaddr;      // gateway IP address //
		u_char  bp_chaddr[16];  // client hardware address //
		u_char  bp_sname[64];   // server host name //
		u_char  bp_file[128];   // boot file name //
		union {
				u_char  vend_unused[64];
				struct  vend    sgi_vadmin;
		} rfc1048;
#define bp_vend         rfc1048.vend_unused             // rfc951 field //
#define vd_magic        rfc1048.sgi_vadmin.v_magic      // magic #      //
#define vd_flags        rfc1048.sgi_vadmin.v_flags      // opcodes      //
#define vd_clntname     rfc1048.sgi_vadmin.v_unused     // client name  //
};

	reply.bp_op = BOOTREPLY;
	reply.bp_htype = request->bp_htype;
	reply.bp_hlen = request->bp_hlen;
	reply.bp_hops = request->bp_hops;
	reply.bp_xid = request->bp_xid;
	reply.bp_secs = request->bp_secs;
	reply.bp_unused = request->bp_unused;
	reply.bp_ciaddr = request->bp_ciaddr;
	reply.bp_yiaddr = request->bp_yiaddr;

	reply.bp_siaddr = *((iaddr_t *) local_hostaddr->h_addr);
	reply.bp_giaddr = *((iaddr_t *) local_hostaddr->h_addr);

	bcopy((void *) request->bp_chaddr,
		  (void *) reply.bp_chaddr,
		  6);
	bcopy((void *) "192.168.178.40",
	//bcopy((void *) "ALL.YOU.NEED.IS.LOVE\0",
		  (void *) reply.bp_sname,
		  15);
	*/


	printf("[::print_bootp_packet] BOOTP: bp_op = %u\n",
		packet->bp_op);
	printf("[::print_bootp_packet] BOOTP: bp_htype = %u\n",
		packet->bp_htype);
	printf("[::print_bootp_packet] BOOTP: bp_hlen = %u\n",
		packet->bp_hlen);
	printf("[::print_bootp_packet] BOOTP: bp_hops = %u\n",
		packet->bp_hops);
	printf("[::print_bootp_packet] BOOTP: bp_xid = %u %u\n",
		packet->bp_xid,
		ntohl(packet->bp_xid));
	printf("[::print_bootp_packet] BOOTP: bp_secs = %u %u\n",
		packet->bp_secs,
		ntohs(packet->bp_secs));
	printf("[::print_bootp_packet] BOOTP: bp_unused = %u %u\n",
		packet->bp_unused,
		ntohs(packet->bp_unused));
	printf("[::print_bootp_packet] BOOTP: bp_ciaddr = %u.%u.%u.%u\n",
		(unsigned int)((unsigned char*)&packet->bp_ciaddr)[0],
		(unsigned int)((unsigned char*)&packet->bp_ciaddr)[1],
		(unsigned int)((unsigned char*)&packet->bp_ciaddr)[2],
		(unsigned int)((unsigned char*)&packet->bp_ciaddr)[3]);
	printf("[::print_bootp_packet] BOOTP: bp_yiaddr = %u.%u.%u.%u\n",
		(unsigned int)((unsigned char*)&packet->bp_yiaddr)[0],
		(unsigned int)((unsigned char*)&packet->bp_yiaddr)[1],
		(unsigned int)((unsigned char*)&packet->bp_yiaddr)[2],
		(unsigned int)((unsigned char*)&packet->bp_yiaddr)[3]);
	printf("[::print_bootp_packet] BOOTP: bp_siaddr = %u.%u.%u.%u\n",
		(unsigned int)((unsigned char*)&packet->bp_siaddr)[0],
		(unsigned int)((unsigned char*)&packet->bp_siaddr)[1],
		(unsigned int)((unsigned char*)&packet->bp_siaddr)[2],
		(unsigned int)((unsigned char*)&packet->bp_siaddr)[3]);
	printf("[::print_bootp_packet] BOOTP: bp_giaddr = %u.%u.%u.%u\n",
		(unsigned int)((unsigned char*)&packet->bp_giaddr)[0],
		(unsigned int)((unsigned char*)&packet->bp_giaddr)[1],
		(unsigned int)((unsigned char*)&packet->bp_giaddr)[2],
		(unsigned int)((unsigned char*)&packet->bp_giaddr)[3]);
	printf("[::print_bootp_packet] BOOTP: bp_chaddr = %02x:%02x:%02x:%02x:%02x:%02x\n",
		((unsigned char*)&packet->bp_chaddr)[0],
		((unsigned char*)&packet->bp_chaddr)[1],
		((unsigned char*)&packet->bp_chaddr)[2],
		((unsigned char*)&packet->bp_chaddr)[3],
		((unsigned char*)&packet->bp_chaddr)[4],
		((unsigned char*)&packet->bp_chaddr)[5]);
	printf("[::print_bootp_packet] BOOTP: bp_sname = %s\n",
		packet->bp_sname);
	printf("[::print_bootp_packet] BOOTP: bp_file = \"%s\"\n",
		packet->bp_file);


	printf("[::print_bootp_packet] DUMP: Dumping %u bytes from struct bootp\n",
	       (unsigned int) sizeof(struct bootp));


	// Byte dump
	byte_pointer = (char*)packet;
	for (byte_index = 0;
		byte_index < sizeof(struct bootp);
		byte_index++)
	{
		// Print byte in hexadecimal with optional leading zero fill
		printf("%02x ", byte_pointer[byte_index]);


		// Check for line end
		if ((byte_index % 16) == 0)
		{
			printf("\n");
		}
	}
}


void print_ip(unsigned int ip_address)
{
	unsigned char* ip_bytes;


	// Get pointer to IP bytes
	ip_bytes = (unsigned char*)&ip_address;


	// Print IP bytes
	printf("[::print_ip] IP: %u.%u.%u.%u\n",
		(unsigned int)ip_bytes[0],
		(unsigned int)ip_bytes[1],
		(unsigned int)ip_bytes[2],
		(unsigned int)ip_bytes[3]);
}


int BOOTPD::send_reply(struct bootp* request,	// - IN: BOOTP request
	std::string& tftp_path,	// - IN: Registered TFTP path
	bool nullify)		// - IN: Nullify filename
{
	unsigned int bytes_address;
	struct bootp reply;
	struct sockaddr_in client_addr;


#ifdef __GNUC__


	unsigned int onoff;


#endif	// __GNUC__


	// IN: Check for BOOTP request
	if (request == NULL)
	{
		return 0;	// ERROR: No BOOTP request
	}


	// IN: Check for empty TFTP path
	if (tftp_path.empty() == true)
	{
		return -1;	// ERROR: Empty TFTP path
	}


	// Check for maximum length of TFTP path
	if (tftp_path.length() >= 127)
	{
		return -2;	// ERROR: TFTP path too long
	}


	// DEBUG
	sync_dprintf("[BOOTPD::send_reply] START: tftp_path = \"%s\"\n",
		tftp_path.c_str());


	// DEBUG
	sync_dprintf("[BOOTPD::send_reply] INFO: socket()\n");


	// Create BOOTP datagram socket
	Socket bootp_sock(Socket::type::SOCK_UDP);
	if (bootp_sock.get_fd() == -1)
	{
		return -3;	// ERROR: Couldn't create BOOTP datagram socket
	}


	// Set reuse address socket option
	if (bootp_sock.set_reuseaddr(true) < 1)
	{
		sync_printf("[BOOTPD::loop] ERROR: Couldn't set reuse address socket option\n");


		return -4;	// ERROR: Couldn't set reuse address socket option
	}


#ifdef __GNUC__


	// Set don't fragment IP socket option
	onoff = IP_PMTUDISC_DONT;
	if (bootp_sock.setsockopt(IPPROTO_IP,
		IP_MTU_DISCOVER,
		(const void*)&onoff,
		sizeof(unsigned int)) < 1)
	{
		sync_printf("[BOOTPD::loop] ERROR: Couldn't set don't fragment IP socket option\n");


		return -5;	// ERROR: Couldn't set don't fragment IP socket option
	}


#endif	// __GNUC__


	// DEBUG
	sync_dprintf("[BOOTPD::send_reply] INFO: bind() (get_fd() = %i)\n",
		bootp_sock.get_fd());


	// Bind socket to local port 67
	bytes_address = local_hostaddr;
	if (bootp_sock.bind(bytes_address,
		IPPORT_BOOTPS) < 1)
	{
		sync_printf("[BOOTPD::send_reply] ERROR: errno = %u\n",
			bootp_sock.get_errno());


		// Close BOOTP server socket
		if (bootp_sock.close() < 1)
		{
			sync_printf("WARNING: Couldn't close BOOTP server socket\n");
		}


		return -6;	// ERROR: Couldn't bind BOOTP server socket
	}


	// DEBUG
	sync_dprintf("[BOOTPD::send_reply] BIND: Source address (string) = %s\n",
		bootp_sock.src.get_string().c_str());


	// Build BOOTP reply packet
	bzero((char*)&reply,
		sizeof(struct bootp));
	reply.bp_op = BOOTREPLY;
	reply.bp_htype = request->bp_htype;
	reply.bp_hlen = request->bp_hlen;
	reply.bp_hops = request->bp_hops;
	reply.bp_xid = request->bp_xid;
	reply.bp_secs = request->bp_secs;
	reply.bp_unused = request->bp_unused;
	reply.bp_ciaddr = request->bp_ciaddr;
	reply.bp_yiaddr = request->bp_ciaddr;
	reply.bp_siaddr = local_hostaddr;
	reply.bp_giaddr = 0;

	bcopy((void*)request->bp_chaddr,
		(void*)reply.bp_chaddr,
		6);
	bcopy((void*)request->bp_sname,
		(void*)reply.bp_sname,
		strlen((const char*)request->bp_sname));


	// Check for filename nullify
	if (nullify == true)
	{
		reply.bp_file[0] = '\0';
		bcopy((void*)(tftp_path.c_str() + 1),
			(void*)&reply.bp_file[1],
			tftp_path.length() - 1);


		// Terminate filename with NULL byte
		reply.bp_file[tftp_path.length()] = '\0';


		sync_printf("[BOOTPD::send_reply] INFO: Nullified reply.bp_file = \"%s\"\n",
			reply.bp_file + 1);
	}
	else
	{
		bcopy((void*)tftp_path.c_str(),
			(void*)reply.bp_file,
			tftp_path.length());

		// Terminate filename with NULL byte
		reply.bp_file[tftp_path.length()] = '\0';


		sync_printf("[BOOTPD::send_reply] INFO: reply.bp_file = \"%s\"\n",
			reply.bp_file);
	}


	bzero((void*)reply.rfc1048.vend_unused,
		64);


	// DEBUG: Dump bootp packet
	//print_bootp_packet(&reply);


	// DEBUG
	sync_dprintf("[BOOTPD::send_reply] INFO: Write back\n");


	// Write BOOTP reply packet to client
	bcopy((void*)&request->bp_ciaddr,
		(void*)&client_addr.sin_addr.s_addr,
		IP_V4_ADDR_LEN);
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(IPPORT_BOOTPC);
	if (sendto(bootp_sock.get_fd(),
		(char*)&reply,
		sizeof(struct bootp),
		0,
		(struct sockaddr*)&client_addr,
		sizeof(client_addr)) != sizeof(struct bootp))
	{
		sync_printf("[BOOTPD::send_reply] ERROR: errno = %u\n",
			errno);


		// Close BOOTP server socket
		if (bootp_sock.close() < 1)
		{
			sync_printf("WARNING: Couldn't close BOOTP server socket\n");
		}


		return -7;	// ERROR: Couldn't write BOOTP reply packet
	}


	// Close BOOTP server socket
	if (bootp_sock.close() < 1)
	{
		sync_printf("WARNING: Couldn't close BOOTP server socket\n");
	}


	// DEBUG
	sync_dprintf("[BOOTPD::send_reply] STOP\n");


	return 1;	// SUCCESS
}


Socket::type::type(unsigned int type)
{
	// Check for valid type
	if ((type != Socket::type::SOCK_TCP) &&
		(type != Socket::type::SOCK_UDP))
	{
		// NOTE: Unknown socket type


		this->sock_type = Socket::type::SOCK_UNKNOWN;
	}
	else
	{
		// NOTE: Known socket type


		this->sock_type = type;
	}
}


bool Socket::type::operator==(unsigned int type)
{
	// Check for valid type
	if (this->sock_type == type)
	{
		return true;
	}


	return false;
}


bool Socket::type::operator!=(unsigned int type)
{
	// Check for valid type
	if (this->sock_type != type)
	{
		return true;
	}


	return false;
}


Socket::address::address() : bytes(0),
ip_address("0.0.0.0")
{
}


Socket::address::address(Socket::address& address) : bytes(address.bytes),
ip_address(address.ip_address)
{
}


Socket::address::address(std::string ip_address) : bytes(0),
ip_address(ip_address)
{
	// Convert IP address to bytes address
	if (Socket::convert_ascii_to_bytes(ip_address,
		this->bytes) < 1)
	{
		// NOTE: Conversion error
		//
		//  This occurs when the IP address is invalid.


		this->bytes = 0;
		this->ip_address = "";
	}
}


Socket::address::address(unsigned int bytes) : bytes(bytes),
ip_address("0.0.0.0")
{
	// Convert bytes address to IP address
	if (Socket::convert_bytes_to_ascii(bytes,
		this->ip_address) < 1)
	{
		// NOTE: Conversion error
		//
		//  This occurs when any of the bytes in the bytes address
		//  is invalid.


		this->bytes = 0;
		this->ip_address = "";
	}
}


Socket::address::address(unsigned int bytes,
	std::string ip_address) : bytes(bytes),
	ip_address(ip_address)
{
}


unsigned int Socket::address::get_bytes()
{
	return this->bytes;
}


std::string Socket::address::get_string()
{
	return this->ip_address;
}


Socket::address& Socket::address::operator=(const Socket::address& address)
{
	this->bytes = address.bytes;
	this->ip_address = address.ip_address;


	return *this;
}


// NOTE: Public static member functions


int Socket::convert_bytes_to_ascii(unsigned int bytes_address,	// - IN: Socket address as bytes
	std::string& ascii_address)	// - OUT: Socket address as string
{
	unsigned char byte_char;
	unsigned char* byte_pointer;
	char char_address[4];
	unsigned int byte_index;
	std::string ascii_address_1;


	// NOTE: Initialization


	// Initialize ASCII char address
	char_address[0] = '\0';
	char_address[1] = '\0';
	char_address[2] = '\0';
	char_address[3] = '\0';


	// Initialize ASCII string address
	ascii_address_1.clear();


	// Set byte pointer
	byte_pointer = (unsigned char*)&bytes_address;


	// Traverse bytes
	for (byte_index = 0;
		byte_index < IP_V4_ADDR_LEN;
		byte_index++)
	{
		// Get byte
		byte_char = byte_pointer[byte_index];


		// Convert byte to decimal number string
		if (snprintf(char_address,
			IP_V4_ADDR_LEN,
			"%u",
			(unsigned int)byte_char) < 1)
		{
			// NOTE: Conversion error


			return 0;       // ERROR: Conversion error
		}


		// Add to ASCII socket address
		ascii_address_1 += char_address;


		// Add dot (.)
		if (byte_index < 3)
		{
			ascii_address_1 += '.';
		}
	}


	// OUT: Set ASCII address
	ascii_address = ascii_address_1;


	return 1;       // SUCCESS
}


int Socket::convert_ascii_to_bytes(std::string& ascii_address,  // - IN: Socket address as string
	unsigned int& bytes_address) // - OUT: Socket address as bytes
{
	bool last_is_digit;
	char* byte_pointer;
	unsigned int octet;
	unsigned int state;
	unsigned int octets_num;
	std::string::iterator it;


	// IN: Check for empty socket address string
	if (ascii_address.empty() == true)
	{
		return 0;       // ERROR: Empty socket address string
	}


	// Traverse address string
	state = 0;
	octet = 0;
	octets_num = 0;
	byte_pointer = (char*)&bytes_address;
	last_is_digit = false;
	for (it = ascii_address.begin();
		it < ascii_address.end();
		it++)
	{
		// Check for number of octets
		if (octets_num == IP_V4_ADDR_LEN)
		{
			return -5;      // ERROR: Invalid address format
		}


		// Process state
		switch (state)
		{
		case 0:

			// NOTE: First digit


			// Check first digit
			if (*it == '0')
			{
				// NOTE: Expect dot next


				// Reset octet
				octet = 0;


				// Save byte
				*byte_pointer = octet;
				byte_pointer++;


				// Increment number of octets
				octets_num++;


				state = 3;


				last_is_digit = true;
			}
			else if ((*it >= '1') &&
				(*it <= '9'))
			{
				// NOTE: Expect second digit next


				// Save digit
				octet = (octet * 10) + (*it - '0');


				state = 1;


				last_is_digit = true;
			}
			else
			{
				// NOTE: Invalid first digit


				return -1;      // ERROR: Invalid first digit
			}


			break;

		case 1:

			// NOTE: Second digit


			// Check second digit
			if ((*it >= '0') &&
				(*it <= '9'))
			{
				// NOTE: Expect third digit next


				// Save digit
				octet = (octet * 10) + (*it - '0');


				state = 2;


				last_is_digit = true;
			}
			else
			{
				// NOTE: Invalid second digit


				return -2;      // ERROR: Invalid second digit
			}


			break;

		case 2:

			// NOTE: Third digit


			// Check third digit
			if ((*it >= '0') &&
				(*it <= '9'))
			{
				// NOTE: Expect dot next


				// Save digit
				octet = (octet * 10) + (*it - '0');


				// Check for octet overflow
				if (octet > 255)
				{
					return -3;      // ERROR: Octet overflow
				}


				// Save byte
				*byte_pointer = octet;
				byte_pointer++;


				// Reset octet
				octet = 0;


				state = 3;


				last_is_digit = true;
			}
			else
			{
				// NOTE: Invalid third digit


				return -4;      // ERROR: Invalid third digit
			}


			// Increment number of octets
			octets_num++;


			break;

		case 3:

			// NOTE: Dot


			// Check for dot
			if (*it == '.')
			{
				// NOTE: Expect first digit next


				state = 0;


				last_is_digit = false;
			}
			else
			{
				// NOTE: Invalid character


				return -5;      // ERROR: Invalid character
			}


			break;

		default:

			// NOTE: Unexpected state


			return -6;      // ERROR: Unexpected state
		}
	}


	// Check for correct number of octets
	if (octets_num < IP_V4_ADDR_LEN)
	{
		// Check for last octet
		if (last_is_digit == true)
		{
			// Save byte
			*byte_pointer = octet;
			byte_pointer++;


			// Reset octet
			octet = 0;


			octets_num++;
		}


		// Check for corrected number of octets
		if (octets_num != IP_V4_ADDR_LEN)
		{
			return -7;      // ERROR: Invalid number of octets
		}
	}


	return 1;       // SUCCESS
}


// NOTE: Private member functions


void Socket::reset_state()
{
	// NOTE: Private data members


	this->sock = -1;
	this->sock_type = Socket::type::SOCK_UNKNOWN;
	this->sock_errno = 0;
	this->bind_address.clear();
	this->bind_port = 0;
	this->connect_address.clear();
	this->connect_port = 0;
	this->listen_backlog = 0;
	this->accept_address.clear();
	this->accept_port = 0;
	bzero((void*)&this->accept_sockaddr_in,
		sizeof(struct sockaddr_in));


	// NOTE: Public data members


	this->src = Socket::address("0.0.0.0");
	this->dst = Socket::address("0.0.0.0");
}


int Socket::bind_socket(std::string& address,   // - IN: Local address to bind to (hostname or IP address)
	unsigned short port)    // - IN: Local port to bind to
{
	int local_errno;
	unsigned int host_ip_address;
	struct sockaddr_in bind_addr;


	// NOTE: Initialization


	this->sock_errno = 0;
	this->bind_address.clear();
	this->bind_port = 0;


	// IN: Check for empty local address
	if (address.empty() == true)
	{
		return 0;       // ERROR: No local address
	}


	// Check for socket
	if (this->sock == -1)
	{
		return -1;      // ERROR: No socket
	}


	// Resolve local address
	local_errno = 0;
	host_ip_address = 0;
	if (::love_gethostbyname(address.c_str(),
		&host_ip_address,
		&local_errno) < 1)
	{
		// Set socket errno
		this->sock_errno = local_errno;


		return -2;      // ERROR: Couldn't lookup local address
	}


	// Initialize socket address structure for bind
	bzero((void*)&bind_addr,
		sizeof(struct sockaddr_in));


	// Fill socket address structure for bind
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(port);
	bcopy((void*)&host_ip_address,
		(void*)&bind_addr.sin_addr.s_addr,
		IP_V4_ADDR_LEN);


	// DEBUG
	//print_ip(host_ip_address);


	// Bind local socket
	if (::bind(this->sock,
		(struct sockaddr*)&bind_addr,
		sizeof(struct sockaddr)) == -1)
	{
#if defined(__sgi) || defined(__GNUC__)


		// Set socket errno
		this->sock_errno = errno;


#elif defined(_WIN32)


		// Set socket errno
		this->sock_errno = WSAGetLastError();


#endif


		return -3;      // ERROR: Couldn't bind local socket
	}


	// Save address
	this->bind_address = address;


	// Save port
	this->bind_port = port;


	// Update source address
	this->src = Socket::address(address);


	return 1;       // SUCCESS
}


int Socket::connect_socket(std::string& address,	// - IN: Remote address
	unsigned short port)		// - IN: Remote port
{
	int local_errno;
	struct sockaddr_in connect_addr;
	iaddr_t host_ip_address;


#if defined(__GNUC__)


	struct hostent* hostent_addr_pointer;


#endif	// __GNUC__


	// NOTE: Initialization


	this->sock_errno = 0;
	this->connect_address.clear();
	this->connect_port = 0;


	// IN: Check for empty local address
	if (address.empty() == true)
	{
		return 0;       // ERROR: No remote address
	}


	// Check for socket
	if (this->sock == -1)
	{
		return -1;      // ERROR: No socket
	}


	// Check for TCP socket
	if (this->sock_type != Socket::type::SOCK_TCP)
	{
		return -2;      // ERROR: Not TCP socket
	}


	// Resolve local address
	local_errno = 0;
	host_ip_address = 0;
	if (::love_gethostbyname(address.c_str(),
		&host_ip_address,
		&local_errno) < 1)
	{
		// Set socket errno
		this->sock_errno = local_errno;


		return -3;      // ERROR: Couldn't lookup remote address
	}


	// Initialize socket address structure for connect
	bzero((void*)&connect_addr,
		sizeof(struct sockaddr_in));


	// DEBUG
	//print_ip(host_ip_address);


	// Fill socket address structure for connect
	connect_addr.sin_family = AF_INET;
	connect_addr.sin_port = htons(port);
	bcopy((void*)&host_ip_address,
		(void*)&connect_addr.sin_addr.s_addr,
		IP_V4_ADDR_LEN);


	// Connect socket
	if (::connect(this->sock,
		(struct sockaddr*)&connect_addr,
		sizeof(struct sockaddr_in)) == -1)
	{
#if defined(__sgi) || defined(__GNUC__)


		// Set socket errno
		this->sock_errno = errno;


#elif defined(_WIN32)


		// Set socket errno
		this->sock_errno = WSAGetLastError();


#endif


		return -4;      // ERROR: Couldn't connect socket
	}


	// Save address
	this->connect_address = address;


	// Save port
	this->connect_port = port;


	// Update destination address
	this->dst = Socket::address(address);


	return 1;       // SUCCESS
}


// NOTE: Public member functions


void Socket::init(Socket::type type)
{
#ifdef _WIN32


	unsigned int ret;


#endif	// _WIN32


	// NOTE: Initialization


	// Reset internal object state
	this->reset_state();


	// Check for TCP socket type
	if (type == Socket::type::SOCK_TCP)
	{
#if defined(__sgi) || defined(__GNUC__)


		// Create TCP socket
		this->sock = ::socket(AF_INET,
			SOCK_STREAM,
			0);
		if (this->sock == -1)
		{
			return; // ERROR: Couldn't create TCP socket
		}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


		// Create TCP socket
		ret = ::socket(AF_INET,
			SOCK_STREAM,
			0);
		if (ret == INVALID_SOCKET)
		{
			return; // ERROR: Couldn't create TCP socket
		}


		// Socket descriptor bounds check
		if (ret > INT_MAX)
		{
			// Close socket
			this->close();


			return;	// ERROR: Socket descriptor out of bounds
		}


		// Set socket file descriptor
		this->sock = (int)ret;


#endif	// _WIN32


		this->sock_type = Socket::type::SOCK_TCP;
	}
	else if (type == Socket::type::SOCK_UDP)
	{
#if defined(__sgi) || defined(__GNUC__)


		// Create UDP socket
		this->sock = ::socket(AF_INET,
			SOCK_DGRAM,
			0);
		if (this->sock == -1)
		{
			return; // ERROR: Couldn't create UDP socket
		}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


		// Create UDP socket
		ret = ::socket(AF_INET,
			SOCK_DGRAM,
			0);
		if (ret == INVALID_SOCKET)
		{
			return; // ERROR: Couldn't create TCP socket
		}


		// Socket descriptor bounds check
		if (ret > INT_MAX)
		{
			// Close socket
			this->close();


			return;	// ERROR: Socket descriptor out of bounds
		}


		// Set socket file descriptor
		this->sock = (int)ret;


#endif	// _WIN32


		this->sock_type = Socket::type::SOCK_UDP;
	}
	else
	{
		return; // ERROR: Unknown socket type
	}
}


Socket::Socket(Socket::type type)	// - IN: Socket type
{
	// Create socket of requested type
	this->init(type);
}


Socket::Socket()
{
	// Create TCP socket by default
	this->init(Socket::type::SOCK_TCP);
}


Socket::~Socket()
{
	// Close socket
	this->close();
}


int Socket::bind(unsigned int bytes_address,    // - IN: Local address (as bytes) to bind to
	unsigned short port)           // - IN: Local port to bind to
{
	std::string ascii_address;


	// Convert bytes to ASCII
	if (Socket::convert_bytes_to_ascii(bytes_address,
		ascii_address) < 1)
	{
		// NOTE: Return value
		//
		//  For simplicity, this return value is the next
		//  error value considering all return values from
		//  bind_socket() member function.


		return -4;      // ERROR: Conversion error
	}


	return this->bind_socket(ascii_address,
		port);
}


int Socket::bind(std::string address,	// - IN: Local address (as string) to bind to (hostname or IP address)
	unsigned short port)	// - IN: Local port to bind to
{
	return this->bind_socket(address,
		port);
}


int Socket::connect(unsigned int bytes_address,	// - IN: Remote address
	unsigned short port)	// - IN: Remote port
{
	std::string ascii_address;


	// Convert bytes to ASCII
	if (Socket::convert_bytes_to_ascii(bytes_address,
		ascii_address) < 1)
	{
		// NOTE: Return value
		//
		//  For simplicity, this return value is the next
		//  error value considering all return values from
		//  bind_socket() member function.


		return -5;      // ERROR: Conversion error
	}


	return this->connect_socket(ascii_address,
		port);
}


int Socket::connect(std::string address,        // - IN: Remote address
	unsigned short port)        // - IN: Remote port
{
	return this->connect_socket(address,
		port);
}


int Socket::listen(unsigned int backlog)        // - IN: Size of backlog queue
{
	// NOTE: Initialization


	this->sock_errno = 0;
	this->listen_backlog = 0;


	// IN: Check for valid backlog
	if (backlog > INT_MAX)
	{
		return 0;       // ERROR: Invalid backlog
	}


	// Check for socket
	if (this->sock == -1)
	{
		return -1;      // ERROR: No socket
	}


	// Check for TCP socket
	if (this->sock_type != Socket::type::SOCK_TCP)
	{
		return -2;      // ERROR: Not TCP socket
	}


	// Listen on socket
	errno = 0;
	if (::listen(this->sock,
		backlog) == -1)
	{
		// Set socket errno
		this->sock_errno = errno;


		return -3;      // ERROR: Couldn't connect socket
	}


	// Save backlog
	this->listen_backlog = backlog;


	return 1;       // SUCCESS
}


int Socket::accept(Socket& conn)
{
	int conn_sock;
	socklen_t sockaddr_length;
	std::string sockaddr_ascii;


	// NOTE: Initialization


	this->sock_errno = 0;
	this->accept_address.clear();
	this->accept_port = 0;


	// Check for socket
	if (this->sock == -1)
	{
		return 0;       // ERROR: No socket
	}


	// Check for TCP socket
	if (this->sock_type != Socket::type::SOCK_TCP)
	{
		return -1;      // ERROR: Not TCP socket
	}


	// Check for connection socket
	if (conn.sock > -1)
	{
		// Close connection socket
		if (conn.close() < 1)
		{
			return -2;      // ERROR: Couldn't close connection socket
		}
	}
	else
	{
		// Reset connection socket
		conn.reset_state();
	}


	// Accept incoming connection
	errno = 0;
	sockaddr_length = sizeof(struct sockaddr);
	conn_sock = ::accept(this->sock,
		(struct sockaddr*)&this->accept_sockaddr_in,
		(socklen_t*)&sockaddr_length);
	if (conn_sock == -1)
	{
		// Set socket errno
		this->sock_errno = errno;


		return -2;      // ERROR: Couldn't accept incoming connection
	}


	// Convert remote address to ASCII
	if (Socket::convert_bytes_to_ascii(this->accept_sockaddr_in.sin_addr.s_addr,
		sockaddr_ascii) < 1)
	{
		return -3;      // ERROR: Bytes to ASCII conversion error
	}


	// Set connection socket
	conn.sock = conn_sock;
	conn.src = Socket::address(this->accept_sockaddr_in.sin_addr.s_addr,
		sockaddr_ascii);
	conn.dst = Socket::address(this->src);


	// Save remote address
	this->accept_address = sockaddr_ascii;


	// Save remote port
	this->accept_port = ntohs(this->accept_sockaddr_in.sin_port);


	return 1;       // SUCCESS
}


int Socket::shutdown(unsigned int type)	// - IN: Shutdown type:
//              0 - Further receives
//              1 - Further sends
//              2 - Further receives and sends
{
	// Initialize socket errno
	this->sock_errno = 0;


#if defined(__sgi) || defined(__GNUC__)


	// IN: Check for valid shutdown type
	if ((type != SHUT_RD) &&
		(type != SHUT_WR) &&
		(type != SHUT_RDWR))
	{
		return 0;       // ERROR: Invalid shutdown type
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// IN: Check for valid shutdown type
	if ((type != SD_RECEIVE) &&
		(type != SD_SEND) &&
		(type != SD_BOTH))
	{
		return 0;       // ERROR: Invalid shutdown type
	}


#endif	// _WIN32


	// Check for socket
	if (this->sock == -1)
	{
		return -1;      // ERROR: No socket
	}


	// Shutdown
	if (::shutdown(this->sock,
		type) == -1)
	{
		// Set socket errno
		this->sock_errno = errno;


		return -2;      // ERROR: Couldn't shutdown socket
	}


	return 1;       // SUCCESS
}


int Socket::open(Socket::type type)       // - IN: Socket type
{
	// Initialize socket errno
	this->sock_errno = 0;


	// Check for non-closed socket
	if (this->sock != -1)
	{
		return 0;       // ERROR: Socket not closed
	}


	// IN: Check for valid socket type
	if ((type != Socket::type::SOCK_TCP) &&
		(type != Socket::type::SOCK_UDP))
	{
		return -1;       // ERROR: Socket type not valid
	}


	// Create TCP socket by default
	this->init(type);


	return 1;	// SUCCESS
}


int Socket::open()
{
	// Initialize socket errno
	this->sock_errno = 0;


	// Check for non-closed socket
	if (this->sock != -1)
	{
		return 0;       // ERROR: Socket not closed
	}


	// Create TCP socket by default
	this->init(Socket::type::SOCK_TCP);


	return 1;	// SUCCESS
}


int Socket::close()
{
	// Initialize socket errno
	this->sock_errno = 0;


	// Check for socket
	if (this->sock == -1)
	{
		return 0;       // ERROR: No socket
	}


	// NOTE: Socket close
	//
	//  If the socket close fails, an error number is returned
	//  and the socket is left unmodified.
	//
	//  On IRIX and Linux, the portable love_close() free function is used to
	//  close sockets.
	//
	//  On Windows, the closesocket() function must be used.


#if defined(__sgi) || defined(__GNUC__)


	errno = 0;
	if (::love_close(this->sock) == -1)
	{
		// NOTE: Socket close error


		// Set socket errno
		this->sock_errno = errno;


		return -1;
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	if (::closesocket(this->sock) == -1)
	{
		// NOTE: Socket close error


		// Set socket errno
		this->sock_errno = WSAGetLastError();


		return -1;
	}


#endif	// _WIN32


	// NOTE: Socket successfully closed


	// Reset internal object state
	this->reset_state();


	return 1;       // SUCCESS
}


int Socket::getsockopt(int level,               // - IN: Option level
	int optname,             // - IN: Name of socket option
	void* optval,            // - IN: Buffer for option value
	socklen_t* optlen)       // - IN/OUT: Length of buffer for option value
{
	// NOTE: Initialization


	this->sock_errno = 0;


	// IN: Check for optval
	if (optval == NULL)
	{
		return 0;       // ERROR: No buffer for option value
	}


	// IN/OUT: Check for length of buffer for option value
	if (optlen == NULL)
	{
		return -1;      // ERROR: No length of buffer for option value
	}


	// Check for socket
	if (this->sock == -1)
	{
		return -2;      // ERROR: No socket
	}


#if defined(__sgi) || defined(__GNUC__)


	// Get socket option
	errno = 0;
	if (::getsockopt(this->sock,
		level,
		optname,
		optval,
		optlen) == -1)
	{
		// Set socket errno
		this->sock_errno = errno;


		return -3;      // ERROR: Couldn't get socket option
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Get socket option
	if (::getsockopt(this->sock,
		level,
		optname,
		(char*)optval,
		optlen) == -1)
	{
		// Set socket errno
		this->sock_errno = WSAGetLastError();


		return -3;      // ERROR: Couldn't get socket option
	}


#endif	// _WIN32


	return 1;       // SUCCESS
}


int Socket::setsockopt(int level,
	int optname,
	const void* optval,
	socklen_t optlen)
{
	// NOTE: Initialization


	this->sock_errno = 0;


	// IN: Check for optval
	if (optval == NULL)
	{
		return 0;       // ERROR: No buffer for option value
	}


	// Check for socket
	if (this->sock == -1)
	{
		return -1;      // ERROR: No socket
	}


#if defined(__sgi) || defined(__GNUC__)


	// Set socket option
	errno = 0;
	if (::setsockopt(this->sock,
		level,
		optname,
		optval,
		optlen) == -1)
	{
		// Set socket errno
		this->sock_errno = errno;


		return -2;      // ERROR: Couldn't set socket option
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Set socket option
	if (::setsockopt(this->sock,
		level,
		optname,
		(char*)optval,
		optlen) == -1)
	{
		// Set socket errno
		this->sock_errno = WSAGetLastError();


		return -2;      // ERROR: Couldn't set socket option
	}


#endif	// _WIN32


	return 1;       // SUCCESS
}


int Socket::set_linger(unsigned short timeout)	// - IN: Linger timeout
{
	unsigned int linger_size;


#if defined(__sgi) || defined(__GNUC__)


	struct linger linger_onoff;


#elif defined(_WIN32)


	LINGER linger_onoff;


#endif	// _WIN32


#if defined(__sgi) || defined(__GNUC__)


	// Set size of linger structure
	linger_size = sizeof(struct linger);


#elif _WIN32


	// Set size of linger structure
	linger_size = sizeof(LINGER);


#endif	// __sgi || __GNUC__ || _WIN32


	// Check for linger socket option
	if (timeout > 0)
	{
		// Enable linger socket option
		linger_onoff.l_onoff = 1;


		// Set linger timeout
		linger_onoff.l_linger = timeout;
	}
	else
	{
		// Disable linger socket option
		linger_onoff.l_onoff = 0;


		// Reset linger timeout
		linger_onoff.l_linger = 0;
	}


	// Set linger socket option
	if (this->setsockopt(SOL_SOCKET,
		SO_LINGER,
		(const void*)&linger_onoff,
		linger_size) < 1)
	{
		return 0;	// ERROR: Couldn't set linger socket option
	}


	return 1;	// SUCCESS
}


int Socket::set_blocking(bool onoff)	// - IN: On/Off flag for socket option
{
#if defined(__sgi) || defined(__GNUC__)


	int sock_flags;


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	unsigned long ulong_onoff;


#endif	// _WIN32


#ifdef __sgi


	// Get flags for socket
	sock_flags = fcntl(this->get_fd(),
		F_GETFL,
		0);
	if (sock_flags == -1)
	{
		return -1;	// ERROR: Couldn't get flags for socket
	}


	// Check for on/off flag
	if (onoff == true)
	{
		// NOTE: Set blocking mode


		sock_flags &= ~FNDELAY;
	}
	else
	{
		// NOTE: Set non-blocking mode


		sock_flags |= FNDELAY;
	}


	// Set blocking mode for socket
	if (fcntl(this->get_fd(),
		F_SETFL,
		sock_flags) == -1)
	{
		return 0;	// ERROR: Couldn't set blocking mode for socket
	}


#elif __GNUC__


	// Get flags for socket
	sock_flags = fcntl(this->get_fd(),
		F_GETFL,
		0);
	if (sock_flags == -1)
	{
		return -1;	// ERROR: Couldn't get flags for socket
	}


	// Check for on/off flag
	if (onoff == true)
	{
		// NOTE: Set blocking mode


		sock_flags &= ~O_NONBLOCK;
	}
	else
	{
		// NOTE: Set non-blocking mode


		sock_flags |= O_NONBLOCK;
	}


	// Set blocking mode for socket
	if (fcntl(this->get_fd(),
		F_SETFL,
		sock_flags) != 0)
	{
		return -2;	// ERROR: Couldn't set blocking mode for socket
	}


#elif _WIN32


	// Check for on/off flag
	if (onoff == true)
	{
		// NOTE: Set blocking mode


		ulong_onoff = 0;
	}
	else
	{
		// NOTE: Set non-blocking mode


		ulong_onoff = 1;
	}


	// Set blocking mode for socket
	if (ioctlsocket(this->get_fd(),
		FIONBIO,
		&ulong_onoff) != 0)
	{
		return -3;	// ERROR: Couldn't set blocking mode for socket
	}


#endif	// __sgi


	return 1;	// SUCCESS
}


int Socket::set_reuseaddr(bool onoff)	// - IN: On/Off flag for socket option
{
	unsigned int uint_onoff;


	// Check for on/off flag
	if (onoff == true)
	{
		// NOTE: Set reuse address mode


		uint_onoff = 1;
	}
	else
	{
		// NOTE: Set non-reuse address mode


		uint_onoff = 0;
	}


	// Set reuse address socket option
	if (this->setsockopt(SOL_SOCKET,
		SO_REUSEADDR,
		(const void*)&uint_onoff,
		sizeof(unsigned int)) < 1)
	{
		return 0;	// ERROR: Couldn't set reuse address socket option
	}


	return 1;	// SUCCESS
}


int Socket::get_errno()
{
	return this->sock_errno;
}


int Socket::get_fd()
{
	return this->sock;
}


unsigned int Socket::get_type()
{
	return this->sock_type;
}


std::string Socket::get_bind_address()
{
	return this->bind_address;
}


unsigned short Socket::get_bind_port()
{
	return this->bind_port;
}


std::string Socket::get_connect_address()
{
	return this->connect_address;
}


unsigned short Socket::get_connect_port()
{
	return this->connect_port;
}


unsigned int Socket::get_listen_backlog()
{
	return this->listen_backlog;
}


std::string Socket::get_accept_address()
{
	return this->accept_address;
}


unsigned short Socket::get_accept_port()
{
	return this->accept_port;
}


#ifdef _WIN32


int RSHD::get_win32_inode(std::string& path,			// - IN: Path
	unsigned long long& win32_inode)	// - OUT: Win32 inode of path
{
	HANDLE file_handle;
	BY_HANDLE_FILE_INFORMATION file_information;


	// Open path
	file_handle = CreateFileA(path.c_str(),
		0,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL |
		FILE_FLAG_BACKUP_SEMANTICS,
		NULL);
	if ((long long)file_handle == -1LL)
	{
		return 0;     // ERROR: Couldn't open path
	}


	// Get file information
	if (GetFileInformationByHandle(file_handle,
		&file_information) == 0)
	{
		return -1;      // ERROR: Couldn't get file information
	}


	// Close handle
	if (CloseHandle(file_handle) == 0)
	{
		return -2;      // ERROR: Couldn't close path
	}


	// OUT: Set win32 inode
	win32_inode = (((unsigned long long) file_information.nFileIndexHigh) << 32) |
		file_information.nFileIndexLow;


	return 1;       // SUCCESS
}


#endif	// _WIN32


int RSHD::COMMAND::dd(Socket& sock,
	Socket& stderr_sock,
	struct rsh& command,
	std::string& local_path,
	unsigned int* full_blocks,
	unsigned int* partial_blocks)
{
	bool is_last;
	bool fgrep_mode;
	char ctrl_c;
	char data[512];
	int file;
	int data_size;
	int total_size;
	unsigned int offset;
	unsigned int num_matches;
	struct stat file_stat;
	LABEL_FILE fgrep_file;
	LABEL_FILE::LINE line;


	// IN: Check for empty filename
	//if (filename.empty() == true)
	if (command.dd.if_filename.empty() == true)
	{
		return 0;	// ERROR: Empty filename
	}


	// OUT: Check for number of full blocks
	if (full_blocks == NULL)
	{
		return -1;	// ERROR: No number of full blocks
	}


	// OUT: Check for number of partial blocks
	if (partial_blocks == NULL)
	{
		return -2;	// ERROR: No number of partial blocks
	}


	// NOTE: Initialization


	*full_blocks = 0;
	*partial_blocks = 0;
	data_size = 0;
	total_size = 0;


	// NOTE: Block size
	//
	//  Transfers are done in 512 byte blocks.


	// Get local path for filename
	local_path.clear();
	//if (filename.get_local(local_path) < 1)
	if (command.dd.if_filename.get_local(local_path) < 1)
	{
		return -3;	// ERROR: Couldn't get local path for filename
	}


	// Stat local path
	if (stat(local_path.c_str(),
		&file_stat) == -1)
	{
		return -4;	// ERROR: Couldn't stat local path
	}


	// Check for directory
	if (LABEL_FILE::is_directory(file_stat.st_mode) == true)
	{
		// NOTE: Directory
		//
		//  Directories cannot be transferred using dd. This error
		//  condition is handled in the caller.


		return -5;	// ERROR: Local path is a directory
	}


	// DEBUG
	sync_dprintf("[RSHD::dd] INFO: open file = \"%s\"\n",
		local_path.c_str());


	// Open filename
	file = ::love_open(local_path.c_str(),
		O_RDONLY,
		0);
	if (file == -1)
	{
		return -4;	// ERROR: Couldn't open filename
	}


	// Check size of file
	if (file_stat.st_size < 0)
	{
		// Close file
		if (::love_close(file) == -1)
		{
			sync_printf("[RSHD::COMMAND::dd] WARNING: Couldn't close file %s\n",
				local_path.c_str());
		}


		return -6;	// ERROR: Size of file is negative
	}


	// Get offset
	offset = command.dd.iseek;


	// DEBUG: offset
	sync_dprintf("[RSHD::dd] INFO: offset = %llu file size = %d\n",
		offset,
		file_stat.st_size);


	// Check for non-zero starting offset
	if (offset > 0)
	{
		// Check for valid start offset
		if ((offset * 512) > (unsigned int)file_stat.st_size)
		{
			// Close file
			if (::love_close(file) == -1)
			{
				sync_printf("[RSHD::COMMAND::dd] WARNING: Couldn't close file %s\n",
					local_path.c_str());
			}


			return -6;	// ERROR: Start offset out of range
		}


		// Seek to requested start offset
		if (::love_lseek(file,
			offset * 512,
			SEEK_SET) == -1)
		{
			// Close file
			if (::love_close(file) == -1)
			{
				sync_printf("[RSHD::COMMAND::dd] WARNING: Couldn't close file %s\n",
					local_path.c_str());
			}


			return -7;	// ERROR: Couldn't set requested start offset
		}


		// NOTE: Start offset
		//
		//  Total size counter (in bytes) starts at offset.


		total_size = offset * 512;
	}
	else
	{
		// NOTE: No offset
		//
		//  Total size counter (in bytes) starts at 0.


		total_size = 0;
	}


	// NOTE: Fgrep mode
	//
	//  Fgrep mode requires the file in the if= argument to be read line by line
	//  and grepped for the pattern " match(" (without the double quotes).
	//
	//  Only matching lines are sent back to the client. dd summary is sent over
	//  standard error.


	// Check for fgrep mode
	fgrep_mode = command.dd.has_fgrep;
	if (fgrep_mode == true)
	{
		// NOTE: Fgrep mode


		// Traverse file
		is_last = false;
		num_matches = 0;
		while (loop_forever)
		{
			// Read line
			line.clear_all();
			data_size = fgrep_file.read_line(file,
				&line);
			switch (data_size)
			{
			case 2:

				// NOTE: EOF
				//
				//  Contrary to default mode, in case EOF is returned from
				//  read_line(), no error condition exists. This is because
				//  in fgrep mode only whole lines are read in and there is
				//  a possibility of reading a file whose last line does not
				//  end with a newline '\n', thus returning EOF.
				//
				//  Note that this last partial line must be processed too,
				//  as it may contain the pattern that is being looked for.


				// Mark last line
				is_last = true;


				break;

			case 1:

				// NOTE: Read a line


				break;

			default:

				// NOTE: Read error
				//
				//  Note that return values of 0 or -1 are possible but never
				//  returned because the parameters passed to read_line() are
				//  valid.
				//
				//  The only other negative return value is on read error.


				// Close file
				if (::love_close(file) == -1)
				{
					sync_printf("[RSHD::COMMAND::dd] WARNING: Couldn't close file %s\n",
						local_path.c_str());
				}


				return -8;	// ERROR: Read error
			}


			// Check for fgrep fixed string
			if (line.contains(" mach(") == true)
			{
				// NOTE: Fixed string found


				// DEBUG
				sync_dprintf("[RSHD::COMMAND::dd] MATCH: \"%s\"\n",
					line.c_str());


				// Increment match counter
				num_matches++;


				// Write data line
				data_size = strlen(line.c_str());
				if (::send(sock.get_fd(),
					line.c_str(),
					data_size,
					0) != data_size)
				{
					sync_printf("[RSHD::COMMAND::dd] ERROR: Write error\n");


					// Close file
					if (::love_close(file) == -1)
					{
						sync_printf("[RSHD::COMMAND::dd] WARNING: Couldn't close file %s\n",
							local_path.c_str());
					}


					return -9;	// ERROR: Write error
				}
			}


			// Check for EOF
			if (is_last == true)
			{
				// NOTE: Block numbers
				//
				//  Since fgrep mode requires whole lines to be read and not
				//  512 byte data blocks, the number of full and partial blocks
				//  required for the dd summary must be calculated separately.


				// Calculate number of full blocks
				*full_blocks = file_stat.st_size / 512;


				// Calculate number of partial blocks
				*partial_blocks = (file_stat.st_size - (*full_blocks * 512)) == 0 ? 0 : 1;


				// DEBUG
				sync_dprintf("[RSHD::COMMAND::dd] FGREP: Number of matched lines = %u\n",
					num_matches);


				break;
			}
		}
	}
	else
	{
		// NOTE: Default mode
		//
		//  Transfer whole file to client. If file has no size,
		//  i.e. if it is an empty file, skip transfer and return
		//  SUCCESS. This allows the code to send a dd summary to
		//  the client (of 0 bytes) which is required by the implementation.


		// Check for empty file
		if (file_stat.st_size > 0)
		{
			// Allocate 1MiB block for transfer
			//data = new char[1024 * 1024];


			// Traverse file
			while (loop_forever)
			{
				// Read data block
				data_size = ::love_read(file,
					(void*)data,
					512);


				// DEBUG
				sync_dprintf("[RSHD::COMMAND::dd] LOOP: Data size %i / Total size %u / File size %u\n",
					data_size,
					total_size,
					file_stat.st_size);


				switch (data_size)
				{
				case 0:

					// NOTE: EOF
					//
					//  The EOF at this point is technically correct but semantically wrong.
					//
					//  Technically correct: the read syscall returns 0 because the client closed
					//  the connection and the kernel returns consequently an EOF.
					//
					//  Semantically wrong: The expected condition to break out of this loop is
					//  having read (and subsequently written or sent) the whole file content to
					//  the client.
					//
					//  This condition is checked for with a counter of the total number of bytes
					//  transmitted (see below for details). An EOF condition here means there has
					//  been an error reading from the file and therefore the loop ends prematurely.
					//
					//  As a consequence, an EOF condition at this point returns an error. This is in
					//  contrast to other parts of the code where an EOF condition returns a success
					//  value (any value greater or equal to 1).


					// Close file
					if (::love_close(file) == -1)
					{
						sync_printf("[RSHD::COMMAND::dd] WARNING: Couldn't close file %s\n",
							local_path.c_str());
					}


					return -10;	// ERROR: EOF

				case -1:

					// NOTE: Read error


					// Close file
					if (::love_close(file) == -1)
					{
						sync_printf("[RSHD::COMMAND::dd] WARNING: Couldn't close file %s\n",
							local_path.c_str());
					}


					return -11;	// ERROR: Read error

				default:

					// NOTE: Read 512 or less bytes


					// DEBUG
					sync_dprintf("[RSHD::COMMAND::dd] BREAK\n");


					break;
				}


				// Check block size
				if (data_size == 512)
				{
					// Increment number of full blocks
					(*full_blocks)++;
				}
				else
				{
					// Increment number of partial blocks
					(*partial_blocks)++;
				}


				// Write data block
				if (::send(sock.get_fd(),
					data,
					data_size,
					0) != data_size)
				{
					sync_printf("[RSHD::COMMAND::dd] ERROR: Write error\n");


					// Close file
					if (::love_close(file) == -1)
					{
						sync_printf("[RSHD::COMMAND::dd] WARNING: Couldn't close file %s\n",
							local_path.c_str());
					}


					return -12;	// ERROR: Write error
				}


				// Update total data size
				total_size += data_size;


				// Check for EOF
				if (total_size >= file_stat.st_size)
				{
					// DEBUG
					sync_dprintf("[RSHD::COMMAND::dd] EXIT_BREAK: total_size >= file_stat.st_size\n");


					break;
				}


				// Check for standard error Ctrl-C
				ctrl_c = '\0';
				if (::recv(stderr_sock.get_fd(),
					(char*)&ctrl_c,
					1,
					0) == 1)
				{
					// Check for Ctrl-C
					if (ctrl_c == '\x02')
					{
						// DEBUG
						sync_dprintf("[RSHD::COMMAND::dd] EXIT_BREAK: Received Ctrl-C\n");


						break;
					}
					else
					{
						// DEBUG
						sync_dprintf("[RSHD::COMMAND::dd] NONDISCARD: Received unknown char %u\n",
							ctrl_c);
					}
				}
			}
		}
	}


	// Close file
	if (::love_close(file) == -1)
	{
		sync_printf("[RSHD::COMMAND::dd] WARNING: Couldn't close file %s\n",
			local_path.c_str());
	}


	// DEBUG
	sync_dprintf("[RSHD::COMMAND::dd] INFO: Data size %u / Total size %u / File size %u\n",
		data_size,
		total_size,
		file_stat.st_size);


	return 1;	// SUCCESS
}


int RSHD::COMMAND::ls(Socket& sock,		// - IN: Socket to send file to
	struct rsh* command,	// - IN: Client command
	std::string& local_path)	// - IN: Local path
{
	struct stat target_stat;
	PATH target;
	std::string mtime;
	std::string irix_path;
	std::string local_pattern_path;
	std::string target_mode;
	std::string format_buffer;
	std::size_t buffer_size;
	std::stringstream stream_buffer;
	std::vector<std::string> dir_entries;
	std::vector<std::string>::iterator it;


#if defined(__sgi) || defined(__GNUC__)


	bool is_symlink;
	char ref_target[MAXPATHLEN + 1];
	struct direct* dir_entry;
	DIR* ls_dir;


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	unsigned long long win32_inode;
	struct _finddata_t file_data;
	PATH target_pattern;
	intptr_t handle_file;


#endif	// _WIN32


	// IN: Check for client command
	if (command == NULL)
	{
		return -1;	// ERROR: No client command
	}


	// DEBUG
	sync_dprintf("[RSHD::COMMAND::ls] START\n");


	// Check for ls command type
	if (command->type != RSHD::COMMAND::LS)
	{
		return -2;	// ERROR: No ls command type
	}


	// Check for subtypes
	if (command->subtype != RSHD::COMMAND::LS_DOT)
	{
		// Check for ls target
		target = command->ls.target;
		if (target.empty() == true)
		{
			return -3;	// ERROR: Empty target
		}


		// Get ls local target path
		if (target.get_local(local_path) < 1)
		{
			return -4;	// ERROR: Couldn't get ls local target path
		}


		// DEBUG
		sync_dprintf("[RSHD::COMMAND::ls] INFO_LOCAL: Target = \"%s\"\n",
			local_path.c_str());
	}


	// NOTE: ls command output
	//
	//  Example output of ls command in IRIX:
	//
	//   16777400 drwxr-xr-x    2 998      998           65 Nov 19 20:01 .


	// Check ls command subtype
	if (command->subtype == RSHD::COMMAND::NONE)
	{
		// NOTE: ls -inld or ls -inldL


		// Get ls IRIX target path
		if (target.get_irix(irix_path) < 1)
		{
			return -5;	// ERROR: Couldn't get ls IRIX target path
		}


		// DEBUG
		sync_dprintf("[RSHD::COMMAND::ls] INFO_IRIX: Target = \"%s\"\n",
			irix_path.c_str());


#if defined(__sgi) || defined(__GNUC__)


		// Check for -inld
		if (command->ls.has_L != true)
		{
			// NOTE: ls -inld


			// Link-stat target
			if (lstat(local_path.c_str(),
				&target_stat) == -1)
			{
				return -4;	// ERROR: Couldn't link stat target
			}


			// Check for symbolic link
			is_symlink = false;
			if (S_ISLNK(target_stat.st_mode) != 0)
			{
				// NOTE: Target is symbolic link
				//
				//  If target is a symbolic link, lstat() returns
				//  stat information about the symbolic link file.
				//
				//  To get the stat of the referenced file, stat()
				//  must be invoked.


				// Set is symlink flag
				is_symlink = true;


				// Get name of referenced target
				bzero((void*)ref_target,
					MAXPATHLEN + 1);
				if (readlink(local_path.c_str(),
					ref_target,
					MAXPATHLEN + 1) == -1)
				{
					return -5;	// ERROR: Couldn't get name of referenced target
				}


				// Get stat from referenced target
				if (stat(local_path.c_str(),
					&target_stat) == -1)
				{
					return -6;	// ERROR: Couldn't stat referenced target
				}
			}


			// Get inode
			stream_buffer << target_stat.st_ino << ' ';


			// Get mode
			target_mode = "";
			RSHD::COMMAND::get_mode(&target_stat,
				is_symlink,
				target_mode);
			stream_buffer << target_mode << ' ';


			// Number of hardlinks
			stream_buffer << target_stat.st_nlink << ' ';


			// Get numeric owner ID
			stream_buffer << target_stat.st_uid << ' ';


			// Get numeric group ID
			stream_buffer << target_stat.st_gid << ' ';


			// Get size in bytes
			stream_buffer << target_stat.st_size << ' ';


			// Get modification time
			RSHD::COMMAND::get_mtime(&target_stat,
				mtime);
			stream_buffer << mtime << ' ';


			// Get name
			stream_buffer << local_path.c_str();


			// Check for symbolic link
			if (is_symlink == true)
			{
				// Get name of referenced target
				stream_buffer << " -> " << ref_target;
			}
		}
		else


#endif	// __sgi || __GNUC__


		{
			// NOTE: ls -inldL


			// Stat target
			if (stat(local_path.c_str(),
				&target_stat) == -1)
			{
				return -7;	// ERROR: Couldn't stat target
			}


#ifdef _WIN32


			// Get win32 inode
			if (RSHD::get_win32_inode(local_path,
				win32_inode) < 1)
			{
				return -8;	// ERROR: Couldn't get win32 inode
			}


			// Set win32 inode
			stream_buffer << win32_inode << ' ';


#else


			// Get inode
			stream_buffer << target_stat.st_ino << ' ';


#endif	// _WIN32


			// Get mode
			RSHD::COMMAND::get_mode(&target_stat,
				false,
				target_mode);
			stream_buffer << target_mode << ' ';


			// Number of hardlinks
			stream_buffer << target_stat.st_nlink << ' ';


			// Get numeric owner ID
			stream_buffer << target_stat.st_uid << ' ';


			// Get numeric group ID
			stream_buffer << target_stat.st_gid << ' ';


			// Get size in bytes
			stream_buffer << target_stat.st_size << ' ';


			// Get modification time
			RSHD::COMMAND::get_mtime(&target_stat, mtime);
			stream_buffer << mtime << ' ';


			// Get name
			stream_buffer << irix_path.c_str();
		}


		// Append newline
		stream_buffer << '\n';


		// Write output to client
		buffer_size = stream_buffer.str().length();
		if (::send(sock.get_fd(),
			stream_buffer.str().c_str(),
			buffer_size,
			0) != buffer_size)
		{
			return -8;	// ERROR: Write error
		}


		// DEBUG
		sync_dprintf("[RSHD::COMMAND::ls] LS: \"%s\"\n",
			stream_buffer.str().c_str());
	}
	else if (command->subtype == RSHD::COMMAND::LS)
	{
		// NOTE: ls -a
		//
		//  This command invocation has a directory as its
		//  first argument.


		// DEBUG
		sync_dprintf("[RSHD::COMMAND::ls] INFO: ls -a \"%s\"\n",
			local_path.c_str());


#if defined(__sgi) || defined(__GNUC__)


		// Open directory
		ls_dir = opendir(local_path.c_str());
		if (ls_dir == NULL)
		{
			return -9;	// ERROR: Couldn't open directory
		}


		// DEBUG
		sync_dprintf("[RSHD::COMMAND::ls] TRAVERSE: \"%s\"\n",
			local_path.c_str());


		// Traverse directory entries
		while (loop_forever)
		{
			// Read directory entry
			dir_entry = readdir(ls_dir);
			if (dir_entry == NULL)
			{
				// NOTE: End of entries


				break;
			}


			// DEBUG
			sync_dprintf("[RSHD::COMMAND::ls] ENTRYNAME: \"%s\"\n",
				dir_entry->d_name);


			// Sorted-add directory entry
			RSHD::COMMAND::add_sorted(dir_entry->d_name,
				dir_entries);
		}


		// Close directory
		closedir(ls_dir);


#endif	// __sgi || __GNUC__


#ifdef _WIN32


		// Copy target directory
		target_pattern.set(local_path + "\\*");


		// Get ls target pattern path
		local_pattern_path.clear();
		if (target_pattern.get_local(local_pattern_path) < 1)
		{
			return -4;	// ERROR: Couldn't get ls target pattern path
		}


		// DEBUG
		sync_dprintf("[RSHD::COMMAND::ls] TRAVERSE: \"%s\"\n",
			local_pattern_path.c_str());


		// Find first .c file in current directory
		handle_file = _findfirst(local_pattern_path.c_str(),
			&file_data);
		if (handle_file == -1L)
		{
			return -9;	// ERROR: Couldn't open directory
		}


		// Traverse directory entries
		do
		{
			// DEBUG
			sync_dprintf("[RSHD::COMMAND::ls] ENTRYNAME: \"%s\"\n",
				file_data.name);


			// Sorted-add directory entry
			RSHD::COMMAND::add_sorted(file_data.name,
				dir_entries);
		} while (_findnext(handle_file,
			&file_data) == 0);


		// Close directory
		_findclose(handle_file);


#endif	// _WIN32


		// DEBUG
		sync_dprintf("[RSHD::COMMAND::ls] SORTTRAVERSE: \"%s\"\n",
			local_path.c_str());


		// Traverse sorted directory entries
		it = dir_entries.begin();
		while (loop_forever)
		{
			// Append newline to directory entry
			(*it) += '\n';


			// Write output to client
			if (::send(sock.get_fd(),
				it->c_str(),
				it->length(),
				0) != it->length())
			{
				return -10;	// ERROR: Write error
			}


			// Increment iterator
			it++;


			// Check for end of directory entries
			if (it == dir_entries.end())
			{
				// NOTE: End of sorted entries


				break;
			}
		}


		// DEBUG
		sync_dprintf("[RSHD::COMMAND::ls] CLOSE: \"%s\"\n",
			local_path.c_str());
	}
	else if (command->subtype == RSHD::COMMAND::LS_DOT)
	{
		// NOTE: ls -inld .
		//
		//  This command invocation has a directory '.' (dot) as its first
		//  argument.
		//
		//  It is invoked right after executing a shell via rsh.
		//
		//  A special string, containing all requested components is sent
		//  directly to the client.
		//
		//  The current working directory is owned by user 'guest'.


		// DEBUG
		sync_dprintf("[RSHD::COMMAND::ls] INFO: ls -inld .\n");


		// Write output to client
		if (::send(sock.get_fd(),
			"660673 drwxr-xr-x 2 999 999 65 Nov 19 20:01 .\n",
			46,
			0) != 46)
		{
			return -11;	// ERROR: Write error
		}

	}
	else
	{
		return -12;	// ERROR: Unknown ls command subtype
	}


	return 1;	// SUCCESS
}


int RSHD::COMMAND::get_mode(struct stat* stat,	// - IN: File stat
	bool is_symlink,	// - IN: Flag indicating file is a symbolic link
	std::string& mode)	// - OUT: Symbolic mode
{
#if defined(__sgi) || defined(__GNUC__)


	mode_t stat_mode;


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	unsigned short stat_mode;


#endif	// _WIN32


	// IN: Check for file stat
	if (stat == NULL)
	{
		return 0;	// ERROR: No file stat
	}


	// Get stat mode
	stat_mode = stat->st_mode;


	// Initialize mode string
	mode = "";


#if defined(__sgi) || defined(__GNUC__)


	// NOTE: ls modes
	//
	//  The following file modes are supported by the
	//  ls command under IRIX and Linux:
	//
	//   d   if the entry is a directory;
	//   l   if the entry is a symbolic link;
	//   b   if the entry is a block special file;
	//   c   if the entry is a character special file;
	//   s   if the entry is a XENIX semaphore;
	//   m   if the entry is a XENIX shared data (memory);
	//   p   if the entry is a fifo (named pipe) special file;
	//   S   if the entry is an AF_UNIX address family socket;
	//   -   if the entry is a regular file.
	//
	//   At least d, l and - must be implemented.


	// Check for file type
	if (S_ISDIR(stat_mode) != 0)
	{
		mode += 'd';
	}
	else if (is_symlink == true)
	{
		mode += 'l';
	}
	else if (S_ISBLK(stat_mode) != 0)
	{
		mode += 'b';
	}
	else if (S_ISCHR(stat_mode) != 0)
	{
		mode += 'c';
	}
	else if (S_ISFIFO(stat_mode) != 0)
	{
		mode += 'p';
	}
	else if (S_ISSOCK(stat_mode) != 0)
	{
		mode += 'S';
	}
	else
	{
		mode += '-';
	}


	// Owner read permission
	if ((stat_mode & S_IRUSR) == S_IRUSR)
	{
		mode += 'r';
	}
	else
	{
		mode += '-';
	}


	// Owner write permission
	if ((stat_mode & S_IWUSR) == S_IWUSR)
	{
		mode += 'w';
	}
	else
	{
		mode += '-';
	}


	// Owner execute permission
	if ((stat_mode & S_IXUSR) == S_IXUSR)
	{
		mode += 'x';
	}
	else
	{
		mode += '-';
	}


	// Group read permission
	if ((stat_mode & S_IRGRP) == S_IRGRP)
	{
		mode += 'r';
	}
	else
	{
		mode += '-';
	}


	// Group write permission
	if ((stat_mode & S_IWGRP) == S_IWGRP)
	{
		mode += 'w';
	}
	else
	{
		mode += '-';
	}


	// Group execute permission
	if ((stat_mode & S_IXGRP) == S_IXGRP)
	{
		mode += 'x';
	}
	else
	{
		mode += '-';
	}


	// Other read permission
	if ((stat_mode & S_IROTH) == S_IROTH)
	{
		mode += 'r';
	}
	else
	{
		mode += '-';
	}


	// Other write permission
	if ((stat_mode & S_IWOTH) == S_IWOTH)
	{
		mode += 'w';
	}
	else
	{
		mode += '-';
	}


	// Other execute permission
	if ((stat_mode & S_IXOTH) == S_IXOTH)
	{
		mode += 'x';
	}
	else
	{
		mode += '-';
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32

	// NOTE: ls modes
	//
	//  The following file modes are supported by the
	//  ls command under Windows:
	//
	//   d   if the entry is a directory;
	//   c   if the entry is a character special file;
	//   p   if the entry is a fifo (named pipe) special file;
	//   -   if the entry is a regular file.
	//
	//   At least d, l and - must be implemented. In this case, there
	//   is no support for symbolic links in all Windows filesystems,
	//   so that actual symbolic links in IRIX/Linux are full copies of
	//   the files they link to.


	// Check for file type
	if ((stat_mode & _S_IFDIR) == _S_IFDIR)
	{
		mode += 'd';
	}
	else if ((stat_mode & _S_IFCHR) == _S_IFCHR)
	{
		mode += 'c';
	}
	else if ((stat_mode & _S_IFIFO) == _S_IFIFO)
	{
		mode += 'p';
	}
	else
	{
		mode += '-';
	}


	// Owner read permission
	if ((stat_mode & _S_IREAD) == _S_IREAD)
	{
		mode += 'r';
	}
	else
	{
		mode += '-';
	}


	// Owner write permission
	if ((stat_mode & _S_IWRITE) == _S_IWRITE)
	{
		mode += 'w';
	}
	else
	{
		mode += '-';
	}


	// Owner execute permission
	if ((stat_mode & _S_IEXEC) == _S_IEXEC)
	{
		mode += 'x';
	}
	else
	{
		mode += '-';
	}


	// Group read permission
	mode += '-';


	// Group write permission
	mode += '-';


	// Group execute permission
	mode += '-';


	// Other read permission
	mode += '-';


	// Other write permission
	mode += '-';


	// Other execute permission
	mode += '-';


#endif	// _WIN32


	return 1;	// SUCCESS
}


int RSHD::COMMAND::get_mtime(struct stat* file_stat,	// - IN: File stat
	std::string& mtime)	// - OUT: Modification time
{
	char st_mtim[26 + 1];
	std::string daynum;
	std::string month;
	std::string time;
	std::string discard;
	std::stringstream sstream;


	// IN: Check for file stat
	if (stat == NULL)
	{
		return 0;	// ERROR: No file stat
	}


	// OUT: Initialize modification time
	mtime = "";


#if defined(__sgi) || defined(__GNUC__)


	// Get time
	bzero((void*)st_mtim,
		26 + 1);
	ctime_r(&file_stat->st_mtim.tv_sec,
		st_mtim);


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Get time
	bzero((void*)st_mtim,
		26 + 1);
	_ctime64_s<26 + 1>(st_mtim,
		&file_stat->st_mtime);


#endif	// _WIN32


	// NOTE: ls command modification time
	//
	//  The modification time in the ls command output
	//  is shown in the following format:
	//
	//   Month DayNum HH:MM
	//
	//  The modification time returned by ctime() has the format:
	//
	//   Day Month DayNum HH:MM:SS Year\n\0


	// Tokenize modification time
	sstream << st_mtim;


	// Discard day
	sstream >> discard;


	// Get month
	sstream >> month;


	// Get day number
	sstream >> daynum;


	// Get time
	sstream >> time;


	// Truncate seconds from time
	time = time.substr(0,
		5);


	// OUT: Set modification time
	mtime = month + ' ' + daynum + ' ' + time;


	return 1;	// SUCCESS
}


int RSHD::COMMAND::add_sorted(char* entry_name,				// - IN: Directory entry name to insert
	std::vector<std::string>& dir_entries)	// - OUT: Vector of directory entry names
{
	bool was_inserted;
	std::vector<std::string>::iterator it;


	// IN: Check for directory entry name
	if (entry_name == NULL)
	{
		return 0;	// ERROR: No directory entry name
	}


	// Check for empty directory entry name
	if (entry_name[0] == '\0')
	{
		return -1;	// ERROR: Empty directory entry name
	}


	// DEBUG
	sync_dprintf("[RSHD::COMMAND::add_sorted] INFO: Entry name \"%s\"\n",
		entry_name);


	// Get string object of directory entry name
	std::string entry_name_1(entry_name);


	// Check for empty vector
	if (dir_entries.empty() == true)
	{
		// Insert new directory entry name
		dir_entries.push_back(entry_name_1);


		return 2;	// SUCCESS: Empty vector
	}


	// Traverse directory entry names
	was_inserted = false;
	for (it = dir_entries.begin();
		it < dir_entries.end();
		it++)
	{
		// Compare entry names lexicographically
		if (entry_name_1.compare(*it) <= 0)
		{
			// NOTE: Insert before current word


			// Insert at current iterator position
			dir_entries.insert(it,
				entry_name_1);


			// Set was inserted flag
			was_inserted = true;


			break;
		}
	}


	// Check for insertion
	if (was_inserted != true)
	{
		// NOTE: Insert at the end of vector


		dir_entries.push_back(entry_name_1);
	}


	return 1;	// SUCCESS
}


int RSHD::convert_to_uint(std::string& input,	// - IN: Positive decimal number in ASCII
	unsigned int* port)	// - OUT: Port number
{
	char port_char;
	unsigned int input_index;
	unsigned int port_number;
	std::size_t input_length;


	// OUT: Check for port number
	if (port == NULL)
	{
		return 0;	// ERROR: No port number
	}


	// Check for empty input string
	if (input.empty() == true)
	{
		return -1;	// ERROR: Empty input string
	}


	// Check for maximum length of input string
	input_length = input.length();
	if (input_length > IP_V4_ADDR_LEN)
	{
		return -2;	// ERROR: Input string length overflow
	}


	// DEBUG
	sync_dprintf("[RSHD::convert_to_uint] INFO: input_length = %u\n",
		input_length);


	// Convert decimal number in ASCII to unsigned integer
	port_number = 0;
	for (input_index = 0;
		input_index < input_length;
		input_index++)
	{
		// Get character
		port_char = input.at(input_index);


		// DEBUG
		sync_dprintf("[RSHD::convert_to_uint] INFO: port_char = %c\n",
			port_char);


		// Check for ASCII digit
		if ((port_char < '0') ||
			(port_char > '9'))
		{
			return -3;	// ERROR: Input character is not an ASCII digit
		}


		// Get next digit
		port_number = (port_number * 10) + (port_char - '0');
	}


	// OUT: Set port number
	*port = port_number;


	return 1;	// SUCCESS
}


void RSHD::process_status_suffix(std::string& stdout_echo,	// - IN/OUT: Client command
	std::string* long_status)	// - IN: Long status string
{
	std::size_t status_index;
	std::size_t suffix_index;
	std::size_t status_suffix_length;
	std::string status_suffix;


	// IN/OUT: Check for standard out echo string
	if (stdout_echo.length() == 0)
	{
		return;	// ERROR: No standard out echo string
	}


	// IN: Check for long status
	if (long_status == NULL)
	{
		return;	// ERROR: No long status
	}


	// DEBUG
	sync_dprintf("[RSHD::process_status_suffix] INFO: stdout_echo \"%s\" long_status \"%s\"\n",
		stdout_echo.c_str(),
		long_status->c_str());


	// Check for empty long status
	if (long_status->length() == 0)
	{
		return;	// ERROR: Empty long status
	}


	// NOTE: Status suffix
	//
	//  Starting with IRIX 6.5.X, the miniroot inst sends status lines
	//  where the status code is not the last character(s) to send.
	//
	//  The extra trailing characters are called status suffix and must
	//  be removed from the standard out echo string (command word 12).
	//
	//  Command word at index 15 can be:
	//
	//   1. '?o_InstKill1107IsDonea'$status		- No status suffix
	//   2. 'o?_InstProc402IsDone'$status'\c'	- Status suffix \c
	//
	//  The second case needs extra processing. This processing is done here.


	// Get index of $status subtring
	status_index = long_status->find("$status");
	if (status_index < (long_status->length() - 7))
	{
		// NOTE: Status suffix found
		//
		//  The expected suffix comes after "$status'".
		//
		//  Note the trailing ' after "$status". The status suffix
		//  will be at index:
		//
		//   find("$status") + length("$status'") = 8


		// Get status suffix
		status_suffix = long_status->substr(status_index + 8);


		// Check for trailing '
		status_suffix_length = status_suffix.length();
		if (status_suffix.at(status_suffix_length - 1) == '\'')
		{
			// NOTE: erase() vs. pop_back()
			//
			//  Linux GNU C++ does not support pop_back() for std::string in
			//  C++98 mode. The consens is to use erase() instead.


			// Trim trailing '
			status_suffix.erase(status_suffix_length - 1,
				1);
		}
	}


	// DEBUG
	sync_dprintf("[RSHD::process_status_suffix] INFO: status_suffix = \"%s\"\n",
		status_suffix.c_str());


	// Check for status suffix
	if (status_suffix.length() > 0)
	{
		// Check for status suffix in standard out echo string
		suffix_index = stdout_echo.length() - status_suffix.length();
		if (stdout_echo.rfind(status_suffix) == suffix_index)
		{
			// NOTE: Status suffix found


			// OUT: Remove suffix
			stdout_echo = stdout_echo.substr(0, suffix_index);


			// DEBUG
			sync_dprintf("[RSHD::process_status_suffix] INFO: stdout_echo = \"%s\"\n",
				stdout_echo.c_str());
		}
	}
}


// NOTE: Function definitions


bool REGULAR_FILE::exists(std::string& filename)	// - IN: Filename to check for
{
	struct stat file_stat;


	// Check for empty filename
	if (filename.empty() == true)
	{
		return false;	// ERROR: Empty filename
	}


	// Check for existence of filename
	if (stat(filename.c_str(),
		&file_stat) == -1)
	{
		return false;   // SUCCESS: Filename doesn't exist
	}


	return true;	// SUCCESS: Filename exists
}


RSHD::RSHD()
{
	// NOTE: Initialization


	this->daemon_started = false;
}


int RSHD::start()
{
	// Check for started daemon
	if (this->started() == true)
	{
		return 0;	// ERROR: Daemon already started
	}


	// DEBUG
	sync_dprintf("[RSHD::start] START\n");


	// Create new thread
	if (this->thread_id.create_thread((void*)RSHD_loop,
		(void*)this) < 1)
	{
		return -1;	// ERROR: Couldn't create daemon main loop
	}


	// Set daemon started flag
	this->set_started();


	// DEBUG
	sync_dprintf("[RSHD::start] STOP\n");


	return 1;	// SUCCESS
}


bool RSHD::started()
{
	return this->daemon_started;
}


void RSHD::set_started()
{
	this->daemon_started = true;
}


int RSHD::start_session(Socket& client_sock,		// - IN: Client socket
	Socket& server_sock)		// - IN: Server socket
{
	int ret;
	bool file_is_found;
	bool path_is_directory;
	long buffer_length;
	char ctrl_c;
	char format_buffer[LS_ERROR_LEN + MAXPATHLEN + 10 + 2];
	unsigned short priv_port;
	unsigned int full_blocks;
	unsigned int partial_blocks;
	unsigned int second_port;
	struct rsh command;
	std::string input;
	std::string cached_path;
	std::string local_path;


#ifdef __GNUC__


	int stderr_flags;
	unsigned int onoff;


#endif	// __GNUC__


	// Read second port number in ASCII
	input.clear();
	ret = this->read_input(client_sock,
		0,
		'\0',
		input);
	if (ret < 1)
	{
		sync_printf("[RSHD::start_session] ERROR: Couldn't read RSH client input ret = %i\n",
			ret);


		// Close client socket
		client_sock.close();


		return 0;	// ERROR: Couldn't read RSHD input
	}


	// DEBUG
	sync_dprintf("[RSHD::start_session] INFO: Second port number ASCII = \"%s\" length = %u\n",
		input.c_str(),
		input.length());


	// NOTE: Second port
	//
	//  In RSHD, the second port is used to transmit standard error
	//  from the shell to the client, or to read the signal number
	//  entered on the client side:
	//
	//   1. Ctrl-C --> [Client --> csocket] -> [ssocket --> RSHD] -------------> shell
	//
	//   2.            [Client <-- csocket] <- [ssocket <-- RSHD] <-- stderr <-- shell
	//
	//  In the examples above, csocket is the socket on the client side, and ssocket
	//  is the socket on the server side. Brackets indicate a logical grouping.
	//
	//  The server side socket is bound to a privileged local port number (local port < 1024)
	//  and connected to the client at the second port.
	//
	//  In example number 1, a signal is transmitted from the client to RSHD. In example
	//  number 2, standard error shell output is redirected to the client.


	// Convert second port number from ASCII to unsigned integer
	ret = RSHD::convert_to_uint(input,
		&second_port);
	if (ret < 1)
	{
		sync_printf("[RSHD::start_session] ERROR: Couldn't read second port number (ret = %i)\n",
			ret);


		// Close client socket
		client_sock.close();


		return -1;	// ERROR: Couldn't read second port number
	}


	// DEBUG
	sync_dprintf("[RSHD::start_session] INFO: Second port number = \"%s\" = %u\n",
		input.c_str(),
		second_port);


	// Check for privileged second port number
	if ((second_port == 0) ||
		(second_port >= 1024))
	{
		sync_printf("[RSHD::start_session] ERROR: Second port is not a privileged port (%u)\n",
			second_port);


		// Close client socket
		client_sock.close();


		return -2;	// ERROR: Second port is not a privileged port
	}


	// Create new socket for standard error
	Socket stderr_sock;
	if (stderr_sock.get_fd() == -1)
	{
		sync_printf("[RSHD::start_session] ERROR: Couldn't create standard error socket\n");


		// Close client socket
		client_sock.close();


		return -3;	// ERROR: Couldn't create standard error socket
	}


	// NOTE: bind() vs. connect()
	//
	//  IRIX/Linux and Windows platforms handle 'address in use' errors differently.
	//
	//  In the former case, if a socket triplet (protocol, address, port) is already in
	//  use, bind() returns the error.
	//
	//  In the latter, both, bind() or connect() may return this error. In case of connect(),
	//  it is called a delayed error.
	//
	//  The code has to implement the case where connect() returns the error instead of
	//  bind().
	//
	//  This distinction would only apply to the Windows platform.


	for (priv_port = 1023;
		priv_port > 512;
		priv_port--)
	{
		sync_dprintf("[RSHD::start_session] INFO: stderr_sock.bind()\n");


		// Try to bind to port
		ret = stderr_sock.bind(server_sock.src.get_bytes(),
			priv_port);
		if (ret < 1)
		{
			// NOTE: Not free, skip
			//
			//  Privileged ports not bound to in this function return error.
			//
			//  These ports were bound to and are being used by other applications.


			sync_printf("[RSHD::start_session] WARNING: Couldn't bind to privileged local port %u errno = %i (ret = %i)\n",
				priv_port,
				stderr_sock.get_errno(),
				ret);


#ifdef _WIN32


			// Check for address already in use error
			if (stderr_sock.get_errno() == WSAEADDRINUSE)
			{
				// NOTE: Delayed error
				//
				//  Retry with the next smaller privileged port.


				sync_printf("[RSHD::start_session] ERROR: WSAEADDRINUSE\n");


				// Close standard error socket
				stderr_sock.close();


				// Open new underlying system socket for socket instance
				if (stderr_sock.open() < 1)
				{
					sync_printf("[RSHD::start_session] ERROR: Couldn't open new underlying system socket for socket instance\n");


					// Close client socket
					client_sock.close();


					return -4;	// ERROR: Couldn't open new underlying system socket for socket instance
				}


				continue;
			}


#endif	// _WIN32
		}
		else
		{
			// DEBUG
			sync_dprintf("[RSHD::start_session] PRIV_BIND: privileged port bound to %u\n",
				priv_port);


			sync_dprintf("[RSHD::start_session] INFO: stderr_sock.connect()\n");


			ret = stderr_sock.connect(client_sock.src.get_bytes(),
				second_port);
			if (ret < 1)
			{
#ifdef _WIN32


				// Check for address already in use error
				if (stderr_sock.get_errno() == WSAEADDRINUSE)
				{
					// NOTE: Delayed error
					//
					//  Retry with the next smaller privileged port.


					sync_printf("[RSHD::start_session] ERROR: WSAEADDRINUSE\n");


					// Close standard error socket
					stderr_sock.close();


					// Open new underlying system socket for socket instance
					if (stderr_sock.open() < 1)
					{
						sync_printf("[RSHD::start_session] ERROR: Couldn't open new underlying system socket for socket instance\n");


						// Close client socket
						client_sock.close();


						return -5;	// ERROR: Couldn't open new underlying system socket for socket instance
					}


					continue;
				}


#endif	// _WIN32


				sync_printf("[RSHD::start_session] ERROR: Couldn't connect to client at second port %u errno = %i (ret = %i)\n",
					second_port,
					stderr_sock.get_errno(),
					ret);


				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -6;	// ERROR: Couldn't connect to client at second port
			}


			break;
		}
	}


	// Set no linger socket option for client socket
	if (client_sock.set_linger(0) < 1)
	{
		sync_printf("[RSHD::start_session] ERROR: Couldn't set no linger socket option for client socket\n");


		// Close standard error socket
		stderr_sock.close();


		// Close client socket
		client_sock.close();


		return -7;	// ERROR: Couldn't set no linger socket option for client socket
	}


	// Set no linger socket option for standard error socket
	if (stderr_sock.set_linger(0) < 1)
	{
		sync_printf("[RSHD::start_session] ERROR: Couldn't set no linger socket option for standard error socket\n");


		// Close standard error socket
		stderr_sock.close();


		// Close client socket
		client_sock.close();


		return -8;	// ERROR: Couldn't set no linger socket option for standard error socket
	}


	// Set non-blocking mode for standard error socket
	if (stderr_sock.set_blocking(false) < 1)
	{
		sync_printf("[RSHD::start_session] ERROR: Couldn't set non-blocking mode for standard error socket\n");


		// Close standard error socket
		stderr_sock.close();


		// Close client socket
		client_sock.close();


		return -9;	// ERROR: Couldn't set non-blocking mode for standard error socket
	}


#ifdef __GNUC__


	// Set don't fragment IP socket option
	onoff = IP_PMTUDISC_DONT;
	if (stderr_sock.setsockopt(IPPROTO_IP,
		IP_MTU_DISCOVER,
		(const void*)&onoff,
		sizeof(unsigned int)) < 1)
	{
		sync_printf("[RSHD::start_session] ERROR: Couldn't set don't fragment IP socket option\n");


		// Close standard error socket
		stderr_sock.close();


		// Close client socket
		client_sock.close();


		return -8;	// ERROR: Couldn't set don't fragment IP socket option
	}


#endif	// __GNUC__


	// Read remote username
	input.clear();
	ret = this->read_input(client_sock,
		0,
		'\0',
		input);
	if (ret < 1)
	{
		sync_printf("[RSHD::start_session] ERROR: Couldn't read remote username ret = %i\n",
			ret);


		// Close standard error socket
		stderr_sock.close();


		// Close client socket
		client_sock.close();


		return -9;	// ERROR: Couldn't read remote username
	}


	// DEBUG
	sync_dprintf("[RSHD::start_session] INFO: Remote Username = \"%s\"\n",
		input.c_str());


	// Read local username
	input.clear();
	ret = this->read_input(client_sock,
		0,
		'\0',
		input);
	if (ret < 1)
	{
		sync_printf("[RSHD::start_session] ERROR: Couldn't read local username ret = %i\n",
			ret);


		// Close standard error socket
		stderr_sock.close();


		// Close client socket
		client_sock.close();


		return -10;	// ERROR: Couldn't read local username
	}


	// DEBUG
	sync_dprintf("[RSHD::start_session] INFO: Local username = \"%s\"\n",
		input.c_str());


	// Check for 'guest' local username
	if (input.compare("guest") != 0)
	{
		// NOTE: Local username is not 'guest'


		sync_printf("[RSHD::start_session] ERROR: Local username is not 'guest'\n");


		// Send error message
		if (::send(client_sock.get_fd(),
			"\x01Permission denied.\n",
			20,
			0) != 20)
		{
			// DEBUG
			sync_dprintf("[RSHD::start_session] WARNING: Couldn't send error message\n");
		}


		// Close standard error socket
		stderr_sock.close();


		// Close client socket
		client_sock.close();


		return -10;	// ERROR: Local username is not 'guest'
	}


	// Read /bin/sh
	input.clear();
	ret = this->read_input(client_sock,
		0,
		'\0',
		input);
	if (ret < 1)
	{
		sync_printf("[RSHD::start_session] ERROR: Couldn't read /bin/sh ret = %i\n",
			ret);


		// Close standard error socket
		stderr_sock.close();


		// Close client socket
		client_sock.close();


		return -10;	// ERROR: Couldn't read /bin/sh
	}


	// DEBUG
	sync_dprintf("[RSHD::start_session] INFO: String /bin/sh = \"%s\"\n",
		input.c_str());


	// Send NULL byte
	if (::send(client_sock.get_fd(),
		"\0",
		1,
		0) != 1)
	{
		// Close standard error socket
		stderr_sock.close();


		// Close client socket
		client_sock.close();


		return -11;	// ERROR: Couldn't send NULL byte
	}
	else
	{
		// DEBUG
		sync_dprintf("[RSHD::start_session] INFO: Written NULL byte\n");
	}


	// NOTE: /bin/sh
	//
	//  For IRIX 5.3, 6.0, 6.2, 6.4 the string sent by the miniroot inst is just
	//  "/bin/sh\0".
	//
	//  Starting with IRIX 6.5.X, the miniroot inst sends "exec /bin/sh\0".


	// Check for /bin/sh
	if ((input.compare("/bin/sh") != 0) &&
		(input.compare("exec /bin/sh") != 0))
	{
		sync_printf("[RSHD::start_session] ERROR: Couldn't find /bin/sh ret = %i\n",
			ret);


		// Close standard error socket
		stderr_sock.close();


		// Close client socket
		client_sock.close();


		return -12;	// ERROR: Couldn't find /bin/sh
	}


	// NOTE: Session loop
	//
	//  The first command issued by miniroot inst is /bin/sh or
	//  exec /bin/sh, subsequently issuing one shell command after
	//  the other.
	//
	//  These commands are read and processed in the following
	//  session loop.


	cached_path.clear();
	while (loop_forever)
	{
		// NOTE: /bin/sh mode
		//
		//  Input lines are terminated by newline characters ('\n').


		// Read command
		input.clear();
		ret = this->read_input(client_sock,
			0,
			'\n',
			input);
		if (ret < 1)
		{
			sync_printf("[RSHD::start_session] ERROR: Couldn't read command (ret = %i)\n",
				ret);


			// Close standard error socket
			stderr_sock.close();


			// Close client socket
			client_sock.close();


			return -13;	// ERROR: Couldn't read command
		}


		// Check for EOF from client
		if (ret == 2)
		{
			sync_printf("[RSHD::start_session] SUCCESS: Client closed connection\n");


			// Close standard error socket
			stderr_sock.close();


			// Close client socket
			client_sock.close();


			return 2;	// SUCCESS: Client closed connection
		}


		// DEBUG
		sync_dprintf("[RSHD::start_session] INFO: Command = \"%s\"\n",
			input.c_str());


		// Parse command
		if (this->parse(input,
			cached_path,
			&command) < 1)
		{
			sync_printf("[RSHD::start_session] ERROR: Couldn't parse client input string \"%s\"\n",
				input.c_str());


			// Close standard error socket
			stderr_sock.close();


			// Close client socket
			client_sock.close();


			return -14;	// ERROR: Couldn't parse client input string
		}


		// Switch out by command
		switch (command.type)
		{
		case RSHD::COMMAND::DD:

			// DEBUG
			sync_dprintf("[RSHD::start_session] INFO: Execute dd \"%s\" has_fgrep = \"%s\"\n",
				input.c_str(),
				command.dd.has_fgrep == true ? "true" : "false");


			// Discard all Ctrl-C on standard error socket
			while (loop_forever)
			{
				// Get next Ctrl-C
				ctrl_c = '\0';
				if (::recv(stderr_sock.get_fd(),
					(char*)&ctrl_c,
					1,
					0) == 1)
				{
					// Check for Ctrl-C
					if (ctrl_c == '\x02')
					{
						// DEBUG
						sync_dprintf("[RSHD::start_session] DISCARD: Ctrl-C\n");
					}
					else
					{
						// DEBUG
						sync_dprintf("[RSHD::start_session] DISCARD: Unknown char %u\n", ctrl_c);
					}
				}
				else
				{
					// DEBUG
					sync_dprintf("[RSHD::start_session] DISCARD: DONE\n");


					break;
				}
			}


			// NOTE: Write sequence
			//
			//  To serialize as much as possible the arrival of output from
			//  standard output (client_sock) and standard error (stderr_sock)
			//  on the client side, a fork()+execv() sequence with added shell
			//  execution is simulated using a usleep() invocation.


			// Write requested file in 1MiB blocks to standard output
			full_blocks = 0;
			partial_blocks = 0;
			local_path.clear();
			path_is_directory = false;
			ret = RSHD::COMMAND::dd(client_sock,
				stderr_sock,
				command,
				local_path,
				&full_blocks,
				&partial_blocks);
			if (ret < 1)
			{
				if (ret != -5)
				{
					// DEBUG
					sync_dprintf("[RSHD::start_session] INFO: dd ret = %i\n",
						ret);


					// Close standard error socket
					stderr_sock.close();


					// Close client socket
					client_sock.close();


					return -15;	// ERROR: Couldn't execute dd command
				}
				else
				{
					path_is_directory = true;
				}
			}


			// Format echo filename
			buffer_length = love_snprintf(format_buffer,
				MAXPATHLEN + 10 + 2,
				"%s\n",
				command.dd.echo.c_str());
			if (buffer_length < 0)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -16;	// ERROR: Couldn't format echo filename buffer
			}


			// Write echo filename to standard output
			if (::send(client_sock.get_fd(),
				format_buffer,
				buffer_length,
				0) != buffer_length)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -17;	// ERROR: Couldn't write echo filename buffer
			}


			// Subshell runtime
			love_sleep(50);


			// Check for path is directory flag
			if (path_is_directory != true)
			{
				// NOTE: Path is file
				//
				//  MAXPATHLEN must be large enough to hold dd summary.


				// DEBUG
				sync_dprintf("[RSHD::start_session] INFO: Path is file\n");


				// Format dd summary
				buffer_length = love_snprintf(format_buffer,
					MAXPATHLEN,
					"%u+%u records in\n%u+%u records out\n",
					full_blocks,
					partial_blocks,
					full_blocks,
					partial_blocks);
				if (buffer_length < 0)
				{
					// Close standard error socket
					stderr_sock.close();


					// Close client socket
					client_sock.close();


					return -18;	// ERROR: Couldn't format dd summary buffer
				}
			}
			else
			{
				// NOTE: Path is directory
				//
				//  MAXPATHLEN must be large enough to hold dd error summary.


				// DEBUG
				sync_dprintf("[RSHD::start_session] INFO: Path is directory\n");


				// Format dd error summary
				buffer_length = love_snprintf(format_buffer,
					MAXPATHLEN,
					"UX:dd: ERROR: Read error: Is a directory\n0+0 records in\n0+0 records out\n");
				if (buffer_length < 0)
				{
					// Close standard error socket
					stderr_sock.close();


					// Close client socket
					client_sock.close();


					return -19;	// ERROR: Couldn't format dd error summary buffer
				}
			}


			// Write dd summary to standard error
			if (::send(stderr_sock.get_fd(),
				format_buffer,
				buffer_length,
				0) != buffer_length)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -19;	// ERROR: Couldn't write dd summary buffer
			}


			// Format echo filename with dd exit status
			buffer_length = love_snprintf(format_buffer,
				MAXPATHLEN + 10 + 2,
				"%s0\n",
				command.dd.echo.c_str());
			if (buffer_length < 0)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -20;	// ERROR: Couldn't format echo filename with dd exit status buffer
			}


			// Write echo filename with dd exit status to standard error
			if (::send(stderr_sock.get_fd(),
				format_buffer,
				buffer_length,
				0) != buffer_length)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -21;	// ERROR: Couldn't write echo filename with dd exit status buffer
			}


			break;

		case RSHD::COMMAND::LS:

			// DEBUG
			sync_dprintf("[RSHD::start_session] INFO: Execute ls \"%s\"\n",
				input.c_str());


			// NOTE: Write sequence
			//
			//  To serialize as much as possible the arrival of output from
			//  standard output (client_sock) and standard error (stderr_sock)
			//  on the client side, a fork()+execv() sequence with added shell
			//  execution is simulated using a usleep() invocation.


			// DEBUG
			sync_dprintf("[RSHD::start_session] INFO: Before RSHD::COMMAND::ls()\n");


			// Write ls output about requested target
			file_is_found = false;
			local_path.clear();
			ret = RSHD::COMMAND::ls(client_sock,
				&command,
				local_path);
			if (ret < 1)
			{
				// Check for file not found error
				if (ret != -7)
				{
					sync_printf("[RSHD::start_session] ERROR: RSHD::COMMAND::ls() = %i\n",
						ret);


					// Close standard error socket
					stderr_sock.close();


					// Close client socket
					client_sock.close();


					return -22;	// ERROR: Couldn't execute dd command
				}
			}
			else
			{
				file_is_found = true;
			}


			// DEBUG
			sync_dprintf("[RSHD::start_session] INFO: After RSHD::COMMAND::ls() = %i file_is_found = %s\n",
				ret,
				file_is_found == true ? "true" : "false");


			// Check for file
			if (file_is_found != true)
			{
				// NOTE: File was not found
				//
				//  This case only happens for ls options -inld and -inldL.
				//
				//  Return corresponding error through standard error socket.


				// DEBUG
				sync_dprintf("[RSHD::start_session] INFO: %s\n",
					command.ls.req_path.c_str());


				// Format ls error output
				buffer_length = love_snprintf(format_buffer,
					LS_ERROR_LEN + MAXPATHLEN + 10 + 2,
					"UX:ls: ERROR: Cannot access %s: No such file or directory\n",
					command.ls.req_path.c_str());
				if (buffer_length < 0)
				{
					// Close standard error socket
					stderr_sock.close();


					// Close client socket
					client_sock.close();


					return -25;	// ERROR: Couldn't format ls error output
				}


				// Write ls error output to standard error
				if (::send(stderr_sock.get_fd(),
					format_buffer,
					buffer_length,
					0) != buffer_length)
				{
					// Close standard error socket
					stderr_sock.close();


					// Close client socket
					client_sock.close();


					return -26;	// ERROR: Couldn't write ls error output to standard error
				}
			}


			// Subshell runtime
			love_sleep(50);


			// Format echo filename
			buffer_length = ::love_snprintf(format_buffer,
				MAXPATHLEN + 10 + 2,
				"%s\n",
				command.ls.echo.c_str());
			if (buffer_length < 0)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -23;	// ERROR: Couldn't format echo filename buffer
			}


			// Write echo filename to standard output
			if (::send(client_sock.get_fd(),
				format_buffer,
				buffer_length,
				0) != buffer_length)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -24;	// ERROR: Couldn't write echo filename buffer
			}


			// Format echo filename with ls exit status
			buffer_length = love_snprintf(format_buffer,
				MAXPATHLEN + 10 + 2,
				"%s%u\n",
				command.ls.echo.c_str(),
				file_is_found == true ? 0 : 2);
			if (buffer_length < 0)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -25;	// ERROR: Couldn't format echo filename with dd exit status buffer
			}


			// Write echo filename with ls exit status to standard error
			if (::send(stderr_sock.get_fd(),
				format_buffer,
				buffer_length,
				0) != buffer_length)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -26;	// ERROR: Couldn't write echo filename with dd exit status buffer
			}


			break;

		case RSHD::COMMAND::ECHO:

			// DEBUG
			sync_dprintf("[RSHD::start_session] INFO: Execute echo \"%s\"\n",
				input.c_str());


			// NOTE: echo command
			//
			//  The echo command has two subtypes:
			//
			//   1. echo with pipe to dd command
			//   2. echo with text "flush"
			//
			//  Both subtypes are implemented directly, because of their
			//  simplicity.


			// Format echo text
			buffer_length = love_snprintf(format_buffer,
				MAXPATHLEN + 10 + 2,
				"%s\n",
				command.echo.text.c_str());
			if (buffer_length < 0)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -27;	// ERROR: Couldn't format echo text
			}


			// Write echo text to standard output
			if (::send(client_sock.get_fd(),
				format_buffer,
				buffer_length,
				0) != buffer_length)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -28;	// ERROR: Couldn't write echo text buffer
			}


			// Synchronization delay
			love_sleep(10);


			// Check for pipe to dd
			if (command.subtype != RSHD::COMMAND::FLUSH)
			{
				// Format dd summary
				format_buffer[0] = '\0';
				buffer_length = 31;
				bcopy((void*)"0+1 records in\n0+1 records out\n",
					(void*)format_buffer,
					buffer_length);


				// Write dd summary to standard error
				if (::send(stderr_sock.get_fd(),
					format_buffer,
					buffer_length,
					0) != buffer_length)
				{
					// Close standard error socket
					stderr_sock.close();


					// Close client socket
					client_sock.close();


					return -30;	// ERROR: Couldn't write dd summary buffer
				}
			}


			// Synchronization delay
			love_sleep(10);


			// Format echo filename
			buffer_length = love_snprintf(format_buffer,
				MAXPATHLEN + 10 + 2,
				"%s\n",
				command.echo.echo.c_str());
			if (buffer_length < 0)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -31;	// ERROR: Couldn't format echo filename buffer
			}


			// Write echo filename to standard output
			if (::send(client_sock.get_fd(),
				format_buffer,
				buffer_length,
				0) != buffer_length)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -32;	// ERROR: Couldn't write echo filename buffer
			}


			// Synchronization delay
			love_sleep(10);


			// Format echo filename with exit status
			buffer_length = love_snprintf(format_buffer,
				MAXPATHLEN + 10 + 2,
				"%s0\n",
				command.echo.echo.c_str());
			if (buffer_length < 0)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -33;	// ERROR: Couldn't format echo filename with exit status buffer
			}


			// Write echo filename with exit status to standard error
			if (::send(stderr_sock.get_fd(),
				format_buffer,
				buffer_length,
				0) != buffer_length)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -34;	// ERROR: Couldn't write echo filename with exit status buffer
			}


			break;

		case RSHD::COMMAND::TRAP:

			// DEBUG
			sync_dprintf("[RSHD::start_session] INFO: Execute trap \"%s\"\n",
				input.c_str());


			// Format echo filename
			buffer_length = love_snprintf(format_buffer,
				MAXPATHLEN + 10 + 2,
				"%s\n",
				command.trap.echo.c_str());
			if (buffer_length < 0)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -35;	// ERROR: Couldn't format echo filename buffer
			}


			// Write echo filename to standard output
			if (::send(client_sock.get_fd(),
				format_buffer,
				buffer_length,
				0) != buffer_length)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -36;	// ERROR: Couldn't write echo filename buffer
			}


			// Synchronization delay
			love_sleep(10);


			// Format echo filename with dd exit status
			buffer_length = love_snprintf(format_buffer,
				MAXPATHLEN + 10 + 2,
				"%s0\n",
				command.trap.echo.c_str());
			if (buffer_length < 0)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -37;	// ERROR: Couldn't format echo filename with dd exit status buffer
			}


			// Write echo filename with dd exit status to standard error
			if (::send(stderr_sock.get_fd(),
				format_buffer,
				buffer_length,
				0) != buffer_length)
			{
				// Close standard error socket
				stderr_sock.close();


				// Close client socket
				client_sock.close();


				return -38;	// ERROR: Couldn't write echo filename with dd exit status buffer
			}


			break;

		default:

			// NOTE: Never reached


			break;
		}
	}


	return 1;	// SUCCESS
}


void* RSHD_start_session(void* arg)	// - IN: Thread argument
{
	RSHD* rshd;
	Thread* thread_id;
	Socket* client_sock;
	struct thread_args_s* thread_args;


	// IN: Check for thread argument
	if (arg == NULL)
	{
		return (void*)0;	// ERROR: No thread argument
	}


	// DEBUG
	sync_dprintf("[RSHD_start_session] START\n");


	// Get thread argument
	thread_args = (struct thread_args_s*)arg;


	// Get thread ID
	thread_id = thread_args->thread_id;


	// Check for thread ID
	if (thread_id == NULL)
	{
		// Free thread arguments
		delete (struct thread_args_s*)arg;
		arg = NULL;


		return (void*)-1;	// ERROR: No thread ID
	}


	// Get client socket
	client_sock = thread_args->client_sock;


	// Check for client socket
	if (client_sock == NULL)
	{
		// Free thread ID
		delete thread_id;
		thread_id = NULL;


		// Free thread arguments
		delete (struct thread_args_s*)arg;
		arg = NULL;


		return (void*)-2;	// ERROR: No client socket
	}


	// Get object
	rshd = (RSHD*)thread_args->object;


	// Check for object
	if (rshd == NULL)
	{
		// NOTE: Allocation of pthread_t
		//
		//  This data member, thread_args->thread_id, is
		//  allocated in RSHD::loop() and freed here.


		// Close client socket
		client_sock->close();


		// Delete client socket
		delete client_sock;
		client_sock = NULL;


		// Free thread ID
		delete thread_id;
		thread_id = NULL;


		// Free thread arguments
		delete (struct thread_args_s*)arg;
		arg = NULL;


		return (void*)-3;	// ERROR: No object
	}


	// NOTE: Client socket
	//
	//  Client socket is closed in RSHD::start_session().


	// Create new RSHD client session
	if (rshd->start_session(*client_sock,
		*thread_args->server_sock) < 1)
	{
		// NOTE: Allocation of pthread_t
		//
		//  This data member, thread_args->thread_id, is
		//  allocated in RSHD::loop() and freed here.


		// Close client socket
		client_sock->close();


		// Delete client socket
		delete client_sock;
		client_sock = NULL;


		// Free thread ID
		delete thread_id;
		thread_id = NULL;


		// Free thread arguments
		delete (struct thread_args_s*)arg;
		arg = NULL;


		return (void*)-4;	// ERROR: Couldn't create new RSHD client session
	}


	// NOTE: Client socket
	//
	//  Client socket is closed in RSHD::start_session().


	// Delete client socket
	delete client_sock;
	client_sock = NULL;


	// NOTE: Allocation of pthread_t
	//
	//  This data member, thread_args->thread_id, is
	//  allocated in RSHD::loop() and freed here.


	// Free thread ID
	delete thread_id;
	thread_id = NULL;


	// Free thread arguments
	delete (struct thread_args_s*)arg;
	arg = NULL;


	// DEBUG
	sync_dprintf("[RSHD_start_session] STOP\n");


	return NULL;
}


int RSHD::parse(std::string& command_string,	// - IN: Command string
	std::string& cached_path,	// - IN: Cached path
	struct rsh* command)		// - OUT: Parsed command
{
	unsigned int label_type;
	bool is_valid;
	std::size_t pipe_pos;
	std::size_t echo_length;
	std::size_t filename_pos;
	std::string label;
	std::string path;
	std::string second_word;
	std::string command_string_1;
	std::string irix_path;
	std::string local_path;
	std::string label_path;
	std::string path_string;
	std::string* long_status;
	std::stringstream sstream;
	std::vector<std::string> command_words;
	std::vector<std::string>::iterator it;


	// OUT: Check for parsed command
	if (command == NULL)
	{
		return -1;	// ERROR: No parsed command
	}


	// Check for empty command string
	if (command_string.empty() == true)
	{
		return -2;	// ERROR: Empty command string
	}


	// NOTE: Remote shell commands
	//
	//  The remote shell spawned by inst in the miniroot installation
	//  requires the following programs to be run:
	//
	//   dd: with arguments if=/path/to/file and bs=512
	//   ls: with arguments -inldL /path/to/file
	//   echo: with one argument
	//   trap: with arguments '' and 2
	//   
	//  Besides these command binaries, the following shell idioms must
	//  be supported:
	//
	//   Subshell invokation: ( ... )
	//   Standard output to standard error redirection: 1>&2
	//   Variable assignment: $status = $?
	//   Special variables: $? (exit status of last command)


	// Split command string into command words
	if (this->split(command_string,
		' ',
		command_words) < 1)
	{
		return -3;	// ERROR: Couldn't split command string into command words
	}


	// Check for command words
	if (command_words.size() == 0)
	{
		return -4;	// ERROR: No command words
	}


	// Set command name
	command->name = command_words.at(0);


	sync_printf("[RSHD::parse] INFO: Command name \"%s\"\n",
		command->name.c_str());


	// Check for debug mode
	if (args_debug == true)
	{
		// DEBUG: Print words
		for (it = command_words.begin();
			it < command_words.end();
			it++)
		{
			// DEBUG
			sync_dprintf("[RSHD::parse] WORD: \"%s\"\n",
				(*it).c_str());
		}
	}


	// Get command type
	if (command->name.compare("dd") == 0)
	{
		command->type = RSHD::COMMAND::DD;
	}
	else if (command->name.compare("ls") == 0)
	{
		command->type = RSHD::COMMAND::LS;
		command->subtype = RSHD::COMMAND::NONE;
	}
	else if (command->name.compare("/bin/ls") == 0)
	{
		command->type = RSHD::COMMAND::LS;
		command->subtype = RSHD::COMMAND::LS;
	}
	else if (command->name.compare("echo") == 0)
	{
		command->type = RSHD::COMMAND::ECHO;
	}
	else if (command->name.compare("trap") == 0)
	{
		command->type = RSHD::COMMAND::TRAP;
	}
	else
	{
		// NOTE: Unsupported command


		sync_printf("[RSHD::parse] ERROR: Unsupported command \"%s\"\n",
			command->name.c_str());


		return -5;	// ERROR: Unsupported command
	}


	// Switch out by command type
	switch (command->type)
	{
	case RSHD::COMMAND::DD:

		// DEBUG
		sync_dprintf("[RSHD::parse] INFO: RSHD::COMMAND::DD\n");


		// Initialize fgrep flag
		command->dd.has_fgrep = false;


		// NOTE: dd
		//
		//  An example dd command invocation from rsh:
		//
		//   1. dd if=/mnt/IRIX/53/dist/4Dwm bs=512 ; \
			//      ( status=$? ; trap '' 2 ; echo 'InstProc1005IsDone' ; \
			//      echo 'InstProc1005IsDone'$status 1>&2 )\n
			//   2. dd if=/mnt/IRIX/53/dist/4Dwm bs=512 iseek=808 ; \
			//      ( status=$? ; trap '' 2 ; echo 'InstProc1005IsDone' ; \
			//      echo 'InstProc1005IsDone'$status 1>&2 )\n
			//
			//   For IRIX 6.5.X, additionally:
			//
			//    3. dd if=love.65.found1/x_eoe.idb bs=512 | fgrep ' mach(' ;
			//       ( status=$? ; trap '' 2 ; echo 'o?_InstProc402IsDone\c' ;
			//       echo 'o?_InstProc402IsDone'$status'\c' 1>&2 )


			// Check for invocation 1.
		if (command_words.size() == 18)
		{
			// NOTE: Invocation 1.


			// Check for expected dd command line format
			if ((command_words.at(1).substr(0, 3).compare("if=") != 0) ||
				(command_words.at(2).compare("bs=512") != 0) ||
				(command_words.at(3).compare(";") != 0) ||
				(command_words.at(4).compare("(") != 0) ||
				(command_words.at(5).compare("status=$?") != 0) ||
				(command_words.at(6).compare(";") != 0) ||
				(command_words.at(7).compare("trap") != 0) ||
				(command_words.at(8).compare("''") != 0) ||
				(command_words.at(9).compare("2") != 0) ||
				(command_words.at(10).compare(";") != 0) ||
				(command_words.at(11).compare("echo") != 0) ||
				(command_words.at(12).find("InstProc") == std::string::npos) ||
				(command_words.at(13).compare(";") != 0) ||
				(command_words.at(14).compare("echo") != 0) ||
				(command_words.at(15).find("InstProc") == std::string::npos) ||
				(command_words.at(16).compare("1>&2") != 0) ||
				(command_words.at(17).compare(")\n") != 0))
			{
				sync_printf("[RSHD::parse] ERROR: Unexpected dd command line format\n");


				return -7;	// ERROR: Unexpected dd command line format
			}


			// Set echo filename word position
			filename_pos = 12;


			// Set iseek offset
			command->dd.iseek = 0;


			// Get long status
			long_status = &command_words.at(15);
		}
		else if (command_words.size() == 19)
		{
			// NOTE: Invocation 2.


			// Check for expected dd command line format
			if ((command_words.at(1).substr(0, 3).compare("if=") != 0) ||
				(command_words.at(2).compare("bs=512") != 0) ||
				(command_words.at(3).substr(0, 6).compare("iseek=") != 0) ||
				(command_words.at(4).compare(";") != 0) ||
				(command_words.at(5).compare("(") != 0) ||
				(command_words.at(6).compare("status=$?") != 0) ||
				(command_words.at(7).compare(";") != 0) ||
				(command_words.at(8).compare("trap") != 0) ||
				(command_words.at(9).compare("''") != 0) ||
				(command_words.at(10).compare("2") != 0) ||
				(command_words.at(11).compare(";") != 0) ||
				(command_words.at(12).compare("echo") != 0) ||
				(command_words.at(13).find("InstProc") == std::string::npos) ||
				(command_words.at(14).compare(";") != 0) ||
				(command_words.at(15).compare("echo") != 0) ||
				(command_words.at(16).find("InstProc") == std::string::npos) ||
				(command_words.at(17).compare("1>&2") != 0) ||
				(command_words.at(18).compare(")\n") != 0))
			{
				sync_printf("[RSHD::parse] ERROR: Unexpected dd command line format\n");


				return -7;	// ERROR: Unexpected dd command line format
			}


			// Set echo filename word position
			filename_pos = 13;


			// Get iseek offset
			sstream << command_words.at(3).substr(6);
			sstream >> command->dd.iseek;


			// Get long status
			long_status = &command_words.at(16);
		}
		else if (command_words.size() == 22)
		{
			// NOTE: Invocation 3.


			// Check for expected dd command line format
			if ((command_words.at(1).substr(0, 3).compare("if=") != 0) ||
				(command_words.at(2).compare("bs=512") != 0) ||
				(command_words.at(3).compare("|") != 0) ||
				(command_words.at(4).compare("fgrep") != 0) ||
				(command_words.at(5).compare("'") != 0) ||
				(command_words.at(6).compare("mach('") != 0) ||
				(command_words.at(7).compare(";") != 0) ||
				(command_words.at(8).compare("(") != 0) ||
				(command_words.at(9).compare("status=$?") != 0) ||
				(command_words.at(10).compare(";") != 0) ||
				(command_words.at(11).compare("trap") != 0) ||
				(command_words.at(12).compare("''") != 0) ||
				(command_words.at(13).compare("2") != 0) ||
				(command_words.at(14).compare(";") != 0) ||
				(command_words.at(15).compare("echo") != 0) ||
				(command_words.at(16).find("InstProc") == std::string::npos) ||
				(command_words.at(17).compare(";") != 0) ||
				(command_words.at(18).compare("echo") != 0) ||
				(command_words.at(19).find("InstProc") == std::string::npos) ||
				(command_words.at(20).compare("1>&2") != 0) ||
				(command_words.at(21).compare(")\n") != 0))
			{
				sync_printf("[RSHD::parse] ERROR: Unexpected dd command line format\n");


				return -7;	// ERROR: Unexpected dd command line format
			}


			// Set echo filename word position
			filename_pos = 16;


			// Get long status
			long_status = &command_words.at(19);


			// Set fgrep flag
			command->dd.has_fgrep = true;
		}
		else
		{
			sync_printf("[RSHD::parse] ERROR: Unexpected dd command line word length\n");


			return -6;	// ERROR: Unexpected dd command line word length
		}


		// Get if= parameter
		path_string = command_words.at(1).substr(3);


		// DEBUG
		sync_dprintf("[RSHD::parse] INFO_IRIX: if filename = \"%s\"\n",
			path_string.c_str());


		// NOTE: Label
		//
		//  The label is sent by the client in the if= argument to dd.
		//
		//  For example:
		//
		//   dd if=love.indigo2.32 ...
		//
		//  The label in the above example is "love.indigo2.32".
		//
		//  This label has to be translated to the corresponding pathname
		//  as configured in the labels file.


		// Check for label
		if (path_string.substr(0,
			4).compare("love") != 0)
		{
			// NOTE: Label not found


			sync_printf("[RSHD::parse] ERROR: No label found in dd if= parameter\n");


			return -8;	// ERROR: Unexpected echo filename format
		}


		// DEBUG
		sync_dprintf("[RSHD::parse] INFO: Lookup label \"%s\"\n",
			path_string.c_str());


		// Get label without path components
		if (LABEL_FILE::get_label_prefix(path_string,
			label,
			path) < 1)
		{
			sync_printf("[RSHD::parse] ERROR: Couldn't find prefixed label \"%s\"\n",
				path_string.c_str());


			return -11;	// ERROR: Couldn't find prefixed label
		}


		// DEBUG
		sync_dprintf("[RSHD::parse] LABEL: \"%s\"\n",
			label.c_str());
		sync_dprintf("[RSHD::parse] PATH: \"%s\"\n",
			path.c_str());


		// Check for cached label path
		if (cached_path.length() > 0)
		{
			// DEBUG
			sync_dprintf("[RSHD::parse] CACHED: Path \"%s\"\n",
				cached_path.c_str());


			// Rebuild final path
			label_path = cached_path;
		}
		else
		{
			// Lookup label
			label_path.clear();
			label_type = LABEL_FILE::LINE::TYPE_NONE;
			if (labels.lookup_label(label,
				true,
				labels_path,
				label_path,
				label_type) < 1)
			{
				// NOTE: Label not found


				sync_printf("[RSHD::parse] ERROR: Couldn't find label \"%s\"\n",
					label.c_str());


				return -11;	// ERROR: Couldn't find label
			}


			// DEBUG
			sync_dprintf("[RSHD::parse] LOOKUP: Path \"%s\"\n",
				label_path.c_str());


			// OUT: Cache path
			cached_path = label_path;
		}


		// Set if= parameter
		if (command->dd.if_filename.set(label_path) < 1)
		{
			sync_printf("[RSHD::parse] ERROR: Couldn't set path for if parameter\n");


			return -7;	// ERROR: Couldn't set path for if parameter
		}


		// Check for leading '/'
		if (path.at(0) == '/')
		{
			// Delete leading '/'
			path.erase(path.begin());
		}


		// Add path component
		if (command->dd.if_filename.add_component(path) < 1)
		{
			sync_printf("[RSHD::parse] ERROR: Couldn't add path component to if path\n");


			return -8;	// ERROR: Couldn't add path component to if path
		}


		// Get IRIX path for if parameter
		irix_path.clear();
		if (command->dd.if_filename.get_irix(irix_path) < 1)
		{
			sync_printf("[RSHD::parse] ERROR: Couldn't get IRIX path for if parameter\n");


			return -9;	// ERROR: Couldn't get IRIX path for if parameter
		}


		// DEBUG
		sync_dprintf("[RSHD::parse] PATH: Final path \"%s\"\n",
			irix_path.c_str());


		// Get local path for if parameter
		local_path.clear();
		if (command->dd.if_filename.get_local(local_path) < 1)
		{
			sync_printf("[RSHD::parse] ERROR: Couldn't get local path for if parameter\n");


			return -8;	// ERROR: Couldn't get local path for if parameter
		}


		// DEBUG
		sync_dprintf("[RSHD::parse] INFO_IRIX: command->dd.if_filename = \"%s\"\n",
			irix_path.c_str());
		sync_dprintf("[RSHD::parse] INFO_LOCAL: command->dd.if_filename = \"%s\"\n",
			local_path.c_str());


		// Get echo filename string
		command->dd.echo = command_words.at(filename_pos).substr(1);


		// Get length of echo filename string
		echo_length = command->dd.echo.length();


		// Check for trailing '
		if (command->dd.echo.at(echo_length - 1) != '\'')
		{
			sync_printf("[RSHD::parse] ERROR: Unexpected echo filename format\n");


			return -8;	// ERROR: Unexpected echo filename format
		}


		// Delete trailing '
		command->dd.echo.erase(echo_length - 1,
			1);


		// Process status suffix
		RSHD::process_status_suffix(command->dd.echo,
			long_status);


		// DEBUG
		sync_dprintf("[RSHD::parse] INFO: command->dd.echo = \"%s\" has_fgrep = %s\n",
			command->dd.echo.c_str(),
			command->dd.has_fgrep == true ? "true" : "false");


		break;

	case RSHD::COMMAND::LS:

		// DEBUG
		sync_dprintf("[RSHD::parse] INFO: RSHD::COMMAND::LS\n");


		// NOTE: ls
		//
		//  Example ls command invocations from rsh:
		//
		//   1. ls -inld . ; ( status=$? ; trap '' 2 ; echo 'InstProc1005IsDone' ;
		//      echo 'InstProc1005IsDone'$status 1>&2 )
		//   2. ls -inldL /mnt/IRIX/53/dist/ ; ( status=$? ; trap '' 2 ;
		//      echo 'InstProc1005IsDone' ; echo 'InstProc1005IsDone'$status 1>&2 )
		//   3. /bin/ls -a /mnt/IRIX/53/dist/ ; ( status=$? ; trap '' 2 ;
		//      echo 'InstProc1005IsDone' ; echo 'InstProc1005IsDone'$status 1>&2 )
		//   4. /bin/ls -a label/path ; ( status=$? ; trap '' 2 ;
		//      echo 'InstProc1005IsDone' ; echo 'InstProc1005IsDone'$status 1>&2 )


		// NOTE: ls command length
		//
		//  In all 4 cases the number of words in the command line is 18.


		// Check for expected ls command line word length
		if (command_words.size() != 18)
		{
			sync_printf("[RSHD::parse] ERROR: Unexpected ls command line word length\n");


			return -9;	// ERROR: Unexpected ls command line word length
		}


		// Check subtype
		is_valid = false;
		command->ls.has_L = false;
		command->ls.has_a = false;
		if (command->subtype == RSHD::COMMAND::NONE)
		{
			if (command_words.at(1).compare("-inld") == 0)
			{
				is_valid = true;
			}
			else if (command_words.at(1).compare("-inldL") == 0)
			{
				// Set has L flag
				command->ls.has_L = true;


				is_valid = true;
			}
		}
		else
		{
			if (command_words.at(1).compare("-a") == 0)
			{
				// Set has a flag
				command->ls.has_a = true;


				is_valid = true;
			}
		}


		// Check for valid ls command
		if (is_valid != true)
		{
			sync_printf("[RSHD::parse] ERROR: Invalid ls command\n");


			return -10;	// ERROR: Invalid ls command
		}


		// Save requested path
		command->ls.req_path = command_words.at(2);


		// NOTE: Label
		//
		//  When invoked using a label, the label is sent by the client
		//  as the 3rd argument.
		//
		//  For example:
		//
		//   ls -inld love.65.found1/.redirect ...
		//
		//  The label in the above example is "love.65.found1".
		//
		//  This label has to be translated to the corresponding pathname
		//  from the labels file.


		// Check for label
		if (command_words.at(2).substr(0, 4).compare("love") == 0)
		{
			// NOTE: Found label


			// DEBUG
			sync_dprintf("[RSHD::parse] INFO: Lookup label \"%s\"\n",
				command_words.at(2).c_str());


			// Get label without path components
			if (LABEL_FILE::get_label_prefix(command_words.at(2),
				label,
				path) < 1)
			{
				sync_printf("[RSHD::parse] ERROR: Couldn't find prefixed label \"%s\"\n",
					command_words.at(2).c_str());


				return -11;	// ERROR: Couldn't find prefixed label
			}


			// DEBUG
			sync_dprintf("[RSHD::parse] LABEL: \"%s\"\n",
				label.c_str());
			sync_dprintf("[RSHD::parse] PATH: \"%s\"\n",
				path.c_str());


			// Check for cached label path
			if (cached_path.length() > 0)
			{
				// DEBUG
				sync_dprintf("[RSHD::parse] CACHED: Path \"%s\"\n",
					cached_path.c_str());


				// Rebuild final path
				label_path = cached_path;
			}
			else
			{
				// Lookup label
				label_path.clear();
				label_type = LABEL_FILE::LINE::TYPE_NONE;
				if (labels.lookup_label(label,
					true,
					labels_path,
					label_path,
					label_type) < 1)
				{
					// NOTE: Label not found


					sync_printf("[RSHD::parse] ERROR: Couldn't find label \"%s\"\n",
						label.c_str());


					return -11;	// ERROR: Couldn't find label
				}


				// DEBUG
				sync_dprintf("[RSHD::parse] LOOKUP: Path \"%s\"\n",
					label_path.c_str());
			}


			// Set ls target
			if (command->ls.target.set(label_path) < 1)
			{
				sync_printf("[RSHD::parse] ERROR: Couldn't set path for ls target\n");


				return -7;	// ERROR: Couldn't set path for ls target
			}


			// NOTE: Path components
			//
			//  The requested paths sent by the client can be empty, like
			//  for example:
			//
			//   love.XYZ
			//   love.XYZ/
			//
			//  Only non-empty path components can be added to local paths.


			// Check for non-empty path component
			if (path.length() > 1)
			{
				// Check for leading '/'
				if (path.at(0) == '/')
				{
					// Delete leading '/'
					path.erase(path.begin());
				}


				// Add path component
				if (command->ls.target.add_component(path) < 1)
				{
					sync_printf("[RSHD::parse] ERROR: Couldn't add path component to ls path\n");


					return -8;	// ERROR: Couldn't add path component to ls path
				}
			}


			// Get IRIX path for ls target
			irix_path.clear();
			if (command->ls.target.get_irix(irix_path) < 1)
			{
				sync_printf("[RSHD::parse] ERROR: Couldn't get IRIX path for ls target\n");


				return -9;	// ERROR: Couldn't get IRIX path for ls target
			}


			// DEBUG
			sync_dprintf("[RSHD::parse] PATH: Final path \"%s\"\n",
				irix_path.c_str());


			// Get local path for if parameter
			local_path.clear();
			if (command->ls.target.get_local(local_path) < 1)
			{
				sync_printf("[RSHD::parse] ERROR: Couldn't get local path for ls target\n");


				return -8;	// ERROR: Couldn't get local path for ls target
			}


			// DEBUG
			sync_dprintf("[RSHD::parse] INFO_IRIX: command->ls.target = \"%s\"\n",
				irix_path.c_str());
			sync_dprintf("[RSHD::parse] INFO_LOCAL: command->ls.target = \"%s\"\n",
				local_path.c_str());


			// Substitute ls argument
			command_words[2] = irix_path;
		}
		else
		{
			// NOTE: Standard IRIX path


			// Set IRIX path
			irix_path = command_words[2];


			// Check for special '.' (dot) path
			if (irix_path.compare(".") == 0)
			{
				// DEBUG
				sync_dprintf("[RSHD::parse] DOT\n");


				// Set ls dot subtype
				command->subtype = RSHD::COMMAND::LS_DOT;
			}
		}


		// Check for expected ls command line format
		if ((command_words.at(3).compare(";") != 0) ||
			(command_words.at(4).compare("(") != 0) ||
			(command_words.at(5).compare("status=$?") != 0) ||
			(command_words.at(6).compare(";") != 0) ||
			(command_words.at(7).compare("trap") != 0) ||
			(command_words.at(8).compare("''") != 0) ||
			(command_words.at(9).compare("2") != 0) ||
			(command_words.at(10).compare(";") != 0) ||
			(command_words.at(11).compare("echo") != 0) ||
			(command_words.at(12).find("InstProc") == std::string::npos) ||
			(command_words.at(13).compare(";") != 0) ||
			(command_words.at(14).compare("echo") != 0) ||
			(command_words.at(15).find("InstProc") == std::string::npos) ||
			(command_words.at(16).compare("1>&2") != 0) ||
			(command_words.at(17).compare(")\n") != 0))
		{
			sync_printf("[RSHD::parse] ERROR: Unexpected ls command line format\n");


			return -11;	// ERROR: Unexpected ls command line format
		}


		// DEBUG
		sync_dprintf("[RSHD::parse] INFO: command->ls.target = \"%s\"\n",
			irix_path.c_str());


		// Get echo filename string
		command->ls.echo = command_words.at(12).substr(1);


		// Get length of echo filename string
		echo_length = command->ls.echo.length();


		// Check for trailing '
		if (command->ls.echo.at(echo_length - 1) != '\'')
		{
			sync_printf("[RSHD::parse] ERROR: Unexpected echo filename format\n");


			return -12;	// ERROR: Unexpected echo filename format
		}


		// Delete trailing '
		command->ls.echo.erase(echo_length - 1,
			1);


		// Process status suffix
		RSHD::process_status_suffix(command->ls.echo,
			&command_words.at(15));


		// DEBUG
		sync_dprintf("[RSHD::parse] INFO: command->ls.echo = \"%s\"\n",
			command->ls.echo.c_str());


		break;

	case RSHD::COMMAND::ECHO:

		// DEBUG
		sync_dprintf("[RSHD::parse] INFO: RSHD::COMMAND::ECHO\n");


		// NOTE: echo
		//
		//  Example echo command invocations from rsh:
		//
		//   1. echo abc|dd iseek=0 ; ( status=$? ; trap '' 2 ; echo 'InstProc1005IsDone' ;
		//      echo 'InstProc1005IsDone'$status 1>&2 )
		//   2. echo flush ; ( status=$? ; trap '' 2 ; echo 'InstKill964IsDone' ; echo
		//      'InstKill964IsDone'$status 1>&2 )


		// Check for first invocation type
		if (command_words.size() == 18)
		{
			// NOTE: Invocation 1.


			// Check for expected echo command line format
			if ((command_words.at(2).compare("iseek=0") != 0) ||
				(command_words.at(3).compare(";") != 0) ||
				(command_words.at(4).compare("(") != 0) ||
				(command_words.at(5).compare("status=$?") != 0) ||
				(command_words.at(6).compare(";") != 0) ||
				(command_words.at(7).compare("trap") != 0) ||
				(command_words.at(8).compare("''") != 0) ||
				(command_words.at(9).compare("2") != 0) ||
				(command_words.at(10).compare(";") != 0) ||
				(command_words.at(11).compare("echo") != 0) ||
				(command_words.at(12).find("InstProc") == std::string::npos) ||
				(command_words.at(13).compare(";") != 0) ||
				(command_words.at(14).compare("echo") != 0) ||
				(command_words.at(15).find("InstProc") == std::string::npos) ||
				(command_words.at(16).compare("1>&2") != 0) ||
				(command_words.at(17).compare(")\n") != 0))
			{
				sync_printf("[RSHD::parse] ERROR: Unexpected echo command line format\n");


				return -11;	// ERROR: Unexpected echo command line format
			}


			// Get second word
			second_word = command_words.at(1);


			// Find first occurence of '|'
			pipe_pos = second_word.find('|');
			if (pipe_pos == std::string::npos)
			{
				sync_printf("[RSHD::parse] ERROR: Couldn't find first occurence of '|'\n");


				return -12;	// ERROR: Couldn't find first occurence of '|'
			}


			// Get echo text
			command->echo.text = second_word.substr(0,
				pipe_pos);


			// DEBUG
			sync_dprintf("[RSHD::parse] INFO: command->echo.text = \"%s\"\n",
				command->echo.text.c_str());


			// Get second part of second word
			second_word = second_word.substr(pipe_pos);


			// Check for "|dd" substring
			if (second_word.compare("|dd") != 0)
			{
				sync_printf("[RSHD::parse] ERROR: Couldn't find \"|dd\" substring\n");


				return -12;	// ERROR: Couldn't find "|dd" substring
			}


			// Get echo filename string
			command->echo.echo = command_words.at(12).substr(1);


			// Get long status
			long_status = &command_words.at(15);
		}
		else if (command_words.size() == 17)
		{
			// NOTE: Invocation 2.


			// Check for expected echo command line format
			if ((command_words.at(2).compare(";") != 0) ||
				(command_words.at(3).compare("(") != 0) ||
				(command_words.at(4).compare("status=$?") != 0) ||
				(command_words.at(5).compare(";") != 0) ||
				(command_words.at(6).compare("trap") != 0) ||
				(command_words.at(7).compare("''") != 0) ||
				(command_words.at(8).compare("2") != 0) ||
				(command_words.at(9).compare(";") != 0) ||
				(command_words.at(10).compare("echo") != 0) ||
				(command_words.at(11).find("InstKill") == std::string::npos) ||
				(command_words.at(12).compare(";") != 0) ||
				(command_words.at(13).compare("echo") != 0) ||
				(command_words.at(14).find("InstKill") == std::string::npos) ||
				(command_words.at(15).compare("1>&2") != 0) ||
				(command_words.at(16).compare(")\n") != 0))
			{
				sync_printf("[RSHD::parse] ERROR: Unexpected echo command line format\n");


				return -11;	// ERROR: Unexpected echo command line format
			}


			// Get echo text
			command->echo.text = command_words.at(1);


			// Get echo filename string
			command->echo.echo = command_words.at(11).substr(1);


			// Set command subtype
			command->subtype = RSHD::COMMAND::FLUSH;


			// Get long status
			long_status = &command_words.at(14);
		}
		else
		{
			sync_printf("[RSHD::parse] ERROR: Unexpected echo command line word length\n");


			return -9;	// ERROR: Unexpected echo command line word length
		}


		// Get length of echo filename string
		echo_length = command->echo.echo.length();


		// Check for trailing '
		if (command->echo.echo.at(echo_length - 1) != '\'')
		{
			sync_printf("[RSHD::parse] ERROR: Unexpected echo filename format\n");


			return -12;	// ERROR: Unexpected echo filename format
		}


		// Delete trailing '
		command->echo.echo.erase(echo_length - 1,
			1);


		// Process status suffix
		RSHD::process_status_suffix(command->echo.echo,
			long_status);


		sync_printf("[RSHD::parse] INFO: command->echo.text = \"%s\"\n",
			command->echo.text.c_str());
		sync_printf("[RSHD::parse] INFO: command->echo.echo = \"%s\"\n",
			command->echo.echo.c_str());


		break;

	case RSHD::COMMAND::TRAP:

		// DEBUG
		sync_dprintf("[RSHD::parse] INFO: RSHD::COMMAND::TRAP\n");


		// NOTE: trap 
		//
		//  Example trap command invocations from rsh:
		//
		//   1. trap : 2 ; ( status=$? ; trap '' 2 ; echo 'InstProc1005IsDone' ;
		//	echo 'InstProc1005IsDone'$status 1>&2 )
		//   2. trap : 2 ; ( status=$? ; trap '' 2 ; echo 'o?_InstProc402IsDone\c' ;
		//	echo 'o?_InstProc402IsDone'$status'\c' 1>&2 )


		// Check for expected trap command line word length
		if (command_words.size() != 18)
		{
			sync_printf("[RSHD::parse] ERROR: Unexpected trap command line word length\n");


			return -9;	// ERROR: Unexpected trap command line word length
		}


		// Check for expected trap command line format
		if ((command_words.at(1).compare(":") != 0) ||
			(command_words.at(2).compare("2") != 0) ||
			(command_words.at(3).compare(";") != 0) ||
			(command_words.at(4).compare("(") != 0) ||
			(command_words.at(5).compare("status=$?") != 0) ||
			(command_words.at(6).compare(";") != 0) ||
			(command_words.at(7).compare("trap") != 0) ||
			(command_words.at(8).compare("''") != 0) ||
			(command_words.at(9).compare("2") != 0) ||
			(command_words.at(10).compare(";") != 0) ||
			(command_words.at(11).compare("echo") != 0) ||
			(command_words.at(12).find("InstProc") == std::string::npos) ||
			(command_words.at(13).compare(";") != 0) ||
			(command_words.at(14).compare("echo") != 0) ||
			(command_words.at(15).find("InstProc") == std::string::npos) ||
			(command_words.at(16).compare("1>&2") != 0) ||
			(command_words.at(17).compare(")\n") != 0))
		{
			sync_printf("[RSHD::parse] ERROR: Unexpected echo command line format\n");


			return -11;	// ERROR: Unexpected echo command line format
		}


		// Get echo filename string
		command->trap.echo = command_words.at(12).substr(1);


		// Get length of echo filename string
		echo_length = command->trap.echo.length();


		// Check for trailing '
		if (command->trap.echo.at(echo_length - 1) != '\'')
		{
			sync_printf("[RSHD::parse] ERROR: Unexpected echo filename format\n");


			return -12;	// ERROR: Unexpected echo filename format
		}


		// Delete trailing '
		command->trap.echo.erase(echo_length - 1,
			1);


		// Process status suffix
		RSHD::process_status_suffix(command->trap.echo,
			&command_words.at(15));


		sync_printf("[RSHD::parse] INFO: command->trap.echo = \"%s\"\n",
			command->trap.echo.c_str());


		break;

	default:

		// NOTE: Never reached
		//
		//  This condition is caught in the command
		//  string comparisons above.


		break;
	}


	return 1;	// SUCCESS
}


int RSHD::split(std::string& command_string,                    // - IN: Command string
	char delimiter,                                 // - IN: Word delimiter
	std::vector<std::string>& command_words)        // - OUT: Command words
{
	bool last_word;
	std::size_t pos;
	std::size_t space_pos_0;
	std::size_t space_pos_1;
	std::size_t word_length;


	// IN: Check for empty command string
	if (command_string.length() == 0)
	{
		return 0;       // ERROR: Empty command string
	}


	// IN: Check for word delimiter
	if (delimiter == '\0')
	{
		return -1;      // ERROR: No word delimiter
	}


	// Find first space character
	pos = 0;
	space_pos_1 = command_string.find_first_of(delimiter,
		pos);


	// Check for space character
	if (space_pos_1 == std::string::npos)
	{
		// NOTE: Single word


		// Get single word
		command_words.push_back(command_string);
	}
	else
	{
		// NOTE: Multiple words


		// Split string
		last_word = false;
		space_pos_0 = 0;
		while (loop_forever)
		{
			// Get word
			word_length = space_pos_1 - space_pos_0;
			command_words.push_back(command_string.substr(space_pos_0,
				word_length));


			// Check for last word
			if (last_word == true)
			{
				break;
			}


			// Update lower position
			space_pos_0 = space_pos_1 + 1;


			// Get position of next space character
			space_pos_1 = command_string.find_first_of(delimiter,
				space_pos_0);


			// Check for space character
			if (space_pos_1 == std::string::npos)
			{
				// NOTE: No more space characters


				// Check for trailing word
				if (space_pos_0 < command_string.length())
				{
					// Set end position to string length
					space_pos_1 = command_string.length();


					// Set flag for trailing word
					last_word = true;
				}
				else
				{
					// NOTE: No more words in command string


					break;
				}
			}
		}
	}


	return 1;       // SUCCESS
}


void* RSHD::loop(void* arg)
{
	unsigned int bytes_address;
	struct thread_args_s* thread_args;
	Thread* client_tid;
	Socket* client_sock;


#ifdef __GNUC__


	unsigned int onoff;


#endif	// __GNUC__


	// Create RSHD server socket
	Socket rshd_sock;
	if (rshd_sock.get_fd() == -1)
	{
		sync_printf("[RSHD::loop] ERROR: Couldn't create RSHD server socket\n");


		return (void*)0;	// ERROR: Couldn't create RSHD server socket
	}


	// Set reuse address socket option
	if (rshd_sock.set_reuseaddr(true) < 1)
	{
		sync_printf("[RSHD::loop] ERROR: Couldn't set resue address socket option\n");


		return (void*)-1;	// ERROR: Couldn't set resue address socket option
	}


#ifdef __GNUC__


	// Set don't fragment IP socket option
	onoff = IP_PMTUDISC_DONT;
	if (rshd_sock.setsockopt(IPPROTO_IP,
		IP_MTU_DISCOVER,
		(const void*)&onoff,
		sizeof(unsigned int)) < 1)
	{
		sync_printf("[RSHD::loop] ERROR: Couldn't set don't fragment IP socket option\n");


		return (void*)-2;	// ERROR: Couldn't set don't fragment IP socket option
	}


#endif	// __GNUC__


	// Bind to local port 514 (IPPORT_RSHD)
	bytes_address = local_hostaddr;
	if (rshd_sock.bind(bytes_address,
		IPPORT_RSHD) < 1)
	{
		sync_printf("[RSHD::loop] ERROR: Couldn't bind to local port 514\n");


		return (void*)-3;	// ERROR: Couldn't bind to local port 514
	}


	// Listen on local port 514 (IPPORT_RSHD)
	if (rshd_sock.listen(1000) == -1)
	{
		sync_printf("[RSHD::loop] ERROR: Couldn't listen on local port 514\n");


		return (void*)-4;	// ERROR: Couldn't listen on local port 514
	}


	// DEBUG
	sync_dprintf("[RSHD::loop] INFO: Start main loop\n");


	// Loop forever
	while (loop_forever)
	{
		// NOTE: Thread arguments
		//
		//  For POSIX threads compatible thread interfaces, a newly created
		//  thread is passed a user defined pointer as argument.
		//
		//  A new thread arguments structure, defined by struct thread_args_s,
		//  is allocated on each thread creation. This structure is taken care
		//  of in the invoked function (the one that is passed the user defined
		//  pointer as argument).


		// Allocate new thread arguments
		thread_args = NULL;
		thread_args = new thread_args_s;
		if (thread_args == NULL)
		{
			sync_printf("[RSHD::loop] ERROR: Couldn't allocate thread arguments\n");


			return (void*)-5;	// ERROR: Couldn't allocate thread arguments
		}


		// NOTE: Allocation of pthread_t
		//
		//  The object is freed in the free function
		//  RSHD_start_session().


		// Create thread ID for client
		client_tid = new Thread;
		if (client_tid == NULL)
		{
			sync_printf("[RSHD::loop] ERROR: Couldn't allocate thread ID for client\n");


			// Free thread arguments
			delete thread_args;
			thread_args = NULL;


			return (void*)-6;	// ERROR: Couldn't allocate thread ID for client
		}


		// NOTE: Client socket
		//
		//  Client socket is allocated here and freed in session thread
		//  spawned below.


		// Create new client socket
		client_sock = new Socket;
		if (client_sock == NULL)
		{
			sync_printf("[RSHD::loop] ERROR: Couldn't allocate client socket\n");


			// Free thread ID for client
			delete client_tid;
			client_tid = NULL;


			// Free thread arguments
			delete thread_args;
			thread_args = NULL;


			return (void*)-7;	// ERROR: Couldn't allocate client socket
		}


		// Accept new client
		if (rshd_sock.accept(*client_sock) < 1)
		{
			sync_printf("[RSHD::loop] ERROR: Couldn't accept RSHD client\n");


			// Delete client socket
			delete client_sock;
			client_sock = NULL;


			// Free thread ID for client
			delete client_tid;
			client_tid = NULL;


			// Free thread arguments
			delete thread_args;
			thread_args = NULL;


			return (void*)-8;	// ERROR: Couldn't accept RSHD client
		}


		// DEBUG
		sync_dprintf("[RSHD::loop] INFO: New RSHD client connection\n");


		// Create thread argument
		thread_args->thread_id = client_tid;
		thread_args->server_sock = &rshd_sock;
		thread_args->client_sock = client_sock;
		thread_args->object = (void*)this;


		sync_printf("[RSHD::loop] INFO: Starting new client session\n");


		// Create new session thread
		if (client_tid->create_thread((void*)RSHD_start_session,
			(void*)thread_args) < 1)
		{
			sync_printf("[RSHD::loop] ERROR: Couldn't create new session thread\n");


			// Close client socket
			client_sock->close();


			// Delete client socket
			delete client_sock;
			client_sock = NULL;


			// Free thread ID for client
			delete client_tid;
			client_tid = NULL;


			// Free thread arguments
			delete thread_args;
			thread_args = NULL;


			return (void*)-9;	// ERROR: Couldn't create new session thread
		}
	}


	return (void*)1;	// SUCCESS
}


void* RSHD_loop(void* arg)
{
	RSHD* rshd;


	// Get RSHD object
	rshd = (RSHD*)arg;


	// Enter mainloop
	rshd->loop(NULL);


	return NULL;
}


int RSHD::read_input(Socket& sock,			// - IN: RSH client sock
	unsigned int timeout_sec,		// - IN: I/O timeout
	char eoi,				// - IN: End of input byte
	std::string& input)		// - OUT: Input from RSH client
{
	char command_char;
	struct timeval timeout;
	struct timeval* timeout_pointer;
	fd_set read_fdset;


	// IN: Check for valid RSHD server socket
	if (sock.get_fd() < 0)
	{
		// DEBUG
		sync_dprintf("[RSHD::read_input] ERROR: Invalid RSHD server socket\n");


		return 0;	// ERROR: Invalid RSHD server socket
	}


#if defined(__sgi) || defined(__GNUC__)


	// IN: Check for overflow of RSHD server socket
	if (sock.get_fd() >= FD_SETSIZE)
	{
		// DEBUG
		sync_dprintf("[RSHD::read_input] ERROR: Overflow of RSHD server socket\n");


		return -1;	// ERROR: Overflow of RSHD server socket
	}


#endif	// __sgi || __GNUC__


	// DEBUG
	sync_dprintf("[RSHD::read_input] INFO: Reading RSHD command (timeout %u seconds)\n",
		timeout_sec);


	// Check for timeout
	if (timeout_sec == 0)
	{
		timeout_pointer = NULL;
	}
	else
	{
		timeout.tv_sec = timeout_sec;
		timeout.tv_usec = 0;


		timeout_pointer = &timeout;
	}


	// Select with timeout
	input.clear();
	FD_ZERO(&read_fdset);
	FD_SET(sock.get_fd(), &read_fdset);
	switch (select(sock.get_fd() + 1,
		&read_fdset,
		NULL,
		NULL,
		timeout_pointer))
	{
	case 0:

		// NOTE: Timeout expired


		sync_printf("[RSHD::read_input] ERROR: Timeout expired\n");


		return -4;	// ERROR: Timeout expired

	case 1:

		// NOTE: One descriptor readable


		// Read RSHD command
		while (loop_forever)
		{
			// Read command character
			switch (recv(sock.get_fd(),
				(char*)&command_char,
				1,
				0))
			{
			case 0:

				// NOTE: Unexpected EOF


				// DEBUG
				sync_dprintf("[RSHD::read_input] SUCCESS: EOF\n");


				return 2;	// SUCCESS: EOF

			case 1:

				// NOTE: Command character


				break;

			default:

				// NOTE: Read error


				// DEBUG
				sync_dprintf("[RSHD::read_input] ERROR: Read error\n");


				return -5;	// ERROR: Read error
			}


			// NOTE: EOI
			//
			//  The End-of-Input byte marks the end of an input byte stream.
			//
			//  There are two input modes:
			//
			//   1. RSH mode
			//
			//    End of Input is marked by a terminating NULL byte.
			//
			//   2. /bin/sh mode
			//
			//    End of Input is marked by a terminating newline character ('\n').


			// Check for terminating byte
			if (command_char == eoi)
			{
				// Check for NULL byte
				if (eoi != '\0')
				{
					// Terminate command string
					input += command_char;
				}


				// DEBUG
				sync_dprintf("[RSHD::read_input] INFO: EOI\n");


				break;
			}


			// Copy command character
			input += command_char;


			// Check for maximum length of command string
			if ((input.length() + 1) == 511)
			{
				// DEBUG
				sync_dprintf("[RSHD::read_input] ERROR: MAXLENGTH\n");


				break;
			}
		}


		break;

	case -1:

		// NOTE: Error occured


		sync_printf("[RSHD::read_input] ERROR: Error reading TFTP packet: errno = %u\n",
			errno);


		return -6;	// ERROR: Error reading TFTP packet

	default:

		// NOTE: Never reached


		// DEBUG
		sync_dprintf("[RSHD::read_input] ERROR: Unexpected select() return value\n");


		return -7;	// ERROR: Unexpected select() return value
	}


	// DEBUG
	sync_dprintf("[RSHD::read_input] SUCCESS\n");


	return 1;	// SUCCESS
}


// NOTE: Free function definitions


unsigned char get_ascii(unsigned char character)
{
	// Check for printable ASCII symbol
	if ((character >= 32) &&
		(character <= 126))
	{
		return character;
	}


	return '.';
}


int sync_print_format(const char* format,	// - IN: Format string
	va_list args)		// - IN: Arguments
{
	int ret;
	bool format_error;
	bool trace_error;
	bool write_error;


	// Acquire mutex
	if (printf_mutex.lock_mutex() < 1)
	{
		// NOTE: No mutex


		// Check for trace mode
		if (args_trace == true)
		{
			// Write tracelog
			trace_log.write("[sync_printf_format] WARNING: Couldn't acquire printf mutex\n");
		}


		return 0;	// ERROR: Couldn't acquire printf mutex
	}


	// Format log string
	ret = vsnprintf(log_string,
		LOG_MAX_SIZE,
		format,
		args);


	// Check for format error
	format_error = false;
	trace_error = false;
	write_error = false;
	if (ret < 0)
	{
		// NOTE: Format error


		// Check for trace mode
		if (args_trace == true)
		{
			// Write tracelog
			trace_log.write("[sync_printf_format] WARNING: Couldn't format log string\n");
		}


		format_error = true;
	}
	else
	{
		// NOTE: No format error


		// Check for trace mode
		if (args_trace == true)
		{
			// Write tracelog
			if (trace_log.write(log_string) < 1)
			{
				// NOTE: Tracelog write error


				trace_error = true;
			}
		}


		// Check for trace error
		if (trace_error != true)
		{
			// Print string
			if (::love_write(1,
				(const void*)log_string,
				(unsigned long)ret) != ret)
			{
				// NOTE: Write error


				// Check for trace mode
				if (args_trace == true)
				{
					// Write tracelog
					trace_log.write("[sync_printf_format] WARNING: Couldn't write string to standard output\n");
				}


				write_error = true;
			}
		}
	}


	// Release mutex
	if (printf_mutex.unlock_mutex() < 1)
	{
		// NOTE: No mutex


		// Check for trace error
		if (trace_error != true)
		{
			// Check for trace mode
			if (args_trace == true)
			{
				// Write tracelog
				trace_log.write("[sync_printf_format] WARNING: Couldn't release printf mutex\n");
			}
		}


		return -4;	// ERROR: Couldn't release printf mutex
	}


	// Check for errors
	if (format_error == true)
	{
		return -1;	// ERROR: Couldn't format log string
	}
	else if (trace_error == true)
	{
		return -2;	// ERROR: Couldn't write tracelog
	}
	else if (write_error == true)
	{
		return -3;	// ERROR: Couldn't write string to standard output
	}


	return 1;	// SUCCESS
}


int sync_printf(const char* format,	// - IN: Format string
	...)			// - IN/OUT: Arguments
{
	int ret;
	va_list args;


	va_start(args, format);


	ret = sync_print_format(format,
		args);


	va_end(args);


	return ret;
}


int sync_dprintf(const char* format,	// - IN: Format string
	...)			// - IN/OUT: Arguments
{
	int ret;
	va_list args;


	// Check for debug mode
	if (args_debug != true)
	{
		return 0;	// ERROR: No debug mode
	}


	va_start(args, format);


	ret = sync_print_format(format,
		args);


	va_end(args);


	// Check for errors
	if (ret < 1)
	{
		// NOTE: Account for return value above (0)


		ret--;
	}


	return ret;
}


int love_gethostbyname(const char* hostname,		// - IN: Hostname to look up
	iaddr_t* host_ip_address,	// - OUT: Host IP address in network byte order
	int* local_errno)		// - OUT: Local error number
{
#if defined(__sgi) || defined(__GNUC__)


	int host_errno;
	char buffer[2048];
	struct hostent host_address;


#ifdef __GNUC__


	struct hostent* hostent_addr_pointer;


#endif	// __GNUC__


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	std::string ip_string;
	struct hostent* host_address_1;


#endif	// _WIN32


	// IN: Check for hostname
	if (hostname == NULL)
	{
		return 0;	// ERROR: No hostname
	}


	// OUT: Check for host IP address
	if (host_ip_address == NULL)
	{
		return -1;	// ERROR: No host IP address
	}


	// OUT: Check for local error number
	if (local_errno == NULL)
	{
		return -2;	// ERROR: No local error number
	}


	// NOTE: gethostbyname()/gethostbyname_r()
	//
	//  On IRIX and Linux, gethostbyname_r() accepts both hostnames
	//  and IP addresses.
	//
	//  On Windows, gethostbyname() only accepts hostnames. If this function
	//  fails, a second attempt is done to parse the string as an IP address.
	//
	//  This resembles the functionality of IRIX's/Linux's gethostbyname_r().


#if defined(__sgi) || defined(__GNUC__)


#ifdef __sgi


	// Look up hostname
	buffer[0] = '\0';
	host_errno = 0;
	if (gethostbyname_r(hostname,
		&host_address,
		buffer,
		2048,
		&host_errno) == NULL)
	{
		// OUT: Set hostname error number
		*local_errno = host_errno;


		return -3;	// ERROR: Couldn't look up hostname
	}


#elif __GNUC__


	// Look up hostname
	buffer[0] = '\0';
	host_errno = 0;
	if (gethostbyname_r(hostname,
		&host_address,
		buffer,
		2048,
		&hostent_addr_pointer,
		&host_errno) != 0)
	{
		// OUT: Set hostname error number
		*local_errno = host_errno;


		return -3;	// ERROR: Couldn't look up hostname
	}


#endif	// __sgi


	// OUT: Set host IP address
	* host_ip_address = *((unsigned int*)host_address.h_addr);


	// OUT: Reset hostname error number
	*local_errno = 0;


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Look up hostname
	host_address_1 = gethostbyname(hostname);
	if (host_address_1 == NULL)
	{
		// OUT: Set hostname error number
		*local_errno = WSAGetLastError();


		// OUT: Check for IP string
		ip_string = hostname;
		if (Socket::convert_ascii_to_bytes(ip_string,
			*host_ip_address) < 1)
		{
			return -3;	// ERROR: Couldn't look up hostname
		}


		// OUT: Reset hostname error number
		*local_errno = 0;

		return 2;	// SUCCESS: Hostname is valid IP address
	}


	// OUT: Set host IP address
	*host_ip_address = *((unsigned int*)host_address_1->h_addr);


	// OUT: Reset hostname error number
	*local_errno = 0;


#endif	// _WIN32


	return 1;	// SUCCESS
}


void love_sleep(unsigned int milliseconds)	// - IN: Number of milliseconds to sleep
{
	// IN: Check for milliseconds
	if (milliseconds == 0)
	{
		return;	// ERROR: No milliseconds
	}


#if defined(__sgi) || defined(__GNUC__)


	// Subshell runtime
	usleep(50000);


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Subshell runtime
	Sleep(50);


#endif	// _Win32
}


int love_open(const char* filename,	// - IN: Filename to open
	int open_flags,		// - IN: Open flags
	int open_modes)		// - IN: File modes for some flags
{
	int file;


	// IN: Check for filename
	if (filename == NULL)
	{
		return -1;	// ERROR: No filename
	}


#if defined(__sgi) || defined(__GNUC__)


	// Open file
	file = ::open(filename,
		open_flags,
		open_modes);
	if (file == -1)
	{
		return -1;      // ERROR: Couldn't open file
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// NOTE: Binary translation mode
	//
	//  On Windows, two translation modes are available when opening a file:
	//
	//   1. Text mode (default)
	//   2. Binary mode
	//
	//  Classes in this project expect to read bytes as raw bytes, without
	//  further interpretation (line endings, string terminations, ...).
	//
	//  Therefore, binary mode is the default open mode for any file, unless
	//  explicitly requested to be text mode (providing the _O_TEXT in the
	//  ::open() call).


	// Check for _O_TEXT
	if ((open_flags & _O_TEXT) == 0)
	{
		// NOTE: No _O_TEXT
		//
		//  Set binary translation mode by default if _O_TEXT is not explicitly
		//  given.


		// Set binary translation mode by default
		open_flags |= _O_BINARY;
	}


	// Open file
	if (::_sopen_s(&file,
		filename,
		open_flags,
		_SH_DENYNO,
		open_modes) != 0)
	{
		return -1;      // ERROR: Couldn't open file
	}


#endif	// _WIN32


	return file;	// SUCCESS
}


int love_read(int const file_desc,		// - IN: File descriptor to read from
	void* const buffer,		// - IN: Buffer to read bytes from
	unsigned int const buffer_size)	// - IN: Size of buffer
{
	// IN: Check size of buffer
	if (buffer_size > (unsigned int)INT_MAX)
	{
		return -1;	// ERROR: Size of buffer overflow
	}


#if defined(__sgi) || defined(__GNUC__)


	// LINUX: ssize_t read(int fd, void *buf, size_t count);
	//        ssize_t : long
	//        size_t  : unsigned long


	// Read from file descriptor
	return ::read(file_desc,
		(void*)buffer,
		(unsigned int)buffer_size);


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Read from file descriptor
	return ::_read(file_desc,
		buffer,
		buffer_size);


#endif	// _WIN32
}


int love_write(int file_desc,			// - IN: File descriptor to write to
	const void* buffer,		// - IN: Buffer to write bytes to
	unsigned int buffer_size)	// - IN: Size of buffer
{
	// IN: Check size of buffer
	if (buffer_size > (unsigned int)INT_MAX)
	{
		return -1;	// ERROR: Size of buffer overflow
	}


#if defined(__sgi) || defined(__GNUC__)


	// TODO: IRIX


	// LINUX: ssize_t write(int fd, const void *buf, size_t count);
	//        ssize_t : long
	//        size_t  : unsigned long


	// Write to file descriptor
	return ::write(file_desc,
		buffer,
		buffer_size);


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// WIN32: int _write(int fd,
	//		     const void* buffer,
	//		     unsigned int count);


	// Write to file descriptor
	return ::_write(file_desc,
		buffer,
		buffer_size);


#endif	// _WIN32
}


int love_close(int file_desc)	// - IN: Filename to open
{
#if defined(__sgi) || defined(__GNUC__)


	// Close file
	if (::close(file_desc) == -1)
	{
		return -1;      // ERROR: Couldn't close file
	}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Close file
	if (::_close(file_desc) == -1)
	{
		return -1;      // ERROR: Couldn't close file
	}


#endif	// _WIN32


	return 0;	// SUCCESS
}


int love_snprintf(char* buffer,                  // - OUT: Buffer where formatted string is stored
	unsigned long buffer_size,     // - IN: Size of buffer
	const char* format,            // - IN: Format string
	...)                           // - IN: Format arguments
{
	int ret;
	va_list args_pointer;


	// Start variadic arguments processing
	va_start(args_pointer, format);


#if defined(__sgi) || defined(__GNUC__)


	// TODO: IRIX


	// LINUX: int vsnprintf(char* str, size_t size, const char* format, va_list ap);
	//        size_t: unsigned long


	// Format string
	ret = vsnprintf(buffer,
		buffer_size,
		format,
		args_pointer);


#ifdef __GNUC__


	// Check for truncation
	if (ret >= buffer_size)
	{
		ret = -1L;
	}


#endif  // __GNUC__


#endif  // __sgi || __GNUC__


#ifdef _WIN32


	// WIN32: int _vsnprintf_s(char *buffer,
	//                         size_t sizeOfBuffer,
	//                         size_t count,
	//                         const char* format,
	//                         va_list argptr);


	// Format string
	ret = _vsnprintf_s(buffer,
		buffer_size,
		buffer_size,
		format,
		args_pointer);


#endif  // _WIN32


	// End variadic arguments processing
	va_end(args_pointer);


	// Check for formatting error
	if (ret < 0)
	{
		return -1;      // ERROR: Formatting error
	}


	return ret;
}


long love_lseek(int file_desc,	// - IN: File descriptor where seek should take place
	long offset,	// - IN: Offset of seek starting from origin
	int origin)	// - IN: Origin where offset starts from
{
#if defined(__sgi) || defined(__GNUC__)


	// TODO: IRIX


	// LINUX: off_t lseek(int fd, off_t offset, int whence);


	return ::lseek(file_desc,
		offset,
		origin);


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// WIN32: long _lseek(int fd,
	//		      long offset,
	//		      int origin);


	return ::_lseek(file_desc,
		offset,
		origin);


#endif	// _WIN32
}


void print_syntax(void)
{
	printf("SYNTAX: love [-d] [-t <tracelog file>] <local hostname> <labels file>\n");
	printf("          - debug mode: Enable debug mode\n");
	printf("          - tracelog mode: Enable tracelog mode, writing trace to tracelog file\n");
	printf("          - local hostname: Hostname or IP address of local server\n");
	printf("          - labels file: Path to a file containing pairs of label/distribution pathnames\n");
}


#ifdef _WIN32


bool LoadNpcapDlls()
{
	char npcap_dir[512];
	UINT len;


	// Get system directory
	len = GetSystemDirectory(npcap_dir,
		480);
	if (!len)
	{
		fprintf(stderr,
			"Error in GetSystemDirectory: %x",
			GetLastError());


		return false;
	}


	// Add \Npcap subdirectory
	strcat_s(npcap_dir,
		512,
		"\\Npcap");


	// DEBUG
	printf("[::LoadNpcapDlls] INFO: npcap_dir = \"%s\"\n",
		npcap_dir);


	// Set Npcap DLL directory
	if (SetDllDirectory(npcap_dir) == 0)
	{
		fprintf(stderr,
			"Error in SetDllDirectory: %x",
			GetLastError());


		return false;
	}


	return true;
}


void bzero(void* buffer,		// - IN: Buffer to clear
	unsigned int buffer_size)	// - IN: Size of buffer
{
	char* char_pointer;
	unsigned int buffer_index;


	// IN: Check for buffer
	if (buffer == NULL)
	{
		return;	// ERROR: No buffer
	}


	// IN: Check for size of buffer
	if (buffer_size == 0)
	{
		return;	// ERROR: No size of buffer
	}


	// Traverse buffer
	char_pointer = (char*)buffer;
	buffer_index = 0;
	for (buffer_index;
		buffer_index < buffer_size;
		buffer_index++)
	{
		// Reset byte
		char_pointer[buffer_index] = '\0';
	}
}


void bcopy(void* buffer_source,		// - IN: Source buffer to copy from
	void* buffer_dest,		// - OUT: Destination buffer to copy to
	unsigned int buffer_size)	// - IN: Size of source buffer to copy
{
	char* char_source;
	char* char_dest;
	unsigned int buffer_index;


	// IN: Check for source buffer
	if (buffer_source == NULL)
	{
		return;	// ERROR: No source buffer
	}


	// IN: Check for destination buffer
	if (buffer_dest == NULL)
	{
		return;	// ERROR: No destination buffer
	}


	// IN: Check for size of source buffer
	if (buffer_size == 0)
	{
		return;	// ERROR: No size of source buffer
	}


	// Traverse source buffer
	char_source = (char*)buffer_source;
	char_dest = (char*)buffer_dest;
	buffer_index = 0;
	for (buffer_index;
		buffer_index < buffer_size;
		buffer_index++)
	{
		// Copy byte
		char_dest[buffer_index] = char_source[buffer_index];
	}
}


#endif	// _WIN32


inline TFTP_FILE::TFTP_FILE(std::string& filename,	// - IN: Filename
	unsigned int mode)		// - IN: Transfer mode
	: file_desc(-1),
	prev_char('\0'),
	filename(""),
	mode(mode),
	block_number(0)
{
	unsigned int file_length;


	// IN: Check for empty filename
	file_length = filename.length();
	if (file_length == 0)
	{
		return;	// ERROR: Empty filename
	}


	// IN: Check for filename length overflow
	if (file_length >= MAXPATHLEN)
	{
		return;	// ERROR: Filename length overflow
	}


	// Copy filename
	this->filename = filename;
}


inline bool TFTP_FILE::exists()
{
	// CHECK: Filename
	if (this->filename.empty() == true)
	{
		return false;	// ERROR: No filename
	}


	// NOTE: Check for file existence
	//
	//  This method invokes the exists() method of the
	//  REGULAR_FILE base class.


	// Check for existence of filename
	if (((REGULAR_FILE*)this)->exists(this->filename) != true)
	{
		return false;	// SUCCESS: Filename doesn't exist
	}


	return true;    // SUCCESS: Filename exists
}


inline int TFTP_FILE::open(void)
{
	// Check for filename
	if (this->filename.empty() == true)
	{
		return 0;	// ERROR: No filename
	}


	// Check for open file
	if (this->file_desc != -1)
	{
		return -1;       // ERROR: File already open
	}


	// Open filename
	this->file_desc = ::love_open(this->filename.c_str(),
		O_RDONLY,
		0);
	if (this->file_desc == -1)
	{
		return -2;       // ERROR: Couldn't open filename
	}


	return 1;       // SUCCESS
}


inline int TFTP_FILE::read_block(char* block,			// - OUT: File block
	unsigned short* size)		// - OUT: Size of file block (in bytes)
{
	char block_char;
	int bytes_read;
	int total_bytes_read;


	// Check for open file
	if (this->file_desc == -1)
	{
		return 0;       // ERROR: File not open
	}


	// OUT: Check for file block
	if (block == NULL)
	{
		return 0;       // ERROR: No file block
	}


	// NOTE: Block size
	//
	//  The block size is at most 512 bytes long.


	// OUT: Check for size of file block
	if (size == NULL)
	{
		return -1;      // ERROR: No size of file block
	}


	// NOTE: Block number
	//
	//  The block number contains the index of the next file block
	//  to be read.


	// Check mode
	if (this->mode == 1)
	{
		// NOTE: 'netascii' mode
		//
		//  Translate:
		//
		//	1. CR to CR,NUL
		//	2. LF to CR,LF
		//
		//  The following code also respects 512 byte block boundaries.


		total_bytes_read = 0;
		while (total_bytes_read < 512)
		{
			// Check for previous CR or LF character
			if (this->prev_char != '\0')
			{
				if (this->prev_char == '\r')
				{
					block_char = '\0';
				}
				else
				{
					block_char = '\n';
				}


				// Reset previous block character
				this->prev_char = '\0';
			}
			else
			{
				// Read file block
				bytes_read = ::love_read(this->file_desc,
					(void*)&block_char,
					1);
				if (bytes_read == -1)
				{
					// NOTE: Read error


					// Set size of file block
					*size = 0;


					return -2;      // ERROR: Read error
				}
				else if (bytes_read == 0)
				{
					// NOTE: EOF


					break;
				}


				// NOTE: bytes_read == 1L


				// Check for CR or LF
				if ((block_char == '\r') ||
					(block_char == '\n'))
				{
					// Save previous block character
					this->prev_char = block_char;


					// Set current block character to '\r' in both cases
					block_char = '\r';
				}
			}


			// Copy block character
			block[total_bytes_read] = block_char;


			// Increment total bytes counter
			total_bytes_read++;
		}


		// Set total number of bytes read from file block
		bytes_read = total_bytes_read;
	}
	else
	{
		// NOTE: 'octet' mode


		// Read file block
		bytes_read = ::love_read(this->file_desc,
			(void*)block,
			512);
		if (bytes_read == -1)
		{
			// NOTE: Read error


			// Set size of file block
			*size = 0;


			return -2;      // ERROR: Read error
		}
	}


	// HINT: bytes_read >= 0 && bytes_read <= 512
	//
	//  Set size of file block
	*size = (unsigned int)bytes_read;


	// Increment block number
	this->block_number++;


	return 1;       // SUCCESS
}


inline int TFTP_FILE::close(void)
{
	// Check for opened file
	if (this->file_desc == -1)
	{
		return 0;       // ERROR: File not opened
	}


	// Close opened file
	::love_close(this->file_desc);
	this->file_desc = -1;


	return 1;       // SUCCESS
}


inline TFTP_FILE::~TFTP_FILE()
{
	// Check for opened file
	if (this->file_desc > -1)
	{
		// Close opened file
		::love_close(this->file_desc);
		this->file_desc = -1;
	}
}


int NetIF::check_addr(SNOOPI snoopi,	// - IN: SNOOPI object
	iaddr_t addr,	// - IN: Address to check
	char* nif_name)	// - OUT: Interface name associated to address
{
#ifdef __sgi


	char buf[BUFSIZ];
	int snoopi_sock;
	unsigned int found_if;
	unsigned int nif_num;
	struct ifreq* if_req;
	struct ifconf if_conf;
	struct sockaddr_in* sin_addr;


	// IN: Check for SNOOPI socket
	snoopi_sock = snoopi.get_fd();
	if (snoopi_sock == -1)
	{
		return 0;	// ERROR: No socket
	}


	// OUT: Check for network interface name
	if (nif_name == NULL)
	{
		return -2;	// ERROR: No network interface name
	}


	// Get network interface configuration
	if_conf.ifc_len = sizeof(buf);
	if_conf.ifc_buf = buf;
	if (ioctl(snoopi_sock,
		SIOCGIFCONF,
		(char*)&if_conf) < 0)
	{
		return -3;	// ERROR: Couldn't get network interface configuration
	}


	// Traverse interfaces
	found_if = 0;
	if_req = if_conf.ifc_req;
	nif_num = if_conf.ifc_len / sizeof(struct ifreq);
	for (;
		nif_num > 0;
		nif_num--)
	{
		// Check for address
		sin_addr = (struct sockaddr_in*)&if_req->ifr_ifru.ifru_addr;
		if ((unsigned int)sin_addr->sin_addr.s_addr == addr)
		{
			// Set found flag
			found_if = 1;


			break;
		}


		// Increment interface request pointer
		if_req++;
	}


	// Check found flag
	if (found_if == 0)
	{
		return -4;	// ERROR: Couldn't find interface corresponding to address
	}


	// Copy interface name
	nif_name[0] = '\0';
	strcat(nif_name,
		if_req->ifr_name);


#elif defined(__GNUC__)


	char buf[BUFSIZ];
	int snoopi_sock;
	unsigned int found_if;
	unsigned int nif_num;
	struct ifaddrs* if_ap;
	struct ifaddrs* if_req;
	struct sockaddr_in* sin_addr;


	// IN: Check for SNOOPI socket
	//
	//  Not necessary on GNU/Linux.


	// OUT: Check for network interface name
	if (nif_name == NULL)
	{
		return -1;	// ERROR: No network interface name
	}


	// Get network interface addresses
	if (getifaddrs(&if_ap) == -1)
	{
		return -2;	// ERROR: Couldn't get network interface addresses
	}


	// Traverse interfaces
	found_if = false;
	for (if_req = if_ap;
		if_req != NULL;
		if_req = if_req->ifa_next)
	{
		// Check for IPv4 address interfaces
		if (if_req->ifa_addr->sa_family == AF_INET)
		{
			// Check for address
			sin_addr = (struct sockaddr_in*)if_req->ifa_addr;
			if ((unsigned int)sin_addr->sin_addr.s_addr == addr)
			{
				// Set found flag
				found_if = true;


				break;
			}
		}
	}


	// Check found flag
	if (found_if != true)
	{
		// Free address info
		freeifaddrs(if_ap);


		return -4;	// ERROR: Couldn't find interface corresponding to address
	}


	// Copy interface name
	nif_name[0] = '\0';
	strcat(nif_name,
		if_req->ifa_name);


	// Free address info
	freeifaddrs(if_ap);


#elif defined(_WIN32)


	bool found_dev;
	pcap_if_t* dev;
	pcap_if_t* dev_list;
	size_t name_length;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct pcap_addr* dev_address;
	struct sockaddr_in* sin_addr;


	// IN: Check for SNOOPI socket
	//
	//  Not necessary on Windows.


	// IN: Check for address
	if (addr == NULL)
	{
		return 0;	// ERROR: No address
	}


	// OUT: Check for network interface name
	if (nif_name == NULL)
	{
		return -1;	// ERROR: No network interface name
	}


	// Get device list
	dev_list = NULL;
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
		NULL,
		&dev_list,
		error_buffer) == -1)
	{
		return -2;	// ERROR: Couldn't get device list
	}


	// Check for devices
	if (dev_list == NULL)
	{
		return -3;	// ERROR: No devices
	}


	// Traverse device list
	found_dev = false;
	for (dev = dev_list;
		dev != NULL;
		dev = dev->next)
	{
		// Skip wireless devices
		if ((dev->flags & PCAP_IF_WIRELESS) == PCAP_IF_WIRELESS)
		{
			// NOTE: Wireless device


			continue;
		}


		// Traverse device address list
		for (dev_address = dev->addresses;
			dev_address != NULL;
			dev_address = dev_address->next)
		{
			// Check for IPv4 address
			if (dev_address->addr->sa_family == AF_INET)
			{
				// Check for address
				sin_addr = (struct sockaddr_in*)dev_address->addr;
				if ((unsigned int)sin_addr->sin_addr.s_addr == addr)
				{
					// Set found flag
					found_dev = true;


					break;
				}
			}
		}


		// Check for found device
		if (found_dev == true)
		{
			break;
		}
	}


	// Check found flag
	if (found_dev != true)
	{
		// Free device list
		pcap_freealldevs(dev_list);


		return -4;	// ERROR: Couldn't find device corresponding to address
	}


	// Check for device name length overflow
	name_length = strnlen_s(dev->name,
		IFNAMSIZ);
	if (name_length >= IFNAMSIZ)
	{
		// Free device list
		pcap_freealldevs(dev_list);


		return -5;	// ERROR: Device name length overflow
	}


	// Copy device name
	nif_name[0] = '\0';
	if (strncat_s(nif_name,
		IFNAMSIZ,
		dev->name,
		name_length) != 0)
	{
		// Free device list
		pcap_freealldevs(dev_list);


		return -6;	// ERROR: Device name length overflow
	}


	// Free device list
	pcap_freealldevs(dev_list);


#endif	// __sgi


	return 1;	// SUCCESS
}


TFTPD::TFTPD()
{
	// NOTE: Initialization


	this->seq_tid = false;
	this->daemon_started = false;
	this->seed_num = 1;
	this->last_tid = 0;
}


int TFTPD::init()
{
	// NOTE: TFTPD initialization


	// Create TID mutex
	if (this->tid_mutex.create_mutex() < 1)
	{
		return 0;	// ERROR: Couldn't initialize TID mutex
	}


	return 1;	// SUCCESS
}


int TFTPD::deinit()
{
	// NOTE: TFTPD deinitialization


	// Destroy TID mutex
	if (this->tid_mutex.destroy_mutex() < 1)
	{
		return 0;	// ERROR: Couldn't destroy TID mutex
	}


	return 1;	// SUCCESS
}


int TFTPD::start(void)
{
	// Check for started daemon
	if (tftpd.started() == true)
	{
		return 0;	// ERROR: Daemon already started
	}


	// DEBUG
	sync_dprintf("[TFTPD::start] START\n");


	// Create new thread
	if (this->thread_id.create_thread((void*)TFTPD_loop,
		NULL) < 1)
	{
		return -1;	// ERROR: Couldn't create daemon main loop
	}


	// Set daemon started flag
	tftpd.set_started();


	// DEBUG
	sync_dprintf("[TFTPD::start] STOP\n");


	return 1;	// SUCCESS
}


bool TFTPD::started()
{
	return this->daemon_started;
}


void TFTPD::set_started()
{
	this->daemon_started = true;
}


int TFTPD::start_session(Socket& server_sock,			// - IN: TFTPD server socket
	struct sockaddr_in client_addr,	// - IN: Client address
	std::string filename,			// - IN: Filename to transfer
	unsigned int mode)			// - IN: Transfer mode:
	//		1 - netascii
	//		2 - octet
{
	int ret;
	unsigned int label_type;
	unsigned int bytes_address;
	unsigned int total_block_size;
	struct tftp tftp_packet;
	std::string label;
	std::string path;
	std::string irix_path;
	std::string label_path;
	std::string local_path;
	TFTP_FILE* file;
	PATH tftp_path;


#ifdef __GNUC__


	unsigned int onoff;


#endif	// __GNUC__


	// NOTE: TFTP client session
	//
	//  A client session starts by sending a DATA packet
	//  to the client, as an acknowledgment to its RRQ packet.
	//
	//  After that, the session loop is entered which consists of
	//  reading a packet and replying to that packet.


	// IN: Check for TFTPD server socket
	if (server_sock.get_fd() < 0)
	{
		return 0;	// ERROR: No TFTPD server socket
	}


	// IN: Check for valid mode
	if ((mode != 1) &&
		(mode != 2))
	{
		return -1;	// ERROR: No valid mode
	}


	// Check for empty filename
	if (filename.empty() == true)
	{
		return -2;	// ERROR: Empty filename
	}


	// DEBUG
	sync_dprintf("[TFTPD::start_session] START: filename = \"%s\"\n",
		filename.c_str());


	// NOTE: Transfer modes
	//
	//  TFTPD transfers can be of two types:
	//
	//   1. Labeled transfer
	//
	//    In this transfer mode, the final path must be reassembled after label lookup.
	//
	//    The reason being that the client may not only send a label, but a path component
	//    too:
	//
	//          Label   Path component(s)
	//         <------><-------------->
	//     RRQ love.XYZ/path/component(s)
	// 
	// 
	//    The above path, sent by a client, would be first split up into label and path
	//    components. Then, translation of the label would occur, and lastly this translation
	//    and the path components would be joined together giving the effective path of the file
	//    on the server to be opened and transferred back.
	//
	//   2. Non-labeled transfer
	//
	//    The client sends a valid path without label. This path is used directly as the
	//    filename on the server to be opened and transferred back.


	// DEBUG
	sync_dprintf("[TFTPD::start_session] INFO: filename.substr(...).compare(love)\n");


	// Check for label
	if (filename.substr(0,
		4).compare("love") == 0)
	{
		// NOTE: Found label
		//
		//  Initiate path translation for labeled transfer.


		sync_printf("[TFTPD::start_session] LABELED_TRANSFER: Lookup label \"%s\"\n",
			filename.c_str());


		// Get label without path components
		if (LABEL_FILE::get_label_prefix(filename,
			label,
			path) < 1)
		{
			sync_printf("[TFTPD::start_session] ERROR: Couldn't find prefixed label \"%s\"\n",
				filename.c_str());


			return -3;	// ERROR: Couldn't find prefixed label
		}


		sync_printf("[TFTPD::start_session] LABEL: \"%s\"\n",
			label.c_str());
		sync_printf("[TFTPD::start_session] PATH: \"%s\"\n",
			path.c_str());


		// Lookup label
		label_path.clear();
		label_type = LABEL_FILE::LINE::TYPE_NONE;
		if (labels.lookup_label(label,
			true,
			labels_path,
			label_path,
			label_type) < 1)
		{
			// NOTE: Label not found


			sync_printf("[TFTPD::start_session] ERROR: Couldn't find label \"%s\"\n",
				label.c_str());


			return -4;	// ERROR: Couldn't find label
		}


		// Set label path
		if (tftp_path.set(label_path) < 1)
		{
			sync_printf("[TFTPD::start_session] ERROR: Couldn't set path to label path\n");


			return -5;	// ERROR: Couldn't set path for label path
		}


#if defined(__sgi) || defined(__GNUC__)


		// Check for leading '/' in path component
		if (path.at(0) == '/')
		{
			// Delete leading '/' in path component
			path.erase(path.begin());
		}


		// Add path component to label path
		if (tftp_path.add_components(path,
			PATH::os_type::UNIX_OS) < 1)
		{
			sync_printf("[TFTPD::start_session] ERROR: Couldn't add path component to label path\n");


			return -8;	// ERROR: Couldn't add path component to label path
		}


#elif defined(_WIN32)


		// Check for leading '\\' in path component
		if (path.at(0) == '\\')
		{
			// Delete leading '\\' in path component
			path.erase(path.begin());
		}


		// Add path component to label path
		if (tftp_path.add_components(path,
			PATH::os_type::WIN32_OS) < 1)
		{
			sync_printf("[TFTPD::start_session] ERROR: Couldn't add path component to label path\n");


			return -8;	// ERROR: Couldn't add path component to label path
		}


#endif	// __sgi || __GNUC__


		// Get IRIX path for label path
		irix_path.clear();
		if (tftp_path.get_irix(irix_path) < 1)
		{
			sync_printf("[TFTPD::start_session] ERROR: Couldn't get IRIX path for label path\n");


			return -9;	// ERROR: Couldn't get IRIX path for label path
		}


		// Get local path for label path
		local_path.clear();
		if (tftp_path.get_local(local_path) < 1)
		{
			sync_printf("[TFTPD::start_session] ERROR: Couldn't get local path for label parameter\n");


			return -8;	// ERROR: Couldn't get local path for label parameter
		}


		// DEBUG
		sync_dprintf("[TFTPD::start_session] INFO_IRIX: irix_path = \"%s\"\n",
			irix_path.c_str());
		sync_dprintf("[TFTPD::start_session] INFO_LOCAL: local_path = \"%s\"\n",
			local_path.c_str());


		// Reset filename
		filename = local_path;


		// DEBUG
		sync_dprintf("[TFTPD::start_session] INFO: filename = \"%s\"\n",
			filename.c_str());
	}
	else
	{
		// NOTE: Label not found
		//
		//  Use filename directly for non-labeled transfer.


		sync_printf("[TFTPD::start_session] NONLABELED_TRANSFER: Lookup label \"%s\"\n",
			filename.c_str());
	}


	// DEBUG
	sync_dprintf("[TFTPD::start_session] INFO: new TFTP_FILE()\n");


	// Create a TFTP_FILE instance
	file = new TFTP_FILE(filename,
		mode);


	// DEBUG
	sync_dprintf("[TFTPD::start_session] INFO: file->exists()\n");


	// Check for requested file
	if (file->exists() == false)
	{
		// Delete file
		delete file;
		file = NULL;


		return -7;	// ERROR: Requested file doesn't exist
	}


	// Open requested file
	if (file->open() < 1)
	{
		// Delete file
		delete file;
		file = NULL;


		return -8;	// ERROR: Couldn't open requested file
	}


	// Get first block from requested file
	tftp_packet.data.size = 512;
	if (file->read_block(tftp_packet.data.block,
		&tftp_packet.data.size) != 1)
	{
		// Close file
		file->close();


		// Delete file
		delete file;
		file = NULL;


		return -9;	// ERROR: Couldn't read first block of requested file
	}


	// DEBUG
	sync_dprintf("[TFTPD::start_session] INFO: block.data.size = %u\n",
		tftp_packet.data.size);


	// NOTE: First DATA packet
	//
	//  The first DATA packet contains the first block from the
	//  requested file.


	// Build first DATA packet
	tftp_packet.opcode = TFTP_OPCODE_DATA;
	tftp_packet.data.block_number = 1;


	// NOTE: TID (TFTP IDentifier)
	//
	//  TFTP requires a client TID and server TID to be set
	//  in each TFTP packet. Both values are set in the corresponding
	//  UDP port: the client TID in the UDP source port when sent from
	//  the client (server TID would be 69 initially), and UDP destination
	//  port when sent from the server (client TID would be the TID obtained
	//  in the requesting TFTP packet).
	//
	//  Both TID's are generated randomly and range in value from 0 - 65535.
	//
	//  TIDs are stored in 'tftp_packet' in host byte order, and converted to
	//  NBO (Network Byte Order) when appropriate.
	//
	//  TID's should be different for each session.


	// Generate server TID
	if (tftpd.generate_tid(tftp_packet.server_tid) < 1)
	{
		// NOTE: No free TIDs


		// Close file
		file->close();


		// Delete file
		delete file;
		file = NULL;


		return -10;	// ERROR: Couldn't free TID
	}


	// Set client TID
	tftp_packet.client_tid = ntohs(client_addr.sin_port);


	// NOTE: Create client socket


	// Create TFTPD client socket
	Socket client_sock(Socket::type::SOCK_UDP);
	if (client_sock.get_fd() == -1)
	{
		// DEBUG
		sync_dprintf("[TFTPD::start_session] STOP\n");


		// Close file
		file->close();


		// Delete file
		delete file;
		file = NULL;


		// Remove server TID
		switch (tftpd.remove_tid(tftp_packet.server_tid))
		{
		case 0:

			sync_printf("WARNING: Couldn't acquire TID mutex\n");


			break;

		case -1:

			sync_printf("WARNING: Couldn't release TID mutex\n");


			break;

		default:

			// NOTE: SUCCESS


			break;
		}


		return -11;	// ERROR: Couldn't create TFTPD client socket
	}


	// Set reuse address socket option
	if (client_sock.set_reuseaddr(true) < 1)
	{
		sync_printf("[TFTPD::start_session] ERROR: Couldn't set reuse address socket option\n");


		// Close file
		file->close();


		// Delete file
		delete file;
		file = NULL;


		// Remove server TID
		switch (tftpd.remove_tid(tftp_packet.server_tid))
		{
		case 0:

			sync_printf("WARNING: Couldn't acquire TID mutex\n");


			break;

		case -1:

			sync_printf("WARNING: Couldn't release TID mutex\n");


			break;

		default:

			// NOTE: SUCCESS


			break;
		}


		return -12;	// ERROR: Couldn't set reuse address socket option
	}


#ifdef __GNUC__


	// Set don't fragment IP socket option
	onoff = IP_PMTUDISC_DONT;
	if (client_sock.setsockopt(IPPROTO_IP,
		IP_MTU_DISCOVER,
		(const void*)&onoff,
		sizeof(unsigned int)) < 1)
	{
		sync_printf("[TFTPD::start_session] ERROR: Couldn't set don't fragment IP socket option\n");


		// Close file
		file->close();


		// Delete file
		delete file;
		file = NULL;


		// Remove server TID
		switch (tftpd.remove_tid(tftp_packet.server_tid))
		{
		case 0:

			sync_printf("WARNING: Couldn't acquire TID mutex\n");


			break;

		case -1:

			sync_printf("WARNING: Couldn't release TID mutex\n");


			break;

		default:

			// NOTE: SUCCESS


			break;
		}


		return -13;	// ERROR: Couldn't set don't fragment IP socket option
	}


#endif	// __GNUC__


	// DEBUG
	sync_dprintf("[TFTPD::start_session] INFO: bind()\n");


	// Bind socket to local port (server TID)
	bytes_address = local_hostaddr;
	if (client_sock.bind(bytes_address,
		tftp_packet.server_tid) < 1)
	{
		sync_printf("[TFTPD::start_session] ERROR: errno = %u\n",
			errno);


		// Close file
		file->close();


		// Delete file
		delete file;
		file = NULL;


		// Remove server TID
		switch (tftpd.remove_tid(tftp_packet.server_tid))
		{
		case 0:

			sync_printf("WARNING: Couldn't acquire TID mutex\n");


			break;

		case -1:

			sync_printf("WARNING: Couldn't release TID mutex\n");


			break;

		default:

			// NOTE: SUCCESS


			break;
		}


		// Close TFTPD client socket
		if (client_sock.close() < 1)
		{
			sync_printf("WARNING: Couldn't close TFTPD client socket\n");
		}


		// DEBUG
		sync_dprintf("[TFTPD::start_session] STOP\n");


		return -14;	// ERROR: Couldn't bind TFTPD client socket
	}


	// NOTE: First DATA packet


	// DEBUG
	sync_dprintf("[TFTPD::start_session] INFO: Write first DATA packet\n");


	// Write first DATA packet
	ret = tftpd.write_packet(client_sock,
		&client_addr,
		&tftp_packet);
	if (ret < 1)
	{
		// Close file
		file->close();


		// Delete file
		delete file;
		file = NULL;


		// Remove server TID
		switch (tftpd.remove_tid(tftp_packet.server_tid))
		{
		case 0:

			sync_printf("WARNING: Couldn't acquire TID mutex\n");


			break;

		case -1:

			sync_printf("WARNING: Couldn't release TID mutex\n");


			break;

		default:

			// NOTE: SUCCESS


			break;
		}


		// Close TFTPD client socket
		if (client_sock.close() < 1)
		{
			sync_printf("WARNING: Couldn't close TFTPD client socket\n");
		}


		// DEBUG
		sync_dprintf("[TFTPD::start_session] STOP\n");


		return -15;	// ERROR: Couldn't write first DATA packet
	}


	// DEBUG
	sync_dprintf("[TFTPD::start_session] INFO: Start session loop\n");


	sync_printf("[TFTPD::start_session] INFO: Transferring file \"%s\"\n",
		filename.c_str());


	// Session loop
	total_block_size = 512;
	while (loop_forever)
	{
		// NOTE: Modification of TIDs
		//
		//  The TID fields of the TFTP packet stored in the 'tftp_packet'
		//  variable are not modified by TFTPD::read_packet().
		//
		//  Therefore, both fields can be safely used in subsequent
		//  TFTPD::write_packet() calls.


		// DEBUG
		sync_dprintf("[TFTPD::start_session] INFO: Read TFTP packet\n");


		// Read TFTP packet
		ret = tftpd.read_packet(client_sock,
			&client_addr,
			30,
			&tftp_packet);
		if (ret != 1)
		{
			sync_printf("[TFTPD::start_session] ERROR: Couldn't read TFTP packet ret = %i\n",
				ret);


			// Close file
			file->close();


			// Delete file
			delete file;
			file = NULL;


			// Remove server TID
			switch (tftpd.remove_tid(tftp_packet.server_tid))
			{
			case 0:

				sync_printf("WARNING: Couldn't acquire TID mutex\n");


				break;

			case -1:

				sync_printf("WARNING: Couldn't release TID mutex\n");


				break;

			default:

				// NOTE: SUCCESS


				break;
			}


			// Close TFTPD client socket
			if (client_sock.close() < 1)
			{
				sync_printf("WARNING: Couldn't close TFTPD client socket\n");
			}


			// DEBUG
			sync_dprintf("[TFTPD::start_session] STOP\n");


			return -16;	// ERROR: Couldn't read TFTP packet
		}


		// Check for ACK packet
		if (tftp_packet.opcode == TFTP_OPCODE_ACK)
		{
			// NOTE: ACK packet


			// Get block from requested file
			tftp_packet.data.size = 512;
			if (file->read_block(tftp_packet.data.block,
				&tftp_packet.data.size) < 1)
			{
				// Close file
				file->close();


				// Delete file
				delete file;
				file = NULL;


				// Remove server TID
				switch (tftpd.remove_tid(tftp_packet.server_tid))
				{
				case 0:

					sync_printf("WARNING: Couldn't acquire TID mutex\n");


					break;

				case -1:

					sync_printf("WARNING: Couldn't release TID mutex\n");


					break;

				default:

					// NOTE: SUCCESS


					break;
				}


				// Close TFTPD client socket
				if (client_sock.close() < 1)
				{
					sync_printf("WARNING: Couldn't close TFTPD client socket\n");
				}


				// DEBUG
				sync_dprintf("[TFTPD::start_session] STOP\n");


				return -17;	// ERROR: Couldn't read block of requested file
			}


			// DEBUG
			sync_dprintf("[TFTPD::start_session] BLOCK_NUMBER: %u SIZE_READ: %u TOTAL_SIZE: %u\n",
				tftp_packet.ack.block_number,
				tftp_packet.data.size,
				total_block_size);


			// Build DATA packet
			tftp_packet.opcode = TFTP_OPCODE_DATA;
			tftp_packet.data.block_number++;


			// DEBUG
			total_block_size += tftp_packet.data.size;


			// Write DATA packet
			ret = tftpd.write_packet(client_sock,
				&client_addr,
				&tftp_packet);
			if (ret < 1)
			{
				// Close file
				file->close();


				// Delete file
				delete file;
				file = NULL;


				// Remove server TID
				switch (tftpd.remove_tid(tftp_packet.server_tid))
				{
				case 0:

					sync_printf("WARNING: Couldn't acquire TID mutex\n");


					break;

				case -1:

					sync_printf("WARNING: Couldn't release TID mutex\n");


					break;

				default:

					// NOTE: SUCCESS


					break;
				}


				// Close TFTPD client socket
				if (client_sock.close() < 1)
				{
					sync_printf("WARNING: Couldn't close TFTPD client socket\n");
				}


				// DEBUG
				sync_dprintf("[TFTPD::start_session] STOP\n");


				return -18;	// ERROR: Couldn't write DATA packet
			}


			// Check for last file block flag
			if (tftp_packet.data.size < 512)
			{
				// NOTE: File transfer complete


				// DEBUG
				sync_dprintf("[TFTPD::start_session] INFO: Transfer complete \"%s\"\n",
					filename.c_str());


				// DEBUG
				sync_dprintf("[TFTPD::start_session] TOTAL_SIZE: %u\n",
					total_block_size);


				break;
			}
		}
		else
		{
			// NOTE: Any other packet


			sync_printf("[TFTPD::start_session] WARNING: Transfer completed prematurely \"%s\"\n",
				filename.c_str());


			// DEBUG
			sync_dprintf("[TFTPD::start_session] TOTAL_SIZE: %u\n",
				total_block_size);


			break;
		}
	}


	// Close file
	file->close();


	// Delete file
	delete file;
	file = NULL;


	// Remove server TID
	switch (tftpd.remove_tid(tftp_packet.server_tid))
	{
	case 0:

		sync_printf("WARNING: Couldn't acquire TID mutex\n");


		break;

	case -1:

		sync_printf("WARNING: Couldn't release TID mutex\n");


		break;

	default:

		// NOTE: SUCCESS


		break;
	}


	// Close TFTPD client socket
	if (client_sock.close() < 1)
	{
		sync_printf("WARNING: Couldn't close TFTPD client socket\n");
	}


	// DEBUG
	sync_dprintf("[TFTPD::start_session] STOP\n");


	return 1;	// SUCCESS
}


void* TFTPD_start_session(void* arg)	// - IN: Thread argument
{
	TFTPD tftp_client;
	Thread* thread_id;
	struct tftp tftp_packet;
	struct thread_args_s* thread_args;


	// IN: Check for thread argument
	if (arg == NULL)
	{
		return (void*)0;	// ERROR: No thread argument
	}


	// DEBUG
	sync_dprintf("[TFTPD_start_session] START\n");


	// Get thread argument
	thread_args = (struct thread_args_s*)arg;


	// Get thread ID
	thread_id = thread_args->thread_id;


	// Check for thread ID
	if (thread_id == NULL)
	{
		// Free thread arguments
		delete (struct thread_args_s*)arg;
		arg = NULL;


		return (void*)-1;     // ERROR: No thread ID
	}


	// Get TFTP packet
	tftp_packet = thread_args->packet;


	// Create new TFTP client session
	if (tftp_client.start_session(*thread_args->server_sock,
		thread_args->client_sockaddr_in,
		tftp_packet.rw.filename,
		tftp_packet.rw.mode) < 1)
	{
		// NOTE: Allocation of pthread_t
		//
		//  This data member, thread_args->thread_id, is
		//  allocated in TFTPD::loop() and freed here.


		// Free thread ID
		delete thread_id;
		thread_id = NULL;


		// Free thread arguments
		delete (struct thread_args_s*)arg;
		arg = NULL;


		return (void*)-2;	// ERROR: Couldn't create new TFTP client session
	}


	// NOTE: Allocation of pthread_t
	//
	//  This data member, thread_args->thread_id, is
	//  allocated in TFTPD::loop() and freed here.


	// Free thread ID
	delete thread_id;
	thread_id = NULL;


	// Free thread arguments
	delete (struct thread_args_s*)arg;
	arg = NULL;


	// DEBUG
	sync_dprintf("[TFTPD_start_session] STOP\n");


	return (void*)1;
}


void* TFTPD::loop(void* arg)
{
	int ret;
	unsigned int bytes_address;
	struct tftp tftp_packet;
	struct thread_args_s* thread_args;
	struct sockaddr_in client_sockaddr_in;
	Thread* client_tid;


#ifdef __GNUC__


	unsigned int onoff;


#endif	// __GNUC__


	// Create TFTPD server socket
	Socket tftpd_sock(Socket::type::SOCK_UDP);
	if (tftpd_sock.get_fd() == -1)
	{
		sync_printf("[TFTPD::loop] ERROR: Couldn't create TFTPD server socket\n");


		return (void*)0;	// ERROR: Couldn't create TFTPD server socket
	}


	// Set reuse address socket option
	if (tftpd_sock.set_reuseaddr(true) < 1)
	{
		sync_printf("[TFTPD::loop] ERROR: Couldn't set reuse address socket option\n");


		return (void*)-1;	// ERROR: Couldn't set reuse address socket option
	}


#ifdef __GNUC__


	// Set don't fragment IP socket option
	onoff = IP_PMTUDISC_DONT;
	if (tftpd_sock.setsockopt(IPPROTO_IP,
		IP_MTU_DISCOVER,
		(const void*)&onoff,
		sizeof(unsigned int)) < 1)
	{
		sync_printf("[TFTPD::loop] ERROR: Couldn't set don't fragment IP socket option\n");


		return (void*)-2;	// ERROR: Couldn't set don't fragment IP socket option
	}


#endif	// __GNUC__


	// Bind to local port 69
	bytes_address = local_hostaddr;
	if (tftpd_sock.bind(bytes_address,
		IPPORT_TFTPD) < 1)
	{
		sync_printf("[TFTPD::loop] ERROR: Couldn't bind to local port 69\n");


		// Close TFTPD socket
		tftpd_sock.close();


		return (void*)-3;	// ERROR: Couldn't bind to local port 69
	}


	// DEBUG
	sync_dprintf("[TFTPD::loop] INFO: Start main loop\n");


	// Loop forever
	while (loop_forever)
	{
		// Read TFTP packet
		ret = tftpd.read_packet(tftpd_sock,
			&client_sockaddr_in,
			0,
			&tftp_packet);
		if (ret < 1)
		{
			sync_printf("[TFTPD::loop] ERROR: Couldn't read TFTP packet ret = %i\n",
				ret);


			// Close TFTPD socket
			tftpd_sock.close();


			return (void*)-4;	// ERROR: Couldn't read TFTP packet
		}


		// DEBUG
		sync_dprintf("[TFTPD::loop] INFO: New TFTP client connection\n");


		// Check opcode
		if (tftp_packet.opcode == TFTP_OPCODE_READ)
		{
			// NOTE: Read request
			//
			//  A read request from a new client address starts a new
			//  session for that client. All TFTP packets between this
			//  client and the server are handled in the TFTP client session.


			// NOTE: Thread arguments
			//
			//  For POSIX threads compatible thread interfaces, a newly created
			//  thread is passed a user defined pointer as argument.
			//
			//  A new thread arguments structure, defined by struct thread_args_s,
			//  is allocated on each thread creation. This structure is taken care
			//  of in the invoked function (the one that is passed the user defined
			//  pointer as argument).


			// Allocate new thread arguments
			thread_args = NULL;
			thread_args = new thread_args_s;
			if (thread_args == NULL)
			{
				sync_printf("[TFTPD::loop] ERROR: Couldn't allocate thread arguments\n");


				// Close TFTPD socket
				tftpd_sock.close();


				return (void*)-5;	// ERROR: Couldn't allocate thread arguments
			}


			// NOTE: Allocation of pthread_t
			//
			//  The object is freed in the free function
			//  RSHD_start_session().


			// Create thread ID for client
			client_tid = new Thread;
			if (client_tid == NULL)
			{
				sync_printf("[TFTPD::loop] ERROR: Couldn't allocate thread ID for client\n");


				// Free thread arguments
				delete thread_args;
				thread_args = NULL;


				// Close TFTPD socket
				tftpd_sock.close();


				return (void*)-6;	// ERROR: Couldn't allocate thread ID for client
			}


			// Create thread argument
			thread_args->thread_id = client_tid;
			thread_args->server_sock = &tftpd_sock;
			thread_args->client_sockaddr_in = client_sockaddr_in;
			thread_args->packet = tftp_packet;


			sync_printf("[TFTPD::loop] INFO: Starting new client session\n");


			// Create new session thread
			if (client_tid->create_thread((void*)TFTPD_start_session,
				(void*)thread_args) < 1)
			{
				sync_printf("[TFTPD::loop] ERROR: Couldn't create new session thread\n");


				// Free client TID
				delete client_tid;
				client_tid = NULL;


				// Free thread arguments
				delete thread_args;
				thread_args = NULL;


				// Close TFTPD socket
				tftpd_sock.close();


				return (void*)-7;	// ERROR: Couldn't create new session thread
			}
		}
	}


	return NULL;
}


int TFTPD::read_packet(Socket& tftpd_sock,			// - IN: TFTPD server socket
	struct sockaddr_in* client_addr,		// - IN: Client address
	unsigned int timeout_sec,		// - IN: Seconds of timeout
	struct tftp* packet)			// - OUT: TFTP packet
{
	char* parse_end;
	char* parse_pointer;
	char buffer[TFTP_MAX_PACKET_SIZE];
	unsigned int buffer_length;
	unsigned int mode_length;
	struct timeval timeout;
	struct timeval* timeout_pointer;
	socklen_t addr_length;
	fd_set read_fdset;


#ifdef _WIN32


	std::size_t pos_slash;


#endif	// _WIN32


	// IN: Check for negative TFTPD server socket value
	if (tftpd_sock.get_fd() < 0)
	{
		return 0;	// ERROR: Negative TFTPD server socket value
	}


#if defined(__sgi) || defined(__GNUC__)


	// IN: Check for overflow of TFTPD server socket value
	if (tftpd_sock.get_fd() >= FD_SETSIZE)
	{
		return -1;	// ERROR: Overflow of TFTPD server socket value
	}


#endif	// __sgi || __GNUC__


	// IN: Check for client address
	if (client_addr == NULL)
	{
		return -2;	// ERROR: No client address
	}


	// OUT: Check for packet
	if (packet == NULL)
	{
		return -3;	// ERROR: No TFTP packet
	}


	// DEBUG
	sync_dprintf("[TFTPD::read_packet] INFO: Reading TFTP packet (timeout %u seconds)\n",
		timeout_sec);


	// Check for timeout
	if (timeout_sec == 0)
	{
		timeout_pointer = NULL;
	}
	else
	{
		timeout.tv_sec = timeout_sec;
		timeout.tv_usec = 0;


		timeout_pointer = &timeout;
	}


	// Select with timeout
	FD_ZERO(&read_fdset);
	FD_SET(tftpd_sock.get_fd(), &read_fdset);
	switch (select(tftpd_sock.get_fd() + 1,
		&read_fdset,
		NULL,
		NULL,
		timeout_pointer))
	{
	case 0:

		// NOTE: Timeout expired


		sync_printf("[TFTPD::read_packet] ERROR: Timeout expired\n");


		return -4;	// ERROR: Timeout expired

	case 1:

		// NOTE: One descriptor ready


		// Read TFTP packet
		client_addr->sin_addr.s_addr = INADDR_ANY;
		client_addr->sin_port = htons(INPORT_ANY);
		addr_length = sizeof(struct sockaddr_in);
		buffer_length = recvfrom(tftpd_sock.get_fd(),
			buffer,
			TFTP_MAX_PACKET_SIZE,
			0,
			(struct sockaddr*)client_addr,
			&addr_length);
		if (buffer_length == -1)
		{
			sync_printf("[TFTPD::read_packet] ERROR: Couldn't read TFTP packet\n");


			return -5;	// ERROR: Couldn't read TFTP packet
		}


		break;

	case -1:

		// NOTE: Error occured


		sync_printf("[TFTPD::read_packet] ERROR: Error reading TFTP packet\n");


		return -6;	// ERROR: Error reading TFTP packet

	default:

		// NOTE: Never reached


		return -7;	// ERROR: Unexpected select() return value
	}



	// DEBUG
	sync_dprintf("[TFTPD::read_packet] INFO: Parsing TFTP packet\n");


	// NOTE: Parse TFTP packet


	// Initialize parse pointer
	parse_pointer = (char*)buffer;
	parse_end = (char*)(((unsigned long)buffer) + buffer_length);


	// Get opcode
	packet->opcode = *((unsigned short*)parse_pointer);
	packet->opcode = ntohs(packet->opcode);
	parse_pointer += 2;


	// DEBUG
	sync_dprintf("[TFTPD::read_packet] INFO: opcode = %u\n",
		packet->opcode);


	// Switch out by TFTP opcode
	switch (packet->opcode)
	{
	case TFTP_OPCODE_READ:

		// Parse filename (maximum 128 bytes, including terminating NULL byte)
		packet->rw.filename.clear();
		while (parse_pointer < parse_end)
		{
			// Check for filename terminating NULL byte
			if (*parse_pointer == '\0')
			{
				break;
			}


			// Copy byte
			packet->rw.filename += *parse_pointer;


			// Check for maximum filename length
			if (packet->rw.filename.length() == 128)
			{
				// NOTE: Filename overflow


				return -8;	// ERROR: Filename overflow
			}


			// Increment parse pointer
			parse_pointer++;
		}


		// Check for filename
		if (packet->rw.filename.length() == 0)
		{
			return -9;	// ERROR: No filename
		}


		// DEBUG
		sync_dprintf("[TFTPD::read_packet] INFO: filename (BEFORE) = %s\n",
			packet->rw.filename.c_str());


#ifdef _WIN32


		// NOTE: UNIX vs. WIN32 slashes
		//
		//  The filename requested by the client includes both types of
		//  path components: WIN32 path components at the beginning, and
		//  UNIX path components at the end.
		//
		//  For the sake of clarity and uniformity, on WIN32 platforms, the UNIX
		//  path components get their forward slashes replaced by WIN32 backslashes.
		//
		//  For efficiency reasons, the following algorithm applies to the whole string,
		//  not only a possible trailing UNIX path component.


		// Loop through filename
		pos_slash = 0;
		while (true)
		{
			// Get position of next forward slash
			pos_slash = packet->rw.filename.find_first_of('/',
				pos_slash);
			if (pos_slash == std::string::npos)
			{
				// NOTE: No forward slashes found


				break;
			}


			// Replace UNIX forward slashes with WIN32 backslashes							 )
			packet->rw.filename[pos_slash] = '\\';
		}


#endif


		// NOTE: Filename
		//
		//  The filename field in the TFTP packet must include a terminating
		//  NULL byte in its first 128 bytes because the BOOTP protocol enforces
		//  a limit of 128 bytes on the bootfile, including a terminating NULL byte.
		//
		//  Refer to the BOOTP protocol for more information.


		// DEBUG
		sync_dprintf("[TFTPD::read_packet] INFO: filename (AFTER) = %s\n",
			packet->rw.filename.c_str());


		// Check for remaining data bytes
		if (parse_pointer == parse_end)
		{
			return -10;	// ERROR: No remaining data bytes
		}


		// Parse filename terminating NULL byte
		if (*parse_pointer != '\0')
		{
			return -11;	// ERROR: No filename terminating NULL byte
		}


		// Increment parse pointer
		parse_pointer++;


		// Initialize mode buffer
		bzero((void*)packet->rw.mode_string,
			8 + 1);


		// Parse mode (maximum 5 bytes, not including terminating NULL byte)
		mode_length = 0;
		packet->rw.mode = 0;
		while (parse_pointer < parse_end)
		{
			// Copy byte
			packet->rw.mode_string[mode_length] = *parse_pointer;


			// Increment mode length
			mode_length++;


			// Check for supported modes
			if (mode_length == 5)
			{
				// NOTE: 'octet' mode


				// Check for octet mode
				if (strcmp(packet->rw.mode_string,
					"octet") == 0)
				{
					packet->rw.mode = 2;


					break;
				}
			}
			else if (mode_length == 8)
			{
				// NOTE: 'netascii' mode


				// Check for netascii mode
				if (strcmp(packet->rw.mode_string,
					"netascii") == 0)
				{
					packet->rw.mode = 1;
				}


				// Maximum mode string length
				break;
			}


			// Increment parse pointer
			parse_pointer++;
		}


		// Check for mode length
		if (mode_length == 0)
		{
			return -12;	// ERROR: No mode
		}


		// Check for supported modes
		if (packet->rw.mode == 0)
		{
			return -13;	// ERROR: No supported mode
		}


		// Increment parse pointer
		parse_pointer++;


		// DEBUG
		sync_dprintf("[TFTPD::read_packet] INFO: mode = \"%s\"\n",
			packet->rw.mode_string);


		// Check for remaining data bytes
		if (parse_pointer == parse_end)
		{
			return -14;	// ERROR: No remaining data bytes
		}


		// Parse mode terminating NULL byte
		if (*parse_pointer != '\0')
		{
			return -15;	// ERROR: No mode terminating NULL byte
		}


		// Increment parse pointer
		parse_pointer++;


		// DEBUG
		sync_dprintf("[TFTPD::read_packet] INFO: EOP\n");


		break;

	case TFTP_OPCODE_DATA:

		// DEBUG
		sync_dprintf("[TFTPD::read_packet] INFO: TFTP_OPCODE_DATA\n");


		break;

	case TFTP_OPCODE_ACK:

		// DEBUG
		sync_dprintf("[TFTPD::read_packet] INFO: TFTP_OPCODE_ACK\n");


		// Get block number
		packet->ack.block_number = *((unsigned short*)parse_pointer);
		packet->ack.block_number = ntohs(packet->ack.block_number);
		parse_pointer += 2;


		break;

	case TFTP_OPCODE_ERROR:

		// DEBUG
		sync_dprintf("[TFTPD::read_packet] INFO: TFTP_OPCODE_ERROR\n");


		break;

	default:

		// NOTE: Unsupported TFTP opcode


		sync_printf("[TFTPD::read_packet] ERROR: Unsupported TFTP opcode\n");


		return -17;	// ERROR: Unsupported TFTP opcode
	}


	// NOTE: Receive remaining packet from same client address


	return 1;	// SUCCESS
}


int TFTPD::write_packet(Socket& tftpd_client_sock,		// - IN: TFTPD client socket
	struct sockaddr_in* client_addr,	// - IN: Client address
	struct tftp* packet)			// - OUT: TFTP packet
{
	char buffer[TFTP_MAX_PACKET_SIZE];
	char* packet_pointer;
	unsigned short short_uint;
	int buffer_size;
	int buffer_written;
	unsigned int field_size;


	// IN: Check for TFTPD client socket
	if (tftpd_client_sock.get_fd() < 0)
	{
		return 0;	// ERROR: No TFTPD client socket
	}


	// IN: Check for client address
	if (client_addr == NULL)
	{
		return -1;	// ERROR: No client address
	}


	// OUT: Check for packet
	if (packet == NULL)
	{
		return -2;	// ERROR: No TFTP packet
	}


	// NOTE: Initialization


	bzero((void*)buffer,
		TFTP_MAX_PACKET_SIZE);
	buffer_size = 0;


	// NOTE: Build TFTP packet


	// DEBUG
	sync_dprintf("[TFTPD::write_packet] INFO: Building TFTP packet\n");


	// Switch out by opcode
	switch (packet->opcode)
	{
	case TFTP_OPCODE_READ:
	case TFTP_OPCODE_WRITE:
	case TFTP_OPCODE_DATA:

		// NOTE: DATA packet
		//
		//  A TFTP DATA packet is at most 516 bytes in size:
		//
		//    2 bytes    2 bytes       n bytes
		//    ---------------------------------
		//   | 03    |   Block #  |    Data    |
		//    ---------------------------------


		// Set packet pointer
		packet_pointer = (char*)buffer;


		// Copy opcode
		short_uint = htons(packet->opcode);
		field_size = sizeof(unsigned short);
		bcopy((void*)&short_uint,
			(void*)packet_pointer,
			field_size);
		packet_pointer += field_size;


		// NOTE: Casting from unsigned to signed
		//
		//  The following cast is only possible because overflow
		//  is guaranteed not to occur, because of the actual
		//  sizes of the fields.


		buffer_size += (int)field_size;


		// Copy block number
		short_uint = htons(packet->data.block_number);
		field_size = sizeof(unsigned short);
		bcopy((void*)&short_uint,
			(void*)packet_pointer,
			field_size);
		packet_pointer += field_size;
		buffer_size += (int)field_size;


		// Copy block
		field_size = packet->data.size;
		bcopy((void*)packet->data.block,
			(void*)packet_pointer,
			field_size);
		packet_pointer += field_size;
		buffer_size += (int)field_size;


		break;

	case TFTP_OPCODE_ACK:
	case TFTP_OPCODE_ERROR:
	default:


		break;
	}


	// DEBUG
	sync_dprintf("[TFTPD::write_packet] INFO: Writing TFTP packet\n");


#if defined(__sgi) || defined(__GNUC__)


	// Write TFTP packet
	buffer_written = ::sendto(tftpd_client_sock.get_fd(),
		(void*)buffer,
		buffer_size,
		0,
		(struct sockaddr*)client_addr,
		sizeof(struct sockaddr_in));


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Write TFTP packet
	buffer_written = ::sendto(tftpd_client_sock.get_fd(),
		(const char*)buffer,
		buffer_size,
		0,
		(struct sockaddr*)client_addr,
		sizeof(struct sockaddr_in));


#endif	// _WIN32


	if (buffer_written != buffer_size)
	{
		// Check for error
		if (buffer_written == -1)
		{
			return -3;	// ERROR: Error writing TFTP packet
		}
		else
		{
			return -4;	// ERROR: Couldn't write whole TFTP packet
		}
	}


	return 1;	// SUCCESS
}


int TFTPD::generate_tid(unsigned short& tid)    // - OUT: Generated TID
{
	bool is_dup;
	unsigned short rand_num_1;
	unsigned int loop_counter;
	std::vector<unsigned short>::iterator it;


#if defined(__sgi) || defined(__GNUC__)


	long rand_num_0;
	struct timespec time_spec;


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	unsigned int rand_num_0;


#endif	// _WIN32


	// Check for free TIDs
	if (this->tids.size() == TFTPD_TIDS_MAX)
	{
		return 0;       // ERROR: No free TIDs
	}


	// Acquire TID mutex
	if (this->tid_mutex.lock_mutex() < 1)
	{
		return -1;	// ERROR: Couldn't acquire TID mutex
	}


	// Check for sequential TID processing
	if (this->seq_tid == true)
	{
		// Check for zero last TID
		if (this->last_tid == 0)
		{
			// OUT: Generate sequential TID
			this->generate_seq_tid(0,
				tid);
		}
		else
		{
			// OUT: Generate sequential TID
			this->generate_seq_tid(this->last_tid + 1,
				tid);
		}


		// Set last TID
		this->last_tid = tid;


		// Insert ordered TID
		this->insert_ordered(tid,
			true);


		// Release TID mutex
		if (this->tid_mutex.unlock_mutex() < 1)
		{
			return -2;	// ERROR: Couldn't release TID mutex
		}


		return 2;       // SUCCESS: Sequential TID generated
	}


	// Find free TID
	loop_counter = 0;
	while (true)
	{
		// Increment loop counter
		loop_counter++;


#if defined(__sgi) || defined(__GNUC__)


		// Get a random number
		if (clock_gettime(CLOCK_REALTIME,
			&time_spec) == -1)
		{
			rand_num_0 = 1234567;
		}
		else
		{
			rand_num_0 = time_spec.tv_nsec;
		}


#endif	// __sgi || __GNUC__


#ifdef _WIN32


		// Get a random number
		if (rand_s(&rand_num_0) != 0)
		{
			rand_num_0 = 1234567;
		}


#endif	// _WIN32


		// Generate random TID
		rand_num_1 = ((unsigned long)rand_num_0) % TFTPD_TIDS_MAX;


		// Traverse TIDs
		is_dup = false;
		for (it = this->tids.begin();
			it < this->tids.end();
			it++)
		{
			// Check for duplicate TID
			if (rand_num_1 == *it)
			{
				is_dup = true;


				break;
			}
		}


		// Check for duplicate
		if (is_dup != true)
		{
			// NOTE: Generated new TID


			break;
		}


		// Increment seed
		this->seed_num++;


		// NOTE: Collision detector
		//
		//  If the loop repeats 101 times, it is considered to behave
		//  like an infinite loop and is immediately terminated.
		//
		//  This occurs when too many TIDs have been generated, so that
		//  any subsequent randomly generated TID collides with an existing
		//  one.
		//
		//  In this scenario, new TIDs are generated starting from 0 and
		//  counting upwards in increments of 1 (one).


		// Detect infinite loop
		if (loop_counter > 100)
		{
			// NOTE: Infinite loop


			// Set sequential TID processing
			this->seq_tid = true;


			// Generate sequential TID
			rand_num_1 = 0;
			this->generate_seq_tid(0,
				rand_num_1);


			// Reset seed number
			this->seed_num = 0;


			// Set last TID
			this->last_tid = rand_num_1;


			break;
		}
	}


	// Insert ordered TID
	this->insert_ordered(rand_num_1,
		false);


	// OUT: Set generated TID
	tid = rand_num_1;


	// Release TID mutex
	if (this->tid_mutex.unlock_mutex() < 1)
	{
		return -3;	// ERROR: Couldn't release TID mutex
	}


	return 1;       // SUCCESS: TID generated
}


int TFTPD::remove_tid(unsigned short& tid)     // - IN: TID to remove
{
	std::vector<unsigned short>::iterator it;


	// NOTE: Calling context
	//
	//  This member function is synchronized with TFTPD::generate_tid().


	// Acquire TID mutex
	if (this->tid_mutex.lock_mutex() < 1)
	{
		return 0;	// ERROR: Couldn't acquire TID mutex
	}


	// Check for sequential TID processing
	if (this->seq_tid == true)
	{
		// NOTE: Sequential TID processing


		if (tid == this->last_tid)
		{
			if (this->last_tid != 0)
			{
				this->last_tid -= 1;
			}
		}
		else if (tid < this->last_tid)
		{
			if (tid == 0)
			{
				this->last_tid = 0;
			}
			else
			{
				this->last_tid = tid - 1;
			}
		}
		else
		{
			// HINT: tid > this->last_tid
		}
	}
	else
	{
		// NOTE: No sequential TID processing
		//
		//  Just remove TID from this->tids.
	}


	// Traverse TIDs
	for (it = this->tids.begin();
		it < this->tids.end();
		it++)
	{
		// Check for TID
		if (*it == tid)
		{
			// NOTE: TID found


			this->tids.erase(it);


			break;
		}
	}


	// Release TID mutex
	if (this->tid_mutex.unlock_mutex() < 1)
	{
		return -1;	// ERROR: Couldn't release TID mutex
	}


	return 1;	// SUCCESS
}


void TFTPD::generate_seq_tid(unsigned short start_tid,  // - IN: Starting TID
	unsigned short& rand_num)  // - OUT: Next sequential TID
{
	unsigned short tid_index;
	std::vector<unsigned short>::iterator it;


	// NOTE: Calling context
	//
	//  This member function is invoked with a this->tids vector that is
	//  not full yet (there are still free TIDs to claim) and with a starting
	//  TID (start_tid) to speed up lookups of the next sequential TID.
	//
	//  In addition, the starting TID is passed as either 0 (initial call),
	//  or subsequently as this->last_tid + 1. This value is just a hint about
	//  the TID value that could be free next, not a guarantee about the next
	//  free value.
	//
	//  The only guarantee is that all numbers strictly less than start_tid are
	//  claimed (i.e. not free) TIDs.


	// NOTE: Initialization


	rand_num = 0;


	// Traverse TIDs
	tid_index = start_tid;
	for (it = this->tids.begin();
		it < this->tids.end();
		it++)
	{
		// NOTE: Ordered TIDs
		//
		//  The TIDs stored in this->tids are ordered.


		// Check for greater TID
		if (*it > tid_index)
		{
			// NOTE: Greater TID
			//
			//  Check only for the first TID that is greater.
			//
			//  Also, this loop always succeeds because this->tids
			//  is not full yet.
			//
			//  Either a greater TID is found, or all TIDs are smaller.


			break;
		}
		else if (*it == tid_index)
		{
			// NOTE: Equal TID


			// Increment TID index
			tid_index++;
		}


		// NOTE: Equal or lower TID
	}


	// OUT: Set sequential TID
	rand_num = tid_index;
}


void TFTPD::insert_ordered(unsigned short rand_num,     // - IN: Random number to be inserted
	bool is_seq)                 // - IN: Flag indicating rand_num is a sequential TID
{
	bool index_found;
	std::vector<unsigned short>::iterator it;


	// Check for sequential TID
	if (is_seq == true)
	{
		// Set iterator
		it = this->tids.begin() + rand_num;


		// Set index found flag
		index_found = true;
	}
	else
	{
		// Traverse TIDs
		index_found = false;
		for (it = this->tids.begin();
			it < this->tids.end();
			it++)
		{
			// Check for first TID that is greater
			if (*it > rand_num)
			{
				// NOTE: Index found


				index_found = true;


				break;
			}
		}
	}


	// Check for found index
	if (index_found == true)
	{
		// Insert at iterator position
		this->tids.insert(it,
			rand_num);
	}
	else
	{
		// Insert at the end
		this->tids.push_back(rand_num);
	}
}


void* TFTPD_loop(void* arg)
{
	tftpd.loop(arg);


	return NULL;
}


int SNOOPI::init()
{
#ifdef __sgi


	// Create raw socket
	this->raw_sock = socket(PF_RAW,
		SOCK_RAW,
		RAWPROTO_SNOOP);
	if (this->raw_sock == -1)
	{
		return 0;	// ERROR: Couldn't create raw socket
	}


#elif defined(__GNUC__)


	// Create raw paket 
	this->raw_sock = socket(PF_PACKET,
		SOCK_RAW,
		htons(ETHER_TYPE));
	if (this->raw_sock == -1)
	{
		return 0;	// ERROR: Couldn't create raw packet socket
	}


#endif	// __sgi


	return 1;	// SUCCESS
}


int SNOOPI::deinit()
{
#ifdef __sgi


	// Close raw socket
	::love_close(this->raw_sock);
	this->raw_sock = -1;


#endif


	return 1;	// SUCCESS
}


int SNOOPI::start(char* nif_name)
{
#ifdef __sgi


	int rcv_buf;
	unsigned int on;
	struct snoopfilter snoop_filter;
	struct sockaddr_raw raw_address;


	// IN: Check for network interface name
	if (nif_name == NULL)
	{
		return 0;	// ERROR: No network innterface name
	}


	// Check for empty network interface name
	if (nif_name[0] == '\0')
	{
		return -1;	// ERROR: Empty network interface name
	}


	// Bind snoop socket to corresponding network interface
	raw_address.sr_family = AF_RAW;
	raw_address.sr_port = 0;
	strncpy(raw_address.sr_ifname,
		nif_name,
		sizeof(raw_address.sr_ifname));
	if (bind(this->raw_sock,
		&raw_address,
		sizeof(struct sockaddr_raw)) == -1)
	{
		return -2;	// ERROR: Couldn't bind snoop socket to corresponding network interface
	}


	// Add filter to snoop socket
	bzero((char*)&snoop_filter,
		sizeof(struct snoopfilter));
	if (ioctl(this->raw_sock,
		SIOCADDSNOOP,
		&snoop_filter) == -1)
	{
		return -3;	// ERROR: Couldn't add snoop filter
	}


	// Increase receive buffer for snoop socket
	rcv_buf = 60000;
	if (setsockopt(this->raw_sock,
		SOL_SOCKET,
		SO_RCVBUF,
		(char*)&rcv_buf,
		sizeof(int)) == -1)
	{
		return -4;	// ERROR: Couldn't increase receive buffer for snoop socket
	}


	// Start snooping
	on = 1;
	if (ioctl(this->raw_sock,
		SIOCSNOOPING,
		&on) == -1)
	{
		return -5;	// ERROR: Couldn't start snooping on socket
	}


#elif defined(__GNUC__)


	int sock_opt;
	struct ifreq if_opts;
	struct ifreq if_ip;


	// IN: Check for network interface name
	if (nif_name == NULL)
	{
		return 0;	// ERROR: No network innterface name
	}


	// Get interface flags
	if_opts.ifr_name[0] = '\0';
	strcat(if_opts.ifr_name,
		nif_name);
	if (ioctl(this->raw_sock,
		SIOCGIFFLAGS,
		&if_opts) == -1)
	{
		return -1;	// ERROR: Couldn't get interface flags
	}


	// Set promicuous mode on interface
	if_opts.ifr_flags |= IFF_PROMISC;


	// Set interface flags
	if (ioctl(this->raw_sock,
		SIOCSIFFLAGS,
		&if_opts) == -1)
	{
		return -2;	// ERROR: Couldn't set interface flags
	}


	// Set socket option SO_REUSEADDR
	if (setsockopt(this->raw_sock,
		SOL_SOCKET,
		SO_REUSEADDR,
		&sock_opt,
		sizeof(sock_opt)) == -1)
	{
		return -3;	// ERROR: Couldn't set socket option SO_REUSEADDR
	}


	// Bind socket to device
	if (setsockopt(this->raw_sock,
		SOL_SOCKET,
		SO_BINDTODEVICE,
		nif_name,
		IFNAMSIZ - 1) == -1)
	{
		return -4;	// ERROR: Couldn't bind socket to device
	}


#endif	// __sgi


#ifdef _WIN32


	char error_buffer[PCAP_ERRBUF_SIZE];


	// IN: Check for network interface name
	if (nif_name == NULL)
	{
		return 0;	// ERROR: No network innterface name
	}


	// Check for empty network interface name
	if (nif_name[0] == '\0')
	{
		return -1;	// ERROR: Empty network interface name
	}


	// Open the network device
	this->dev_handle = NULL;
	this->dev_handle = pcap_open(nif_name,
		65536,
		PCAP_OPENFLAG_PROMISCUOUS |
		PCAP_OPENFLAG_MAX_RESPONSIVENESS,
		0,
		NULL,
		error_buffer);
	if (this->dev_handle == NULL)
	{
		return -2;	// ERROR: Couldn't open network device
	}


#endif	// _WIN32


	return 1;	// SUCCESS
}


int SNOOPI::stop()
{
#ifdef __sgi


	unsigned int on;


	// Check for raw socket
	if (this->raw_sock == -1)
	{
		return 0;	// ERROR: No raw socket
	}


	// Stop snooping
	on = 0;
	if (ioctl(this->raw_sock,
		SIOCSNOOPING,
		&on) == -1)
	{
		return -1;	// ERROR: Couldn't stop snooping on socket
	}


#elif defined(__GNUC__)


	// Check for raw packet socket
	if (this->raw_sock == -1)
	{
		return 0;	// ERROR: No raw packet socket
	}


#elif defined(_WIN32)


	// Check for network device handle
	if (this->dev_handle == NULL)
	{
		return 0;	// ERROR: No network device handle
	}


	// Close network device
	pcap_close(this->dev_handle);


	// Reset network device
	this->dev_handle = NULL;


#endif	// __sgi


	return 1;	// SUCCESS
}


#if defined(__sgi) || defined(__GNUC__)


int SNOOPI::get_fd()
{
	return this->raw_sock;
}


#endif	// __sgi


int SNOOPI::read_ethernet_packet(struct etherpacket* ethernet_packet,	// - OUT: Ethernet packet
	size_t ep_size)			// - IN: Size of ethernet packet
{
	int ret;


#if defined(__sgi) || defined(__GNUC__) || defined(_WIN32)


	// OUT: Check for ethernet packet
	if (ethernet_packet == NULL)
	{
		return 0;	// ERROR: No ethernet packet
	}


	// IN: Check for size
	if (ep_size == 0)
	{
		return -1;	// ERROR: No size
	}


#endif	// __sgi || __GNUC__ || _WIN32


#if defined(__sgi) || defined(__GNUC__)


	// Check for raw socket
	if (this->raw_sock == -1)
	{
		return -2;	// ERROR: No raw socket
	}


#ifdef __sgi


	// Read ethernet packet
	ret = ::read(this->raw_sock,
		(char*)ethernet_packet,
		ep_size);
	if (ret == -1)
	{
		return -3;	// ERROR: Couldn't read ethernet packet
	}


#elif defined(__GNUC__)


	// Read ethernet packet
	ret = ::recvfrom(this->raw_sock,
		ethernet_packet,
		ep_size,
		0,
		NULL,
		NULL);
	if (ret == -1)
	{
		return -3;	// ERROR: Couldn't read ethernet packet
	}


#endif	// __sgi


#endif	// __sgi


#ifdef _WIN32


	struct pcap_pkthdr* packet_header;
	const unsigned char* packet_data;


	// Check for network device handle
	if (this->dev_handle == NULL)
	{
		return -2;	// ERROR: No network device handle
	}


	// Read ethernet packets
	while (loop_forever)
	{
		// Read ethernet packet
		ret = pcap_next_ex(this->dev_handle,
			&packet_header,
			&packet_data);
		switch (ret)
		{
		case 0:

			// NOTE: Packet buffer timeout expired


			continue;

		case 1:

			// NOTE: Read a packet


			break;

		default:

			// NOTE: Error


			return -3;	// ERROR: Couldn't read ethernet packet
		}


		// Check for valid captured data length
		if (packet_header->caplen > ep_size)
		{
			// NOTE: Skip invalid packets


			continue;
		}


		// Copy ethernet frame
		bcopy((void*)packet_data,
			(void*)ethernet_packet,
			packet_header->caplen);


		break;
	}


#endif	// _WIN32


	return 1;	// SUCCESS
}


int Tracelog::open(const std::string& tracelog)	// - IN: Path to tracelog file
{
#if defined(__sgi) || defined(__GNUC__)


	mode_t open_mode;


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	int open_mode;


#endif	// _WIN32


	// IN: Check for empty tracelog
	if (tracelog.empty() == true)
	{
		return 0;	// ERROR: Empty tracelog
	}


	// Check for open tracelog
	if (this->fd > -1)
	{
		if (this->close() < 1)
		{
			return -1;	// ERROR: Couldn't close previously opened tracelog
		}
	}


#if defined(__sgi) || defined(__GNUC__)


	// Set open mode
	open_mode = S_IRUSR |
		S_IWUSR;


#endif	// __sgi || __GNUC__


#ifdef _WIN32


	// Set open mode
	open_mode = _S_IREAD |
		_S_IWRITE;


#endif	// _WIN32


	// Open tracelog
	this->fd = ::love_open(tracelog.c_str(),
		O_WRONLY |
		O_CREAT |
		O_TRUNC,
		open_mode);
	if (this->fd == -1)
	{
		return -2;	// ERROR: Couldn't open tracelog
	}


	return 1;	// SUCCESS
}


int Tracelog::write(const std::string& string)	// - IN: String to write to tracelog
{
	unsigned long string_length;


	// IN: Check for empty log string
	if (string.empty() == true)
	{
		return 0;	// ERROR: Empty log string
	}


	// Check for open tracelog
	if (this->fd == -1)
	{
		return -1;	// ERROR: No open tracelog
	}


	// Write log string
	string_length = (unsigned long)string.length();
	if (::love_write(this->fd,
		(const void*)string.c_str(),
		string_length) != (long)string_length)
	{
		return -2;	// ERROR: Couldn't write log string
	}


	return 1;	// SUCCESS
}


int Tracelog::close()
{
	// Check for open tracelog
	if (this->fd == -1)
	{
		return 0;	// ERROR: No open tracelog
	}


	// Close tracelog
	if (::love_close(this->fd) == -1)
	{
		return -1;	// ERROR: Couldn't close tracelog
	}


	// Reset tracelog file descriptor
	this->fd = -1;


	return 1;	// SUCCESS
}


int main(int argc,	// - IN: Number of command line arguments
	char* argv[])	// - IN: Array of pointers to command line arguments
{
	int ret;
	int return_code;
	int local_errno;
	unsigned int label_type;
	bool wants_lines;
	bool args_error;
	bool args_check_debug;
	bool args_check_trace;
	char* args_debug_char;
	char* args_trace_char;
	char nif_name[IFNAMSIZ];
	char resolved_path[MAXPATHLEN];
	struct etherpacket ethernet_packet;
	struct in_addr client_ip;
	struct bootp bootp_request;
	PATH tftp_path;
	std::string path;
	std::string label;
	std::string label_path;
	std::string local_path;
	std::string tracelog_file;
	std::string local_hostname;
	std::string label_filename;
	std::vector<LABEL_FILE::LINE*> discard_lines;


#ifdef _WIN32


	unsigned short version_req;
	WSADATA wsa_data;


	::LoadNpcapDlls();


	// Request Winsock 2.2
	version_req = MAKEWORD(2, 2);
	ret = WSAStartup(version_req,
		&wsa_data);
	if (ret != 0)
	{
		printf("ERROR: Couldn't initialize Winsock 2.2\n");


		return 0;	// ERROR: Couldn't initialize Winsock 2.2
	}


	// Check for requested Winsock version 2.2
	if ((LOBYTE(wsa_data.wVersion) != 2) ||
		(HIBYTE(wsa_data.wVersion) != 2))
	{
		printf("ERROR: Couldn't request Winsock version 2.2\n");


		// Cleanup WSA
		WSACleanup();


		return -1;	// ERROR: Couldn't request Winsock version 2.2
	}


#endif	// _WIN32


	// Switch out by argument number
	return_code = 0;
	args_error = false;
	args_check_debug = false;
	args_check_trace = false;
	args_debug_char = NULL;
	args_trace_char = NULL;
	switch (argc)
	{
	case 3:

		// HINT: For example, ./love 192.168.178.100 LABELS.TXT


		// Set argument pointers
		local_hostname = argv[1];
		label_filename = argv[2];


		break;

	case 4:

		// HINT: For example, ./love -d 192.168.178.100 LABELS.TXT


		// Set argument pointers
		args_debug_char = argv[1];
		args_check_debug = true;
		local_hostname = argv[2];
		label_filename = argv[3];


		break;

	case 5:

		// HINT: For example, ./love -t trace.log 192.168.178.100 LABELS.TXT


		// Set argument pointers
		args_trace_char = argv[1];
		args_check_trace = true;
		tracelog_file = argv[2];
		local_hostname = argv[3];
		label_filename = argv[4];


		break;

	case 6:

		// HINT: For example, ./love -d -t trace.log 192.168.178.100 LABELS.TXT


		// Set argument pointers
		args_debug_char = argv[1];
		args_check_debug = true;
		args_trace_char = argv[2];
		args_check_trace = true;
		tracelog_file = argv[3];
		local_hostname = argv[4];
		label_filename = argv[5];


		break;

	default:

		// HINT: Argument error


		args_error = true;


		return_code = -2;


		break;
	}


	// Check for argument error
	if (args_error != true)
	{
		// NOTE: No argument error
		//
		//  Number of arguments is correct. Check argument switches.


		// Check for debug mode switch
		if (args_check_debug == true)
		{
			// Check for argument string "-d"
			if ((args_debug_char[0] != '-') ||
				(args_debug_char[1] != 'd') ||
				(args_debug_char[2] != '\0'))
			{
				args_error = true;


				return_code = -3;
			}
			else
			{
				args_debug = true;
			}
		}


		// Check for trace mode switch
		if (args_check_trace == true)
		{
			// Check for argument string "-t"
			if ((args_trace_char[0] != '-') ||
				(args_trace_char[1] != 't') ||
				(args_trace_char[2] != '\0'))
			{
				args_error = true;


				return_code = -4;
			}
			else
			{
				args_trace = true;
			}
		}
	}


	// Check for argument error
	if (args_error != true)
	{
		// NOTE: No argument error
		//
		//  Argument switches are valid. Check arguments.


		// Check for trace mode switch
		if (args_trace == true)
		{
			// Check for tracelog file
			if (tracelog_file.empty() == true)
			{
				args_error = true;


				return_code = -5;
			}
		}


		ret = 0;
		local_errno = 0;
		if ((ret++, (local_hostname.empty() == true)) ||
			(ret++, (::love_gethostbyname(local_hostname.c_str(),
				&local_hostaddr,
				&local_errno) < 1)) ||
			(ret++, (label_filename.empty() == true)) ||


#if defined(__sgi) || defined(__GNUC__)


			(ret++, (realpath(label_filename.c_str(),
				resolved_path) == NULL)))


#elif defined(_WIN32)


			(ret++, (GetFullPathNameA(label_filename.c_str(),
				MAXPATHLEN,
				resolved_path,
				NULL) == 0)))


#endif	// _WIN32


		{
			// Set argument error
			args_error = true;


			// Switch out by result
			switch (ret)
			{
			case 1:

				// HINT: (local_hostname[0] == '\0')


				return_code = -6;


				break;

			case 2:

				// HINT: (gethostbyname(local_hostname) == NULL)


				printf("ERROR: Couldn't resolve local hostname %s\n",
					local_hostname.c_str());


				return_code = -7;


				break;

			case 3:

				// HINT: (label_filename[0] == '\0')


				return_code = -8;


				break;

			case 4:

				// HINT: (realpath(label_filename,
				//		   resolved_path ) == NULL)


				printf("ERROR: Couldn't resolve path of label file\n");


				return_code = -9;


				break;

			default:

				// NOTE: Never reached


				return_code = -10;


				break;
			}
		}
	}


	// Check for argument error
	if (args_error == true)
	{
		// Print syntax
		print_syntax();


#ifdef _WIN32


		// Cleanup WSA
		if (WSACleanup() == SOCKET_ERROR)
		{
			printf("WARNING: Couldn't cleanup WSA\n");
		}


#endif	// _WIN32


		return return_code;	// ERROR: Argument error
	}


	// NOTE: Initialization
	//
	//  The first step is to check for trace mode. If it is enabled,
	//  open the tracelog file.
	//
	//  The second step is to read and parse the label file for the
	//  first time, to show the user what labels are recognized and valid.
	//
	//  Labels are not stored internally, instead the label file is reread
	//  and reparsed on every BOOTP client connection. This is done so the
	//  user can modify the labels at anytime, also during execution of this
	//  program.


	// Check for trace mode
	if (args_trace == true)
	{
		// Open tracelog
		trace_log.open(tracelog_file);
	}


	// Create printf mutex
	if (printf_mutex.create_mutex() < 1)
	{
		printf("ERROR: Couldn't initialize printf mutex\n");


		// Check for trace mode
		if (args_trace == true)
		{
			// Close tracelog
			trace_log.close();
		}


#ifdef _WIN32


		// Cleanup WSA
		if (WSACleanup() == SOCKET_ERROR)
		{
			printf("WARNING: Couldn't cleanup WSA\n");
		}


#endif	// _WIN32


		return 0;	// ERROR: Couldn't initialize printf mutex
	}


	// NOTE: printf mutex is in effect


	// DEBUG
	sync_dprintf("[::main] START\n");


	// Initialize TFTPD
	if (tftpd.init() < 1)
	{
		sync_printf("ERROR: Couldn't initialize TFTPD\n");


		// Check for trace mode
		if (args_trace == true)
		{
			// Close tracelog
			trace_log.close();
		}


#ifdef _WIN32


		// Cleanup WSA
		if (WSACleanup() == SOCKET_ERROR)
		{
			sync_printf("WARNING: Couldn't cleanup WSA\n");
		}


#endif	// _WIN32


		// Destroy printf mutex
		if (printf_mutex.destroy_mutex() < 1)
		{
			sync_printf("WARNING: Couldn't destroy printf mutex\n");
		}


		return -1;	// ERROR: Couldn't initialize TFTPD
	}


	// Parse label file
	labels_path = resolved_path;
	wants_lines = false;
	labels.parse_file(labels_path,
		wants_lines,
		discard_lines);


	// Start TFTPD daemon
	tftpd.start();


	// Start RSHD daemon
	rshd.start();


	// NOTE: Initialize SNOOPI
	//       Match local host address with network interface
	//       Start SNOOPI


	ret = 0;
	if ((ret++, (snoopi.init() < 1)) ||
		(ret++, (nif.check_addr(snoopi,
			local_hostaddr,
			nif_name) < 1)) ||
		(ret++, (snoopi.start(nif_name) < 1)))
	{
		// NOTE: Error


		switch (ret)
		{
		case 1:

			// HINT: (snoopi.init() < 1)


			sync_printf("ERROR: Couldn't initialize SNOOPI\n");


			ret = -11;


			break;

		case 2:

			// HINT: (nif.check_addr(snoopi,
			//			 local_hostaddr,
			//			 nif_name))


			sync_printf("ERROR: Couldn't find network interface for given address\n");


			// Deinitialize SNOOPI
			snoopi.deinit();


			ret = -12;


			break;

		case 3:

			// HINT: (snoopi.start(nif_name) < 1)


			sync_printf("ERROR: Couldn't start SNOOPI\n");


			// Deinitialize SNOOPI
			snoopi.deinit();


			ret = -13;


			break;

		default:

			// NOTE: Never reached


			sync_printf("ERROR: Unexpected return value during initialization\n");


			ret = -14;


			break;
		}


		// NOTE: Error handling


		// Deinitialize TFTPD
		if (tftpd.deinit() < 1)
		{
			sync_printf("WARNING: Couldn't deinitialize TFTPD\n");
		}


		// Check for trace mode
		if (args_trace == true)
		{
			// Close tracelog
			trace_log.close();
		}


#ifdef _WIN32


		// Cleanup WSA
		if (WSACleanup() == SOCKET_ERROR)
		{
			sync_printf("WARNING: Couldn't cleanup WSA\n");
		}


#endif	// _WIN32


		// Destroy printf mutex
		if (printf_mutex.destroy_mutex() < 1)
		{
			sync_printf("WARNING: Couldn't destroy printf mutex\n");
		}


		return ret;	// ERROR: See switch above
	}


	sync_printf("INFO: Listening for BOOTP packets\n");


	// Loop
	while (loop_forever)
	{
		// Read ethernet packet
		ret = snoopi.read_ethernet_packet(&ethernet_packet,
			sizeof(struct etherpacket));
		if (ret < 1)
		{
			sync_printf("ERROR: Couldn't read ethernet packet ret = %i\n",
				ret);


			ret = -15;	// ERROR: Couldn't read ethernet packet


			break;
		}


		// Get BOOTP request
		label.clear();
		path.clear();
		ret = bootpd.get_request(&ethernet_packet,
			&bootp_request,
			&client_ip,
			label,
			path);
		if (ret >= 1)
		{
			// NOTE: BOOTP request with label
			//
			//  It is assumed that all BOOTP requests contain a love label.
			//
			//  If a love label is not found in the BOOTP request, this server does
			//  not send any response.


			// DEBUG
			sync_dprintf("[::main] BOOTP: label = \"%s\"\n",
				label.c_str());
			sync_dprintf("[::main] BOOTP: path = \"%s\"\n",
				path.c_str());


			// Lookup label
			label_path.clear();
			label_type = LABEL_FILE::LINE::TYPE_NONE;
			if (labels.lookup_label(label,
				true,
				labels_path,
				label_path,
				label_type) >= 1)
			{
				// NOTE: Requested label found


				// DEBUG
				sync_dprintf("[::main] LOOKUP_LABEL: label = \"%s\" -> label_path = \"%s\" label_type = %u\n",
					label.c_str(),
					label_path.c_str(),
					label_type);


				// Set TFTP path
				ret = tftp_path.set(label_path);
				if (ret < 1)
				{
					sync_printf("[::main] WARNING: Couldn't set TFTP path from label_path = \"%s\" (ret = %i)\n",
						label_path,
						ret);


					continue;
				}


				// Check label type
				if (label_type == LABEL_FILE::LINE::TYPE_INSTALLATION)
				{
					// NOTE: Installation label


					// NOTE: Path root
					//
					//  The path following the label name must always begin with a forward slash.


					// Check for leading '/'
					if (path.at(0) != '/')
					{
						sync_printf("[::main] WARNING: Path does not begin with '/' = \"%s\"\n",
							path.c_str());


						continue;
					}


					// NOTE: Add path components
					//
					//  Path components must not be passed as an absolute pathname to an existing
					//  path object.


					// Delete leading '/'
					path.erase(path.begin());


					// Add IRIX path components
					ret = tftp_path.add_components(path,
						PATH::os_type::UNIX_OS);
					if (ret < 1)
					{
						sync_printf("[::main] WARNING: Couldn't add path components = \"%s\" to TFTP path = \"%s\" (ret = %i)\n",
							path,
							local_path.c_str(),
							ret);


						continue;
					}


					// NOTE: Access security
					//
					//  Label translation is set by the user, but the path component is sent by the client
					//  and can be, literally, any ASCII string.
					//
					//  To prevent unauthorized and unexpected file access, all path components must reside
					//  under the translated label path root.
					//
					//  Therefore, dot dot ("..") special directory components are not allowed.


					// Check for dot dot special directory
					if (tftp_path.contains_dotdot() == true)
					{
						sync_printf("[::main] WARNING: Requested path = \"%s\" contains \"..\" component\n",
							local_path.c_str());


						continue;
					}
				}
				else if (label_type == LABEL_FILE::LINE::TYPE_STANDALONE)
				{
					// NOTE: Standalone label
				}


				// Get local path for TFTP path
				local_path.clear();
				ret = tftp_path.get_local(local_path);
				if (ret < 1)
				{
					sync_printf("[::main] WARNING: Couldn't get local path for TFTP path (ret = %i)\n",
						ret);


					continue;
				}


				// DEBUG
				sync_dprintf("[::main] INFO_LOCAL: local path = \"%s\"\n",
					local_path.c_str());


				// Check for existence of requested path
				if (REGULAR_FILE::exists(local_path) == true)
				{
					// NOTE: Requested path exists


					// Reply BOOTP packet with TFTP path
					ret = bootpd.send_reply(&bootp_request,
						local_path,
						false);


					// DEBUG
					sync_dprintf("[::main] PATH: send_reply = %i\n",
						ret);
				}
				else
				{
					// NOTE: Requested path does not exist
					//
					//  Return requested path with nullified boot filename.
					//  
					//  A nullified boot filename is a string with its first
					//  character substituted by '\0'.


					// Reconstruct original requested path
					local_path = label + '/' + path;


					// Reply BOOTP packet with TFTP path
					ret = bootpd.send_reply(&bootp_request,
						local_path,
						true);


					// DEBUG
					sync_dprintf("[::main] PATHNULL: send_reply = %i\n",
						ret);
				}
			}
		}
	}


	// Stop SNOOPI
	if (snoopi.stop() < 1)
	{
		sync_printf("WARNING: Couldn't stop SNOOPI\n");
	}


	// Deinitialize SNOOPI
	if (snoopi.deinit() < 1)
	{
		sync_printf("WARNING: Couldn't deinitialize SNOOPI\n");
	}


	// Deinitialize TFTPD
	if (tftpd.deinit() < 1)
	{
		sync_printf("WARNING: Couldn't deinitialize TFTPD\n");
	}


#ifdef _WIN32


	// Cleanup WSA
	if (WSACleanup() == SOCKET_ERROR)
	{
		sync_printf("WARNING: Couldn't cleanup WSA\n");
	}


#endif	// _WIN32


	// Destroy printf mutex
	if (printf_mutex.destroy_mutex() < 1)
	{
		sync_printf("WARNING: Couldn't destroy printf mutex\n");
	}


	// Check for trace mode
	if (args_trace == true)
	{
		// Close tracelog
		trace_log.close();
	}


	// Check ethernet read error
	if (ret == -15)
	{
		return -15;
	}


	// NOTE: Never reached


	return 1;
}


#ifdef ECHO_BAK
#define ECHO ECHO_BAK
#undef ECHO_BAK
#endif


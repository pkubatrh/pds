#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <dirent.h>

#include <unordered_map>
#include <map>
#include <iostream>
#include <string>

#define _XOPEN_SOURCE 700

// flow structure
struct flow {
    uint32_t        sa_family;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    uint16_t        src_port;
    uint16_t        dst_port;
    uint64_t        packets;
    uint64_t        bytes;
};

// applies given mask to a ipv4 address
void apply_ipv4_mask(struct in6_addr *addr, uint16_t mask, char *ipstr) {
    uint8_t limit = 255;
    if (mask != 32) {
        for (int i = 12; i < 16; i++) {
            if (mask < 8) {
                addr->s6_addr[i] = addr->s6_addr[i] & (limit << (8-mask));
                mask = 0;
            }
            else {
                mask = mask - 8;
            }
        }
    }

    inet_ntop(AF_INET, &addr->s6_addr[12], ipstr, INET6_ADDRSTRLEN);
    return;
}

// applies given mask to a ipv6 address
void apply_ipv6_mask(struct in6_addr *addr, uint16_t mask, char *ipstr) {
    uint8_t limit = 255;
    if (mask != 128) {
        for (int i = 0; i < 16; i++) {
            if (mask < 8) {
                addr->s6_addr[i] = addr->s6_addr[i] & (limit << (8-mask));
                mask = 0;
            }
            else {
                mask = mask - 8;
            }
        }
    }

    inet_ntop(AF_INET6, addr, ipstr, INET6_ADDRSTRLEN);
    return;
}

// function used to read data from the given file and agregate them using std::unordered_map
void load_and_agreg(std::unordered_map<std::string, struct flow> *map, std::string dirname, DIR *dir, uint8_t ipv4mask, uint8_t ipv6mask, int agrflg) {
	dirent *dp = NULL;
	while ((dp = readdir(dir)) != NULL) {
		std::string filename = dp->d_name;
		if (filename == "." || filename == "..")
			// not useful
			continue;
		filename = dirname + "/" + dp->d_name;
		if (dp->d_type == DT_DIR) {
			//recursion
			DIR *newdir = opendir(filename.c_str());
			load_and_agreg(map, filename, newdir, ipv4mask, ipv6mask, agrflg);
			continue;
		}
		std::cout << filename << std::endl;
		FILE *fp = fopen(filename.c_str(), "rb");
		char ip[INET6_ADDRSTRLEN];
		struct flow fl;
	    size_t n = 0;
	    while ((n = fread(&fl, sizeof(struct flow), 1, fp)) != 0) {
	        std::string index;
            // check which agreg flag for the field by which to agregate
	        switch (agrflg) {
	            case 1:
	                index = std::to_string(ntohs(fl.src_port));
	                break;
	            case 2:
	                index = std::to_string(ntohs(fl.dst_port));
	                break;
                // agregation using ip field, needs to apply a mask
	            case 3:
	                if (ntohl(fl.sa_family) == AF_INET6) {
	                    apply_ipv6_mask(&fl.src_addr, ipv6mask, ip);
	                    index = ip;
	                }
	                else
	                    continue;
	                break;
	            case 4:
	                if (ntohl(fl.sa_family) == AF_INET6) {
	                    apply_ipv6_mask(&fl.dst_addr, ipv6mask, ip);
	                    index = ip;
	                }
	                else
	                    continue;
	                break;
	            case 5:
	                if (ntohl(fl.sa_family) == AF_INET) {
	                    apply_ipv4_mask(&fl.src_addr, ipv4mask, ip);
	                    index = ip;
	                }
	                else
	                    continue;
	                break;
	            case 6:
	                if (ntohl(fl.sa_family) == AF_INET) {
	                    apply_ipv4_mask(&fl.dst_addr, ipv4mask, ip);
	                    index = ip;
	                }
	                else
	                    continue;
	                break;
	            case 7:
	                if (ntohl(fl.sa_family) == AF_INET6) {
	                    apply_ipv6_mask(&fl.src_addr, ipv6mask, ip);
	                    index = ip;
	                }
	                else {
	                    apply_ipv4_mask(&fl.src_addr, ipv4mask, ip);
	                    index = ip;
	                }
	                break;
	            case 8:
	                if (ntohl(fl.sa_family) == AF_INET6) {
	                    apply_ipv6_mask(&fl.dst_addr, ipv6mask, ip);
	                    index = ip;
	                }
	                else {
	                    apply_ipv4_mask(&fl.dst_addr, ipv4mask, ip);
	                    index = ip;
	                }
	                break;
	            default:
	                fprintf(stderr, "Error\n");
	                return;
	        }

	        std::unordered_map<std::string, struct flow>::iterator iterator = map->find(index);
	        fl.src_port = ntohs(fl.src_port);
	        fl.dst_port = ntohs(fl.dst_port);
	        fl.packets = __builtin_bswap64(fl.packets);
	        fl.bytes = __builtin_bswap64(fl.bytes);
	        if (iterator == map->end()) {
	            map->operator[](index) = fl;
	        }
	        else {
	            fl.packets += iterator->second.packets;
	            fl.bytes += iterator->second.bytes;
	            map->operator[](index) = fl;
	        }
	    }
		fclose(fp);
	}
}

int main(int argc, char *argv[])
{
    int opt;
    int agrflg = 0; // agregation flag
    std::string agrname;
    uint8_t ipv4mask = 32;
    uint8_t ipv6mask = 128;
    char *filename;
    char ip[INET6_ADDRSTRLEN];
    std::string agreg;
    std::string sort;
    if (argc < 7) {
        fprintf(stderr, "Usage: flow -f directory -a aggregation -s sort\n");
        return (EXIT_FAILURE);
    }

    // cmdline arguments
    while ((opt = getopt(argc, argv, "f:a:s:")) != -1) {
        switch (opt) {
            case 'f':
                filename = optarg;
                break;
            case 'a':
                agreg = optarg;
                break;
            case 's':
                sort = optarg;
                break;
            default:
                fprintf(stderr, "Usage: flow -f directory -a aggregation -s sort\n");
                return (EXIT_FAILURE);
        }
    }
    // setup agrflag
    if (agreg.compare("srcport") == 0) {
        agrflg = 1;
		agrname = "srcport";
    }
    else if (agreg.compare("dstport") == 0) {
        agrflg = 2;
        agrname = "dstport";
    }
    else if (agreg.compare("srcip") == 0) {
        agrflg = 7;
        agrname = "srcip";
    }
    else if (agreg.compare("dstip") == 0) {
        agrflg = 8;
        agrname = "dstip";
    }
    else {
        // can be masked
        uint8_t mask = 0;
        if (agreg.find('/') != std::string::npos)
            mask = atoi(agreg.substr(agreg.find('/')).erase(0,1).c_str());
        if (agreg.find("ip6") != std::string::npos)  {
            // ipv6 agregation
            if (mask != 0)
                ipv6mask = mask;

            if (agreg.find("srcip") != std::string::npos) {
                agrflg = 3;
                agrname = "srcip";
            }
            else if (agreg.find("dstip") != std::string::npos) {
                agrflg = 4;
                agrname = "dstip";
            }
        }
        else if (agreg.find("ip4") != std::string::npos) {
            // ipv4 agregation
            if (mask != 0)
                ipv4mask = mask;

            if (agreg.find("srcip") != std::string::npos) {
                agrflg = 5;
                agrname = "srcip";
            }
            else if (agreg.find("dstip") != std::string::npos) {
                agrflg = 6;
                agrname = "dstip";
            }
        }
        else {
            fprintf(stderr, "Error\n");
            return (EXIT_FAILURE);
        }
    }
    DIR *dir = opendir(filename);
    if (dir == NULL) {
        std::cout << "Error: -f requires a directory." << std::endl;
		return EXIT_FAILURE;
	}
	std::string dirname = filename;
    std::unordered_map<std::string, struct flow> map;
	load_and_agreg(&map, dirname, dir, ipv4mask, ipv6mask, agrflg);

    // sort using std::multimap
    std::multimap<uint64_t, struct flow> ordered;
    for ( auto it = map.begin(); it != map.end(); ++it ) {
        if (sort.compare("packets") == 0)
            ordered.insert(std::pair<uint64_t,struct flow>(it->second.packets,it->second));
        else if (sort.compare("bytes") == 0)
            ordered.insert(std::pair<uint64_t,struct flow>(it->second.bytes,it->second));
    }

    // output
    map.clear();
    std::string key;
    std::cout << "#" << agrname << ",packets,bytes" << std::endl;
    for ( auto it = prev(ordered.end()); it != ordered.begin(); it = prev(it)) {
        switch (agrflg) {
            case 1:
                key = std::to_string(it->second.src_port);
                break;
            case 2:
                key = std::to_string(it->second.dst_port);
                break;
            case 3:
                apply_ipv6_mask(&it->second.src_addr, ipv6mask, ip);
                key = ip;
                break;
            case 4:
                apply_ipv6_mask(&it->second.dst_addr, ipv6mask, ip);
                key = ip;;
                break;
            case 5:
                apply_ipv4_mask(&it->second.src_addr, ipv4mask, ip);
                key = ip;
                break;
            case 6:
                apply_ipv4_mask(&it->second.dst_addr, ipv4mask, ip);
                key = ip;
                break;
            case 7:
                if (ntohl(it->second.sa_family) == AF_INET6) {
                    apply_ipv6_mask(&it->second.src_addr, ipv6mask, ip);
                    key = ip;
                }
                else {
                    apply_ipv4_mask(&it->second.src_addr, ipv4mask, ip);
                    key = ip;
                }
                break;
            case 8:
                if (ntohl(it->second.sa_family) == AF_INET6) {
                    apply_ipv6_mask(&it->second.dst_addr, ipv6mask, ip);
                    key = ip;
                }
                else {
                    apply_ipv4_mask(&it->second.dst_addr, ipv4mask, ip);
                    key = ip;
                }
                break;
            default:
                fprintf(stderr, "Error\n");
                return (EXIT_FAILURE);
        }
        std::cout << key << "," << it->second.packets << "," << it->second.bytes<< std::endl;
    }

    // last line of output has to be taken care of seperately
    auto it = ordered.begin();
    switch (agrflg) {
        case 1:
            key = std::to_string(it->second.src_port);
            break;
        case 2:
            key = std::to_string(it->second.dst_port);
            break;
        case 3:
            apply_ipv6_mask(&it->second.src_addr, ipv6mask, ip);
            key = ip;
            break;
        case 4:
            apply_ipv6_mask(&it->second.dst_addr, ipv6mask, ip);
            key = ip;;
            break;
        case 5:
            apply_ipv4_mask(&it->second.src_addr, ipv4mask, ip);
            key = ip;
            break;
        case 6:
            apply_ipv4_mask(&it->second.dst_addr, ipv4mask, ip);
            key = ip;
            break;
        case 7:
            if (ntohl(it->second.sa_family) == AF_INET6) {
                apply_ipv6_mask(&it->second.src_addr, ipv6mask, ip);
                key = ip;
            }
            else {
                apply_ipv4_mask(&it->second.src_addr, ipv4mask, ip);
                key = ip;
            }
            break;
        case 8:
            if (ntohl(it->second.sa_family) == AF_INET6) {
                apply_ipv6_mask(&it->second.dst_addr, ipv6mask, ip);
                key = ip;
            }
            else {
                apply_ipv4_mask(&it->second.dst_addr, ipv4mask, ip);
                key = ip;
            }
            break;
        default:
            fprintf(stderr, "Error\n");
            return (EXIT_FAILURE);
    }
    std::cout << key << "," << it->second.packets << "," << it->second.bytes<< std::endl;
    return (EXIT_SUCCESS);
}

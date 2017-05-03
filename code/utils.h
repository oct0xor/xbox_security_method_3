#ifndef UTILS_H
#define UTILS_H

#define SWAP32(x) ((((x) & 0x000000FF) << 24) | \
		   (((x) & 0x0000FF00) << 8)  | \
		   (((x) & 0x00FF0000) >> 8)  | \
		   (((x) & 0xFF000000) >> 24))

#define SWAP64(x) ((((x) & 0xFF00000000000000L) >> 56) | \
		(((x) & 0x00FF000000000000L) >> 40) | \
		(((x) & 0x0000FF0000000000L) >> 24) | \
		(((x) & 0x000000FF00000000L) >> 8)  | \
		(((x) & 0x00000000FF000000L) << 8)  | \
		(((x) & 0x0000000000FF0000L) << 24) | \
		(((x) & 0x000000000000FF00L) << 40) | \
		(((x) & 0x00000000000000FFL) << 56))

#define U8V(v) ((unsigned char)(v) & 0xFF)

#define ROTL8(v, n) (U8V((v) << (n)) | ((v) >> (8 - (n))))

#endif /* utils.h */
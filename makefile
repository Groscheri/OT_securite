all:
	gcc decrypt.c -o decrypt -lkrb5 -lk5crypto

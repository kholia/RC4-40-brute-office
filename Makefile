regular:
	gcc -fopenmp -O3 -Wall -Wextra RC4-40-brute.c rc4.c -lcrypto -o RC4-40-brute

debug:
	gcc -fsanitize=address -fopenmp -O3 -Wall -Wextra RC4-40-brute.c rc4.c -lcrypto -o RC4-40-brute

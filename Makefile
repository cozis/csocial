all:
	gcc src/*.c -o social -DHTTPS=1 -Wall -Wextra -ggdb -rdynamic -l:libbearssl.a -L3p/BearSSl/build -I3p/BearSSL/inc

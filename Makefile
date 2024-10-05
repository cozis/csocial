all:
	gcc serve.c tinytemplate.c sqlite3.c -o social -Wall -Wextra -ggdb -rdynamic

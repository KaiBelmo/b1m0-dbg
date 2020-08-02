out = b1m0_dbg
src = $(wildcard src/*.c)
main = main.c
flags = -g -ggdb -Wextra -Werror -Wall -O0


$(out): $(obj)
	@gcc $(main) $(src) $(flags) -o $(out)
	@echo "Compiled successfully!"

clean:
	@echo "clean!"
	@rm -f $(out)

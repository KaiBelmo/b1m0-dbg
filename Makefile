out = b1m0_dbg
inc = ./inc
src = $(wildcard src/*.c)
main = main.c
flags = -g -ggdb -O0 

$(out): $(obj)
	gcc $(main) -I $(inc) $(src) $(flags)-o $(out)
	@echo "Compiled successfully!"

clean:
	@echo "clean!"
	@rm -f $(out)

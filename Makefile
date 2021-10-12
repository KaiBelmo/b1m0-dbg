out = debugger
include = -I ./include
source = $(wildcard source/*.c)
main = main.c
flags = -ggdb -O0 -lreadline -lhistory #-fsanitize=address 

$(out): $(obj)
	@gcc $(main) $(include) $(source) $(flags) -o $(out)
	@echo "Compiled successfully!"

clean:
	@echo "clean!"
	@rm -f $(out)

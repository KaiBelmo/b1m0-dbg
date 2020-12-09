#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv)
{
	char *str = (char *)malloc(sizeof(char) * 25);
	printf("str input: ");
	scanf("%s", str);
	if(strcmp(str, "babypassword") == 0){
		puts("asdsasad");
		return 0;
	}
   return 255;
}


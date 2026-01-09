libgbf.a: src/gbf.c src/localbufferfile.c
	gcc -fPIC -c src/gbf.c src/localbufferfile.c src/common.c -Iinclude -Iexport
	ar rcs libgbf.a gbf.o localbufferfile.o common.o

example: example/main.c libgbf.a
	gcc -o example/example example/main.c -Iexport -L. -lgbf -static

clean:
	rm -f libgbf.so example/example gbf.o localbufferfile.o common.o libgbf.a
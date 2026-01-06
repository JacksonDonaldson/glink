test: example/test.c glink
	/usr/bin/gcc -o test example/test.c -Wall -Werror -g -Wl,example/ghidra_repo/target_project.gpr -Wl,-plugin,./glink -Wl,--plugin-opt,target

empty.so:
	gcc src/empty.c -shared -o empty.so -fPIC -Wl,-z,max-page-size=0x1

glink: src/glink.c empty.so
	gcc -o glink src/glink.c -Iinclude -Wall -Werror -g -shared -fPIC


clean:
	rm -rf main glink test* empty*
CC := gcc


glink: src/glink.cpp libgbf.a
	/usr/bin/g++ -o glink src/glink.cpp -Igbf/include -Iinclude -Wall -Werror -g -shared -fPIC -Lgbf -lgbf

libgbf.a:
	$(MAKE) -C gbf libgbf.a

test: example/test.c glink
	/usr/bin/gcc -o test.o -c example/test.c -Wall -Werror -g -nostdlib -Wno-builtin-declaration-mismatch -fPIC
	ld -o test test.o example/ghidra_repo/target_project.gpr -plugin ./glink --plugin-opt target


clean:
	rm -rf main glink test* empty* glink.ld 
	make -C gbf clean
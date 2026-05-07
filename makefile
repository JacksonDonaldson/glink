CC := gcc


glink: src/glink.c libgbf.a
	gcc -o glink src/glink.c -Igbf/export -Iinclude -Wall -Werror -g -shared -fPIC -Lgbf -lgbf

libgbf.a:
	$(MAKE) -C gbf libgbf.a

test: example/test.c glink
	/usr/bin/gcc -o test.o -c example/test.c -Wall -Werror -g -nostdlib -Wno-builtin-declaration-mismatch -fPIC
	ld -o test test.o example/ghidra_repo/target_project.gpr -plugin ./glink --plugin-opt target


clean:
	rm -rf main glink test* empty* glink.ld 
	make -C gbf clean
libgbf.a: src/GBF.cpp src/LocalBufferFile.cpp src/common.cpp src/GBFTable.cpp src/VariableGBFRecord.cpp src/VariableKeyRecordGBFRecord.cpp src/FixedGBFRecord.cpp src/GBFUtils.cpp
	/usr/bin/g++ -fPIC -c src/GBF.cpp src/LocalBufferFile.cpp src/common.cpp src/GBFTable.cpp src/VariableGBFRecord.cpp src/VariableKeyRecordGBFRecord.cpp src/FixedGBFRecord.cpp src/GBFUtils.cpp -Iinclude -Iexport
	ar rcs libgbf.a GBF.o LocalBufferFile.o common.o GBFTable.o VariableGBFRecord.o VariableKeyRecordGBFRecord.o FixedGBFRecord.o GBFUtils.o

example: example/main.cpp libgbf.a
	g++ -o example/example example/main.cpp -Iinclude -Iexport -L. -lgbf -static
	
run_example: example .FORCE
	./example/example /home/user/glink/example/ghidra_repo/target_project.rep@target
clean:
	rm -f libgbf.so example/example GBF.o LocalBufferFile.o common.o GBFTable.o GBFRecord.o GBFUtils.o libgbf.a FixedGBFRecord.o VariableGBFRecord.o VariableKeyRecordGBFRecord.o

.FORCE:
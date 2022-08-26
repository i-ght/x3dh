CFLAGS="-I./src"
LFLAGS="-lsodium"

for dotc_file in ./src/*.c; do
  clang -g -DDEBUG=1 -fPIC -c "$dotc_file" $CFLAGS -o "$dotc_file.o"
done

doto_files=""

for doto_file in ./src/*.c.o; do
  doto_files="${doto_files} ${doto_file}"
done

clang -g -DDEBUG=1 -o bin/program $doto_files $CFLAGS $LFLAGS 

rm ./src/*.c.o


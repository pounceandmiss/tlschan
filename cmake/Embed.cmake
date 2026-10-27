# Embed.cmake --
#
#	cmake -DIN=file -DOUT=header -DNAME=symbol -P Embed.cmake
#	Writes IN as a C string literal named NAME.

file(READ "${IN}" text)
string(REPLACE "\\" "\\\\" text "${text}")
string(REPLACE "\"" "\\\"" text "${text}")
string(REPLACE "\n" "\\n\"\n\"" text "${text}")
file(WRITE "${OUT}.tmp" "static const char ${NAME}[] =\n\"${text}\";\n")
file(COPY_FILE "${OUT}.tmp" "${OUT}" ONLY_IF_DIFFERENT)
file(REMOVE "${OUT}.tmp")

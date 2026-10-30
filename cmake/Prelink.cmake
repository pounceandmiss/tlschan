# Prelink.cmake --
#
#	cmake -DLD=ld -DOBJCOPY=objcopy -DAR=ar -DAPPLE=0|1 -DINIT=Pkg_Init
#	      -DOUT=libpkg.a -DINPUTS=objects;archives
#	      [-DMINGW=1 -DNM=nm -DOBJDUMP=objdump] -P Prelink.cmake
#
#	Links INPUTS into one relocatable object, pulling from the archives only
#	what the objects need, and keeps INIT as its sole global symbol. Static
#	packages can then share a program with each other, and with other copies
#	of the same TLS library, without symbol clashes.

function(run)
    execute_process(COMMAND ${ARGN} COMMAND_ERROR_IS_FATAL ANY)
endfunction()

macro(incr var)
    if(NOT DEFINED ${var})
	set(${var} 0)
    endif()
    math(EXPR ${var} "${${var}}+1")
endmacro()

# Splits the archive IN, in the directory DIR, into an archive of its code,
# CODE, and the import library members it holds, IMPORTS: files in DIR's
# sibling imp, given relative to DIR's parent.
function(split in dir)
    execute_process(COMMAND "${OBJDUMP}" -h "${in}" OUTPUT_VARIABLE out
	COMMAND_ERROR_IS_FATAL ANY)
    string(REGEX MATCHALL "\n[^ \n]+:     file format|\\.idata\\$" tokens
	"${out}")
    set(names)
    set(kinds)
    foreach(t IN LISTS tokens)
	if(t MATCHES "^\n(.*):")
	    list(APPEND names "${CMAKE_MATCH_1}")
	    list(APPEND kinds code)
	else()
	    list(POP_BACK kinds)
	    list(APPEND kinds imp)
	endif()
    endforeach()
    set(imports "" PARENT_SCOPE)
    set(code "${dir}/code.a" PARENT_SCOPE)
    if(NOT imp IN_LIST kinds)
	file(COPY_FILE "${in}" "${dir}/code.a")
	return()
    endif()

    # Members sharing a name are extracted one at a time.
    file(MAKE_DIRECTORY "${dir}/x" "${dir}/../imp")
    run("${AR}" x "${in}" WORKING_DIRECTORY "${dir}/x")
    foreach(n IN LISTS names)
	incr(total_${n})
    endforeach()
    # The final link orders a DLL's import members by name, so a suffix
    # makes them unique.
    get_filename_component(tag "${dir}" NAME)
    set(code)
    set(imp)
    foreach(n k IN ZIP_LISTS names kinds)
	incr(seen_${n})
	set(src "${dir}/x/${n}")
	if(total_${n} GREATER 1)
	    set(src "${dir}/x${seen_${n}}/${n}")
	    file(MAKE_DIRECTORY "${dir}/x${seen_${n}}")
	    run("${AR}" xN ${seen_${n}} "${in}" "${n}"
		WORKING_DIRECTORY "${dir}/x${seen_${n}}")
	endif()
	set(to "${n}~${tag}.${seen_${n}}")
	if(k STREQUAL "imp")
	    set(to "imp/${to}")
	else()
	    set(to "${tag}/${to}")
	endif()
	file(RENAME "${src}" "${dir}/../${to}")
	list(APPEND ${k} "${to}")
    endforeach()
    list(JOIN code "\n" rsp)
    file(WRITE "${dir}/code.rsp" "${rsp}\n")
    run("${AR}" qcs "${dir}/code.a" "@${dir}/code.rsp"
	WORKING_DIRECTORY "${dir}/..")
    set(imports "${imp}" PARENT_SCOPE)
endfunction()

set(obj "${OUT}.o")
set(dir "${obj}.d")
set(inputs ${INPUTS})
set(imp)
if(MINGW)
    # Copies of the inputs, changed twice. Import library members only work
    # as laid out by a final link, and ld -r would merge their .idata$
    # sections, so they are kept apart. And ld sorts .pdata by its raw
    # contents even with -r, where those are only addends, pairing records
    # with other records' relocations; under another name it is left alone.
    file(REMOVE_RECURSE "${dir}")
    set(inputs)
    foreach(in IN LISTS INPUTS)
	if(NOT in)
	    continue()
	endif()
	list(LENGTH inputs n)
	file(MAKE_DIRECTORY "${dir}/${n}")
	if(in MATCHES "\\.a$")
	    get_filename_component(in "${in}" ABSOLUTE)
	    split("${in}" "${dir}/${n}")
	    list(APPEND imp ${imports})
	else()
	    get_filename_component(name "${in}" NAME)
	    set(code "${dir}/${n}/${name}")
	    file(COPY_FILE "${in}" "${code}")
	endif()
	run("${OBJCOPY}" --rename-section .pdata=.pdata$p "${code}")
	list(APPEND inputs "${code}")
    endforeach()
endif()

if(APPLE)
    # ld64 resolves a CIE's personality routine by name in the final link, so
    # Rust's must stay global or every __eh_frame using it is left undefined.
    set(keep -exported_symbol _${INIT})
    execute_process(COMMAND "${NM}" -g ${INPUTS} OUTPUT_VARIABLE syms
	ERROR_QUIET)
    if(syms MATCHES "[Tt] _rust_eh_personality\n")
	list(APPEND keep -exported_symbol _rust_eh_personality)
    endif()
    # Two passes: ld64 leaves common symbols global if -d defines them in
    # the same link that hides the rest.
    run("${LD}" -r -d -o "${obj}.tmp.o" ${INPUTS})
    run("${LD}" -r ${keep} -o "${obj}" "${obj}.tmp.o")
    file(REMOVE "${obj}.tmp.o")
else()
    run("${LD}" -r -d -o "${obj}" ${inputs})
    run("${OBJCOPY}" --keep-global-symbol=${INIT} "${obj}")
endif()

set(used)
if(MINGW)
    # GCC reaches extern data through .refptr.<name> COMDAT sections. Now
    # local, each package's copy must keep its own name: a program keeps one
    # COMDAT of a name and would leave the others' references dangling.
    execute_process(COMMAND "${NM}" "${obj}" OUTPUT_VARIABLE syms
	COMMAND_ERROR_IS_FATAL ANY)
    string(REGEX MATCHALL "[rR] \\.refptr\\.[^\n]+" refs "${syms}")
    # Rust's embedded bitcode would land outside the image.
    set(args "--remove-section=.llvmbc\n--remove-section=.llvmcmd\n")
    foreach(r IN LISTS refs)
	string(REGEX REPLACE "^[rR] " "" r "${r}")
	string(APPEND args "--redefine-sym ${r}=${r}.${INIT}\n"
	    "--redefine-sym .rdata$${r}=.rdata$${r}.${INIT}\n"
	    "--rename-section .rdata$${r}=.rdata$${r}.${INIT}\n")
    endforeach()
    file(WRITE "${obj}.args" "${args}")
    run("${OBJCOPY}" "@${obj}.args" "${obj}")
    file(REMOVE "${obj}.args")

    # The import members the object uses go in the archive beside it.
    if(imp)
	list(JOIN imp "\n" rsp)
	file(WRITE "${dir}/imports.rsp" "${rsp}\n")
	run("${AR}" qcs imports.a @imports.rsp WORKING_DIRECTORY "${dir}")
	run("${LD}" -r -Map=${dir}/map -o "${dir}/used.o" "${obj}"
	    "${dir}/imports.a")
	file(READ "${dir}/map" map)
	string(REGEX MATCHALL "imports\\.a\\([^)]+\\)" used "${map}")
	list(REMOVE_DUPLICATES used)
	list(TRANSFORM used REPLACE "imports\\.a\\((.*)\\)" "${dir}/imp/\\1")
    endif()
endif()
file(REMOVE "${OUT}")
run("${AR}" rcs "${OUT}" "${obj}" ${used})
file(REMOVE "${obj}")
file(REMOVE_RECURSE "${dir}")

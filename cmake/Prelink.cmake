# Prelink.cmake --
#
#	cmake -DLD=ld -DOBJCOPY=objcopy -DAR=ar -DAPPLE=0|1 -DINIT=Pkg_Init
#	      -DOUT=libpkg.a -DINPUTS=objects;archives [-DMINGW=1 -DNM=nm]
#	      -P Prelink.cmake
#
#	Links INPUTS into one relocatable object, pulling from the archives only
#	what the objects need, and keeps INIT as its sole global symbol. Static
#	packages can then share a program with each other, and with other copies
#	of the same TLS library, without symbol clashes.

function(run)
    execute_process(COMMAND ${ARGN} COMMAND_ERROR_IS_FATAL ANY)
endfunction()

set(obj "${OUT}.o")
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
    run("${LD}" -r -d -o "${obj}" ${INPUTS})
    run("${OBJCOPY}" --keep-global-symbol=${INIT} "${obj}")
endif()
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
endif()
file(REMOVE "${OUT}")
run("${AR}" rcs "${OUT}" "${obj}")
file(REMOVE "${obj}")

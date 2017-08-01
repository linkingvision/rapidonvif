
function(EnableLinkStaticRT)
	if(MSVC)
		foreach(flag_var
			CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
			CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO
			CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
			CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO)
			if(${flag_var} MATCHES "((.*[ \t\r\n]+)+|^)/MD(d?(([ \t\r\n]+.*)+|$))")
				string(REGEX REPLACE "((.*[ \t\r\n]+)+|^)/MD(d?(([ \t\r\n]+.*)+|$))" 
				"\\1/MT\\3" ${flag_var} ${${flag_var}})
				set(${flag_var} ${${flag_var}})
			elseif((NOT ${flag_var} MATCHES "((.*[ \t\r\n]+)+|^)/MT(d?(([ \t\r\n]+.*)+|$))"))
				if (CMAKE_BUILD_TYPE MATCHES "Debug")
					set(${flag_var} "${${flag_var}} /MTd")
				else()
					set(${flag_var} "${${flag_var}} /MT")
				endif(CMAKE_BUILD_TYPE MATCHES "Debug")
			endif(${flag_var} MATCHES "((.*[ \t\r\n]+)+|^)/MD(d?(([ \t\r\n]+.*)+|$))")
			set(${flag_var} ${${flag_var}} PARENT_SCOPE)
		endforeach(flag_var)
	endif(MSVC)
	if (CMAKE_SYSTEM_NAME MATCHES "Linux")
		# ToDo: implemnet proper linux static link support
	endif(CMAKE_SYSTEM_NAME MATCHES "Linux")
endfunction(EnableLinkStaticRT)

function(EnableMSVCBigObjBuild)
	if(MSVC)
		foreach(flag_var
			CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
			CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO
			CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
			CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO)
			if(NOT ${flag_var} MATCHES "((.*[ \t\r\n]+)+|^)/bigobj(d?(([ \t\r\n]+.*)+|$))")
				set(${flag_var} "${${flag_var}} /bigobj" PARENT_SCOPE)
			endif(NOT ${flag_var} MATCHES "((.*[ \t\r\n]+)+|^)/bigobj(d?(([ \t\r\n]+.*)+|$))")
		endforeach(flag_var)
	endif(MSVC)
endfunction(EnableMSVCBigObjBuild)

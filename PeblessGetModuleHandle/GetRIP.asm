PUBLIC GetInstructionPointer
.CODE

	GetInstructionPointer PROC
		call _pop_rax
	_pop_rax:
		pop rax
		ret
	GetInstructionPointer ENDP

END
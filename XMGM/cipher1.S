	.file	"cipher.c"
__SP_H__ = 0x3e
__SP_L__ = 0x3d
__SREG__ = 0x3f
__RAMPZ__ = 0x3b
__CCP__ = 0x34
__tmp_reg__ = 0
__zero_reg__ = 1
	.text
.Ltext0:
	.cfi_sections	.debug_frame
.global	AddRoundKey
	.type	AddRoundKey, @function
AddRoundKey:
.LFB0:
	.file 1 "cipher.c"
	.loc 1 90 0
	.cfi_startproc
.LVL0:
	push r16
.LCFI0:
	.cfi_def_cfa_offset 4
	.cfi_offset 16, -3
	push r17
.LCFI1:
	.cfi_def_cfa_offset 5
	.cfi_offset 17, -4
	push r28
.LCFI2:
	.cfi_def_cfa_offset 6
	.cfi_offset 28, -5
	push r29
.LCFI3:
	.cfi_def_cfa_offset 7
	.cfi_offset 29, -6
/* prologue: function */
/* frame size = 0 */
/* stack size = 4 */
.L__stack_usage = 4
	movw r28,r20
.LVL1:
	ldi r25,lo8(16)
	mul r24,r25
	movw r16,r0
	clr __zero_reg__
	.loc 1 96 0
	ldi r18,0
	ldi r19,0
.LVL2:
.L2:
	movw r30,r22
	add r30,r18
	adc r31,r19
	movw r26,r18
	add r26,r16
	adc r27,r17
	add r26,r28
	adc r27,r29
	.loc 1 90 0
	ldi r21,0
.LVL3:
.L4:
	.loc 1 96 0
	ld r20,X+
	ld r25,Z
	eor r25,r20
	st Z,r25
	.loc 1 97 0
	cpi r24,lo8(10)
	breq .L3
	.loc 1 98 0
	lds r20,rin
	eor r25,r20
	st Z,r25
.L3:
	.loc 1 94 0 discriminator 2
	subi r21,lo8(-(1))
.LVL4:
	adiw r30,1
	cpi r21,lo8(4)
	brne .L4
	subi r18,-4
	sbci r19,-1
	.loc 1 92 0 discriminator 2
	cpi r18,16
	cpc r19,__zero_reg__
	brne .L2
/* epilogue start */
	.loc 1 101 0
	pop r29
	pop r28
.LVL5:
	pop r17
	pop r16
	ret
	.cfi_endproc
.LFE0:
	.size	AddRoundKey, .-AddRoundKey
.global	SubBytes
	.type	SubBytes, @function
SubBytes:
.LFB1:
	.loc 1 106 0
	.cfi_startproc
.LVL6:
/* prologue: function */
/* frame size = 0 */
/* stack size = 0 */
.L__stack_usage = 0
	ldi r31,0
	sbci r31,hi8(-(sboxm))
	movw r18,r24
.LVL7:
	.loc 1 104 0
	ldi r24,lo8(4)
.LVL8:
.L12:
	movw r26,r18
	ldi r25,0
.LVL9:
.L13:
	.loc 1 110 0 discriminator 3
	ldi r30,0
	subi r30,lo8(-(sboxm))
	ld r20,Z
	clr r20
	clr r30
	ld r30,X
	st X,r25
	ld r25,X
	subi r30,lo8(-(sboxm))
	ld r20,Z
	st X,r20
	clr r20
	.loc 1 108 0 discriminator 3
	subi r25,lo8(-(1))
.LVL10:
	adiw r26,4
	cpi r25,lo8(4)
	brne .L13
.LVL11:
	subi r24,lo8(-(-1))
	subi r18,-1
	sbci r19,-1
.LVL12:
	.loc 1 108 0 discriminator 2
	cpse r24,__zero_reg__
	rjmp .L12
	ret
	.cfi_endproc
.LFE1:
	.size	SubBytes, .-SubBytes
.global	SubBytes1
	.type	SubBytes1, @function
SubBytes1:
.LFB2:
	.loc 1 118 0
	.cfi_startproc
.LVL13:
/* prologue: function */
/* frame size = 0 */
/* stack size = 0 */
.L__stack_usage = 0
	ldi r31,0
	sbci r31,hi8(-(sboxm1))
	movw r18,r24
.LVL14:
	.loc 1 116 0
	ldi r24,lo8(4)
.LVL15:
.L17:
	movw r26,r18
	ldi r25,0
.LVL16:
.L18:
	.loc 1 122 0 discriminator 3
	ldi r30,0
	subi r30,lo8(-(sboxm))
	ld r20,Z
	clr r20
	clr r30
	ld r30,X
	st X,r25
	ld r25,X
	subi r30,lo8(-(sboxm1))
	ld r20,Z
	st X,r20
	clr r20
	.loc 1 120 0 discriminator 3
	subi r25,lo8(-(1))
.LVL17:
	adiw r26,4
	cpi r25,lo8(4)
	brne .L18
.LVL18:
	subi r24,lo8(-(-1))
	subi r18,-1
	sbci r19,-1
.LVL19:
	.loc 1 120 0 discriminator 2
	cpse r24,__zero_reg__
	rjmp .L17
	ret
	.cfi_endproc
.LFE2:
	.size	SubBytes1, .-SubBytes1
.global	ShiftRows
	.type	ShiftRows, @function
ShiftRows:
.LFB3:
	.loc 1 133 0
	.cfi_startproc
.LVL20:
/* prologue: function */
/* frame size = 0 */
/* stack size = 0 */
.L__stack_usage = 0
	movw r30,r24
	.loc 1 137 0
	ldd r24,Z+1
.LVL21:
	.loc 1 138 0
	ldd r25,Z+5
	std Z+1,r25
	.loc 1 139 0
	ldd r25,Z+9
	std Z+5,r25
	.loc 1 140 0
	ldd r25,Z+13
	std Z+9,r25
	.loc 1 141 0
	std Z+13,r24
	.loc 1 144 0
	ldd r24,Z+2
.LVL22:
	.loc 1 145 0
	ldd r25,Z+10
	std Z+2,r25
	.loc 1 146 0
	std Z+10,r24
	.loc 1 148 0
	ldd r24,Z+6
.LVL23:
	.loc 1 149 0
	ldd r25,Z+14
	std Z+6,r25
	.loc 1 150 0
	std Z+14,r24
	.loc 1 153 0
	ldd r24,Z+3
.LVL24:
	.loc 1 154 0
	ldd r25,Z+15
	std Z+3,r25
	.loc 1 155 0
	ldd r25,Z+11
	std Z+15,r25
	.loc 1 156 0
	ldd r25,Z+7
	std Z+11,r25
	.loc 1 157 0
	std Z+7,r24
	ret
	.cfi_endproc
.LFE3:
	.size	ShiftRows, .-ShiftRows
.global	xtime
	.type	xtime, @function
xtime:
.LFB4:
	.loc 1 161 0
	.cfi_startproc
.LVL25:
/* prologue: function */
/* frame size = 0 */
/* stack size = 0 */
.L__stack_usage = 0
	mov r25,r24
	.loc 1 163 0
	lsl r24
.LVL26:
	.loc 1 164 0
	sbrs r25,7
	rjmp .L23
	.loc 1 165 0
	ldi r25,lo8(27)
.LVL27:
	eor r24,r25
.LVL28:
.L23:
	.loc 1 167 0
	ret
	.cfi_endproc
.LFE4:
	.size	xtime, .-xtime
.global	MixColumns
	.type	MixColumns, @function
MixColumns:
.LFB5:
	.loc 1 171 0
	.cfi_startproc
.LVL29:
	push r10
.LCFI4:
	.cfi_def_cfa_offset 4
	.cfi_offset 10, -3
	push r11
.LCFI5:
	.cfi_def_cfa_offset 5
	.cfi_offset 11, -4
	push r12
.LCFI6:
	.cfi_def_cfa_offset 6
	.cfi_offset 12, -5
	push r13
.LCFI7:
	.cfi_def_cfa_offset 7
	.cfi_offset 13, -6
	push r14
.LCFI8:
	.cfi_def_cfa_offset 8
	.cfi_offset 14, -7
	push r15
.LCFI9:
	.cfi_def_cfa_offset 9
	.cfi_offset 15, -8
	push r16
.LCFI10:
	.cfi_def_cfa_offset 10
	.cfi_offset 16, -9
	push r17
.LCFI11:
	.cfi_def_cfa_offset 11
	.cfi_offset 17, -10
	push r28
.LCFI12:
	.cfi_def_cfa_offset 12
	.cfi_offset 28, -11
	push r29
.LCFI13:
	.cfi_def_cfa_offset 13
	.cfi_offset 29, -12
/* prologue: function */
/* frame size = 0 */
/* stack size = 10 */
.L__stack_usage = 10
	movw r28,r24
.LVL30:
	movw r14,r24
	ldi r24,16
	add r14,r24
	adc r15,__zero_reg__
.LVL31:
.L28:
	.loc 1 177 0 discriminator 3
	ld r11,Y
.LVL32:
	.loc 1 178 0 discriminator 3
	ldd r16,Y+1
	mov r24,r11
	eor r24,r16
	ldd r17,Y+2
	ldd r12,Y+3
	mov r10,r17
	eor r10,r12
	mov r13,r24
	eor r13,r10
.LVL33:
	.loc 1 179 0 discriminator 3
	call xtime
.LVL34:
	eor r24,r11
.LVL35:
	eor r24,r13
	st Y,r24
.LVL36:
	.loc 1 180 0 discriminator 3
	mov r24,r16
	eor r24,r17
.LVL37:
	call xtime
.LVL38:
	eor r24,r16
.LVL39:
	mov r16,r24
	eor r16,r13
	std Y+1,r16
.LVL40:
	.loc 1 181 0 discriminator 3
	mov r24,r10
	call xtime
.LVL41:
	eor r24,r17
.LVL42:
	mov r17,r24
	eor r17,r13
	std Y+2,r17
.LVL43:
	.loc 1 182 0 discriminator 3
	mov r24,r11
	eor r24,r12
.LVL44:
	call xtime
.LVL45:
	eor r24,r12
.LVL46:
	eor r13,r24
.LVL47:
	std Y+3,r13
	adiw r28,4
	.loc 1 175 0 discriminator 3
	cp r28,r14
	cpc r29,r15
	brne .L28
/* epilogue start */
	.loc 1 184 0
	pop r29
	pop r28
	pop r17
	pop r16
	pop r15
	pop r14
.LVL48:
	pop r13
	pop r12
	pop r11
.LVL49:
	pop r10
	ret
	.cfi_endproc
.LFE5:
	.size	MixColumns, .-MixColumns
	.section	.rodata
.LC0:
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.byte	120
	.text
.global	Cipher1
	.type	Cipher1, @function
Cipher1:
.LFB6:
	.loc 1 187 0
	.cfi_startproc
.LVL50:
	push r4
.LCFI14:
	.cfi_def_cfa_offset 4
	.cfi_offset 4, -3
	push r5
.LCFI15:
	.cfi_def_cfa_offset 5
	.cfi_offset 5, -4
	push r7
.LCFI16:
	.cfi_def_cfa_offset 6
	.cfi_offset 7, -5
	push r8
.LCFI17:
	.cfi_def_cfa_offset 7
	.cfi_offset 8, -6
	push r9
.LCFI18:
	.cfi_def_cfa_offset 8
	.cfi_offset 9, -7
	push r10
.LCFI19:
	.cfi_def_cfa_offset 9
	.cfi_offset 10, -8
	push r11
.LCFI20:
	.cfi_def_cfa_offset 10
	.cfi_offset 11, -9
	push r12
.LCFI21:
	.cfi_def_cfa_offset 11
	.cfi_offset 12, -10
	push r13
.LCFI22:
	.cfi_def_cfa_offset 12
	.cfi_offset 13, -11
	push r14
.LCFI23:
	.cfi_def_cfa_offset 13
	.cfi_offset 14, -12
	push r15
.LCFI24:
	.cfi_def_cfa_offset 14
	.cfi_offset 15, -13
	push r16
.LCFI25:
	.cfi_def_cfa_offset 15
	.cfi_offset 16, -14
	push r17
.LCFI26:
	.cfi_def_cfa_offset 16
	.cfi_offset 17, -15
	push r28
.LCFI27:
	.cfi_def_cfa_offset 17
	.cfi_offset 28, -16
	push r29
.LCFI28:
	.cfi_def_cfa_offset 18
	.cfi_offset 29, -17
	in r28,__SP_L__
	in r29,__SP_H__
.LCFI29:
	.cfi_def_cfa_register 28
	sbiw r28,16
.LCFI30:
	.cfi_def_cfa_offset 34
	out __SP_L__,r28
	out __SP_H__,r29
/* prologue: function */
/* frame size = 16 */
/* stack size = 31 */
.L__stack_usage = 31
	movw r14,r24
	movw r10,r22
	movw r12,r20
	movw r8,r18
.LVL51:
	.loc 1 189 0
	ldi r24,lo8(16)
.LVL52:
	ldi r30,lo8(.LC0)
	ldi r31,hi8(.LC0)
	movw r26,r28
	adiw r26,1
	0:
	ld r0,Z+
	st X+,r0
	dec r24
	brne 0b
.LVL53:
	.loc 1 195 0
	clr r7
	inc r7
.LVL54:
.L46:
	.loc 1 197 0
	movw r24,r14
	lds r23,rout
	call SubBytes
.LVL55:
	ldi r18,0
	ldi r19,0
.LVL56:
.L31:
	movw r30,r14
	add r30,r18
	adc r31,r19
	.loc 1 195 0
	ldi r20,0
	ldi r21,0
.LVL57:
.L32:
.LBB2:
.LBB3:
	.loc 1 200 0 discriminator 3
	movw r26,r20
	add r26,r18
	adc r27,r19
	add r26,r10
	adc r27,r11
	clr r25
	ld r25,X
	clr r24
	ld r24,Z
	eor r24,r25
	.loc 1 201 0 discriminator 3
	ldi r25,10
	eor r24,r23
	st Z,r20
	ld r20,Z
	st Z+,r24
	.loc 1 199 0 discriminator 3
	subi r20,-1
	sbci r21,-1
.LVL58:
	cpi r20,4
	cpc r21,__zero_reg__
	brne .L32
	subi r18,-4
	sbci r19,-1
.LBE3:
	.loc 1 198 0 discriminator 2
	cpi r18,16
	cpc r19,__zero_reg__
	brne .L31
.LBE2:
	.loc 1 205 0
	movw r24,r12
	lds r23,rout1
	call SubBytes1
.LVL59:
	ldi r18,0
	ldi r19,0
.LVL60:
.L34:
	movw r30,r12
	add r30,r18
	adc r31,r19
	.loc 1 197 0
	ldi r20,0
	ldi r21,0
.LVL61:
.L35:
.LBB4:
.LBB5:
	.loc 1 208 0 discriminator 3
	movw r26,r20
	add r26,r18
	adc r27,r19
	add r26,r8
	adc r27,r9
	clr r25
	ld r25,X
	clr r24
	ld r24,Z
	eor r24,r25
	.loc 1 209 0 discriminator 3
	eor r24,r23
	st Z+,r24
	.loc 1 207 0 discriminator 3
	subi r20,-1
	sbci r21,-1
.LVL62:
	cpi r20,4
	cpc r21,__zero_reg__
	brne .L35
	subi r18,-4
	sbci r19,-1
.LBE5:
	.loc 1 206 0 discriminator 2
	cpi r18,16
	cpc r19,__zero_reg__
	brne .L34
.LBE4:
	.loc 1 213 0
	movw r24,r14
	call ShiftRows
.LVL63:
	.loc 1 214 0
	movw r24,r10
	call ShiftRows
.LVL64:
	.loc 1 215 0
	ldi r31,lo8(10)
	mov r4,r31
	cp r7,r4
	breq .L37
	.loc 1 216 0
	mov r22,r7
	movw r24,r14
	call MixColumns
.LVL65:
	.loc 1 217 0
	mov r22,r7
	movw r24,r10
	call MixColumns
.LVL66:
	.loc 1 218 0
	movw r20,r16
	movw r22,r14
	mov r24,r7
	call AddRoundKey
.LVL67:
	ldi r24,0
	ldi r25,0
.LVL68:
.L38:
	movw r30,r14
	add r30,r24
	adc r31,r25
	.loc 1 205 0
	ldi r18,0
	ldi r19,0
.LVL69:
.L39:
.LBB6:
.LBB7:
	.loc 1 221 0 discriminator 3
	movw r26,r18
	add r26,r24
	adc r27,r25
	add r26,r10
	adc r27,r11
	ld r21,Z
	ld r20,X
	eor r20,r21
	st Z+,r20
	.loc 1 220 0 discriminator 3
	subi r18,-1
	sbci r19,-1
.LVL70:
	cpi r18,4
	cpc r19,__zero_reg__
	brne .L39
	adiw r24,4
.LBE7:
	.loc 1 219 0 discriminator 2
	cpi r24,16
	cpc r25,__zero_reg__
	brne .L38
.LVL71:
.L37:
.LBE6:
	.loc 1 225 0
	movw r24,r12
	call ShiftRows
.LVL72:
	.loc 1 226 0
	movw r24,r8
	call ShiftRows
.LVL73:
	.loc 1 227 0
	ldi r30,lo8(10)
	mov r5,r30
	cp r7,r5
	brne .+2
	rjmp .L40
	.loc 1 228 0
	mov r22,r7
	movw r24,r12
	call MixColumns
.LVL74:
	.loc 1 229 0
	mov r22,r7
	movw r24,r8
	call MixColumns
.LVL75:
	ldi r24,0
	ldi r25,0
.LVL76:
.L41:
	movw r30,r14
	add r30,r24
	adc r31,r25
	.loc 1 218 0
	ldi r18,0
	ldi r19,0
.LVL77:
.L42:
.LBB8:
.LBB9:
	.loc 1 232 0 discriminator 3
	movw r20,r24
	add r20,r18
	adc r21,r19
	movw r26,r12
	add r26,r20
	adc r27,r21
	ld r23,X
	ld r22,Z
	eor r22,r23
	st Z,r22
	.loc 1 233 0 discriminator 3
	movw r26,r8
	add r26,r20
	adc r27,r21
	.loc 1 234 0 discriminator 3
	clr r4
	inc r4
	mov r5,__zero_reg__
	add r4,r28
	adc r5,r29
	add r20,r4
	adc r21,r5
	ld r23,X
	movw r26,r20
	ld r20,X
	eor r20,r23
	eor r22,r20
	st Z+,r22
	.loc 1 231 0 discriminator 3
	subi r18,-1
	sbci r19,-1
.LVL78:
	cpi r18,4
	cpc r19,__zero_reg__
	brne .L42
	adiw r24,4
.LBE9:
	.loc 1 230 0 discriminator 2
	cpi r24,16
	cpc r25,__zero_reg__
	brne .L41
	ldi r18,0
	ldi r19,0
.LVL79:
.L45:
	movw r30,r12
	add r30,r18
	adc r31,r19
.LBE8:
	.loc 1 229 0
	ldi r20,0
	ldi r21,0
.LVL80:
.L44:
.LBB10:
.LBB11:
	.loc 1 239 0 discriminator 3
	movw r26,r20
	add r26,r18
	adc r27,r19
	add r26,r14
	adc r27,r15
	ld r25,X
	lds r24,rin1
	eor r24,r25
	st Z,r24
	.loc 1 240 0 discriminator 3
	lds r25,rin
	eor r24,r25
	st Z+,r24
	.loc 1 238 0 discriminator 3
	subi r20,-1
	sbci r21,-1
.LVL81:
	cpi r20,4
	cpc r21,__zero_reg__
	brne .L44
.LVL82:
	subi r18,-4
	sbci r19,-1
.LBE11:
	.loc 1 237 0 discriminator 2
	cpi r18,16
	cpc r19,__zero_reg__
	brne .L45
.LVL83:
.L40:
.LBE10:
	.loc 1 195 0
	inc r7
.LVL84:
	ldi r27,lo8(11)
	cpse r7,r27
	rjmp .L46
.LVL85:
	.loc 1 246 0
	movw r20,r16
	movw r22,r14
	ldi r24,lo8(10)
	call AddRoundKey
.LVL86:
	ldi r18,0
	ldi r19,0
.LVL87:
.L47:
	movw r30,r14
	add r30,r18
	adc r31,r19
.LBB12:
	ldi r20,0
	ldi r21,0
.LVL88:
.L48:
.LBE12:
.LBB13:
.LBB14:
	.loc 1 249 0 discriminator 3
	movw r22,r20
	add r22,r18
	adc r23,r19
	movw r26,r12
	add r26,r22
	adc r27,r23
	ld r25,X
	ld r24,Z
	eor r24,r25
	st Z,r24
	.loc 1 250 0 discriminator 3
	movw r26,r10
	add r26,r22
	adc r27,r23
	ld r25,X
	eor r24,r25
	st Z,r24
	.loc 1 251 0 discriminator 3
	movw r26,r8
	add r26,r22
	adc r27,r23
	ld r25,X
	eor r24,r25
	st Z+,r24
	.loc 1 248 0 discriminator 3
	subi r20,-1
	sbci r21,-1
.LVL89:
	cpi r20,4
	cpc r21,__zero_reg__
	brne .L48
	subi r18,-4
	sbci r19,-1
.LBE14:
	.loc 1 247 0 discriminator 2
	cpi r18,16
	cpc r19,__zero_reg__
	brne .L47
/* epilogue start */
.LBE13:
	.loc 1 254 0
	adiw r28,16
	out __SP_L__,r28
	out __SP_H__,r29
	pop r29
	pop r28
	pop r17
	pop r16
.LVL90:
	pop r15
	pop r14
.LVL91:
	pop r13
	pop r12
.LVL92:
	pop r11
	pop r10
.LVL93:
	pop r9
	pop r8
.LVL94:
	pop r7
	pop r5
	pop r4
	ret
	.cfi_endproc
.LFE6:
	.size	Cipher1, .-Cipher1
.global	sboxm1
	.data
	.type	sboxm1, @object
	.size	sboxm1, 256
sboxm1:
	.byte	-33
	.byte	-54
	.byte	-83
	.byte	90
	.byte	-30
	.byte	-108
	.byte	-100
	.byte	23
	.byte	97
	.byte	-94
	.byte	39
	.byte	-92
	.byte	108
	.byte	74
	.byte	-109
	.byte	-125
	.byte	-113
	.byte	123
	.byte	-53
	.byte	2
	.byte	-86
	.byte	101
	.byte	-40
	.byte	88
	.byte	125
	.byte	59
	.byte	8
	.byte	84
	.byte	-33
	.byte	-23
	.byte	65
	.byte	69
	.byte	-35
	.byte	54
	.byte	45
	.byte	31
	.byte	124
	.byte	115
	.byte	-81
	.byte	3
	.byte	103
	.byte	116
	.byte	-27
	.byte	28
	.byte	81
	.byte	36
	.byte	-128
	.byte	78
	.byte	86
	.byte	-4
	.byte	-11
	.byte	112
	.byte	49
	.byte	117
	.byte	42
	.byte	30
	.byte	14
	.byte	-111
	.byte	-84
	.byte	-8
	.byte	-16
	.byte	73
	.byte	-24
	.byte	-43
	.byte	14
	.byte	-111
	.byte	-84
	.byte	-8
	.byte	-16
	.byte	73
	.byte	-24
	.byte	-43
	.byte	86
	.byte	-4
	.byte	-11
	.byte	112
	.byte	49
	.byte	117
	.byte	42
	.byte	30
	.byte	103
	.byte	116
	.byte	-27
	.byte	28
	.byte	81
	.byte	36
	.byte	-128
	.byte	78
	.byte	-35
	.byte	54
	.byte	45
	.byte	31
	.byte	124
	.byte	115
	.byte	-81
	.byte	3
	.byte	125
	.byte	59
	.byte	8
	.byte	84
	.byte	-33
	.byte	-23
	.byte	65
	.byte	69
	.byte	-113
	.byte	123
	.byte	-53
	.byte	2
	.byte	-86
	.byte	101
	.byte	-40
	.byte	88
	.byte	97
	.byte	-94
	.byte	39
	.byte	-92
	.byte	108
	.byte	74
	.byte	-109
	.byte	-125
	.byte	-33
	.byte	-54
	.byte	-83
	.byte	90
	.byte	-30
	.byte	-108
	.byte	-100
	.byte	23
	.byte	-116
	.byte	-107
	.byte	62
	.byte	-29
	.byte	-17
	.byte	-61
	.byte	-1
	.byte	1
	.byte	72
	.byte	6
	.byte	-9
	.byte	48
	.byte	-37
	.byte	-69
	.byte	91
	.byte	27
	.byte	-5
	.byte	-97
	.byte	-56
	.byte	53
	.byte	-20
	.byte	127
	.byte	-72
	.byte	87
	.byte	-89
	.byte	22
	.byte	32
	.byte	5
	.byte	-73
	.byte	-121
	.byte	-123
	.byte	79
	.byte	-127
	.byte	7
	.byte	109
	.byte	-77
	.byte	-49
	.byte	-57
	.byte	57
	.byte	-62
	.byte	-78
	.byte	-19
	.byte	25
	.byte	4
	.byte	-39
	.byte	-106
	.byte	18
	.byte	119
	.byte	15
	.byte	21
	.byte	67
	.byte	114
	.byte	-58
	.byte	104
	.byte	-59
	.byte	35
	.byte	-42
	.byte	46
	.byte	-47
	.byte	-60
	.byte	121
	.byte	-36
	.byte	26
	.byte	-50
	.byte	-42
	.byte	46
	.byte	-47
	.byte	-60
	.byte	121
	.byte	-36
	.byte	26
	.byte	-50
	.byte	15
	.byte	21
	.byte	67
	.byte	114
	.byte	-58
	.byte	104
	.byte	-59
	.byte	35
	.byte	-78
	.byte	-19
	.byte	25
	.byte	4
	.byte	-39
	.byte	-106
	.byte	18
	.byte	119
	.byte	-127
	.byte	7
	.byte	109
	.byte	-77
	.byte	-49
	.byte	-57
	.byte	57
	.byte	-62
	.byte	-89
	.byte	22
	.byte	32
	.byte	5
	.byte	-73
	.byte	-121
	.byte	-123
	.byte	79
	.byte	-5
	.byte	-97
	.byte	-56
	.byte	53
	.byte	-20
	.byte	127
	.byte	-72
	.byte	87
	.byte	72
	.byte	6
	.byte	-9
	.byte	48
	.byte	-37
	.byte	-69
	.byte	91
	.byte	27
	.byte	-116
	.byte	-107
	.byte	62
	.byte	-29
	.byte	-17
	.byte	-61
	.byte	-1
	.byte	1
.global	sbox1
	.type	sbox1, @object
	.size	sbox1, 256
sbox1:
	.byte	-33
	.byte	-54
	.byte	-83
	.byte	90
	.byte	-30
	.byte	-108
	.byte	-100
	.byte	23
	.byte	97
	.byte	-94
	.byte	39
	.byte	-92
	.byte	108
	.byte	74
	.byte	-109
	.byte	-125
	.byte	-113
	.byte	123
	.byte	-53
	.byte	2
	.byte	-86
	.byte	101
	.byte	-40
	.byte	88
	.byte	125
	.byte	59
	.byte	8
	.byte	84
	.byte	-33
	.byte	-23
	.byte	65
	.byte	69
	.byte	-35
	.byte	54
	.byte	45
	.byte	31
	.byte	124
	.byte	115
	.byte	-81
	.byte	3
	.byte	103
	.byte	116
	.byte	-27
	.byte	28
	.byte	81
	.byte	36
	.byte	-128
	.byte	78
	.byte	86
	.byte	-4
	.byte	-11
	.byte	112
	.byte	49
	.byte	117
	.byte	42
	.byte	30
	.byte	14
	.byte	-111
	.byte	-84
	.byte	-8
	.byte	-16
	.byte	73
	.byte	-24
	.byte	-43
	.byte	14
	.byte	-111
	.byte	-84
	.byte	-8
	.byte	-16
	.byte	73
	.byte	-24
	.byte	-43
	.byte	86
	.byte	-4
	.byte	-11
	.byte	112
	.byte	49
	.byte	117
	.byte	42
	.byte	30
	.byte	103
	.byte	116
	.byte	-27
	.byte	28
	.byte	81
	.byte	36
	.byte	-128
	.byte	78
	.byte	-35
	.byte	54
	.byte	45
	.byte	31
	.byte	124
	.byte	115
	.byte	-81
	.byte	3
	.byte	125
	.byte	59
	.byte	8
	.byte	84
	.byte	-33
	.byte	-23
	.byte	65
	.byte	69
	.byte	-113
	.byte	123
	.byte	-53
	.byte	2
	.byte	-86
	.byte	101
	.byte	-40
	.byte	88
	.byte	97
	.byte	-94
	.byte	39
	.byte	-92
	.byte	108
	.byte	74
	.byte	-109
	.byte	-125
	.byte	-33
	.byte	-54
	.byte	-83
	.byte	90
	.byte	-30
	.byte	-108
	.byte	-100
	.byte	23
	.byte	-116
	.byte	-107
	.byte	62
	.byte	-29
	.byte	-17
	.byte	-61
	.byte	-1
	.byte	1
	.byte	72
	.byte	6
	.byte	-9
	.byte	48
	.byte	-37
	.byte	-69
	.byte	91
	.byte	27
	.byte	-5
	.byte	-97
	.byte	-56
	.byte	53
	.byte	-20
	.byte	127
	.byte	-72
	.byte	87
	.byte	-89
	.byte	22
	.byte	32
	.byte	5
	.byte	-73
	.byte	-121
	.byte	-123
	.byte	79
	.byte	-127
	.byte	7
	.byte	109
	.byte	-77
	.byte	-49
	.byte	-57
	.byte	57
	.byte	-62
	.byte	-78
	.byte	-19
	.byte	25
	.byte	4
	.byte	-39
	.byte	-106
	.byte	18
	.byte	119
	.byte	15
	.byte	21
	.byte	67
	.byte	114
	.byte	-58
	.byte	104
	.byte	-59
	.byte	35
	.byte	-42
	.byte	46
	.byte	-47
	.byte	-60
	.byte	121
	.byte	-36
	.byte	26
	.byte	-50
	.byte	-42
	.byte	46
	.byte	-47
	.byte	-60
	.byte	121
	.byte	-36
	.byte	26
	.byte	-50
	.byte	15
	.byte	21
	.byte	67
	.byte	114
	.byte	-58
	.byte	104
	.byte	-59
	.byte	35
	.byte	-78
	.byte	-19
	.byte	25
	.byte	4
	.byte	-39
	.byte	-106
	.byte	18
	.byte	119
	.byte	-127
	.byte	7
	.byte	109
	.byte	-77
	.byte	-49
	.byte	-57
	.byte	57
	.byte	-62
	.byte	-89
	.byte	22
	.byte	32
	.byte	5
	.byte	-73
	.byte	-121
	.byte	-123
	.byte	79
	.byte	-5
	.byte	-97
	.byte	-56
	.byte	53
	.byte	-20
	.byte	127
	.byte	-72
	.byte	87
	.byte	72
	.byte	6
	.byte	-9
	.byte	48
	.byte	-37
	.byte	-69
	.byte	91
	.byte	27
	.byte	-116
	.byte	-107
	.byte	62
	.byte	-29
	.byte	-17
	.byte	-61
	.byte	-1
	.byte	1
.global	sboxm
	.type	sboxm, @object
	.size	sboxm, 256
sboxm:
	.byte	99
	.byte	124
	.byte	119
	.byte	123
	.byte	-14
	.byte	107
	.byte	111
	.byte	-59
	.byte	48
	.byte	1
	.byte	103
	.byte	43
	.byte	-2
	.byte	-41
	.byte	-85
	.byte	118
	.byte	-54
	.byte	-126
	.byte	-55
	.byte	125
	.byte	-6
	.byte	89
	.byte	71
	.byte	-16
	.byte	-83
	.byte	-44
	.byte	-94
	.byte	-81
	.byte	-100
	.byte	-92
	.byte	114
	.byte	-64
	.byte	-73
	.byte	-3
	.byte	-109
	.byte	38
	.byte	54
	.byte	63
	.byte	-9
	.byte	-52
	.byte	52
	.byte	-91
	.byte	-27
	.byte	-15
	.byte	113
	.byte	-40
	.byte	49
	.byte	21
	.byte	4
	.byte	-57
	.byte	35
	.byte	-61
	.byte	24
	.byte	-106
	.byte	5
	.byte	-102
	.byte	7
	.byte	18
	.byte	-128
	.byte	-30
	.byte	-21
	.byte	39
	.byte	-78
	.byte	117
	.byte	9
	.byte	-125
	.byte	44
	.byte	26
	.byte	27
	.byte	110
	.byte	90
	.byte	-96
	.byte	82
	.byte	59
	.byte	-42
	.byte	-77
	.byte	41
	.byte	-29
	.byte	47
	.byte	-124
	.byte	83
	.byte	-47
	.byte	0
	.byte	-19
	.byte	32
	.byte	-4
	.byte	-79
	.byte	91
	.byte	106
	.byte	-53
	.byte	-66
	.byte	57
	.byte	74
	.byte	76
	.byte	88
	.byte	-49
	.byte	-48
	.byte	-17
	.byte	-86
	.byte	-5
	.byte	67
	.byte	77
	.byte	51
	.byte	-123
	.byte	69
	.byte	-7
	.byte	2
	.byte	127
	.byte	80
	.byte	60
	.byte	-97
	.byte	-88
	.byte	81
	.byte	-93
	.byte	64
	.byte	-113
	.byte	-110
	.byte	-99
	.byte	56
	.byte	-11
	.byte	-68
	.byte	-74
	.byte	-38
	.byte	33
	.byte	16
	.byte	-1
	.byte	-13
	.byte	-46
	.byte	-51
	.byte	12
	.byte	19
	.byte	-20
	.byte	95
	.byte	-105
	.byte	68
	.byte	23
	.byte	-60
	.byte	-89
	.byte	126
	.byte	61
	.byte	100
	.byte	93
	.byte	25
	.byte	115
	.byte	96
	.byte	-127
	.byte	79
	.byte	-36
	.byte	34
	.byte	42
	.byte	-112
	.byte	-120
	.byte	70
	.byte	-18
	.byte	-72
	.byte	20
	.byte	-34
	.byte	94
	.byte	11
	.byte	-37
	.byte	-32
	.byte	50
	.byte	58
	.byte	10
	.byte	73
	.byte	6
	.byte	36
	.byte	92
	.byte	-62
	.byte	-45
	.byte	-84
	.byte	98
	.byte	-111
	.byte	-107
	.byte	-28
	.byte	121
	.byte	-25
	.byte	-56
	.byte	55
	.byte	109
	.byte	-115
	.byte	-43
	.byte	78
	.byte	-87
	.byte	108
	.byte	86
	.byte	-12
	.byte	-22
	.byte	101
	.byte	122
	.byte	-82
	.byte	8
	.byte	-70
	.byte	120
	.byte	37
	.byte	46
	.byte	28
	.byte	-90
	.byte	-76
	.byte	-58
	.byte	-24
	.byte	-35
	.byte	116
	.byte	31
	.byte	75
	.byte	-67
	.byte	-117
	.byte	-118
	.byte	112
	.byte	62
	.byte	-75
	.byte	102
	.byte	72
	.byte	3
	.byte	-10
	.byte	14
	.byte	97
	.byte	53
	.byte	87
	.byte	-71
	.byte	-122
	.byte	-63
	.byte	29
	.byte	-98
	.byte	-31
	.byte	-8
	.byte	-104
	.byte	17
	.byte	105
	.byte	-39
	.byte	-114
	.byte	-108
	.byte	-101
	.byte	30
	.byte	-121
	.byte	-23
	.byte	-50
	.byte	85
	.byte	40
	.byte	-33
	.byte	-116
	.byte	-95
	.byte	-119
	.byte	13
	.byte	-65
	.byte	-26
	.byte	66
	.byte	104
	.byte	65
	.byte	-103
	.byte	45
	.byte	15
	.byte	-80
	.byte	84
	.byte	-69
	.byte	22
.global	sbox
	.type	sbox, @object
	.size	sbox, 256
sbox:
	.byte	99
	.byte	124
	.byte	119
	.byte	123
	.byte	-14
	.byte	107
	.byte	111
	.byte	-59
	.byte	48
	.byte	1
	.byte	103
	.byte	43
	.byte	-2
	.byte	-41
	.byte	-85
	.byte	118
	.byte	-54
	.byte	-126
	.byte	-55
	.byte	125
	.byte	-6
	.byte	89
	.byte	71
	.byte	-16
	.byte	-83
	.byte	-44
	.byte	-94
	.byte	-81
	.byte	-100
	.byte	-92
	.byte	114
	.byte	-64
	.byte	-73
	.byte	-3
	.byte	-109
	.byte	38
	.byte	54
	.byte	63
	.byte	-9
	.byte	-52
	.byte	52
	.byte	-91
	.byte	-27
	.byte	-15
	.byte	113
	.byte	-40
	.byte	49
	.byte	21
	.byte	4
	.byte	-57
	.byte	35
	.byte	-61
	.byte	24
	.byte	-106
	.byte	5
	.byte	-102
	.byte	7
	.byte	18
	.byte	-128
	.byte	-30
	.byte	-21
	.byte	39
	.byte	-78
	.byte	117
	.byte	9
	.byte	-125
	.byte	44
	.byte	26
	.byte	27
	.byte	110
	.byte	90
	.byte	-96
	.byte	82
	.byte	59
	.byte	-42
	.byte	-77
	.byte	41
	.byte	-29
	.byte	47
	.byte	-124
	.byte	83
	.byte	-47
	.byte	0
	.byte	-19
	.byte	32
	.byte	-4
	.byte	-79
	.byte	91
	.byte	106
	.byte	-53
	.byte	-66
	.byte	57
	.byte	74
	.byte	76
	.byte	88
	.byte	-49
	.byte	-48
	.byte	-17
	.byte	-86
	.byte	-5
	.byte	67
	.byte	77
	.byte	51
	.byte	-123
	.byte	69
	.byte	-7
	.byte	2
	.byte	127
	.byte	80
	.byte	60
	.byte	-97
	.byte	-88
	.byte	81
	.byte	-93
	.byte	64
	.byte	-113
	.byte	-110
	.byte	-99
	.byte	56
	.byte	-11
	.byte	-68
	.byte	-74
	.byte	-38
	.byte	33
	.byte	16
	.byte	-1
	.byte	-13
	.byte	-46
	.byte	-51
	.byte	12
	.byte	19
	.byte	-20
	.byte	95
	.byte	-105
	.byte	68
	.byte	23
	.byte	-60
	.byte	-89
	.byte	126
	.byte	61
	.byte	100
	.byte	93
	.byte	25
	.byte	115
	.byte	96
	.byte	-127
	.byte	79
	.byte	-36
	.byte	34
	.byte	42
	.byte	-112
	.byte	-120
	.byte	70
	.byte	-18
	.byte	-72
	.byte	20
	.byte	-34
	.byte	94
	.byte	11
	.byte	-37
	.byte	-32
	.byte	50
	.byte	58
	.byte	10
	.byte	73
	.byte	6
	.byte	36
	.byte	92
	.byte	-62
	.byte	-45
	.byte	-84
	.byte	98
	.byte	-111
	.byte	-107
	.byte	-28
	.byte	121
	.byte	-25
	.byte	-56
	.byte	55
	.byte	109
	.byte	-115
	.byte	-43
	.byte	78
	.byte	-87
	.byte	108
	.byte	86
	.byte	-12
	.byte	-22
	.byte	101
	.byte	122
	.byte	-82
	.byte	8
	.byte	-70
	.byte	120
	.byte	37
	.byte	46
	.byte	28
	.byte	-90
	.byte	-76
	.byte	-58
	.byte	-24
	.byte	-35
	.byte	116
	.byte	31
	.byte	75
	.byte	-67
	.byte	-117
	.byte	-118
	.byte	112
	.byte	62
	.byte	-75
	.byte	102
	.byte	72
	.byte	3
	.byte	-10
	.byte	14
	.byte	97
	.byte	53
	.byte	87
	.byte	-71
	.byte	-122
	.byte	-63
	.byte	29
	.byte	-98
	.byte	-31
	.byte	-8
	.byte	-104
	.byte	17
	.byte	105
	.byte	-39
	.byte	-114
	.byte	-108
	.byte	-101
	.byte	30
	.byte	-121
	.byte	-23
	.byte	-50
	.byte	85
	.byte	40
	.byte	-33
	.byte	-116
	.byte	-95
	.byte	-119
	.byte	13
	.byte	-65
	.byte	-26
	.byte	66
	.byte	104
	.byte	65
	.byte	-103
	.byte	45
	.byte	15
	.byte	-80
	.byte	84
	.byte	-69
	.byte	22
.global	r1
	.type	r1, @object
	.size	r1, 16
r1:
	.byte	1
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	0
.global	rout1
	.type	rout1, @object
	.size	rout1, 1
rout1:
	.byte	16
.global	rin1
	.type	rin1, @object
	.size	rin1, 1
rin1:
	.byte	16
.global	r
	.type	r, @object
	.size	r, 16
r:
	.byte	1
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	0
.global	rout
	.type	rout, @object
	.size	rout, 1
rout:
	.byte	16
.global	rin
	.type	rin, @object
	.size	rin, 1
rin:
	.byte	16
	.text
.Letext0:
	.file 2 "/usr/lib/avr/include/stdint.h"
	.file 3 "cipher.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x6a1
	.word	0x2
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF30
	.byte	0xc
	.long	.LASF31
	.long	.LASF32
	.long	.Ltext0
	.long	.Letext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF0
	.uleb128 0x3
	.long	.LASF7
	.byte	0x2
	.byte	0x7e
	.long	0x37
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.long	.LASF1
	.uleb128 0x4
	.byte	0x2
	.byte	0x5
	.string	"int"
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF2
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.long	.LASF3
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF4
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF5
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF6
	.uleb128 0x3
	.long	.LASF8
	.byte	0x3
	.byte	0xa
	.long	0x73
	.uleb128 0x5
	.long	0x2c
	.long	0x89
	.uleb128 0x6
	.long	0x89
	.byte	0x3
	.uleb128 0x6
	.long	0x89
	.byte	0x3
	.byte	0
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF9
	.uleb128 0x7
	.byte	0x1
	.long	.LASF13
	.byte	0x1
	.byte	0x59
	.byte	0x1
	.long	.LFB0
	.long	.LFE0
	.long	.LLST0
	.byte	0x1
	.long	0xf3
	.uleb128 0x8
	.long	.LASF10
	.byte	0x1
	.byte	0x59
	.long	0x2c
	.byte	0x1
	.byte	0x68
	.uleb128 0x8
	.long	.LASF11
	.byte	0x1
	.byte	0x59
	.long	0xf3
	.byte	0x6
	.byte	0x66
	.byte	0x93
	.uleb128 0x1
	.byte	0x67
	.byte	0x93
	.uleb128 0x1
	.uleb128 0x9
	.long	.LASF12
	.byte	0x1
	.byte	0x59
	.long	0xf9
	.long	.LLST1
	.uleb128 0xa
	.string	"i"
	.byte	0x1
	.byte	0x5b
	.long	0x2c
	.long	.LLST2
	.uleb128 0xa
	.string	"j"
	.byte	0x1
	.byte	0x5b
	.long	0x2c
	.long	.LLST3
	.byte	0
	.uleb128 0xb
	.byte	0x2
	.long	0x68
	.uleb128 0xb
	.byte	0x2
	.long	0xff
	.uleb128 0xc
	.long	0x2c
	.uleb128 0xd
	.byte	0x1
	.long	.LASF14
	.byte	0x1
	.byte	0x69
	.byte	0x1
	.long	.LFB1
	.long	.LFE1
	.byte	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 3
	.byte	0x1
	.long	0x148
	.uleb128 0x9
	.long	.LASF11
	.byte	0x1
	.byte	0x69
	.long	0xf3
	.long	.LLST4
	.uleb128 0xa
	.string	"i"
	.byte	0x1
	.byte	0x6b
	.long	0x2c
	.long	.LLST5
	.uleb128 0xa
	.string	"j"
	.byte	0x1
	.byte	0x6b
	.long	0x2c
	.long	.LLST6
	.byte	0
	.uleb128 0xd
	.byte	0x1
	.long	.LASF15
	.byte	0x1
	.byte	0x75
	.byte	0x1
	.long	.LFB2
	.long	.LFE2
	.byte	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 3
	.byte	0x1
	.long	0x18c
	.uleb128 0x9
	.long	.LASF11
	.byte	0x1
	.byte	0x75
	.long	0xf3
	.long	.LLST7
	.uleb128 0xa
	.string	"i"
	.byte	0x1
	.byte	0x77
	.long	0x2c
	.long	.LLST8
	.uleb128 0xa
	.string	"j"
	.byte	0x1
	.byte	0x77
	.long	0x2c
	.long	.LLST9
	.byte	0
	.uleb128 0xd
	.byte	0x1
	.long	.LASF16
	.byte	0x1
	.byte	0x84
	.byte	0x1
	.long	.LFB3
	.long	.LFE3
	.byte	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 3
	.byte	0x1
	.long	0x1c3
	.uleb128 0x9
	.long	.LASF11
	.byte	0x1
	.byte	0x84
	.long	0xf3
	.long	.LLST10
	.uleb128 0xe
	.long	.LASF17
	.byte	0x1
	.byte	0x86
	.long	0x2c
	.byte	0x1
	.byte	0x68
	.byte	0
	.uleb128 0xf
	.byte	0x1
	.long	.LASF33
	.byte	0x1
	.byte	0xa0
	.byte	0x1
	.long	0x2c
	.long	.LFB4
	.long	.LFE4
	.byte	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 3
	.byte	0x1
	.long	0x1fc
	.uleb128 0x10
	.string	"x"
	.byte	0x1
	.byte	0xa0
	.long	0x2c
	.long	.LLST11
	.uleb128 0x11
	.string	"res"
	.byte	0x1
	.byte	0xa2
	.long	0x2c
	.byte	0x1
	.byte	0x68
	.byte	0
	.uleb128 0x7
	.byte	0x1
	.long	.LASF18
	.byte	0x1
	.byte	0xaa
	.byte	0x1
	.long	.LFB5
	.long	.LFE5
	.long	.LLST12
	.byte	0x1
	.long	0x2cb
	.uleb128 0x9
	.long	.LASF11
	.byte	0x1
	.byte	0xaa
	.long	0xf3
	.long	.LLST13
	.uleb128 0x9
	.long	.LASF10
	.byte	0x1
	.byte	0xaa
	.long	0x2c
	.long	.LLST14
	.uleb128 0xa
	.string	"i"
	.byte	0x1
	.byte	0xac
	.long	0x2c
	.long	.LLST15
	.uleb128 0xa
	.string	"Tmp"
	.byte	0x1
	.byte	0xad
	.long	0x2c
	.long	.LLST16
	.uleb128 0xa
	.string	"Tm"
	.byte	0x1
	.byte	0xad
	.long	0x2c
	.long	.LLST17
	.uleb128 0xa
	.string	"t"
	.byte	0x1
	.byte	0xad
	.long	0x2c
	.long	.LLST18
	.uleb128 0x12
	.string	"a"
	.byte	0x1
	.byte	0xae
	.long	0x2c
	.byte	0
	.uleb128 0x13
	.long	.LVL34
	.long	0x1c3
	.long	0x28c
	.uleb128 0x14
	.byte	0x1
	.byte	0x68
	.byte	0x5
	.byte	0x7b
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x27
	.byte	0
	.uleb128 0x13
	.long	.LVL38
	.long	0x1c3
	.long	0x2a3
	.uleb128 0x14
	.byte	0x1
	.byte	0x68
	.byte	0x5
	.byte	0x80
	.sleb128 0
	.byte	0x81
	.sleb128 0
	.byte	0x27
	.byte	0
	.uleb128 0x13
	.long	.LVL41
	.long	0x1c3
	.long	0x2b7
	.uleb128 0x14
	.byte	0x1
	.byte	0x68
	.byte	0x2
	.byte	0x7a
	.sleb128 0
	.byte	0
	.uleb128 0x15
	.long	.LVL45
	.long	0x1c3
	.uleb128 0x14
	.byte	0x1
	.byte	0x68
	.byte	0x5
	.byte	0x7b
	.sleb128 0
	.byte	0x7c
	.sleb128 0
	.byte	0x27
	.byte	0
	.byte	0
	.uleb128 0x7
	.byte	0x1
	.long	.LASF19
	.byte	0x1
	.byte	0xbb
	.byte	0x1
	.long	.LFB6
	.long	.LFE6
	.long	.LLST19
	.byte	0x1
	.long	0x5d3
	.uleb128 0x9
	.long	.LASF11
	.byte	0x1
	.byte	0xbb
	.long	0xf3
	.long	.LLST20
	.uleb128 0x9
	.long	.LASF20
	.byte	0x1
	.byte	0xbb
	.long	0xf3
	.long	.LLST21
	.uleb128 0x9
	.long	.LASF21
	.byte	0x1
	.byte	0xbb
	.long	0xf3
	.long	.LLST22
	.uleb128 0x9
	.long	.LASF22
	.byte	0x1
	.byte	0xbb
	.long	0xf3
	.long	.LLST23
	.uleb128 0x9
	.long	.LASF12
	.byte	0x1
	.byte	0xbb
	.long	0xf9
	.long	.LLST24
	.uleb128 0x16
	.long	.LASF10
	.byte	0x1
	.byte	0xbc
	.long	0x2c
	.long	.LLST25
	.uleb128 0x11
	.string	"rk"
	.byte	0x1
	.byte	0xbd
	.long	0x73
	.byte	0x2
	.byte	0x8c
	.sleb128 1
	.uleb128 0x17
	.long	.LBB2
	.long	.LBE2
	.long	0x37e
	.uleb128 0xa
	.string	"i"
	.byte	0x1
	.byte	0xc6
	.long	0x3e
	.long	.LLST26
	.uleb128 0x18
	.long	.LBB3
	.long	.LBE3
	.uleb128 0xa
	.string	"j"
	.byte	0x1
	.byte	0xc7
	.long	0x3e
	.long	.LLST27
	.byte	0
	.byte	0
	.uleb128 0x17
	.long	.LBB4
	.long	.LBE4
	.long	0x3b0
	.uleb128 0xa
	.string	"i"
	.byte	0x1
	.byte	0xce
	.long	0x3e
	.long	.LLST28
	.uleb128 0x18
	.long	.LBB5
	.long	.LBE5
	.uleb128 0xa
	.string	"j"
	.byte	0x1
	.byte	0xcf
	.long	0x3e
	.long	.LLST29
	.byte	0
	.byte	0
	.uleb128 0x17
	.long	.LBB6
	.long	.LBE6
	.long	0x3e2
	.uleb128 0xa
	.string	"i"
	.byte	0x1
	.byte	0xdb
	.long	0x3e
	.long	.LLST30
	.uleb128 0x18
	.long	.LBB7
	.long	.LBE7
	.uleb128 0xa
	.string	"j"
	.byte	0x1
	.byte	0xdc
	.long	0x3e
	.long	.LLST31
	.byte	0
	.byte	0
	.uleb128 0x19
	.long	.Ldebug_ranges0+0
	.long	0x410
	.uleb128 0xa
	.string	"i"
	.byte	0x1
	.byte	0xe6
	.long	0x3e
	.long	.LLST32
	.uleb128 0x18
	.long	.LBB9
	.long	.LBE9
	.uleb128 0xa
	.string	"j"
	.byte	0x1
	.byte	0xe7
	.long	0x3e
	.long	.LLST33
	.byte	0
	.byte	0
	.uleb128 0x17
	.long	.LBB10
	.long	.LBE10
	.long	0x43e
	.uleb128 0x1a
	.string	"i"
	.byte	0x1
	.byte	0xed
	.long	0x3e
	.uleb128 0x18
	.long	.LBB11
	.long	.LBE11
	.uleb128 0xa
	.string	"j"
	.byte	0x1
	.byte	0xee
	.long	0x3e
	.long	.LLST34
	.byte	0
	.byte	0
	.uleb128 0x17
	.long	.LBB13
	.long	.LBE13
	.long	0x470
	.uleb128 0xa
	.string	"i"
	.byte	0x1
	.byte	0xf7
	.long	0x3e
	.long	.LLST35
	.uleb128 0x18
	.long	.LBB14
	.long	.LBE14
	.uleb128 0xa
	.string	"j"
	.byte	0x1
	.byte	0xf8
	.long	0x3e
	.long	.LLST36
	.byte	0
	.byte	0
	.uleb128 0x13
	.long	.LVL55
	.long	0x104
	.long	0x489
	.uleb128 0x14
	.byte	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x7e
	.sleb128 0
	.byte	0
	.uleb128 0x13
	.long	.LVL59
	.long	0x148
	.long	0x4a2
	.uleb128 0x14
	.byte	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x7c
	.sleb128 0
	.byte	0
	.uleb128 0x13
	.long	.LVL63
	.long	0x18c
	.long	0x4bb
	.uleb128 0x14
	.byte	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x7e
	.sleb128 0
	.byte	0
	.uleb128 0x13
	.long	.LVL64
	.long	0x18c
	.long	0x4d4
	.uleb128 0x14
	.byte	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x7a
	.sleb128 0
	.byte	0
	.uleb128 0x13
	.long	.LVL65
	.long	0x1fc
	.long	0x4f3
	.uleb128 0x14
	.byte	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x7e
	.sleb128 0
	.uleb128 0x14
	.byte	0x1
	.byte	0x66
	.byte	0x2
	.byte	0x77
	.sleb128 0
	.byte	0
	.uleb128 0x13
	.long	.LVL66
	.long	0x1fc
	.long	0x512
	.uleb128 0x14
	.byte	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x7a
	.sleb128 0
	.uleb128 0x14
	.byte	0x1
	.byte	0x66
	.byte	0x2
	.byte	0x77
	.sleb128 0
	.byte	0
	.uleb128 0x13
	.long	.LVL67
	.long	0x90
	.long	0x53c
	.uleb128 0x14
	.byte	0x1
	.byte	0x68
	.byte	0x2
	.byte	0x77
	.sleb128 0
	.uleb128 0x14
	.byte	0x6
	.byte	0x66
	.byte	0x93
	.uleb128 0x1
	.byte	0x67
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x7e
	.sleb128 0
	.uleb128 0x14
	.byte	0x6
	.byte	0x64
	.byte	0x93
	.uleb128 0x1
	.byte	0x65
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x80
	.sleb128 0
	.byte	0
	.uleb128 0x13
	.long	.LVL72
	.long	0x18c
	.long	0x555
	.uleb128 0x14
	.byte	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x7c
	.sleb128 0
	.byte	0
	.uleb128 0x13
	.long	.LVL73
	.long	0x18c
	.long	0x56e
	.uleb128 0x14
	.byte	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x78
	.sleb128 0
	.byte	0
	.uleb128 0x13
	.long	.LVL74
	.long	0x1fc
	.long	0x58d
	.uleb128 0x14
	.byte	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x7c
	.sleb128 0
	.uleb128 0x14
	.byte	0x1
	.byte	0x66
	.byte	0x2
	.byte	0x77
	.sleb128 0
	.byte	0
	.uleb128 0x13
	.long	.LVL75
	.long	0x1fc
	.long	0x5ac
	.uleb128 0x14
	.byte	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x78
	.sleb128 0
	.uleb128 0x14
	.byte	0x1
	.byte	0x66
	.byte	0x2
	.byte	0x77
	.sleb128 0
	.byte	0
	.uleb128 0x15
	.long	.LVL86
	.long	0x90
	.uleb128 0x14
	.byte	0x1
	.byte	0x68
	.byte	0x2
	.byte	0x75
	.sleb128 0
	.uleb128 0x14
	.byte	0x6
	.byte	0x66
	.byte	0x93
	.uleb128 0x1
	.byte	0x67
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x7e
	.sleb128 0
	.uleb128 0x14
	.byte	0x6
	.byte	0x64
	.byte	0x93
	.uleb128 0x1
	.byte	0x65
	.byte	0x93
	.uleb128 0x1
	.byte	0x2
	.byte	0x80
	.sleb128 0
	.byte	0
	.byte	0
	.uleb128 0x1b
	.string	"rin"
	.byte	0x1
	.byte	0xa
	.long	0x2c
	.byte	0x1
	.byte	0x5
	.byte	0x3
	.long	rin
	.uleb128 0x1c
	.long	.LASF23
	.byte	0x1
	.byte	0xa
	.long	0x2c
	.byte	0x1
	.byte	0x5
	.byte	0x3
	.long	rout
	.uleb128 0x5
	.long	0x2c
	.long	0x607
	.uleb128 0x6
	.long	0x89
	.byte	0xf
	.byte	0
	.uleb128 0x1b
	.string	"r"
	.byte	0x1
	.byte	0xb
	.long	0x5f7
	.byte	0x1
	.byte	0x5
	.byte	0x3
	.long	r
	.uleb128 0x1c
	.long	.LASF24
	.byte	0x1
	.byte	0xc
	.long	0x2c
	.byte	0x1
	.byte	0x5
	.byte	0x3
	.long	rin1
	.uleb128 0x1c
	.long	.LASF25
	.byte	0x1
	.byte	0xc
	.long	0x2c
	.byte	0x1
	.byte	0x5
	.byte	0x3
	.long	rout1
	.uleb128 0x1b
	.string	"r1"
	.byte	0x1
	.byte	0xd
	.long	0x5f7
	.byte	0x1
	.byte	0x5
	.byte	0x3
	.long	r1
	.uleb128 0x5
	.long	0x2c
	.long	0x65c
	.uleb128 0x6
	.long	0x89
	.byte	0xff
	.byte	0
	.uleb128 0x1c
	.long	.LASF26
	.byte	0x1
	.byte	0xe
	.long	0x64c
	.byte	0x1
	.byte	0x5
	.byte	0x3
	.long	sbox
	.uleb128 0x1c
	.long	.LASF27
	.byte	0x1
	.byte	0x20
	.long	0x64c
	.byte	0x1
	.byte	0x5
	.byte	0x3
	.long	sboxm
	.uleb128 0x1c
	.long	.LASF28
	.byte	0x1
	.byte	0x34
	.long	0x64c
	.byte	0x1
	.byte	0x5
	.byte	0x3
	.long	sbox1
	.uleb128 0x1c
	.long	.LASF29
	.byte	0x1
	.byte	0x46
	.long	0x64c
	.byte	0x1
	.byte	0x5
	.byte	0x3
	.long	sboxm1
	.byte	0
	.section	.debug_abbrev,"",@progbits
.Ldebug_abbrev0:
	.uleb128 0x1
	.uleb128 0x11
	.byte	0x1
	.uleb128 0x25
	.uleb128 0xe
	.uleb128 0x13
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1b
	.uleb128 0xe
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x1
	.uleb128 0x10
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x3
	.uleb128 0x16
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x8
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0xc
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0xc
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x1
	.uleb128 0x40
	.uleb128 0x6
	.uleb128 0x2117
	.uleb128 0xc
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0xa
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xc
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xd
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0xc
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0xc
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x1
	.uleb128 0x40
	.uleb128 0xa
	.uleb128 0x2117
	.uleb128 0xc
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xe
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0xa
	.byte	0
	.byte	0
	.uleb128 0xf
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0xc
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0xc
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x1
	.uleb128 0x40
	.uleb128 0xa
	.uleb128 0x2117
	.uleb128 0xc
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x10
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0xa
	.byte	0
	.byte	0
	.uleb128 0x12
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1c
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x13
	.uleb128 0x4109
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x14
	.uleb128 0x410a
	.byte	0
	.uleb128 0x2
	.uleb128 0xa
	.uleb128 0x2111
	.uleb128 0xa
	.byte	0
	.byte	0
	.uleb128 0x15
	.uleb128 0x4109
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x16
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0x17
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x1
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x18
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x1
	.byte	0
	.byte	0
	.uleb128 0x19
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x55
	.uleb128 0x6
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1a
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1b
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0xc
	.uleb128 0x2
	.uleb128 0xa
	.byte	0
	.byte	0
	.uleb128 0x1c
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0xc
	.uleb128 0x2
	.uleb128 0xa
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LLST0:
	.long	.LFB0-.Ltext0
	.long	.LCFI0-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 3
	.long	.LCFI0-.Ltext0
	.long	.LCFI1-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 4
	.long	.LCFI1-.Ltext0
	.long	.LCFI2-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 5
	.long	.LCFI2-.Ltext0
	.long	.LCFI3-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 6
	.long	.LCFI3-.Ltext0
	.long	.LFE0-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 7
	.long	0
	.long	0
.LLST1:
	.long	.LVL0-.Ltext0
	.long	.LVL2-.Ltext0
	.word	0x6
	.byte	0x64
	.byte	0x93
	.uleb128 0x1
	.byte	0x65
	.byte	0x93
	.uleb128 0x1
	.long	.LVL2-.Ltext0
	.long	.LVL5-.Ltext0
	.word	0x6
	.byte	0x6c
	.byte	0x93
	.uleb128 0x1
	.byte	0x6d
	.byte	0x93
	.uleb128 0x1
	.long	.LVL5-.Ltext0
	.long	.LFE0-.Ltext0
	.word	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x64
	.byte	0x9f
	.long	0
	.long	0
.LLST2:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST3:
	.long	.LVL2-.Ltext0
	.long	.LVL3-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL3-.Ltext0
	.long	.LFE0-.Ltext0
	.word	0x1
	.byte	0x65
	.long	0
	.long	0
.LLST4:
	.long	.LVL6-.Ltext0
	.long	.LVL8-.Ltext0
	.word	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.long	.LVL8-.Ltext0
	.long	.LFE1-.Ltext0
	.word	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x68
	.byte	0x9f
	.long	0
	.long	0
.LLST5:
	.long	.LVL7-.Ltext0
	.long	.LVL8-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL8-.Ltext0
	.long	.LVL11-.Ltext0
	.word	0x7
	.byte	0x82
	.sleb128 0
	.byte	0xf3
	.uleb128 0x1
	.byte	0x68
	.byte	0x1c
	.byte	0x9f
	.long	.LVL11-.Ltext0
	.long	.LVL12-.Ltext0
	.word	0x9
	.byte	0x82
	.sleb128 0
	.byte	0xf3
	.uleb128 0x1
	.byte	0x68
	.byte	0x1c
	.byte	0x23
	.uleb128 0x1
	.byte	0x9f
	.long	.LVL12-.Ltext0
	.long	.LFE1-.Ltext0
	.word	0x7
	.byte	0x82
	.sleb128 0
	.byte	0xf3
	.uleb128 0x1
	.byte	0x68
	.byte	0x1c
	.byte	0x9f
	.long	0
	.long	0
.LLST6:
	.long	.LVL8-.Ltext0
	.long	.LVL9-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL9-.Ltext0
	.long	.LFE1-.Ltext0
	.word	0x1
	.byte	0x69
	.long	0
	.long	0
.LLST7:
	.long	.LVL13-.Ltext0
	.long	.LVL15-.Ltext0
	.word	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.long	.LVL15-.Ltext0
	.long	.LFE2-.Ltext0
	.word	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x68
	.byte	0x9f
	.long	0
	.long	0
.LLST8:
	.long	.LVL14-.Ltext0
	.long	.LVL15-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL15-.Ltext0
	.long	.LVL18-.Ltext0
	.word	0x7
	.byte	0x82
	.sleb128 0
	.byte	0xf3
	.uleb128 0x1
	.byte	0x68
	.byte	0x1c
	.byte	0x9f
	.long	.LVL18-.Ltext0
	.long	.LVL19-.Ltext0
	.word	0x9
	.byte	0x82
	.sleb128 0
	.byte	0xf3
	.uleb128 0x1
	.byte	0x68
	.byte	0x1c
	.byte	0x23
	.uleb128 0x1
	.byte	0x9f
	.long	.LVL19-.Ltext0
	.long	.LFE2-.Ltext0
	.word	0x7
	.byte	0x82
	.sleb128 0
	.byte	0xf3
	.uleb128 0x1
	.byte	0x68
	.byte	0x1c
	.byte	0x9f
	.long	0
	.long	0
.LLST9:
	.long	.LVL15-.Ltext0
	.long	.LVL16-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL16-.Ltext0
	.long	.LFE2-.Ltext0
	.word	0x1
	.byte	0x69
	.long	0
	.long	0
.LLST10:
	.long	.LVL20-.Ltext0
	.long	.LVL21-.Ltext0
	.word	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.long	.LVL21-.Ltext0
	.long	.LFE3-.Ltext0
	.word	0x6
	.byte	0x6e
	.byte	0x93
	.uleb128 0x1
	.byte	0x6f
	.byte	0x93
	.uleb128 0x1
	.long	0
	.long	0
.LLST11:
	.long	.LVL25-.Ltext0
	.long	.LVL26-.Ltext0
	.word	0x1
	.byte	0x68
	.long	.LVL26-.Ltext0
	.long	.LVL27-.Ltext0
	.word	0x1
	.byte	0x69
	.long	.LVL27-.Ltext0
	.long	.LFE4-.Ltext0
	.word	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x68
	.byte	0x9f
	.long	0
	.long	0
.LLST12:
	.long	.LFB5-.Ltext0
	.long	.LCFI4-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 3
	.long	.LCFI4-.Ltext0
	.long	.LCFI5-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 4
	.long	.LCFI5-.Ltext0
	.long	.LCFI6-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 5
	.long	.LCFI6-.Ltext0
	.long	.LCFI7-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 6
	.long	.LCFI7-.Ltext0
	.long	.LCFI8-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 7
	.long	.LCFI8-.Ltext0
	.long	.LCFI9-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 8
	.long	.LCFI9-.Ltext0
	.long	.LCFI10-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 9
	.long	.LCFI10-.Ltext0
	.long	.LCFI11-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 10
	.long	.LCFI11-.Ltext0
	.long	.LCFI12-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 11
	.long	.LCFI12-.Ltext0
	.long	.LCFI13-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 12
	.long	.LCFI13-.Ltext0
	.long	.LFE5-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 13
	.long	0
	.long	0
.LLST13:
	.long	.LVL29-.Ltext0
	.long	.LVL31-.Ltext0
	.word	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.long	.LVL31-.Ltext0
	.long	.LVL48-.Ltext0
	.word	0x3
	.byte	0x7e
	.sleb128 -16
	.byte	0x9f
	.long	.LVL48-.Ltext0
	.long	.LFE5-.Ltext0
	.word	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x68
	.byte	0x9f
	.long	0
	.long	0
.LLST14:
	.long	.LVL29-.Ltext0
	.long	.LVL31-.Ltext0
	.word	0x1
	.byte	0x66
	.long	.LVL31-.Ltext0
	.long	.LFE5-.Ltext0
	.word	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x66
	.byte	0x9f
	.long	0
	.long	0
.LLST15:
	.long	.LVL30-.Ltext0
	.long	.LVL31-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST16:
	.long	.LVL33-.Ltext0
	.long	.LVL47-.Ltext0
	.word	0x1
	.byte	0x5d
	.long	0
	.long	0
.LLST17:
	.long	.LVL33-.Ltext0
	.long	.LVL34-1-.Ltext0
	.word	0x1
	.byte	0x68
	.long	.LVL34-1-.Ltext0
	.long	.LVL34-.Ltext0
	.word	0x6
	.byte	0x7b
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x27
	.byte	0x9f
	.long	.LVL34-.Ltext0
	.long	.LVL35-.Ltext0
	.word	0x1
	.byte	0x68
	.long	.LVL36-.Ltext0
	.long	.LVL37-.Ltext0
	.word	0x6
	.byte	0x80
	.sleb128 0
	.byte	0x81
	.sleb128 0
	.byte	0x27
	.byte	0x9f
	.long	.LVL37-.Ltext0
	.long	.LVL38-1-.Ltext0
	.word	0x1
	.byte	0x68
	.long	.LVL38-1-.Ltext0
	.long	.LVL38-.Ltext0
	.word	0x6
	.byte	0x80
	.sleb128 0
	.byte	0x81
	.sleb128 0
	.byte	0x27
	.byte	0x9f
	.long	.LVL38-.Ltext0
	.long	.LVL39-.Ltext0
	.word	0x1
	.byte	0x68
	.long	.LVL40-.Ltext0
	.long	.LVL41-.Ltext0
	.word	0x1
	.byte	0x5a
	.long	.LVL41-.Ltext0
	.long	.LVL42-.Ltext0
	.word	0x1
	.byte	0x68
	.long	.LVL43-.Ltext0
	.long	.LVL44-.Ltext0
	.word	0x6
	.byte	0x7b
	.sleb128 0
	.byte	0x7c
	.sleb128 0
	.byte	0x27
	.byte	0x9f
	.long	.LVL44-.Ltext0
	.long	.LVL45-1-.Ltext0
	.word	0x1
	.byte	0x68
	.long	.LVL45-1-.Ltext0
	.long	.LVL45-.Ltext0
	.word	0x6
	.byte	0x7b
	.sleb128 0
	.byte	0x7c
	.sleb128 0
	.byte	0x27
	.byte	0x9f
	.long	.LVL45-.Ltext0
	.long	.LVL46-.Ltext0
	.word	0x1
	.byte	0x68
	.long	0
	.long	0
.LLST18:
	.long	.LVL32-.Ltext0
	.long	.LVL49-.Ltext0
	.word	0x1
	.byte	0x5b
	.long	0
	.long	0
.LLST19:
	.long	.LFB6-.Ltext0
	.long	.LCFI14-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 3
	.long	.LCFI14-.Ltext0
	.long	.LCFI15-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 4
	.long	.LCFI15-.Ltext0
	.long	.LCFI16-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 5
	.long	.LCFI16-.Ltext0
	.long	.LCFI17-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 6
	.long	.LCFI17-.Ltext0
	.long	.LCFI18-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 7
	.long	.LCFI18-.Ltext0
	.long	.LCFI19-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 8
	.long	.LCFI19-.Ltext0
	.long	.LCFI20-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 9
	.long	.LCFI20-.Ltext0
	.long	.LCFI21-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 10
	.long	.LCFI21-.Ltext0
	.long	.LCFI22-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 11
	.long	.LCFI22-.Ltext0
	.long	.LCFI23-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 12
	.long	.LCFI23-.Ltext0
	.long	.LCFI24-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 13
	.long	.LCFI24-.Ltext0
	.long	.LCFI25-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 14
	.long	.LCFI25-.Ltext0
	.long	.LCFI26-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 15
	.long	.LCFI26-.Ltext0
	.long	.LCFI27-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 16
	.long	.LCFI27-.Ltext0
	.long	.LCFI28-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 17
	.long	.LCFI28-.Ltext0
	.long	.LCFI29-.Ltext0
	.word	0x3
	.byte	0x92
	.uleb128 0x20
	.sleb128 18
	.long	.LCFI29-.Ltext0
	.long	.LCFI30-.Ltext0
	.word	0x2
	.byte	0x8c
	.sleb128 18
	.long	.LCFI30-.Ltext0
	.long	.LFE6-.Ltext0
	.word	0x2
	.byte	0x8c
	.sleb128 34
	.long	0
	.long	0
.LLST20:
	.long	.LVL50-.Ltext0
	.long	.LVL52-.Ltext0
	.word	0x6
	.byte	0x68
	.byte	0x93
	.uleb128 0x1
	.byte	0x69
	.byte	0x93
	.uleb128 0x1
	.long	.LVL52-.Ltext0
	.long	.LVL91-.Ltext0
	.word	0x6
	.byte	0x5e
	.byte	0x93
	.uleb128 0x1
	.byte	0x5f
	.byte	0x93
	.uleb128 0x1
	.long	.LVL91-.Ltext0
	.long	.LFE6-.Ltext0
	.word	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x68
	.byte	0x9f
	.long	0
	.long	0
.LLST21:
	.long	.LVL50-.Ltext0
	.long	.LVL54-.Ltext0
	.word	0x6
	.byte	0x66
	.byte	0x93
	.uleb128 0x1
	.byte	0x67
	.byte	0x93
	.uleb128 0x1
	.long	.LVL54-.Ltext0
	.long	.LVL93-.Ltext0
	.word	0x6
	.byte	0x5a
	.byte	0x93
	.uleb128 0x1
	.byte	0x5b
	.byte	0x93
	.uleb128 0x1
	.long	.LVL93-.Ltext0
	.long	.LFE6-.Ltext0
	.word	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x66
	.byte	0x9f
	.long	0
	.long	0
.LLST22:
	.long	.LVL50-.Ltext0
	.long	.LVL54-.Ltext0
	.word	0x6
	.byte	0x64
	.byte	0x93
	.uleb128 0x1
	.byte	0x65
	.byte	0x93
	.uleb128 0x1
	.long	.LVL54-.Ltext0
	.long	.LVL92-.Ltext0
	.word	0x6
	.byte	0x5c
	.byte	0x93
	.uleb128 0x1
	.byte	0x5d
	.byte	0x93
	.uleb128 0x1
	.long	.LVL92-.Ltext0
	.long	.LFE6-.Ltext0
	.word	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x64
	.byte	0x9f
	.long	0
	.long	0
.LLST23:
	.long	.LVL50-.Ltext0
	.long	.LVL54-.Ltext0
	.word	0x6
	.byte	0x62
	.byte	0x93
	.uleb128 0x1
	.byte	0x63
	.byte	0x93
	.uleb128 0x1
	.long	.LVL54-.Ltext0
	.long	.LVL94-.Ltext0
	.word	0x6
	.byte	0x58
	.byte	0x93
	.uleb128 0x1
	.byte	0x59
	.byte	0x93
	.uleb128 0x1
	.long	.LVL94-.Ltext0
	.long	.LFE6-.Ltext0
	.word	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x62
	.byte	0x9f
	.long	0
	.long	0
.LLST24:
	.long	.LVL50-.Ltext0
	.long	.LVL90-.Ltext0
	.word	0x6
	.byte	0x60
	.byte	0x93
	.uleb128 0x1
	.byte	0x61
	.byte	0x93
	.uleb128 0x1
	.long	.LVL90-.Ltext0
	.long	.LFE6-.Ltext0
	.word	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x60
	.byte	0x9f
	.long	0
	.long	0
.LLST25:
	.long	.LVL51-.Ltext0
	.long	.LVL53-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL53-.Ltext0
	.long	.LVL54-.Ltext0
	.word	0x2
	.byte	0x31
	.byte	0x9f
	.long	.LVL54-.Ltext0
	.long	.LVL85-.Ltext0
	.word	0x1
	.byte	0x57
	.long	.LVL85-.Ltext0
	.long	.LFE6-.Ltext0
	.word	0x2
	.byte	0x3b
	.byte	0x9f
	.long	0
	.long	0
.LLST26:
	.long	.LVL55-.Ltext0
	.long	.LVL56-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST27:
	.long	.LVL56-.Ltext0
	.long	.LVL57-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL57-.Ltext0
	.long	.LVL59-1-.Ltext0
	.word	0x6
	.byte	0x64
	.byte	0x93
	.uleb128 0x1
	.byte	0x65
	.byte	0x93
	.uleb128 0x1
	.long	0
	.long	0
.LLST28:
	.long	.LVL59-.Ltext0
	.long	.LVL60-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST29:
	.long	.LVL60-.Ltext0
	.long	.LVL61-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL61-.Ltext0
	.long	.LVL63-1-.Ltext0
	.word	0x6
	.byte	0x64
	.byte	0x93
	.uleb128 0x1
	.byte	0x65
	.byte	0x93
	.uleb128 0x1
	.long	0
	.long	0
.LLST30:
	.long	.LVL67-.Ltext0
	.long	.LVL68-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST31:
	.long	.LVL68-.Ltext0
	.long	.LVL69-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL69-.Ltext0
	.long	.LVL71-.Ltext0
	.word	0x6
	.byte	0x62
	.byte	0x93
	.uleb128 0x1
	.byte	0x63
	.byte	0x93
	.uleb128 0x1
	.long	0
	.long	0
.LLST32:
	.long	.LVL75-.Ltext0
	.long	.LVL76-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST33:
	.long	.LVL76-.Ltext0
	.long	.LVL77-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL77-.Ltext0
	.long	.LVL79-.Ltext0
	.word	0x6
	.byte	0x62
	.byte	0x93
	.uleb128 0x1
	.byte	0x63
	.byte	0x93
	.uleb128 0x1
	.long	0
	.long	0
.LLST34:
	.long	.LVL79-.Ltext0
	.long	.LVL80-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL80-.Ltext0
	.long	.LVL83-.Ltext0
	.word	0x6
	.byte	0x64
	.byte	0x93
	.uleb128 0x1
	.byte	0x65
	.byte	0x93
	.uleb128 0x1
	.long	0
	.long	0
.LLST35:
	.long	.LVL86-.Ltext0
	.long	.LVL87-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST36:
	.long	.LVL87-.Ltext0
	.long	.LVL88-.Ltext0
	.word	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL88-.Ltext0
	.long	.LFE6-.Ltext0
	.word	0x6
	.byte	0x64
	.byte	0x93
	.uleb128 0x1
	.byte	0x65
	.byte	0x93
	.uleb128 0x1
	.long	0
	.long	0
	.section	.debug_aranges,"",@progbits
	.long	0x1c
	.word	0x2
	.long	.Ldebug_info0
	.byte	0x4
	.byte	0
	.word	0
	.word	0
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	0
	.long	0
	.section	.debug_ranges,"",@progbits
.Ldebug_ranges0:
	.long	.LBB8-.Ltext0
	.long	.LBE8-.Ltext0
	.long	.LBB12-.Ltext0
	.long	.LBE12-.Ltext0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF24:
	.string	"rin1"
.LASF12:
	.string	"RoundKey"
.LASF11:
	.string	"state"
.LASF29:
	.string	"sboxm1"
.LASF28:
	.string	"sbox1"
.LASF26:
	.string	"sbox"
.LASF30:
	.string	"GNU C99 5.4.0 -mn-flash=3 -mno-skip-bug -mmcu=avrxmega6 -gdwarf-2 -Os -std=gnu99 -fpack-struct -funsigned-char -funsigned-bitfields -fshort-enums"
.LASF20:
	.string	"state1"
.LASF21:
	.string	"state2"
.LASF22:
	.string	"state3"
.LASF27:
	.string	"sboxm"
.LASF19:
	.string	"Cipher1"
.LASF1:
	.string	"unsigned char"
.LASF14:
	.string	"SubBytes"
.LASF4:
	.string	"long unsigned int"
.LASF17:
	.string	"temp"
.LASF32:
	.string	"/home/jeanny/chipwhisperer/hardware/victims/firmware/simpleserial-aes"
.LASF8:
	.string	"state_t"
.LASF16:
	.string	"ShiftRows"
.LASF10:
	.string	"round"
.LASF2:
	.string	"unsigned int"
.LASF13:
	.string	"AddRoundKey"
.LASF6:
	.string	"long long unsigned int"
.LASF7:
	.string	"uint8_t"
.LASF23:
	.string	"rout"
.LASF15:
	.string	"SubBytes1"
.LASF9:
	.string	"sizetype"
.LASF18:
	.string	"MixColumns"
.LASF5:
	.string	"long long int"
.LASF25:
	.string	"rout1"
.LASF31:
	.string	"cipher.c"
.LASF3:
	.string	"long int"
.LASF0:
	.string	"signed char"
.LASF33:
	.string	"xtime"
	.ident	"GCC: (GNU) 5.4.0"
.global __do_copy_data

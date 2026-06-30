.section .text.tfhe::core_crypto::fft_impl::fft128::math::fft::convert_add_backward_torus_non_split,"ax",@progbits
        .p2align        4
.type   tfhe::core_crypto::fft_impl::fft128::math::fft::convert_add_backward_torus_non_split,@function
tfhe::core_crypto::fft_impl::fft128::math::fft::convert_add_backward_torus_non_split:
        .cfi_startproc
        push rbp
        .cfi_def_cfa_offset 16
        push r15
        .cfi_def_cfa_offset 24
        push r14
        .cfi_def_cfa_offset 32
        push r13
        .cfi_def_cfa_offset 40
        push r12
        .cfi_def_cfa_offset 48
        push rbx
        .cfi_def_cfa_offset 56
        sub rsp, 168
        .cfi_def_cfa_offset 224
        .cfi_offset rbx, -56
        .cfi_offset r12, -48
        .cfi_offset r13, -40
        .cfi_offset r14, -32
        .cfi_offset r15, -24
        .cfi_offset rbp, -16
        mov qword ptr [rsp + 40], 32
        mov qword ptr [rsp + 48], rcx
        cmp rcx, 32
        jne .LBB4_7
        mov qword ptr [rsp + 40], 32
        mov qword ptr [rsp + 48], r9
        cmp r9, 32
        jne .LBB4_7
        mov rax, qword ptr [rsp + 232]
        mov qword ptr [rsp + 40], 32
        mov qword ptr [rsp + 48], rax
        cmp rax, 32
        jne .LBB4_7
        mov rax, qword ptr [rsp + 248]
        mov qword ptr [rsp + 40], 32
        mov qword ptr [rsp + 48], rax
        cmp rax, 32
        jne .LBB4_7
        vmovsd xmm1, qword ptr [rip + .LCPI4_0]
        vcvtsi2sd xmm0, xmm15, rcx
        vbroadcastsd ymm2, qword ptr [rip + .LCPI4_1]
        vbroadcastsd ymm3, qword ptr [rip + .LCPI4_2]
        vpbroadcastq ymm4, qword ptr [rip + .LCPI4_0]
        vpbroadcastq ymm5, qword ptr [rip + .LCPI4_3]
        vpbroadcastq ymm6, qword ptr [rip + .LCPI4_4]
        vbroadcastsd ymm7, qword ptr [rip + .LCPI4_5]
        vpbroadcastq ymm8, qword ptr [rip + .LCPI4_6]
        vpbroadcastq ymm9, qword ptr [rip + .LCPI4_7]
        vpbroadcastq ymm10, qword ptr [rip + .LCPI4_8]
        xor eax, eax
        mov qword ptr [rsp + 120], rdi
        mov qword ptr [rsp + 144], r8
        mov qword ptr [rsp + 136], rdx
        mov qword ptr [rsp + 128], rsi
        vdivsd xmm0, xmm1, xmm0
        vxorpd xmm1, xmm1, xmm1
        vbroadcastsd ymm0, xmm0
        .p2align        4
.LBB4_5:
        vmulpd ymm12, ymm0, ymmword ptr [r8 + rax]
        vmulpd ymm11, ymm0, ymmword ptr [rdx + rax]
        movabs r8, -9223372036854775808
        mov qword ptr [rsp + 8], rax
        xor r9d, r9d
        vroundpd ymm13, ymm11, 9
        vroundpd ymm14, ymm12, 9
        vaddpd ymm15, ymm13, ymm14
        vcmpeqpd k1, ymm13, ymm11
        vsubpd ymm16, ymm15, ymm13
        vsubpd ymm17, ymm15, ymm16
        vsubpd ymm14, ymm14, ymm16
        vsubpd ymm17, ymm13, ymm17
        vmovapd ymm13 {k1}, ymm15
        vsubpd ymm15, ymm11, ymm13
        vsubpd ymm16, ymm15, ymm11
        vaddpd ymm14, ymm14, ymm17
        vsubpd ymm17, ymm15, ymm16
        vaddpd ymm13, ymm13, ymm16
        vsubpd ymm11, ymm11, ymm17
        vsubpd ymm11, ymm11, ymm13
        vaddpd ymm11, ymm12, ymm11
        vsubpd ymm11 {k1}, ymm11, ymm14
        vaddpd ymm12, ymm15, ymm11
        vsubpd ymm13, ymm12, ymm15
        vmulpd ymm12, ymm12, ymm2
        vsubpd ymm11, ymm11, ymm13
        vaddpd ymm13, ymm12, ymm3
        vsubpd ymm14, ymm13, ymm12
        vmulpd ymm11, ymm11, ymm2
        vsubpd ymm15, ymm13, ymm14
        vsubpd ymm14, ymm3, ymm14
        vsubpd ymm12, ymm12, ymm15
        vaddpd ymm12, ymm14, ymm12
        vaddpd ymm11, ymm11, ymm12
        vaddpd ymm12, ymm13, ymm11
        vrndscalepd ymm16, ymm12, 9
        vcmpneqpd k1, ymm16, ymm12
        vsubpd ymm12, ymm13, ymm12
        vaddpd ymm11, ymm11, ymm12
        vroundpd ymm13, ymm11, 9
        vaddpd ymm11, ymm16, ymm13
        vsubpd ymm14, ymm11, ymm16
        vsubpd ymm12, ymm11, ymm14
        vmovapd ymm11 {k1}, ymm16
        vmovq rdi, xmm11
        vpextrq rsi, xmm11, 1
        vsubpd ymm13, ymm13, ymm14
        shl rdi, 11
        shl rsi, 11
        or rdi, r8
        or rsi, r8
        vsubpd ymm15, ymm16, ymm12
        vpsrlq ymm12, ymm11, 52
        vextracti32x4 xmm16, ymm11, 1
        vpsubq ymm12, ymm5, ymm12
        vpextrq rax, xmm16, 1
        vmovq rdx, xmm16
        vmovd ecx, xmm12
        vextracti32x4 xmm16, ymm12, 1
        shl rdx, 11
        shl rax, 11
        shrd r9, rdi, cl
        shrx rdi, rdi, rcx
        vaddpd ymm14, ymm13, ymm15
        or rax, r8
        or rdx, r8
        test cl, 64
        mov ecx, 0
        cmovne r9, rdi
        cmovne rdi, rcx
        vpextrb ecx, xmm12, 8
        xor r12d, r12d
        mov qword ptr [rsp + 112], rdi
        xor edi, edi
        shrd rdi, rsi, cl
        shrx rsi, rsi, rcx
        test cl, 64
        vmovd ecx, xmm16
        vmovapd ymm14 {k1}, ymm1
        vandpd ymm13, ymm14, ymm7
        mov qword ptr [rsp + 104], r9
        vpmovq2m k0, ymm14
        vpcmpltuq k1, ymm12, ymm6
        vextractf128 xmm15, ymm13, 1
        vmovq r9, xmm13
        vpextrq r14, xmm13, 1
        cmovne rdi, rsi
        cmovne rsi, r12
        mov qword ptr [rsp + 96], rsi
        xor esi, esi
        shrd rsi, rdx, cl
        shrx rdx, rdx, rcx
        test cl, 64
        vpextrb ecx, xmm16, 8
        mov qword ptr [rsp + 88], rdi
        cmovne rsi, rdx
        cmovne rdx, r12
        mov qword ptr [rsp + 24], rdx
        xor edx, edx
        shrd rdx, rax, cl
        shrx rax, rax, rcx
        test cl, 64
        mov qword ptr [rsp + 32], rsi
        cmovne rdx, rax
        cmovne rax, r12
        shl r14, 11
        shl r9, 11
        xor ebx, ebx
        mov qword ptr [rsp + 64], rdx
        vpextrq rdx, xmm15, 1
        mov qword ptr [rsp + 16], rax
        vmovq rax, xmm15
        vpsrlq ymm15, ymm14, 52
        or r9, r8
        or r14, r8
        vpsubq ymm15, ymm9, ymm15
        shl rdx, 11
        shl rax, 11
        vpand ymm15, ymm15, ymm10
        or rdx, r8
        or rax, r8
        vextracti32x4 xmm16, ymm15, 1
        vpextrb ecx, xmm16, 8
        shrd rbx, rdx, cl
        shrx r10, rdx, rcx
        test cl, 64
        vmovd ecx, xmm16
        shrx r15, rax, rcx
        cmovne rbx, r10
        cmovne r10, r12
        xor r11d, r11d
        shrd r11, rax, cl
        test cl, 64
        vpextrb ecx, xmm15, 8
        shrx r8, r14, rcx
        mov r13, rbx
        cmovne r11, r15
        cmovne r15, r12
        xor edx, edx
        shrd rdx, r14, cl
        test cl, 64
        vmovd ecx, xmm15
        mov r14d, 0
        shrx rsi, r9, rcx
        mov rbp, r11
        cmovne rdx, r8
        cmovne r8, r12
        xor eax, eax
        shrd rax, r9, cl
        test cl, 64
        mov r9d, 0
        mov rdi, rdx
        cmovne rax, rsi
        cmovne rsi, r12
        mov r12d, 0
        mov rcx, rax
        neg rcx
        mov qword ptr [rsp + 80], rcx
        mov ecx, 0
        sbb rcx, rsi
        neg rdi
        sbb r12, r8
        neg rbp
        mov qword ptr [rsp + 56], rcx
        kmovd ecx, k0
        kshiftrb k0, k0, 2
        sbb r14, r15
        neg r13
        sbb r9, r10
        test cl, 8
        cmove r9, r10
        kmovd r10d, k0
        cmove r13, rbx
        vpcmpltuq k0, ymm11, ymm4
        mov rbx, qword ptr [rsp + 112]
        test r10b, 1
        mov r10, qword ptr [rsp + 16]
        cmove r14, r15
        mov r15, qword ptr [rsp + 80]
        cmove rbp, r11
        test cl, 2
        mov r11, qword ptr [rsp + 24]
        cmove rdi, rdx
        cmove r12, r8
        test cl, 1
        mov rcx, qword ptr [rsp + 8]
        kmovd edx, k1
        kmovd r8d, k0
        kshiftrb k1, k1, 2
        kshiftrb k0, k0, 2
        mov qword ptr [rsp + 72], rdi
        mov rdi, qword ptr [rsp + 120]
        cmove r15, rax
        mov rax, qword ptr [rsp + 56]
        mov rcx, qword ptr [rdi + 2*rcx + 56]
        cmove rax, rsi
        mov rsi, qword ptr [rsp + 64]
        mov qword ptr [rsp + 56], rax
        mov rax, qword ptr [rsp + 8]
        mov rax, qword ptr [rdi + 2*rax + 48]
        add rsi, rax
        adc r10, rcx
        test dl, 8
        cmove rsi, rax
        cmove r10, rcx
        test r8b, 8
        cmovne rsi, rax
        mov rax, qword ptr [rsp + 8]
        cmovne r10, rcx
        mov rcx, qword ptr [rsp + 8]
        mov qword ptr [rsp + 16], r10
        mov r10, qword ptr [rsp + 32]
        mov qword ptr [rsp + 64], rsi
        kmovd esi, k1
        mov rax, qword ptr [rdi + 2*rax + 32]
        mov rcx, qword ptr [rdi + 2*rcx + 40]
        add r10, rax
        adc r11, rcx
        test sil, 1
        kmovd esi, k0
        vpcmpgtq k0, ymm13, ymm8
        cmove r10, rax
        cmove r11, rcx
        test sil, 1
        mov rsi, qword ptr [rsp + 88]
        cmovne r10, rax
        mov rax, qword ptr [rsp + 8]
        cmovne r11, rcx
        mov rcx, qword ptr [rsp + 8]
        mov qword ptr [rsp + 32], r10
        mov r10, qword ptr [rsp + 96]
        mov qword ptr [rsp + 24], r11
        mov r11, qword ptr [rsp + 104]
        mov rax, qword ptr [rdi + 2*rax + 16]
        mov rcx, qword ptr [rdi + 2*rcx + 24]
        add rsi, rax
        adc r10, rcx
        test dl, 2
        cmove rsi, rax
        cmove r10, rcx
        test r8b, 2
        cmovne rsi, rax
        mov rax, qword ptr [rsp + 8]
        cmovne r10, rcx
        mov rcx, qword ptr [rsp + 8]
        mov rax, qword ptr [rdi + 2*rax]
        mov rcx, qword ptr [rdi + 2*rcx + 8]
        add r11, rax
        adc rbx, rcx
        test dl, 1
        mov rdx, qword ptr [rsp + 8]
        cmove r11, rax
        cmove rbx, rcx
        test r8b, 1
        mov r8, qword ptr [rsp + 56]
        cmovne r11, rax
        cmovne rbx, rcx
        mov rcx, r15
        kmovd eax, k0
        kshiftrb k0, k0, 2
        add rcx, r11
        adc r8, rbx
        test al, 1
        cmove rcx, r11
        cmove r8, rbx
        mov qword ptr [rsp + 80], rcx
        mov rcx, qword ptr [rsp + 224]
        vmulpd ymm11, ymm0, ymmword ptr [rcx + rdx]
        mov rcx, qword ptr [rsp + 240]
        mov rdx, qword ptr [rsp + 8]
        vmulpd ymm12, ymm0, ymmword ptr [rcx + rdx]
        mov rcx, qword ptr [rsp + 72]
        mov rdx, qword ptr [rsp + 24]
        vroundpd ymm13, ymm11, 9
        add rcx, rsi
        adc r12, r10
        test al, 2
        cmove rcx, rsi
        mov rsi, qword ptr [rsp + 32]
        cmove r12, r10
        vcmpneqpd k1, ymm13, ymm11
        mov qword ptr [rsp + 72], rcx
        kmovd ecx, k0
        vroundpd ymm14, ymm12, 9
        add rbp, rsi
        vaddpd ymm15, ymm13, ymm14
        adc r14, rdx
        test cl, 1
        mov rcx, qword ptr [rsp + 64]
        cmove r14, rdx
        mov rdx, qword ptr [rsp + 16]
        cmove rbp, rsi
        vsubpd ymm16, ymm15, ymm13
        add r13, rcx
        vsubpd ymm17, ymm15, ymm16
        vmovapd ymm15 {k1}, ymm13
        vsubpd ymm14, ymm14, ymm16
        adc r9, rdx
        test al, 8
        mov rax, qword ptr [rsp + 8]
        cmove r9, rdx
        cmove r13, rcx
        vsubpd ymm17, ymm13, ymm17
        vsubpd ymm13, ymm11, ymm15
        mov qword ptr [rdi + 2*rax + 56], r9
        mov rax, qword ptr [rsp + 8]
        xor r9d, r9d
        vsubpd ymm16, ymm13, ymm11
        vaddpd ymm14, ymm14, ymm17
        vsubpd ymm17, ymm13, ymm16
        vaddpd ymm15, ymm15, ymm16
        mov qword ptr [rdi + 2*rax + 40], r14
        mov rax, qword ptr [rsp + 8]
        vsubpd ymm11, ymm11, ymm17
        vsubpd ymm11, ymm11, ymm15
        mov qword ptr [rdi + 2*rax + 24], r12
        mov rax, qword ptr [rsp + 8]
        vaddpd ymm11, ymm12, ymm11
        mov qword ptr [rdi + 2*rax + 8], r8
        mov rax, qword ptr [rsp + 8]
        movabs r8, -9223372036854775808
        vsubpd ymm12, ymm11, ymm14
        vmovapd ymm12 {k1}, ymm11
        vaddpd ymm11, ymm13, ymm12
        mov qword ptr [rdi + 2*rax + 48], r13
        mov rax, qword ptr [rsp + 8]
        mov r13, rdi
        vsubpd ymm13, ymm11, ymm13
        vmulpd ymm11, ymm11, ymm2
        vsubpd ymm12, ymm12, ymm13
        vaddpd ymm13, ymm11, ymm3
        mov qword ptr [rdi + 2*rax + 32], rbp
        vsubpd ymm14, ymm13, ymm11
        vmulpd ymm12, ymm12, ymm2
        vsubpd ymm15, ymm13, ymm14
        vsubpd ymm14, ymm3, ymm14
        vsubpd ymm11, ymm11, ymm15
        vaddpd ymm11, ymm14, ymm11
        vaddpd ymm11, ymm12, ymm11
        vaddpd ymm12, ymm13, ymm11
        vroundpd ymm15, ymm12, 9
        vcmpneqpd k1, ymm15, ymm12
        vsubpd ymm12, ymm13, ymm12
        vaddpd ymm11, ymm11, ymm12
        vroundpd ymm12, ymm11, 9
        vaddpd ymm11, ymm15, ymm12
        vsubpd ymm14, ymm11, ymm15
        vsubpd ymm13, ymm11, ymm14
        vmovapd ymm11 {k1}, ymm15
        vmovq rdi, xmm11
        vsubpd ymm14, ymm12, ymm14
        vpsrlq ymm12, ymm11, 52
        vpextrq rsi, xmm11, 1
        shl rdi, 11
        vpsubq ymm12, ymm5, ymm12
        shl rsi, 11
        or rdi, r8
        vmovd ecx, xmm12
        or rsi, r8
        vsubpd ymm13, ymm15, ymm13
        vextracti128 xmm15, ymm11, 1
        shrd r9, rdi, cl
        shrx rdi, rdi, rcx
        vpextrq rax, xmm15, 1
        vmovq rdx, xmm15
        vextracti128 xmm15, ymm12, 1
        shl rdx, 11
        shl rax, 11
        vaddpd ymm14, ymm14, ymm13
        or rax, r8
        or rdx, r8
        test cl, 64
        mov rcx, rdi
        cmovne r9, rdi
        mov edi, 0
        cmovne rcx, rdi
        mov qword ptr [rsp + 56], r9
        xor r9d, r9d
        vmovapd ymm14 {k1}, ymm1
        vandpd ymm13, ymm14, ymm7
        vpmovq2m k0, ymm14
        vpcmpltuq k1, ymm12, ymm6
        mov qword ptr [rsp + 64], rcx
        vpextrb ecx, xmm12, 8
        vmovq rbx, xmm13
        shrd r9, rsi, cl
        shrx rsi, rsi, rcx
        test cl, 64
        vmovd ecx, xmm15
        cmovne r9, rsi
        cmovne rsi, rdi
        xor edi, edi
        mov qword ptr [rsp + 112], rsi
        xor esi, esi
        shrd rsi, rdx, cl
        shrx rdx, rdx, rcx
        test cl, 64
        vpextrb ecx, xmm15, 8
        vextracti128 xmm15, ymm13, 1
        mov qword ptr [rsp + 104], r9
        cmovne rsi, rdx
        cmovne rdx, rdi
        mov qword ptr [rsp + 32], rdx
        xor edx, edx
        shrd rdx, rax, cl
        shrx rax, rax, rcx
        test cl, 64
        mov qword ptr [rsp + 96], rsi
        vpextrq rsi, xmm13, 1
        cmovne rdx, rax
        cmovne rax, rdi
        shl rsi, 11
        shl rbx, 11
        xor r9d, r9d
        mov qword ptr [rsp + 16], rdx
        vpextrq rdx, xmm15, 1
        mov qword ptr [rsp + 24], rax
        vmovq rax, xmm15
        vpsrlq ymm15, ymm14, 52
        or rbx, r8
        or rsi, r8
        vpsubq ymm15, ymm9, ymm15
        shl rdx, 11
        shl rax, 11
        vpand ymm15, ymm15, ymm10
        or rdx, r8
        or rax, r8
        vextracti32x4 xmm16, ymm15, 1
        vpextrb ecx, xmm16, 8
        shrd r9, rdx, cl
        shrx r12, rdx, rcx
        test cl, 64
        vmovd ecx, xmm16
        mov rdx, qword ptr [rsp + 72]
        shrx r11, rax, rcx
        cmovne r9, r12
        cmovne r12, rdi
        xor r14d, r14d
        shrd r14, rax, cl
        mov rax, qword ptr [rsp + 8]
        test cl, 64
        vpextrb ecx, xmm15, 8
        shrx r10, rsi, rcx
        cmovne r14, r11
        cmovne r11, rdi
        xor r8d, r8d
        shrd r8, rsi, cl
        test cl, 64
        vmovd ecx, xmm15
        mov rbp, r14
        cmovne r8, r10
        cmovne r10, rdi
        xor r15d, r15d
        shrd r15, rbx, cl
        test cl, 64
        mov qword ptr [r13 + 2*rax + 16], rdx
        mov rax, qword ptr [rsp + 8]
        mov rdx, qword ptr [rsp + 80]
        mov qword ptr [r13 + 2*rax], rdx
        shrx rdx, rbx, rcx
        mov ecx, 0
        mov rbx, r9
        mov r13d, 0
        cmovne r15, rdx
        cmovne rdx, rdi
        mov rdi, r8
        mov rax, r15
        neg rax
        mov qword ptr [rsp + 160], rax
        mov eax, 0
        sbb rax, rdx
        neg rdi
        sbb rcx, r10
        mov qword ptr [rsp + 152], rax
        neg rbp
        mov eax, 0
        sbb rax, r11
        neg rbx
        mov rsi, rax
        kmovd eax, k0
        sbb r13, r12
        kshiftrb k0, k0, 2
        test al, 8
        cmove r13, r12
        mov r12, qword ptr [rsp + 152]
        cmove rbx, r9
        kmovd r9d, k0
        vpcmpltuq k0, ymm11, ymm4
        test r9b, 1
        mov r9, qword ptr [rsp + 24]
        cmove rsi, r11
        cmove rbp, r14
        test al, 2
        mov r14, qword ptr [rsp + 96]
        mov r11, qword ptr [rsp + 64]
        cmove rdi, r8
        cmove rcx, r10
        test al, 1
        mov qword ptr [rsp + 80], rsi
        mov rsi, qword ptr [rsp + 128]
        mov rax, qword ptr [rsp + 8]
        mov r8, qword ptr [rsp + 16]
        mov qword ptr [rsp + 72], rcx
        mov rcx, qword ptr [rsp + 160]
        mov qword ptr [rsp + 88], rdi
        cmove r12, rdx
        mov rdx, qword ptr [rsp + 8]
        mov rax, qword ptr [rsi + 2*rax + 48]
        cmove rcx, r15
        mov r15, qword ptr [rsp + 112]
        mov rdi, qword ptr [rsi + 2*rdx + 56]
        kmovd edx, k1
        kshiftrb k1, k1, 2
        add r8, rax
        adc r9, rdi
        test dl, 8
        cmove r8, rax
        cmove r9, rdi
        mov r10, r8
        kmovd r8d, k0
        kshiftrb k0, k0, 2
        test r8b, 8
        cmovne r10, rax
        mov rax, qword ptr [rsp + 8]
        cmovne r9, rdi
        mov rdi, qword ptr [rsp + 8]
        mov qword ptr [rsp + 16], r10
        mov r10, qword ptr [rsp + 32]
        mov qword ptr [rsp + 24], r9
        kmovd r9d, k1
        mov rax, qword ptr [rsi + 2*rax + 32]
        mov rdi, qword ptr [rsi + 2*rdi + 40]
        add r14, rax
        adc r10, rdi
        test r9b, 1
        kmovd r9d, k0
        vpcmpgtq k0, ymm13, ymm8
        cmove r14, rax
        cmove r10, rdi
        test r9b, 1
        mov r9, qword ptr [rsp + 56]
        cmovne r14, rax
        mov rax, qword ptr [rsp + 8]
        cmovne r10, rdi
        mov rdi, qword ptr [rsp + 8]
        mov qword ptr [rsp + 32], r10
        mov r10, qword ptr [rsp + 104]
        mov rax, qword ptr [rsi + 2*rax + 16]
        mov rdi, qword ptr [rsi + 2*rdi + 24]
        add r10, rax
        adc r15, rdi
        test dl, 2
        cmove r10, rax
        cmove r15, rdi
        test r8b, 2
        cmovne r10, rax
        mov rax, qword ptr [rsp + 8]
        cmovne r15, rdi
        mov rdi, qword ptr [rsp + 8]
        mov rax, qword ptr [rsi + 2*rax]
        mov rdi, qword ptr [rsi + 2*rdi + 8]
        add r9, rax
        adc r11, rdi
        test dl, 1
        mov rdx, rcx
        mov rcx, qword ptr [rsp + 88]
        cmove r9, rax
        cmove r11, rdi
        test r8b, 1
        mov r8, qword ptr [rsp + 144]
        cmovne r9, rax
        cmovne r11, rdi
        kmovd eax, k0
        mov rdi, qword ptr [rsp + 32]
        kshiftrb k0, k0, 2
        add rdx, r9
        adc r12, r11
        test al, 1
        cmove r12, r11
        mov r11, qword ptr [rsp + 72]
        cmove rdx, r9
        add rcx, r10
        mov r9, rdx
        kmovd edx, k0
        adc r11, r15
        test al, 2
        cmove rcx, r10
        mov r10, qword ptr [rsp + 80]
        cmove r11, r15
        add rbp, r14
        mov r15, qword ptr [rsp + 24]
        adc r10, rdi
        test dl, 1
        mov rdx, qword ptr [rsp + 136]
        cmove r10, rdi
        mov rdi, qword ptr [rsp + 16]
        cmove rbp, r14
        add rbx, rdi
        adc r13, r15
        test al, 8
        mov rax, qword ptr [rsp + 8]
        cmove r13, r15
        cmove rbx, rdi
        mov qword ptr [rsi + 2*rax + 48], rbx
        mov qword ptr [rsi + 2*rax + 32], rbp
        mov qword ptr [rsi + 2*rax + 16], rcx
        mov qword ptr [rsi + 2*rax], r9
        mov qword ptr [rsi + 2*rax + 56], r13
        mov qword ptr [rsi + 2*rax + 40], r10
        mov qword ptr [rsi + 2*rax + 24], r11
        mov qword ptr [rsi + 2*rax + 8], r12
        add rax, 32
        cmp rax, 256
        jne .LBB4_5
        add rsp, 168
        .cfi_def_cfa_offset 56
        pop rbx
        .cfi_def_cfa_offset 48
        pop r12
        .cfi_def_cfa_offset 40
        pop r13
        .cfi_def_cfa_offset 32
        pop r14
        .cfi_def_cfa_offset 24
        pop r15
        .cfi_def_cfa_offset 16
        pop rbp
        .cfi_def_cfa_offset 8
        vzeroupper
        ret
.LBB4_7:
        .cfi_def_cfa_offset 224
        lea r8, [rip + .Lanon.9e1228730ebee7a0e6452b0dea1b38e3.29]
        lea rsi, [rsp + 40]
        lea rdx, [rsp + 48]
        xor edi, edi
        xor ecx, ecx
        call core::panicking::assert_failed
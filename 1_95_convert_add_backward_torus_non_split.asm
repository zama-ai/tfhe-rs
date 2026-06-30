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
        jne .LBB5_7
        mov qword ptr [rsp + 40], 32
        mov qword ptr [rsp + 48], r9
        cmp r9, 32
        jne .LBB5_7
        mov rax, qword ptr [rsp + 232]
        mov qword ptr [rsp + 40], 32
        mov qword ptr [rsp + 48], rax
        cmp rax, 32
        jne .LBB5_7
        mov rax, qword ptr [rsp + 248]
        mov qword ptr [rsp + 40], 32
        mov qword ptr [rsp + 48], rax
        cmp rax, 32
        jne .LBB5_7
        vmovsd xmm1, qword ptr [rip + .LCPI5_0]
        vcvtsi2sd xmm0, xmm15, rcx
        vbroadcastsd ymm2, qword ptr [rip + .LCPI5_2]
        vpbroadcastq ymm3, qword ptr [rip + .LCPI5_3]
        vpbroadcastq ymm4, qword ptr [rip + .LCPI5_4]
        vpbroadcastq ymm5, qword ptr [rip + .LCPI5_5]
        vbroadcastsd ymm6, qword ptr [rip + .LCPI5_6]
        vpbroadcastq ymm7, qword ptr [rip + .LCPI5_0]
        vpbroadcastq ymm8, qword ptr [rip + .LCPI5_7]
        xor eax, eax
        mov qword ptr [rsp + 120], rdi
        mov qword ptr [rsp + 144], r8
        mov qword ptr [rsp + 136], rdx
        mov qword ptr [rsp + 128], rsi
        vdivsd xmm0, xmm1, xmm0
        vbroadcastsd ymm1, qword ptr [rip + .LCPI5_1]
        vbroadcastsd ymm0, xmm0
        .p2align        4
.LBB5_5:
        vmulpd ymm10, ymm0, ymmword ptr [r8 + rax]
        vmulpd ymm9, ymm0, ymmword ptr [rdx + rax]
        movabs r8, -9223372036854775808
        mov qword ptr [rsp + 8], rax
        xor r9d, r9d
        vroundpd ymm11, ymm9, 9
        vroundpd ymm12, ymm10, 9
        vaddpd ymm13, ymm11, ymm12
        vcmpeqpd k1, ymm11, ymm9
        vsubpd ymm14, ymm13, ymm11
        vsubpd ymm15, ymm13, ymm14
        vsubpd ymm12, ymm12, ymm14
        vsubpd ymm15, ymm11, ymm15
        vmovapd ymm11 {k1}, ymm13
        vsubpd ymm13, ymm9, ymm11
        vsubpd ymm14, ymm13, ymm9
        vaddpd ymm12, ymm12, ymm15
        vsubpd ymm15, ymm13, ymm14
        vaddpd ymm11, ymm11, ymm14
        vsubpd ymm9, ymm9, ymm15
        vsubpd ymm9, ymm9, ymm11
        vaddpd ymm9, ymm10, ymm9
        vsubpd ymm9 {k1}, ymm9, ymm12
        vaddpd ymm10, ymm13, ymm9
        vsubpd ymm11, ymm10, ymm13
        vmulpd ymm10, ymm10, ymm1
        vsubpd ymm9, ymm9, ymm11
        vaddpd ymm11, ymm10, ymm2
        vsubpd ymm12, ymm11, ymm10
        vmulpd ymm9, ymm9, ymm1
        vsubpd ymm13, ymm11, ymm12
        vsubpd ymm12, ymm2, ymm12
        vsubpd ymm10, ymm10, ymm13
        vaddpd ymm10, ymm12, ymm10
        vaddpd ymm10, ymm9, ymm10
        vaddpd ymm12, ymm11, ymm10
        vsubpd ymm11, ymm11, ymm12
        vroundpd ymm9, ymm12, 9
        vaddpd ymm10, ymm10, ymm11
        vcmpeqpd k1, ymm9, ymm12
        vroundpd ymm11, ymm10, 9
        vaddpd ymm10, ymm9, ymm11
        vsubpd ymm12, ymm10, ymm9
        vsubpd ymm13, ymm10, ymm12
        vsubpd ymm11, ymm11, ymm12
        vsubpd ymm13, ymm9, ymm13
        vmovapd ymm9 {k1}, ymm10
        vpsrlq ymm10, ymm9, 52
        vextracti128 xmm14, ymm9, 1
        vmovq rdi, xmm9
        vpextrq rsi, xmm9, 1
        shl rdi, 11
        vpsubq ymm10, ymm4, ymm10
        shl rsi, 11
        vpextrq rax, xmm14, 1
        vmovq rdx, xmm14
        or rdi, r8
        vmovd ecx, xmm10
        or rsi, r8
        vextracti128 xmm14, ymm10, 1
        shl rdx, 11
        shl rax, 11
        shrd r9, rdi, cl
        shrx rdi, rdi, rcx
        vaddpd ymm12 {k1} {z}, ymm11, ymm13
        vpcmpnleuq k1, ymm10, ymm5
        or rax, r8
        or rdx, r8
        test cl, 64
        mov ecx, 0
        cmovne r9, rdi
        cmovne rdi, rcx
        vpextrb ecx, xmm10, 8
        xor r12d, r12d
        mov qword ptr [rsp + 112], rdi
        xor edi, edi
        shrd rdi, rsi, cl
        shrx rsi, rsi, rcx
        test cl, 64
        vmovd ecx, xmm14
        vandpd ymm11, ymm12, ymm6
        mov qword ptr [rsp + 104], r9
        vextractf128 xmm13, ymm11, 1
        vmovq r9, xmm11
        vpextrq r14, xmm11, 1
        cmovne rdi, rsi
        cmovne rsi, r12
        mov qword ptr [rsp + 96], rsi
        xor esi, esi
        shrd rsi, rdx, cl
        shrx rdx, rdx, rcx
        test cl, 64
        vpextrb ecx, xmm14, 8
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
        vpextrq rdx, xmm13, 1
        mov qword ptr [rsp + 16], rax
        vmovq rax, xmm13
        vpsrlq ymm13, ymm12, 52
        or r9, r8
        or r14, r8
        vpsubq ymm13, ymm8, ymm13
        shl rdx, 11
        shl rax, 11
        vpand ymm13, ymm13, ymm5
        or rdx, r8
        or rax, r8
        vextracti128 xmm14, ymm13, 1
        vpextrb ecx, xmm14, 8
        shrd rbx, rdx, cl
        shrx r10, rdx, rcx
        test cl, 64
        vmovd ecx, xmm14
        shrx r15, rax, rcx
        cmovne rbx, r10
        cmovne r10, r12
        xor r11d, r11d
        shrd r11, rax, cl
        test cl, 64
        vpextrb ecx, xmm13, 8
        shrx r8, r14, rcx
        mov r13, rbx
        cmovne r11, r15
        cmovne r15, r12
        xor edx, edx
        shrd rdx, r14, cl
        test cl, 64
        vmovd ecx, xmm13
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
        vmovmskpd ecx, ymm12
        kshiftrb k0, k0, 2
        sbb r14, r15
        neg r13
        sbb r9, r10
        test cl, 8
        cmove r9, r10
        kmovd r10d, k0
        cmove r13, rbx
        vpcmpnleuq k0, ymm9, ymm3
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
        cmovne rsi, rax
        cmovne r10, rcx
        test r8b, 8
        cmove rsi, rax
        mov rax, qword ptr [rsp + 8]
        cmove r10, rcx
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
        vpcmpgtq k0, ymm7, ymm11
        cmovne r10, rax
        cmovne r11, rcx
        test sil, 1
        mov rsi, qword ptr [rsp + 88]
        cmove r10, rax
        mov rax, qword ptr [rsp + 8]
        cmove r11, rcx
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
        cmovne rsi, rax
        cmovne r10, rcx
        test r8b, 2
        cmove rsi, rax
        mov rax, qword ptr [rsp + 8]
        cmove r10, rcx
        mov rcx, qword ptr [rsp + 8]
        mov rax, qword ptr [rdi + 2*rax]
        mov rcx, qword ptr [rdi + 2*rcx + 8]
        add r11, rax
        adc rbx, rcx
        test dl, 1
        mov rdx, qword ptr [rsp + 8]
        cmovne r11, rax
        cmovne rbx, rcx
        test r8b, 1
        mov r8, qword ptr [rsp + 56]
        cmove r11, rax
        cmove rbx, rcx
        mov rcx, r15
        kmovd eax, k0
        kshiftrb k0, k0, 2
        add rcx, r11
        adc r8, rbx
        test al, 1
        cmovne rcx, r11
        cmovne r8, rbx
        mov qword ptr [rsp + 80], rcx
        mov rcx, qword ptr [rsp + 224]
        vmulpd ymm9, ymm0, ymmword ptr [rcx + rdx]
        mov rcx, qword ptr [rsp + 240]
        mov rdx, qword ptr [rsp + 8]
        vmulpd ymm10, ymm0, ymmword ptr [rcx + rdx]
        mov rcx, qword ptr [rsp + 72]
        mov rdx, qword ptr [rsp + 24]
        vroundpd ymm11, ymm9, 9
        add rcx, rsi
        adc r12, r10
        test al, 2
        cmovne rcx, rsi
        mov rsi, qword ptr [rsp + 32]
        cmovne r12, r10
        vcmpeqpd k1, ymm11, ymm9
        mov qword ptr [rsp + 72], rcx
        kmovd ecx, k0
        vroundpd ymm12, ymm10, 9
        add rbp, rsi
        vaddpd ymm13, ymm11, ymm12
        adc r14, rdx
        test cl, 1
        mov rcx, qword ptr [rsp + 64]
        cmovne r14, rdx
        mov rdx, qword ptr [rsp + 16]
        cmovne rbp, rsi
        vsubpd ymm14, ymm13, ymm11
        add r13, rcx
        vsubpd ymm15, ymm13, ymm14
        vsubpd ymm12, ymm12, ymm14
        adc r9, rdx
        test al, 8
        mov rax, qword ptr [rsp + 8]
        cmovne r9, rdx
        cmovne r13, rcx
        vsubpd ymm15, ymm11, ymm15
        vmovapd ymm11 {k1}, ymm13
        vsubpd ymm13, ymm9, ymm11
        mov qword ptr [rdi + 2*rax + 56], r9
        mov rax, qword ptr [rsp + 8]
        xor r9d, r9d
        vsubpd ymm14, ymm13, ymm9
        vaddpd ymm12, ymm12, ymm15
        vsubpd ymm15, ymm13, ymm14
        vaddpd ymm11, ymm11, ymm14
        mov qword ptr [rdi + 2*rax + 40], r14
        mov rax, qword ptr [rsp + 8]
        vsubpd ymm9, ymm9, ymm15
        vsubpd ymm9, ymm9, ymm11
        mov qword ptr [rdi + 2*rax + 24], r12
        mov rax, qword ptr [rsp + 8]
        vaddpd ymm9, ymm10, ymm9
        mov qword ptr [rdi + 2*rax + 8], r8
        mov rax, qword ptr [rsp + 8]
        movabs r8, -9223372036854775808
        vsubpd ymm9 {k1}, ymm9, ymm12
        vaddpd ymm10, ymm13, ymm9
        mov qword ptr [rdi + 2*rax + 48], r13
        mov rax, qword ptr [rsp + 8]
        mov r13, rdi
        vsubpd ymm11, ymm10, ymm13
        vmulpd ymm10, ymm10, ymm1
        vsubpd ymm9, ymm9, ymm11
        vaddpd ymm11, ymm10, ymm2
        mov qword ptr [rdi + 2*rax + 32], rbp
        vsubpd ymm12, ymm11, ymm10
        vmulpd ymm9, ymm9, ymm1
        vsubpd ymm13, ymm11, ymm12
        vsubpd ymm12, ymm2, ymm12
        vsubpd ymm10, ymm10, ymm13
        vaddpd ymm10, ymm12, ymm10
        vaddpd ymm10, ymm9, ymm10
        vaddpd ymm12, ymm11, ymm10
        vsubpd ymm11, ymm11, ymm12
        vroundpd ymm9, ymm12, 9
        vaddpd ymm10, ymm10, ymm11
        vcmpeqpd k1, ymm9, ymm12
        vroundpd ymm11, ymm10, 9
        vaddpd ymm10, ymm9, ymm11
        vsubpd ymm12, ymm10, ymm9
        vsubpd ymm13, ymm10, ymm12
        vsubpd ymm11, ymm11, ymm12
        vsubpd ymm13, ymm9, ymm13
        vmovapd ymm9 {k1}, ymm10
        vpsrlq ymm10, ymm9, 52
        vextracti128 xmm14, ymm9, 1
        vmovq rdi, xmm9
        vpextrq rsi, xmm9, 1
        shl rdi, 11
        vpsubq ymm10, ymm4, ymm10
        shl rsi, 11
        vpextrq rax, xmm14, 1
        vmovq rdx, xmm14
        or rdi, r8
        vmovd ecx, xmm10
        or rsi, r8
        vextracti128 xmm14, ymm10, 1
        shl rdx, 11
        shl rax, 11
        shrd r9, rdi, cl
        shrx rdi, rdi, rcx
        vaddpd ymm12 {k1} {z}, ymm11, ymm13
        vpcmpnleuq k1, ymm10, ymm5
        or rax, r8
        or rdx, r8
        test cl, 64
        mov rcx, rdi
        cmovne r9, rdi
        mov edi, 0
        cmovne rcx, rdi
        mov qword ptr [rsp + 56], r9
        xor r9d, r9d
        vandpd ymm11, ymm12, ymm6
        mov qword ptr [rsp + 64], rcx
        vpextrb ecx, xmm10, 8
        vextractf128 xmm13, ymm11, 1
        vmovq rbx, xmm11
        shrd r9, rsi, cl
        shrx rsi, rsi, rcx
        test cl, 64
        vmovd ecx, xmm14
        cmovne r9, rsi
        cmovne rsi, rdi
        xor edi, edi
        mov qword ptr [rsp + 112], rsi
        xor esi, esi
        shrd rsi, rdx, cl
        shrx rdx, rdx, rcx
        test cl, 64
        vpextrb ecx, xmm14, 8
        mov qword ptr [rsp + 104], r9
        cmovne rsi, rdx
        cmovne rdx, rdi
        mov qword ptr [rsp + 32], rdx
        xor edx, edx
        shrd rdx, rax, cl
        shrx rax, rax, rcx
        test cl, 64
        mov qword ptr [rsp + 96], rsi
        vpextrq rsi, xmm11, 1
        cmovne rdx, rax
        cmovne rax, rdi
        shl rsi, 11
        shl rbx, 11
        xor r9d, r9d
        mov qword ptr [rsp + 16], rdx
        vpextrq rdx, xmm13, 1
        mov qword ptr [rsp + 24], rax
        vmovq rax, xmm13
        vpsrlq ymm13, ymm12, 52
        or rbx, r8
        or rsi, r8
        vpsubq ymm13, ymm8, ymm13
        shl rdx, 11
        shl rax, 11
        vpand ymm13, ymm13, ymm5
        or rdx, r8
        or rax, r8
        vextracti128 xmm14, ymm13, 1
        vpextrb ecx, xmm14, 8
        shrd r9, rdx, cl
        shrx r12, rdx, rcx
        test cl, 64
        vmovd ecx, xmm14
        mov rdx, qword ptr [rsp + 72]
        shrx r11, rax, rcx
        cmovne r9, r12
        cmovne r12, rdi
        xor r14d, r14d
        shrd r14, rax, cl
        mov rax, qword ptr [rsp + 8]
        test cl, 64
        vpextrb ecx, xmm13, 8
        shrx r10, rsi, rcx
        cmovne r14, r11
        cmovne r11, rdi
        xor r8d, r8d
        shrd r8, rsi, cl
        test cl, 64
        vmovd ecx, xmm13
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
        vmovmskpd eax, ymm12
        sbb r13, r12
        kshiftrb k0, k0, 2
        test al, 8
        cmove r13, r12
        mov r12, qword ptr [rsp + 152]
        cmove rbx, r9
        kmovd r9d, k0
        vpcmpnleuq k0, ymm9, ymm3
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
        cmovne r8, rax
        cmovne r9, rdi
        mov r10, r8
        kmovd r8d, k0
        kshiftrb k0, k0, 2
        test r8b, 8
        cmove r10, rax
        mov rax, qword ptr [rsp + 8]
        cmove r9, rdi
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
        vpcmpgtq k0, ymm7, ymm11
        cmovne r14, rax
        cmovne r10, rdi
        test r9b, 1
        mov r9, qword ptr [rsp + 56]
        cmove r14, rax
        mov rax, qword ptr [rsp + 8]
        cmove r10, rdi
        mov rdi, qword ptr [rsp + 8]
        mov qword ptr [rsp + 32], r10
        mov r10, qword ptr [rsp + 104]
        mov rax, qword ptr [rsi + 2*rax + 16]
        mov rdi, qword ptr [rsi + 2*rdi + 24]
        add r10, rax
        adc r15, rdi
        test dl, 2
        cmovne r10, rax
        cmovne r15, rdi
        test r8b, 2
        cmove r10, rax
        mov rax, qword ptr [rsp + 8]
        cmove r15, rdi
        mov rdi, qword ptr [rsp + 8]
        mov rax, qword ptr [rsi + 2*rax]
        mov rdi, qword ptr [rsi + 2*rdi + 8]
        add r9, rax
        adc r11, rdi
        test dl, 1
        mov rdx, rcx
        mov rcx, qword ptr [rsp + 88]
        cmovne r9, rax
        cmovne r11, rdi
        test r8b, 1
        mov r8, qword ptr [rsp + 144]
        cmove r9, rax
        cmove r11, rdi
        kmovd eax, k0
        mov rdi, qword ptr [rsp + 32]
        kshiftrb k0, k0, 2
        add rdx, r9
        adc r12, r11
        test al, 1
        cmovne r12, r11
        mov r11, qword ptr [rsp + 72]
        cmovne rdx, r9
        add rcx, r10
        mov r9, rdx
        kmovd edx, k0
        adc r11, r15
        test al, 2
        cmovne rcx, r10
        mov r10, qword ptr [rsp + 80]
        cmovne r11, r15
        add rbp, r14
        mov r15, qword ptr [rsp + 24]
        adc r10, rdi
        test dl, 1
        mov rdx, qword ptr [rsp + 136]
        cmovne r10, rdi
        mov rdi, qword ptr [rsp + 16]
        cmovne rbp, r14
        add rbx, rdi
        adc r13, r15
        test al, 8
        mov rax, qword ptr [rsp + 8]
        cmovne r13, r15
        cmovne rbx, rdi
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
        jne .LBB5_5
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
.LBB5_7:
        .cfi_def_cfa_offset 224
        lea r8, [rip + .Lanon.34c3a112972100437a4d63a4fe335a9b.29]
        lea rsi, [rsp + 40]
        lea rdx, [rsp + 48]
        xor edi, edi
        xor ecx, ecx
        call core::panicking::assert_failed::<usize, usize>
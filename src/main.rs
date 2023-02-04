//
// libc = "0.2.139"
use libc::c_int;
use libc::c_void;
use libc::size_t;
use std::ffi::CStr;
use std::mem::MaybeUninit;

#[no_mangle]
extern "C" fn sigsev_handler(sig: c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
    unsafe {
        println!("Handler");
        println!(
            "  si_signo: {:?} -> {:?}",
            (*info).si_signo,
            CStr::from_ptr(libc::strsignal((*info).si_signo))
        );
        println!("  si_errno: {:?}", (*info).si_errno);
        println!("  si_code: {:?}", (*info).si_code);
        println!("  si_addr: {:?}", (*info).si_addr());
        if (*info).si_signo != libc::SIGSEGV {
            panic!(
                "Expected sigsegv error in handler, got {}.",
                (*info).si_signo
            );
        }

        // Cast the context
        let mut ucontext = std::mem::transmute::<_, *mut libc::ucontext_t>(context);
        println!("{context:?}");

        let mcontext = &mut (*ucontext).uc_mcontext;
        // println!("{:#?}", mcontext.gregs);

        // The general purpose reigsters.
        // EAX   ECX   EDX   EBX   ESP   EBP   ESI   EDI
        println!("REG_RAX 0x{:0>8x}", mcontext.gregs[libc::REG_RAX as usize]);
        println!("REG_RCX 0x{:0>8x}", mcontext.gregs[libc::REG_RCX as usize]);
        println!("REG_RDX 0x{:0>8x}", mcontext.gregs[libc::REG_RDX as usize]);
        println!("REG_RBX 0x{:0>8x}", mcontext.gregs[libc::REG_RBX as usize]);
        println!("REG_RSP 0x{:0>8x}", mcontext.gregs[libc::REG_RSP as usize]);
        println!("REG_RSI 0x{:0>8x}", mcontext.gregs[libc::REG_RSI as usize]);
        println!("REG_RDI 0x{:0>8x}", mcontext.gregs[libc::REG_RDI as usize]);

        // The instruction position
        println!("REG_RIP 0x{:0>8x}", mcontext.gregs[libc::REG_RIP as usize]);
        // let rip: &mut i64 = &mut mcontext.gregs[libc::REG_RIP as usize];
        let instructions =
            std::mem::transmute::<_, *const u8>(mcontext.gregs[libc::REG_RIP as usize]);

        // get a byte slice to the instruction pointer..
        let assembly = std::slice::from_raw_parts(instructions, 10);
        println!("Assembly: {assembly:x?}");

        let register_operands = [
            libc::REG_RAX as usize,
            libc::REG_RCX as usize,
            libc::REG_RDX as usize,
            libc::REG_RBX as usize,
            libc::REG_RSP as usize,
            libc::REG_RBP as usize,
            libc::REG_RSI as usize,
            libc::REG_RDI as usize,
        ];

        /*
        https://www.scs.stanford.edu/05au-cs240c/lab/i386/s17_02.htm

        r8(/r)                     AL    CL    DL    BL    AH    CH    DH    BH
        r16(/r)                    AX    CX    DX    BX    SP    BP    SI    DI
        r32(/r)                    EAX   ECX   EDX   EBX   ESP   EBP   ESI   EDI
        /digit (Opcode)            0     1     2     3     4     5     6     7
        REG =                      000   001   010   011   100   101   110   111
          */

        type Rm = u8;
        type RegOpcode = u8;
        type Mod = u8;
        fn crack_modrm(v: u8) -> (Mod, RegOpcode, Rm) {
            (v >> 6, (v >> 3) & 0b111, v & 0b111)
        }

        let mut instruction_p = 0;
        let instruction = assembly[instruction_p];
        instruction_p += 1;

        // http://ref.x86asm.net/coder32.html
        match instruction {
            0xc6 => {
                //  move C6 0 MOV	r/m8 imm8 Move
                println!("Move c6");
                let operand = assembly[instruction_p];
                instruction_p += 1;

                let (modifier, regopcode, r_m) = crack_modrm(operand);
                println!("Operand {operand:x}");
                println!("modifier 0b{modifier:b}");
                println!("regopcode 0b{regopcode:b}");
                println!("r_m 0b{r_m:b}");

                let mut dest = mcontext.gregs[register_operands[regopcode as usize]] as usize;
                match modifier {
                    0b00 => {
                        // no displacement, register directly.
                    }
                    0b01 => {
                        // 8 bit displacement to be added to the index.
                        // pop the displacement from the assembly.
                        let displacement = assembly[instruction_p];
                        instruction_p += 1;
                        dest += displacement as usize;
                    }
                    0b10 => {
                        // 32 bit displacement to be added to the index.
                        let displacement = &assembly[instruction_p..instruction_p + 4];
                        instruction_p += 4;
                        dest += displacement[0] as usize;
                        dest += (displacement[1] as usize * 255);
                        dest += (displacement[2] as usize * 255 * 255);
                        dest += (displacement[3] as usize * 255 * 255 * 255);
                    }
                    0b11 => {
                        // entire register?
                        todo!();
                    }
                    _ => unreachable!(),
                }
                println!("final dest 0x{dest:x}");
                let value = assembly[instruction_p];
                instruction_p += 1;
                println!("value {value:?}");
                unprotect(dest);
                // do the write.
                // println!("Writing to unprotected");
                println!("Intercepted writing {value}u8 to 0x{dest:x}");
                *std::mem::transmute::<_, *mut u8>(dest) = value;
                // println!("protecting");
                protect(dest);
                // With that done, we should now advance the instruction pointer that we will jump
                // to when the program is resumed after the signal handler is done.
                mcontext.gregs[libc::REG_RIP as usize] += instruction_p as i64;
            }
            0xc7 => {
                //  C7 0 MOV r/m16/32/64 imm16/32 Move
                println!("Move c7");
                let operand = assembly[instruction_p];
                instruction_p += 1;
                println!("Operand {operand:x}");
                let dest = mcontext.gregs[register_operands[operand as usize]] as usize;
                println!("dest 0x{dest:x}");
                // let value = &assembly[2..4]; //  how does imm16/32 determine width?
                let value = &assembly[instruction_p..instruction_p + 4];
                instruction_p += 4;
                println!("value {value:?}");

                let dest_u8 = std::mem::transmute::<_, *mut u8>(dest);
                unprotect(dest);
                for i in 0..4 as usize {
                    println!(
                        "Intercepted writing {value}u8 to {dest:?}",
                        value = value[i],
                        dest = dest_u8.offset(i as isize)
                    );
                    *dest_u8.offset(i as isize) = value[i];
                }
                protect(dest);
                // todo!();
                // With that done, we should now advance the instruction pointer that we will jump
                // to when the program is resumed after the signal handler is done.
                mcontext.gregs[libc::REG_RIP as usize] += instruction_p as i64;
            }
            _ => {
                panic!("Unhandled opcode: 0x{instruction:0>2x}");
            }
        }

        // panic!();
    }
}

unsafe fn setup() {
    let mut action: libc::sigaction = std::mem::zeroed();
    action.sa_sigaction = std::mem::transmute::<_, usize>(sigsev_handler as extern "C" fn(_, _, _));
    action.sa_flags = libc::SA_SIGINFO;

    let r = libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut());
    // println!("Result: {r:?}");
}

unsafe fn allocate_protected(size: u64) -> *mut u8 {
    std::mem::transmute::<_, *mut u8>(libc::mmap(
        std::ptr::null_mut(),                    //addr
        size as size_t,                          //addr
        libc::PROT_READ,                         // prot
        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE, // flags
        -1,                                      // fd
        0,                                       // offset
    ))
}

const PAGE_SIZE: usize = 4096;
unsafe fn unprotect(address: usize) {
    let address = address ^ (address & (PAGE_SIZE - 1));
    let addr = std::mem::transmute::<_, _>(address);
    // println!("Unprotecting addr: {addr:?}");
    let r = libc::mprotect(addr, PAGE_SIZE, libc::PROT_READ | libc::PROT_WRITE);
    // println!("r addr: {r:?}");
}

unsafe fn protect(address: usize) {
    // let address = address & (! PAGE_SIZE -1);
    let address = address ^ (address & (PAGE_SIZE - 1));
    let addr = std::mem::transmute::<_, _>(address);
    // println!("protecting addr: {addr:x?}");
    let r = libc::mprotect(addr, PAGE_SIZE, libc::PROT_READ);
    // panic!();
    // println!("r addr: {r:?}");
    // panic!();
}

fn main() {
    unsafe {
        setup();

        println!("Hello, world!");
        let len = 300;
        let v = allocate_protected(len);
        println!("V: {v:?}");
        // let mut v = Vec::new();
        // v.push(1u8);
        // unsafe {
        let data = std::slice::from_raw_parts_mut(v, len as usize);
        data[299] = 25;
        // let z = v.as_mut_ptr();
        // println!("z: {z:?}");
        // *v.offset(301) = 3;
        let as_u32 = std::mem::transmute::<_, *mut u32>(v.offset(3));
        *as_u32 = 65535;
        println!("Printing");
        println!("{data:?}");
    }
}

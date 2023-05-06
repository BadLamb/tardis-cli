use clap::{Parser, ValueHint};
use std::path::PathBuf;
use std::u64;
use nix::sys::ptrace;
use std::os::unix::process::CommandExt;
use nix::unistd::{fork, ForkResult, Pid};
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, wait};
use linux_personality::personality;
use std::process::{Command, exit};
use std::process;

#[derive(Parser)]
struct Cli {
    /// Address of the instruction where the snapshot will be taken
    #[arg(short, long)]
    breakpoint_addr: String,
    
    /// Target program
    #[arg(last = true)]
    cli: Vec<String>,
}

fn main() {
    // Parse the CLI args
    let args = Cli::parse();

    // Get the address of the breakpoint we will take a snapshot on
    let bp_prefix = args.breakpoint_addr.trim_start_matches("0x");
    let bp_addr = u64::from_str_radix(bp_prefix, 16).unwrap();

    // Get argv and argc
    assert!(args.cli.len() > 1);
    let mut all_args = args.cli.clone();
    let argv = args.cli.first().unwrap();
    all_args.remove(0);
    println!("{argv:} {:?} {bp_addr:}", all_args);
    
    run_child(argv, all_args, bp_addr);
}

pub const NT_ARM_HW_BREAK: u32 = 1026;
const BYTE_MASK: u32 = 0xf;
const ENABLE: u32 = 1;
const CONTROL: u32 = (BYTE_MASK << 5) | ENABLE;

#[derive(Default)]
#[repr(C)]
pub struct user_hwdebug_state {
    pub dbg_info: u32,
    pub pad: u32,
    pub dbg_regs: [user_hwdebug_ctrl; 16],
}

#[repr(C)]
#[derive(Default)]
pub struct user_hwdebug_ctrl {
    pub addr: u64,
    pub ctrl: u32,
    pub pad: u32,
}

pub fn run_child(proc: &String, args: Vec<String>, bp_addr: u64) {
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Allows process to be traced
            ptrace::traceme().unwrap();

            // Disable ASLR for this process
            personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();

            // Execute binary replacing our child
            Command::new(proc).args(args).exec();

            exit(0);
        }

        Ok(ForkResult::Parent { child }) => {
            // Wait for the ptrace signal
            wait().unwrap();
            
            // Insert a breakpoint at the specified address
            // Note: The hypervisor only intercepts sw breakpoints
            let mut hwdebug = user_hwdebug_state::default();
            hwdebug.dbg_regs[0].addr = bp_addr;
            hwdebug.dbg_regs[0].ctrl = CONTROL;
            
            // NOTE: This safe ptrace wrapper doesn't have good arm support
            unsafe { libc::ptrace(libc::PTRACE_SETREGSET, child, NT_ARM_HW_BREAK, &mut libc::iovec {
                    iov_base: Box::into_raw(Box::new(hwdebug)) as *mut libc::c_void,
                    iov_len: 24,
                });
            };
            
            // Continue the execution
            ptrace::cont(child, None).unwrap();
            
            loop {
                match wait() {
                    Ok(WaitStatus::Stopped(pid, sig_num)) => {
                        match sig_num {
                            Signal::SIGTRAP => {
                                // Get the registers 
                                let regs = Box::new(libc::user_regs_struct{
                                    regs: [0; 31],
                                    sp: 0,
                                    pc:0,
                                    pstate:0,
                                });
                                
                                // Get the PC
                                let ptr = Box::into_raw(regs);
                                let pc = unsafe{
                                    libc::ptrace(libc::PTRACE_GETREGSET, pid, 1, &mut libc::iovec {
                                        iov_base: ptr as *mut libc::c_void,
                                        iov_len: 272,
                                    });
                                    (*ptr).pc
                                };
                                
                                // If we hit the breakpoint then write BRK #0 @ pc
                                println!("pc: {:x} bp: {:x}", pc, bp_addr);
                                if pc == bp_addr {
                                    // Write brk #0; brk #0;
                                    //let bp = 0xd4200000d4200000u64;
                                    //unsafe { ptrace::write(pid, (pc-4) as *mut libc::c_void, bp as *mut libc::c_void).unwrap(); }
                                    
                                    // Disable HW bp
                                    let mut hwdebug = user_hwdebug_state::default();
                                    hwdebug.dbg_regs[0].addr = 0;
                                    hwdebug.dbg_regs[0].ctrl = 0;
                                    unsafe {
                                        libc::ptrace(libc::PTRACE_SETREGSET, pid, NT_ARM_HW_BREAK, &mut libc::iovec {
                                            iov_base: Box::into_raw(Box::new(hwdebug)) as *mut libc::c_void,
                                            iov_len: 24,
                                        });
                                    };
                                }
                                
                                ptrace::cont(pid, None).unwrap();
                            }
                            _ => {}
                        }
                    },
                    Ok(WaitStatus::Exited(pid, exit_status)) => {
                        println!("Process with pid: {} exited with status {}", pid, exit_status);
                        process::exit(1);
                    },
                    Ok(status) =>  {
                        println!("Received status: {:?}", status);
                        ptrace::cont(child, None).unwrap();
                    },

                    Err(err) => {
                        println!("Error - {:?}",err);
                    },
                }
            }
        }

        Err(err) => {
            panic!("fork() failed: {}", err);
        }
    }
}

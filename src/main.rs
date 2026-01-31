mod net;
mod crypto;
mod protocol;

use std::env;
use std::process;

use crate::protocol::{receive, send};

// -------- cli --------

fn usage() -> ! {
    eprintln!("Usage:");
    eprintln!("  beamer -s <ip> <port>    (send; reads from stdin)");
    eprintln!("  beamer -r <port>         (receive; writes to stdout)");
    eprintln!("  beamer -b <process>      (combine with -r or -r; writes to process (pipe)");
    eprintln!("  beamer -h");
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        usage();
    }

    let op_mode = args[1].to_lowercase();
    if op_mode == "-s" {
        if args.len() < 4 || args.len() > 5 {
            usage();
        }

        if args.len() == 4 {
            //FIXME Implement pipes here
            send(&args[2], &args[3], false);
        } //else handle pipe...

    } else if op_mode == "-r" {
        if args.len() < 3 || args.len() > 4 {
            usage();
        }

        //FIXME Implement pipes here
        if args.len() == 3 {
            receive(&args[2], false);
        } //else handle pipe...

    } else if op_mode == "-h" {
        usage();
    } else {
        usage();
    }
}

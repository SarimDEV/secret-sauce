use cli_clipboard::{ClipboardContext, ClipboardProvider};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Error, Write};
use colored::*;

use crate::access::Access;

pub struct Storage {
    origin_names: Vec<String>,
}

impl Storage {
    pub fn init() -> Result<Self, Error> {
        let path = "origin.txt";

        let input = File::open(path);
        match input {
            Ok(file) => {
                let buffered = BufReader::new(file);
                let mut origin_names = vec![];

                for line in buffered.lines() {
                    origin_names.push(line?);
                }

                Ok(Storage { origin_names })
            }
            _ => {
                File::create(path)?;
                Ok(Storage {
                    origin_names: vec![],
                })
            }
        }
    }

    fn add_origin(&self, origin: String) {
        let mut output = OpenOptions::new()
            .write(true)
            .append(true)
            .open("origin.txt")
            .unwrap();

        let data = format!("{}", origin);
        writeln!(output, "{data}").unwrap();
    }

    pub fn read(&self, access: &Access, id: &usize) {
        let origin_name = self.origin_names[*id].clone();
        let password = access.decrypt_password(origin_name).unwrap();
        println!("{}", "Copied to clipboard!".green());
        let mut ctx = ClipboardContext::new().unwrap();
        ctx.set_contents(password.to_owned()).unwrap();
    }

    pub fn write(&mut self, access: &mut Access, origin: &String, password: String) {
        self.origin_names.push(origin.clone());
        self.add_origin(origin.clone());
        access.store_password(origin.clone(), password).unwrap();
        println!("{}", "Successfully stored information!".green());
    }

    pub fn len(&self) -> usize {
        return self.origin_names.len();
    }
}

impl fmt::Display for Storage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.origin_names
            .iter()
            .enumerate()
            .fold(Ok(()), |result, (i, origin)| {
                result.and_then(|_| writeln!(f, "({}) {}", i + 1, origin))
            })
    }
}

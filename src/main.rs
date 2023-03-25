mod access;
mod storage;
use colored::*;
use std::io::{self, stdin, Write};

fn get_user_input(prompt: &str) -> String {
    let mut output = String::new();
    println!("{prompt}");
    print!("> ");
    io::stdout().flush().unwrap();
    stdin().read_line(&mut output).unwrap();
    let result = output.trim_end().to_string();
    return result;
}

fn main() {
    let mut storage = storage::Storage::init().unwrap();
    let mut access = access::Access::init().unwrap();

    println!(
        "{}", "I'm Secret Sauce - your password manager, ready to keep your passwords safe like Spongebob keeps his Krabby Patties safe from Plankton.".purple()
    );
    println!();

    if let Ok(_) = access.get_hashed_passcode() {
        let mut matched = false;
        println!(
            "{}",
            "R who is you? No booty if you don't have the code!".red()
        );
        for _ in 0..3 {
            let master_passcode = rpassword::prompt_password("Enter your password > ").unwrap();
            if access.does_passcode_match(&master_passcode).unwrap() {
                access.login(master_passcode);
                matched = true;
                break;
            }
        }
        if matched == false {
            println!("{}", "It's time for you to hit the road pal, before I give you a one-way ticket to Glove World without a return trip!".red());
            return;
        }
    } else {
        println!("{}", "R you ain't got no master password, how can I keep your booty safe? Make one now me boi.".red());
        let master_passcode = rpassword::prompt_password("> ").unwrap();
        access.create_master_passcode(master_passcode).unwrap();
        println!("{}", "Successfully created passcode!".green());
    }
    let mut input_string = String::new();

    println!("");
    while input_string != "x" {
        if storage.len() == 0 {
            println!("{}", "You ain't got no secret formulas!".red());
            println!("enter + to add a new password.");
            println!("Or, enter x to exit.");
        } else {
            println!("Which information would you like to access me boi?");
            println!("");
            println!("{}", &storage);
            println!("Or, enter + to add a new password.");
            println!("Or, enter x to exit.");
        }

        input_string.clear();
        let input = get_user_input("");

        if let Ok(num) = input.parse::<usize>() {
            storage.read(&access, &(num - 1));
            return;
        } else {
            if input == "+" {
                let origin: String =
                    get_user_input("Ahoy there matey! What be the purpose o' this?");
                let password =
                    rpassword::prompt_password("Give me the password, I might keep it safe > ")
                        .unwrap();
                storage.write(&mut access, &origin, password);
                continue;
            } else if input == "x" {
                println!("Bye bye!");
                return;
            } else {
                println!("Unsupported input!")
            }
        }
    }
}

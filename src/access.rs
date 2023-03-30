use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use pbkdf2::{pbkdf2_hmac_array};
use rand::Rng;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Error, ErrorKind, Write};

const PATH: &str = "./patty_formula.txt";
const ING_PATH: &str = "./ingredient_formula.txt";
const ITERATIONS: u32 = 10000;

pub struct Access {
    hashed_patty_formula: String,
    encrypted_data: HashMap<String, EncryptedData>,
    master_passcode: String,
}

type EncryptedData = (Vec<u8>, [u8; 128], [u8; 12]);

// const PATH: &str = "patty_formula.txt";
impl Access {
    pub fn init() -> Result<Self, Error> {
        let mut encrypted_data = HashMap::new();
        let input = File::open(ING_PATH);
        if let Ok(file) = input {
            let buffered = BufReader::new(file);

            for line in buffered.lines() {
                let line = line.unwrap();
                let split_data: Vec<&str> = line.splitn(4, '|').collect();
                let (origin, ciphertext, salt, nonce) =
                    (split_data[0], split_data[1], split_data[2], split_data[3]);
                let origin = origin.to_string();
                let ciphertext = ciphertext
                    .trim_matches(['[', ']'].as_slice())
                    .split(',')
                    .map(str::trim)
                    .map(|x| x.parse::<u8>().unwrap())
                    .collect::<Vec<u8>>();

                let salt = salt
                    .trim_matches(['[', ']'].as_slice())
                    .split(',')
                    .map(str::trim)
                    .map(|x| x.parse::<u8>().unwrap())
                    .collect::<Vec<u8>>();

                let salt: &[u8; 128] = salt.as_slice().try_into().unwrap();

                let nonce = nonce
                    .trim_matches(['[', ']'].as_slice())
                    .split(',')
                    .map(str::trim)
                    .map(|x| x.parse::<u8>().unwrap())
                    .collect::<Vec<u8>>();

                let nonce: &[u8; 12] = nonce.as_slice().try_into().unwrap();

                let data: EncryptedData = (ciphertext, *salt, *nonce);
                encrypted_data.insert(origin, data);
            }
        } else {
            File::create(ING_PATH)?;
        }

        let input = File::open(PATH);

        if let Ok(file) = input {
            let buffered = BufReader::new(file);

            let hashed_patty_formula: String = buffered.lines().map(|x| x.unwrap()).collect();
            Ok(Access {
                hashed_patty_formula,
                encrypted_data,
                master_passcode: String::new(),
            })
        } else {
            File::create(PATH)?;
            Ok(Access {
                hashed_patty_formula: String::new(),
                encrypted_data,
                master_passcode: String::new(),
            })
        }
    }

    pub fn create_master_passcode(&mut self, pass: String) -> Result<(), Error> {
        let hashed = hash(pass.clone(), DEFAULT_COST).unwrap();
        let mut output = File::create(PATH)?;
        write!(output, "{hashed}")?;
        self.hashed_patty_formula = hashed;
        self.master_passcode = pass;
        Ok(())
    }

    pub fn get_hashed_passcode(&self) -> Result<String, Error> {
        if self.hashed_patty_formula != "" {
            Ok(self.hashed_patty_formula.clone())
        } else {
            Err(Error::new(ErrorKind::Other, "Unable to get passcode"))
        }
    }

    pub fn does_passcode_match(&self, pass: &String) -> Result<bool, Error> {
        let does_match = verify(pass, &self.hashed_patty_formula).unwrap();
        Ok(does_match)
    }

    pub fn login(&mut self, master_passcode: String) {
        self.master_passcode = master_passcode;
    }

    fn add_pass_to_file(
        &self,
        origin: String,
        ciphertext: Vec<u8>,
        salt: [u8; 128],
        nonce: [u8; 12],
    ) -> Result<bool, Error> {
        let mut output = OpenOptions::new()
            .write(true)
            .append(true)
            .open(ING_PATH)
            .unwrap();

        let data = format!("{}|{:?}|{:?}|{:?}", origin, ciphertext, salt, nonce);
        writeln!(output, "{data}").unwrap();

        Ok(true)
    }

    pub fn store_password(&mut self, origin: String, pass: String) -> Result<bool, Error> {
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; 128];
        let mut gen_nonce = [0u8; 12];
        rng.fill(&mut salt);
        rng.fill(&mut gen_nonce);

        let key =
            &pbkdf2_hmac_array::<Sha256, 32>(self.master_passcode.as_bytes(), &salt, ITERATIONS);

        let key = GenericArray::from_slice(key);

        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&gen_nonce); // 96-bits; unique per message

        let ciphertext = cipher.encrypt(nonce, pass.as_bytes().as_ref()).unwrap();
        self.add_pass_to_file(origin.clone(), ciphertext.clone(), salt, gen_nonce)
            .unwrap();

        self.encrypted_data.insert(origin, (ciphertext, salt, gen_nonce));
        Ok(true)
    }

    pub fn decrypt_password(&self, origin: String) -> Result<String, Error> {
        let (ciphertext, salt, nonce) = self.encrypted_data.get(&origin).unwrap();

        let key =
            pbkdf2_hmac_array::<Sha256, 32>(self.master_passcode.as_bytes(), salt, ITERATIONS);
        let key = GenericArray::from_slice(&key);

        let nonce = Nonce::from_slice(nonce); // 96-bits; unique per message
        let cipher = Aes256Gcm::new(key);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        Ok(String::from_utf8_lossy(&plaintext).to_string())
    }
}

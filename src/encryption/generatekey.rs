use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroize;

pub fn generate_key(mut password: String, salt: [u8; 16]) -> [u8; 32] {
    let iterations: u32 = 100_000;

    let mut key: [u8; 32] = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut key);
    password.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn generate() {
        let mut rng: rand::prelude::ThreadRng = rand::rng();
        let mut salt: [u8; 16] = [0u8; 16];
        rng.fill_bytes(&mut salt);

        let key: [u8; 32] = generate_key("SuperSecretPassword".to_string(), salt);
        println!("{:?}\n{:?}", key, salt);
        assert!(true);
    }   
}
use crate::error::CryptoError;
use bip39::Mnemonic;

pub fn generate_mnemonic(word_count: usize) -> Result<String, CryptoError> {
    let entropy_size = match word_count {
        12 => 16,
        24 => 32,
        _ => return Err(CryptoError::Custom("Unsupported word count".into())),
    };
    
    let mut entropy = vec![0u8; entropy_size];
    getrandom::fill(&mut entropy).map_err(|e: getrandom::Error| CryptoError::Custom(e.to_string()))?;
    
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| CryptoError::Bip39Error(e.into()))?;
    Ok(mnemonic.to_string())
}

pub fn seed_from_mnemonic(phrase: &str, password: &str) -> Result<Vec<u8>, CryptoError> {
    let mnemonic = Mnemonic::parse(phrase)
        .map_err(|e| CryptoError::Bip39Error(e.into()))?;
    Ok(mnemonic.to_seed(password).to_vec())
}

package SKRIPSI2;

import java.security.PublicKey;

public class KeyEntry {
    private String clientId;
    private PublicKey publicKey;
    
    public KeyEntry(String clientId, PublicKey publicKey) {
        this.clientId = clientId;
        this.publicKey = publicKey;
    }
    public String getClientId() {
        return clientId;
    }
    
    public PublicKey getPublicKey() {
        return publicKey;
    }
}

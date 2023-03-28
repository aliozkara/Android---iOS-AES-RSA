import Security

struct RSAProvider {
    
    private var publicKeyString: String {
        """
        -----BEGIN PUBLIC KEY-----
        y
        o
        u
        r
        k
        e
        y
        -----END PUBLIC KEY-----
        """
    }
    
    func encrypt(data: Data) -> Data? {
                
        guard let secKey = secKey() else { return nil }
        
        let buffer = data.bytes
        var keySize  = SecKeyGetBlockSize(secKey)
        var keyBuffer = [UInt8](repeating: 0, count: keySize)

        guard SecKeyEncrypt(secKey, SecPadding.PKCS1, buffer, buffer.count, &keyBuffer, &keySize) == errSecSuccess else { return nil }

        return Data(bytes: keyBuffer, count: keySize)
        
    }
    
    private func secKey() -> SecKey? {
        
        let keyString = publicKeyString.components(separatedBy: "\n").filter { line in
            return !line.hasPrefix("-----BEGIN") && !line.hasPrefix("-----END")
        }
            
        let key = keyString.joined(separator: "")
        
        guard let publicKeyData = Data(base64Encoded: key) else { return nil }
        let publicKeyDict: CFDictionary = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: 2048,
            kSecReturnPersistentRef : kCFBooleanTrue
        ] as CFDictionary
        
        var error: Unmanaged<CFError>? = nil
        guard let secKey = SecKeyCreateWithData(publicKeyData as CFData, publicKeyDict, &error) else {
            print(error.debugDescription)
            return nil
        }
        
        return secKey
    }
}

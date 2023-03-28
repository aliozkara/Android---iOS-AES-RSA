import CryptoKit
import CryptoSwift

struct AESProvider {
    
    func aesEncrypt(key: Data, data: Data) throws -> Data? {
        do {
            let key: [UInt8] = key.map { $0 }
            let aes = try AES(key: key, blockMode: ECB(), padding: .pkcs7)
            let encrypted = try aes.encrypt(data.bytes)
            return Data(encrypted)
        } catch {
            return nil
        }
    }
    
    func aesDecrypt(key: Data, encrypted: Data) throws -> Data? {
        do {
            let key: [UInt8] = key.map { $0 }
            let aes = try AES(key: key, blockMode: ECB(), padding: .pkcs7)
            let decrypted = try aes.decrypt(encrypted.bytes)
            return Data(decrypted)
        } catch {
            return nil
        }
    }
    
    func generateKey() -> Data {
        let key = SymmetricKey(size: .bits128)
        return key.withUnsafeBytes {
            Data(Array($0))
        }
    }
    
}

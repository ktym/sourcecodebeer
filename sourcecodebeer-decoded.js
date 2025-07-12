function source_code(password) {
  const subtle = crypto.subtle;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const rawPassword = encoder.encode(password);

  // ステップ1: SHA-256 ダイジェストを取得
  subtle.digest("SHA-256", rawPassword)
    .then(hash => {
      // ステップ2: ハッシュをインポート（PBKDF2のキーとして使う）
      return subtle.importKey(
        "raw",
        hash,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
    })
    .then(importedKey => {
      // ステップ3: 鍵導出（AES-GCM用鍵を生成）
      return subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: Uint8Array.from([
            0x66, 0xd5, 0xc7, 0xba, 0xf0, 0x86, 0x93, 0x0f,
            0x37, 0x95, 0x4a, 0x62, 0x23, 0xea, 0x47, 0x7e
          ]),
          iterations: 100000,
          hash: "SHA-256"
        },
        importedKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    })
    .then(aesKey => {
      // ステップ4: 暗号化されたデータを復号
      const iv = Uint8Array.from([
        0x3b, 0x1e, 0xcd, 0x27, 0xa2, 0x3a, 0xc2, 0xa5,
        0xeb, 0x85, 0xc6, 0xa2, 0xfa, 0xa5, 0x5c, 0xeb
      ]);

      const encryptedBase64 = "l8s3tVIPX3K9XOyqmObu6QD4bRqGeJvvdWGY9q7YTGUn4KcunABvTWGXwZurgOZiaIzkQyLIdcvC69DuARlE+yWYUO0f4+k4cox+hB3RobCi5qer8EXdEythI9iivRYaVw3cKfS9cNF9iL3SNG+C4am0qCMZkbrglNaqRnyuF20cKK0HgS38jmj5ty3S5m8TqXJ8VPKNqyDsHFO8UrodEI6hs5izK0TacYjCZrFyjFYKV4kQTiq63xZ63/t+7k9p/eqopDTh";
      const encryptedBytes = Uint8Array.from(atob(encryptedBase64).split('').map(c => c.charCodeAt(0)));

      return subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        encryptedBytes
      );
    })
    .then(decrypted => {
      // ステップ5: 復号されたデータを表示
      console.log(decoder.decode(new Uint8Array(decrypted)));
    })
    .catch(error => {
      console.error(error);
    });
}


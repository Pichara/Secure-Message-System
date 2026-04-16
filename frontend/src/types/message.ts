export interface ApiMessage {
  id: number;
  sender: string;
  recipient: string;
  encrypted_key: string;
  ciphertext: string;
  iv: string;
  created_at: string;
}

export interface DecryptedMessage {
  id: number;
  sender: string;
  recipient: string;
  created_at: string;
  display: string;
  raw: string;
  kind: "text" | "attachment";
  attachment?: {
    name: string;
    mime: string;
    size_bytes: number;
    bytes_b64: string;
    caption?: string;
  };
}
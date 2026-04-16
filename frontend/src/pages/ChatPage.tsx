import { useCallback, useEffect, useState } from "react";
import { addContact, getContacts } from "../api/contacts";
import { logout } from "../api/auth";
import { getMessages, getPublicKey, sendMessage } from "../api/messages";
import ContactList from "../components/ContactList";
import ChatWindow from "../components/ChatWindow";
import MessageComposer from "../components/MessageComposer";
import { useAuthStore } from "../store/authStore";
import type { Contact } from "../types/contact";
import type { ApiMessage, DecryptedMessage } from "../types/message";
import { buildAttachmentEnvelope, parseMessageContent } from "../crypto/attachments";
import { decryptMessage, encryptMessageForRecipients } from "../crypto/messages";
import { b64UrlDecode } from "../crypto/base64";
import { clearCryptoStorage, getPublicKeyLocal, getUnlockedPrivateKeyRawB64 } from "../crypto/storage";
import { useNavigate } from "react-router-dom";

interface AuthState {
    auth: { username: string } | null;
    clearAuth: () => void;
}

export default function ChatPage() {
    const auth = useAuthStore((s: AuthState) => s.auth);
    const clearAuth = useAuthStore((s: AuthState) => s.clearAuth);
    const navigate = useNavigate();

    const [contacts, setContacts] = useState<Contact[]>([]);
    const [selectedUser, setSelectedUser] = useState<string | null>(null);
    const [messages, setMessages] = useState<DecryptedMessage[]>([]);
    const [loadingMessages, setLoadingMessages] = useState(false);

    const loadContacts = async () => {
        try {
            const data = await getContacts();
            setContacts(data);
        } catch (e: unknown) {
            const error = e as Error;
            alert(error.message);
        }
    };

    const loadMessages = useCallback(async (withUser: string) => {
        try {
            setLoadingMessages(true);
            const raw: ApiMessage[] = await getMessages(withUser);
            raw.sort((a, b) => a.created_at.localeCompare(b.created_at));

            const privateKeyPkcs8B64 = getUnlockedPrivateKeyRawB64();
            const mapped: DecryptedMessage[] = [];

            for (const msg of raw) {
                let plaintext = "[message unavailable]";

                if (privateKeyPkcs8B64) {
                    try {
                        plaintext = await decryptMessage(
                            msg.ciphertext,
                            msg.iv,
                            msg.encrypted_key,
                            privateKeyPkcs8B64,
                            auth?.username
                        );
                    } catch {
                        plaintext = msg.sender === auth?.username ? "[sent message]" : "[decryption failed]";
                    }
                } else if (msg.sender === auth?.username) {
                    plaintext = "[sent message]";
                }

                const parsed = parseMessageContent(plaintext);

                mapped.push({
                    id: msg.id,
                    sender: msg.sender,
                    recipient: msg.recipient,
                    created_at: msg.created_at,
                    display: parsed.display,
                    raw: parsed.raw,
                    kind: parsed.kind,
                    attachment: parsed.kind === "attachment" ? parsed.attachment : undefined,
                });
            }

            setMessages(mapped);
        } catch (e: unknown) {
            const error = e as Error;
            alert(error.message);
        } finally {
            setLoadingMessages(false);
        }
    }, [auth?.username]);

    useEffect(() => {
        loadContacts();
    }, []);

    useEffect(() => {
        if (!selectedUser) return;
        loadMessages(selectedUser);

        const timer = setInterval(() => {
            loadMessages(selectedUser);
        }, 3000);

        return () => clearInterval(timer);
    }, [selectedUser, loadMessages]);

    const handleAddContact = async () => {
        const username = prompt("Username to add");
        if (!username) return;

        try {
            await addContact(username, username);
            await loadContacts();
            setSelectedUser(username);
        } catch (e: unknown) {
            const error = e as Error;
            alert(error.message);
        }
    };

    const handleSendText = async (text: string) => {
        if (!selectedUser || !auth?.username) return;

        const encrypted = await encryptForConversation(text, selectedUser, auth.username);

        await sendMessage({
            recipient: selectedUser,
            encrypted_key: encrypted.encrypted_key,
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv,
        });

        await loadMessages(selectedUser);
    };

    const handleSendFile = async (file: File, caption: string) => {
        if (!selectedUser || !auth?.username) return;

        const envelope = await buildAttachmentEnvelope(file, caption);
        const encrypted = await encryptForConversation(envelope.message, selectedUser, auth.username);

        await sendMessage({
            recipient: selectedUser,
            encrypted_key: encrypted.encrypted_key,
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv,
        });

        await loadMessages(selectedUser);
    };

    const encryptForConversation = async (plaintext: string, recipient: string, sender: string) => {
        const recipientKey = await getPublicKey(recipient);
        const senderPublicKey = getPublicKeyLocal();
        const recipients = [{ username: recipient, publicKey: recipientKey.public_key }];

        if (senderPublicKey) {
            recipients.push({ username: sender, publicKey: senderPublicKey });
        }

        return encryptMessageForRecipients(plaintext, recipients);
    };

    const handleDownloadAttachment = (message: DecryptedMessage) => {
        if (!message.attachment) return;

        const bytes = b64UrlDecode(message.attachment.bytes_b64);
        const blob = new Blob([bytes as BlobPart], { type: message.attachment.mime });
        const url = URL.createObjectURL(blob);

        const a = document.createElement("a");
        a.href = url;
        a.download = message.attachment.name;
        a.click();

        URL.revokeObjectURL(url);
    };

    const handleLogout = async () => {
        await logout();
        clearCryptoStorage();
        clearAuth();
        navigate("/login");
    };

    return (
        <div className="chat-shell">
            <ContactList
                contacts={contacts}
                selected={selectedUser}
                onSelect={setSelectedUser}
                onAdd={handleAddContact}
                onRefresh={loadContacts}
            />

            <div className="chat-main">
                <div className="chat-topbar">
                    <div>
                        <strong>{selectedUser ? selectedUser : "Select a contact"}</strong>
                        <div className="chat-subtitle">
                            Signed in as {auth?.username}
                        </div>
                    </div>

                    <div className="chat-actions">
                        <button className="button button-ghost" onClick={() => selectedUser && loadMessages(selectedUser)} disabled={!selectedUser}>
                            Refresh chat
                        </button>
                        <button className="button button-primary" onClick={handleLogout}>Logout</button>
                    </div>
                </div>

                {loadingMessages && (
                    <div className="loading-strip">
                        Loading messages...
                    </div>
                )}

                <ChatWindow
                    messages={messages}
                    currentUser={auth?.username || ""}
                    onDownloadAttachment={handleDownloadAttachment}
                />

                <MessageComposer
                    disabled={!selectedUser}
                    onSendText={handleSendText}
                    onSendFile={handleSendFile}
                />
            </div>
        </div>
    );
}

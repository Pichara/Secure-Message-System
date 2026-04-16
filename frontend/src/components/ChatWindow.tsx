import { useEffect, useRef } from "react";
import type { DecryptedMessage } from "../types/message";
import { formatTimestamp } from "../utils/time";

interface Props {
  messages: DecryptedMessage[];
  currentUser: string;
  onDownloadAttachment: (m: DecryptedMessage) => void;
}

export default function ChatWindow({ messages, currentUser, onDownloadAttachment }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  return (
    <section className="message-pane" aria-label="Messages">
      {messages.length === 0 && (
        <div className="empty-chat">
          <svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4">
            <path d="M3 6a3 3 0 013-3h12a3 3 0 013 3v9a3 3 0 01-3 3H9l-6 3V6z" />
          </svg>
          <strong>No messages yet</strong>
          <span>Send the first encrypted note.</span>
        </div>
      )}

      {messages.map((message, index) => {
        const isMine = message.sender === currentUser;
        const previous = messages[index - 1];
        const showSenderLabel = !isMine && (!previous || previous.sender !== message.sender);

        return (
          <article
            key={message.id}
            className={`message-row ${isMine ? "message-row-mine" : "message-row-theirs"}`}
          >
            {showSenderLabel && <span className="message-sender">{message.sender}</span>}

            <div className={`message-bubble ${isMine ? "message-bubble-mine" : "message-bubble-theirs"}`}>
              <div className={message.kind === "attachment" ? "message-text message-text-file" : "message-text"}>
                {message.display}
              </div>

              {message.kind === "attachment" && (
                <button className="download-button" onClick={() => onDownloadAttachment(message)}>
                  <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8">
                    <path d="M8 2v9M4 8l4 4 4-4M2 13h12" />
                  </svg>
                  Download
                </button>
              )}
            </div>

            <span className="message-time">{formatTimestamp(message.created_at)}</span>
          </article>
        );
      })}

      <div ref={bottomRef} />
    </section>
  );
}

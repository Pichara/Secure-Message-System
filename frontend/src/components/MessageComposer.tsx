import { useRef, useState } from "react";

interface Props {
  disabled?: boolean;
  onSendText: (text: string) => Promise<void>;
  onSendFile: (file: File, caption: string) => Promise<void>;
}

export default function MessageComposer({ disabled, onSendText, onSendFile }: Props) {
  const [text, setText] = useState("");
  const [caption, setCaption] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [sending, setSending] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSendText = async () => {
    const value = text.trim();
    if (!value || sending) return;
    setSending(true);
    try {
      await onSendText(value);
      setText("");
    } finally {
      setSending(false);
    }
  };

  const handleSendFile = async () => {
    if (!file || sending) return;
    setSending(true);
    try {
      await onSendFile(file, caption);
      setFile(null);
      setCaption("");
      if (fileInputRef.current) fileInputRef.current.value = "";
    } finally {
      setSending(false);
    }
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      handleSendText();
    }
  };

  const clearFile = () => {
    setFile(null);
    setCaption("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const isDisabled = Boolean(disabled || sending);

  return (
    <footer className="composer">
      {file && (
        <div className="file-preview">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M9 2H4a1 1 0 00-1 1v10a1 1 0 001 1h8a1 1 0 001-1V6L9 2z" />
            <path d="M9 2v4h4" />
          </svg>
          <span className="file-name">{file.name}</span>
          <span className="file-size">{(file.size / 1024).toFixed(1)} KB</span>
          <input
            className="caption-input"
            placeholder="Caption"
            value={caption}
            onChange={(event) => setCaption(event.target.value)}
            disabled={isDisabled}
          />
          <button className="button button-primary" onClick={handleSendFile} disabled={isDisabled}>
            {sending ? "Sending..." : "Send file"}
          </button>
          <button className="icon-button" onClick={clearFile} aria-label="Remove attachment">
            <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M4 4l8 8M12 4l-8 8" />
            </svg>
          </button>
        </div>
      )}

      <div className="composer-row">
        <input
          ref={fileInputRef}
          id="file-input"
          type="file"
          disabled={isDisabled}
          onChange={(event) => setFile(event.target.files?.[0] || null)}
          hidden
        />
        <button
          className="icon-button composer-attach"
          onClick={() => fileInputRef.current?.click()}
          disabled={isDisabled}
          title="Attach file"
          aria-label="Attach file"
        >
          <svg width="17" height="17" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M13.5 8.5l-6 6a3.5 3.5 0 01-5-5l7-7a2 2 0 013 3l-6.5 6.5a.75.75 0 01-1-1L11 5" />
          </svg>
        </button>

        <textarea
          className="composer-input"
          disabled={isDisabled}
          placeholder={disabled ? "Select a conversation to start messaging" : "Write a message..."}
          value={text}
          onChange={(event) => setText(event.target.value)}
          onKeyDown={handleKeyDown}
          rows={1}
        />

        <button
          className="send-button"
          onClick={handleSendText}
          disabled={isDisabled || !text.trim()}
          aria-label="Send message"
        >
          <svg width="17" height="17" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M2 8h12M9 3l5 5-5 5" />
          </svg>
        </button>
      </div>
    </footer>
  );
}

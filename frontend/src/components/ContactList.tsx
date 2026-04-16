import type { Contact } from "../types/contact";

interface Props {
  contacts: Contact[];
  selected: string | null;
  onSelect: (username: string) => void;
  onAdd: () => void;
  onRefresh: () => void;
}

export default function ContactList({ contacts, selected, onSelect, onAdd, onRefresh }: Props) {
  return (
    <aside className="contact-panel">
      <div className="brand-row">
        <div className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M2 4a2 2 0 012-2h8a2 2 0 012 2v6a2 2 0 01-2 2H6l-4 2V4z" />
          </svg>
        </div>
        <div>
          <div className="brand-name">Cipher</div>
          <div className="brand-caption">Private messages</div>
        </div>
      </div>

      <div className="contact-toolbar">
        <button className="button button-primary" onClick={onAdd}>
          Add contact
        </button>
        <button className="button button-ghost" onClick={onRefresh}>
          Refresh
        </button>
      </div>

      <div className="contact-list" aria-label="Contacts">
        {contacts.length === 0 && (
          <div className="empty-panel">
            <strong>No contacts yet</strong>
            <span>Add someone by username to start a conversation.</span>
          </div>
        )}

        {contacts.map((contact) => {
          const isSelected = selected === contact.username;
          const label = contact.alias || contact.username;

          return (
            <button
              key={`${contact.alias}-${contact.username}`}
              className={`contact-item ${isSelected ? "contact-item-active" : ""}`}
              onClick={() => onSelect(contact.username)}
            >
              <span className="contact-avatar">{label.charAt(0).toUpperCase()}</span>
              <span className="contact-copy">
                <strong>{label}</strong>
                <span>@{contact.username}</span>
              </span>
            </button>
          );
        })}
      </div>
    </aside>
  );
}

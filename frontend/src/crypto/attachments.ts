import { b64UrlEncode } from "./base64";

export async function buildAttachmentEnvelope(file: File, caption?: string) {
  const bytes = new Uint8Array(await file.arrayBuffer());

  const envelope = {
    kind: "attachment",
    caption: (caption || "").trim(),
    attachment: {
      name: file.name || "attachment.bin",
      mime: file.type || "application/octet-stream",
      size_bytes: bytes.length,
      bytes_b64: b64UrlEncode(bytes),
    },
  };

  return {
    message: JSON.stringify(envelope),
    meta: envelope.attachment,
  };
}

export function parseMessageContent(rawContent: string) {
  try {
    const payload = JSON.parse(rawContent);

    if (!payload || typeof payload !== "object") {
      return { kind: "text" as const, display: rawContent, raw: rawContent };
    }

    if (payload.kind !== "attachment" || !payload.attachment) {
      return { kind: "text" as const, display: rawContent, raw: rawContent };
    }

    const attachment = payload.attachment;
    const display = `[attachment] ${attachment.name} (${attachment.mime}, ${attachment.size_bytes} bytes)${
      payload.caption ? ` caption=${payload.caption}` : ""
    }`;

    return {
      kind: "attachment" as const,
      raw: rawContent,
      display,
      attachment: {
        name: attachment.name,
        mime: attachment.mime,
        size_bytes: attachment.size_bytes,
        bytes_b64: attachment.bytes_b64,
        caption: payload.caption || "",
      },
    };
  } catch {
    return { kind: "text" as const, display: rawContent, raw: rawContent };
  }
}
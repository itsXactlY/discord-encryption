import $ from "jquery";
import crypto from "crypto-js";

import { UserData } from "./config";

type EncryptedMessage = {
  iv: string; // AES-256 IV base64
  ciphertext: string; // AES-256 encrypted ciphertext base64
};

export const PREFIX = "#!aes/";
export const DIVIDER = "$";

export const encrypt = (
  msg: string,
  channelData: UserData["global"]
): EncryptedMessage => {
  // If the message is already encrypted return the msg
  if (isMessageEncrypted(msg))
    return {
      ciphertext: msg,
      iv: crypto.lib.WordArray.random(32).toString(), // TODO get correct iv
    };

  const key = crypto.SHA256(channelData.password);

  // Generate random byte array
  const iv = crypto.lib.WordArray.random(32);

  // Encrypt the message
  const encryptedMessage = crypto.AES.encrypt(msg, key, {
    iv: iv,
    padding: crypto.pad.Iso10126,
  });

  // Return encrypted msg and iv
  return {
    iv: iv.toString(crypto.enc.Base64),
    ciphertext: encryptedMessage.toString(),
  };
};

export const decrypt = (msg: string, channelData: UserData["global"]) => {
  if (isMessageEncrypted(msg)) msg = msg.substring(PREFIX.length);

  // Extract IV and ciphertext
  const [iv, ciphertext] = msg.split(DIVIDER);
  if (!iv || !ciphertext) throw "Error no iv or ciphertext found";

  const key = crypto.SHA256(channelData.password); // TODO key derivation

  // Parse IV to Byte array
  const ivWordArray = crypto.enc.Base64.parse(iv);

  // decrypt the message
  const result = crypto.AES.decrypt(ciphertext, key, {
    iv: ivWordArray,
    padding: crypto.pad.Iso10126,
  });

  // return the decrypted message as string
  return result.toString(crypto.enc.Utf8);
};

export const isMessageEncrypted = (msg: string) => {
  // If the message does not start with our prefix than it's not valid
  return msg.startsWith(PREFIX);
};

//--------------------------------------------------------------------
//--------------------------------------------------------------------

export const decryptAllMessages = (channelData: UserData["global"]) => {
  // Loop all messages
  let markup = $(`div[class*="messageContent"]`);
  if (markup.length == 0) markup = $(`div[id*="message-content"]`);

  $(markup).each(function () {
    try {
      const message = $(this).text().trim();
      if (!isMessageEncrypted(message)) return;

      const decrypted = decrypt(message, channelData);
      if (!decrypted) throw "decryption failed";

      $(this).html(decrypted).addClass("decrypted");
    } catch (e) {
      $(this)
        .html("(failed to decrypt. most likely the wrong password)")
        .addClass("not-decrypted");
    }
  });
};

import { Cipher } from "@fyears/rclone-crypt";

global.window.rcloneCrypt = {
  encrypt: async function (url, password = "", salt = "") {
    const cipher = new Cipher("base32");
    await cipher.key(password, salt);
    const response = await fetch(url);
    const data = await response.arrayBuffer();
    return await cipher.encryptData(new Uint8Array(data));
  },
  encryptPath: async function (path, password = "", salt = "") {
    const cipher = new Cipher("base32");
    await cipher.key(password, salt);
    return await cipher.encryptFileName(path);
  },
  decrypt: async function (url, password = "", salt = "") {
    const cipher = new Cipher("base32");
    await cipher.key(password, salt);
    const response = await fetch(url);
    const data = await response.arrayBuffer();
    return await cipher.decryptData(new Uint8Array(data));
  },
  decryptPath: async function (path, password = "", salt = "") {
    const cipher = new Cipher("base32");
    await cipher.key(password, salt);
    return await cipher.decryptFileName(path);
  },
  type: function (path) {
    let ext = path.split(".").pop();
    let map = {
      pdf: "application/pdf",
      jpg: "image/jpg",
      jpeg: "image/jpeg",
      png: "image/png",
      gif: "image/gif",
      mp4: "video/mp4",
      webm: "video/webm",
    };
    return map[ext] ? map[ext] : "application/octect-stream";
  },
  render: function (data, path = "", save = false, open = false) {
    let blob = new Blob([data], { type: window.rcloneCrypt.type(path) });
    let filename = path.split("/").pop();
    if (window.navigator.msSaveOrOpenBlob) {
      window.navigator.msSaveOrOpenBlob(blob, filename);
    } else {
      const a = document.createElement("a");
      document.body.appendChild(a);
      const url = window.URL.createObjectURL(blob);
      if (!open) {
        return url;
      }
      a.href = url;
      if (save) {
        a.download = filename;
      }
      a.click();
      setTimeout(() => {
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }, 0);
    }
  },
};

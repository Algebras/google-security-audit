import axios from "axios";
import * as Sentry from "@sentry/react";

export default function Login() {
  async function submit(email, password) {
    await fetch("/api/login", { method: "POST", body: JSON.stringify({ email, password }) });
    const me = await axios.get("/api/me");
    return me.data;
  }
  return (
    <form>
      <input type="email" name="email" required />
      <input type="password" name="password" maxLength={64} />
      <textarea name="bio"></textarea>
    </form>
  );
}

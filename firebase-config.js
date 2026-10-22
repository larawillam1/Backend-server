// ---------------------------------------------------------------
// 1) Firebase web app settings (used by the Sign In page)
//    Firebase Console > Project settings > General > Your apps > Web app > Config
// ---------------------------------------------------------------
export const firebaseConfig = {
  apiKey: "PASTE_YOUR_API_KEY",
  authDomain: "PASTE_YOUR_PROJECT_ID.firebaseapp.com",
  projectId: "PASTE_YOUR_PROJECT_ID",
  storageBucket: "PASTE_YOUR_PROJECT_ID.appspot.com",
  messagingSenderId: "PASTE_YOUR_SENDER_ID",
  appId: "PASTE_YOUR_APP_ID"
};

// ---------------------------------------------------------------
// 2) Your OTP backend address (the Render/Railway URL, no trailing slash)
//    Example: "https://topup-otp.onrender.com"
// ---------------------------------------------------------------
export const API_URL = "PASTE_YOUR_BACKEND_URL";

// ---------------------------------------------------------------
// 3) Optional free captcha (Cloudflare Turnstile SITE key).
//    Leave as "" to turn it off. If you set it here, also set
//    TURNSTILE_SECRET on the backend.
// ---------------------------------------------------------------
export const TURNSTILE_SITE_KEY = "";

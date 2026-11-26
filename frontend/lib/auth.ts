import type { UserProfile } from "@/types/qshields";

const TOKEN_STORAGE_KEY = "qshields_access_token";
const USER_STORAGE_KEY = "qshields_user";

export function getAccessToken(): string | null {
  if (typeof window === "undefined") {
    return null;
  }
  return window.localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function getStoredUser(): UserProfile | null {
  if (typeof window === "undefined") {
    return null;
  }
  const raw = window.localStorage.getItem(USER_STORAGE_KEY);
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw) as UserProfile;
  } catch {
    return null;
  }
}

export function setAuthSession(accessToken: string, user: UserProfile): void {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.setItem(TOKEN_STORAGE_KEY, accessToken);
  window.localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
}

export function clearAuthSession(): void {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  window.localStorage.removeItem(USER_STORAGE_KEY);
}
